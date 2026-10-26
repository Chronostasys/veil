package inbound

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"veil/internal/logx"
)

const (
	// maxHeaderBytes caps the request header block; bigger requests are
	// rejected with 431 instead of buffered without limit.
	maxHeaderBytes = 16 << 10
)

var errHeaderTooLarge = errors.New("http header too large")

// hopByHopHeaders are never forwarded (RFC 7230 §6.1).
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// HTTP is a local proxy listener speaking HTTP/1.1 (CONNECT + absolute-form).
type HTTP struct {
	handler Handler
	log     *logx.Logger
	counter
	listenerBase
}

// NewHTTP binds addr and returns an HTTP proxy listener. addr may use port 0.
func NewHTTP(addr string, h Handler, log *logx.Logger) (*HTTP, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("http listen %s: %w", addr, err)
	}
	p := newHTTP(h, log)
	p.listenerBase = newListenerBase("http", ln, log)
	return p, nil
}

// newHTTP returns an HTTP protocol handler without a listener (used by mixed).
func newHTTP(h Handler, log *logx.Logger) *HTTP {
	if log == nil {
		log = logx.New(logx.Info, 128)
	}
	return &HTTP{handler: h, log: log, listenerBase: newListenerBase("http", nil, log)}
}

// Serve implements Server.
func (p *HTTP) Serve() error { return p.listenerBase.Serve(p.serveConn) }

// Close implements Server.
func (p *HTTP) Close() error { return p.listenerBase.Close() }

func (p *HTTP) serveConn(c net.Conn) {
	p.serveBuffered(c, bufio.NewReader(c))
}

func (p *HTTP) serveBuffered(c net.Conn, br *bufio.Reader) {
	p.enter()
	defer p.leave()

	handoff := false
	defer func() {
		if !handoff {
			_ = c.Close()
		}
	}()
	if err := p.handle(c, br, &handoff); err != nil {
		p.log.Debugf("http %s: %v", c.RemoteAddr(), err)
	}
}

// handle parses one request and hands the connection to the Handler.
func (p *HTTP) handle(c net.Conn, br *bufio.Reader, handoff *bool) error {
	source := c.RemoteAddr().String()
	_ = c.SetReadDeadline(time.Now().Add(handshakeTimeout))

	block, err := readHeaderBlock(br, maxHeaderBytes)
	if err != nil {
		if errors.Is(err, errHeaderTooLarge) {
			_ = writeHTTPError(c, http.StatusRequestHeaderFieldsTooLarge)
		}
		return fmt.Errorf("read request: %w", err)
	}
	_ = c.SetReadDeadline(time.Time{})

	// Re-parse from the raw block; br2 keeps any body bytes buffered in br.
	br2 := bufio.NewReader(io.MultiReader(bytes.NewReader(block), br))
	req, err := http.ReadRequest(br2)
	if err != nil {
		_ = writeHTTPError(c, http.StatusBadRequest)
		return fmt.Errorf("parse request: %w", err)
	}

	if req.Method == http.MethodConnect {
		return p.handleConnect(c, br2, req, source, handoff)
	}
	return p.handleForward(c, br2, req, source, handoff)
}

func (p *HTTP) handleConnect(c net.Conn, br *bufio.Reader, req *http.Request, source string, handoff *bool) error {
	target := req.Host
	if target == "" {
		target = req.URL.Host
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	if err := writeRaw(c, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return fmt.Errorf("write connect response: %w", err)
	}
	hc := &handoffConn{Conn: c, r: br}
	*handoff = true
	if err := p.handler.HandleTCP(p.ctx, hc, target, source); err != nil {
		p.log.Debugf("http connect %s -> %s: %v", source, target, err)
	}
	_ = c.Close()
	return nil
}

func (p *HTTP) handleForward(c net.Conn, br *bufio.Reader, req *http.Request, source string, handoff *bool) error {
	if req.URL == nil || req.URL.Host == "" {
		// Origin-form means the client talked to us as if we were the origin.
		_ = writeHTTPError(c, http.StatusBadRequest)
		return errors.New("origin-form request")
	}
	if req.URL.Scheme != "" && !strings.EqualFold(req.URL.Scheme, "http") {
		_ = writeHTTPError(c, http.StatusBadRequest)
		return fmt.Errorf("unsupported scheme %q", req.URL.Scheme)
	}
	target := req.URL.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "80")
	}

	header := buildForwardHeader(req)
	hc := &handoffConn{Conn: c, r: io.MultiReader(bytes.NewReader(header), br)}
	*handoff = true

	err := p.handler.HandleTCP(p.ctx, hc, target, source)
	if err != nil {
		p.log.Debugf("http %s %s: %v", source, target, err)
		// Nothing reached the client yet: we are still able to report the
		// dial/relay failure ourselves (handoffConn swallowed the Handler's
		// close for exactly this reason).
		if hc.wrote.Load() == 0 {
			_ = writeHTTPError(c, http.StatusBadGateway)
		}
	}
	_ = c.Close()
	return nil
}

// buildForwardHeader re-serialises the request in origin form with hop-by-hop
// headers stripped. Body framing is preserved verbatim: the body bytes are
// relayed untouched, so chunked stays chunked.
func buildForwardHeader(req *http.Request) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	if req.Host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", req.Host)
	}

	drop := make(map[string]bool, len(hopByHopHeaders))
	for _, h := range hopByHopHeaders {
		drop[http.CanonicalHeaderKey(h)] = true
	}
	// Connection lists extra hop-by-hop header names.
	for _, v := range req.Header.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				drop[http.CanonicalHeaderKey(name)] = true
			}
		}
	}
	for name, values := range req.Header {
		canonical := http.CanonicalHeaderKey(name)
		if drop[canonical] || canonical == "Content-Length" {
			continue
		}
		for _, v := range values {
			fmt.Fprintf(&b, "%s: %s\r\n", canonical, v)
		}
	}

	switch {
	case req.ContentLength > 0:
		fmt.Fprintf(&b, "Content-Length: %d\r\n", req.ContentLength)
	case len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked":
		b.WriteString("Transfer-Encoding: chunked\r\n")
	}
	// This listener does not implement upstream keep-alive: ask for a close so
	// the relay terminates when the origin is done.
	b.WriteString("Connection: close\r\n\r\n")
	return b.Bytes()
}

// readHeaderBlock reads bytes up to the blank line that ends the header block,
// never exceeding max. It stops exactly at the delimiter, so nothing of the
// body is consumed.
func readHeaderBlock(br *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		line, err := br.ReadSlice('\n')
		if len(buf)+len(line) > max {
			return nil, errHeaderTooLarge
		}
		buf = append(buf, line...)
		if err == nil {
			if bytes.HasSuffix(buf, []byte("\r\n\r\n")) || bytes.HasSuffix(buf, []byte("\n\n")) {
				return buf, nil
			}
			continue
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return nil, err
	}
}

func writeHTTPError(c net.Conn, code int) error {
	body := http.StatusText(code)
	_, err := fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s", code, body, len(body), body)
	return err
}

// handoffConn is what the Handler receives: reads are served from a prepared
// reader (rewritten headers + buffered body) while writes go to the real
// connection and are counted, so a relay failure can still be reported.
type handoffConn struct {
	net.Conn
	r      io.Reader
	wrote  atomic.Int64
	closed atomic.Bool
}

func (c *handoffConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *handoffConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.wrote.Add(int64(n))
	return n, err
}

// Close is swallowed: a Handler closes the connection when its dial fails, but
// the listener still needs the socket to report a 502. The real close happens
// once HandleTCP returns.
func (c *handoffConn) Close() error {
	c.closed.Store(true)
	return nil
}

// CloseWrite is forwarded so the relay can still half-close the client when the
// upstream is done (the relay type-asserts for this method).
func (c *handoffConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
