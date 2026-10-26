package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"veil/internal/config"
)

// gRPC transport, Xray flavour: one HTTP/2 stream per connection, POST
// /<service>/Tun, and every Write becomes a length-prefixed gRPC message
// (1 flag byte + 4-byte big-endian length).
const (
	grpcContentType = "application/grpc"
	grpcFrameHdrLen = 5
	grpcMaxMessage  = 4 << 20 // Xray hunks are far smaller; this is a sanity cap
)

// GRPC returns a Dialer tunnelling through gRPC on the stream from base.
func GRPC(base Dialer, cfg *config.Transport) (Dialer, error) {
	if base == nil {
		return nil, errors.New("transport: grpc needs a base dialer")
	}
	c := config.Transport{}
	if cfg != nil {
		c = *cfg
	}
	// Xray's newer config format packs the stream name into the path
	// ("/service|multi/Tun"); only the last segment names the Tun method.
	service := c.ServiceName
	if strings.HasPrefix(service, "/") {
		parts := strings.Split(strings.TrimPrefix(service, "/"), "/")
		last := parts[len(parts)-1]
		if i := strings.Index(last, "|"); i >= 0 {
			last = last[:i]
		}
		service = last
	}
	path := "/Tun"
	if s := strings.Trim(service, "/"); s != "" {
		path = "/" + url.PathEscape(s) + "/Tun"
	}
	authority := c.Host
	if authority == "" {
		authority = headerValue(c.Headers, "Host")
	}
	if authority == "" {
		authority = "localhost"
	}
	return &grpcDialer{base: base, cfg: c, path: path, authority: authority}, nil
}

type grpcDialer struct {
	base      Dialer
	cfg       config.Transport
	path      string
	authority string
}

// Dial implements Dialer.
func (d *grpcDialer) Dial(ctx context.Context) (net.Conn, error) {
	raw, err := d.base.Dial(ctx)
	if err != nil {
		return nil, err
	}
	header := http.Header{
		"Content-Type": []string{grpcContentType},
		"Te":           []string{"trailers"},
		"User-Agent":   []string{"grpc-go/1.62.0"},
	}
	for k, v := range d.cfg.Headers {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Type") {
			continue
		}
		header.Set(k, v)
	}

	// The HTTP/2 stream owns the socket from here on; a failed handshake must
	// close it so no goroutine is left reading a dead stream.
	stream, err := dialH2Stream(raw, http.MethodPost, d.authority, d.path, header)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("transport: grpc %s%s: %w", d.authority, d.path, err)
	}
	if ct := stream.Headers().Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, grpcContentType) {
		stream.Close()
		return nil, fmt.Errorf("transport: grpc unexpected content-type %q", ct)
	}
	return &grpcConn{stream: stream, raw: raw}, nil
}

// grpcConn adapts a gRPC stream to net.Conn.
type grpcConn struct {
	stream *h2Stream
	raw    net.Conn

	wmu sync.Mutex

	rmu     sync.Mutex
	buf     []byte
	readErr error
}

// Write implements net.Conn: one gRPC message per call.
func (c *grpcConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > grpcMaxMessage {
		return 0, fmt.Errorf("transport: grpc message too large (%d bytes)", len(p))
	}
	frame := make([]byte, grpcFrameHdrLen+len(p))
	frame[0] = 0 // not compressed
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(p)))
	copy(frame[grpcFrameHdrLen:], p)

	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.stream.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read implements net.Conn by stripping the gRPC message header.
func (c *grpcConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		if len(c.buf) > 0 {
			n := copy(p, c.buf)
			c.buf = c.buf[n:]
			return n, nil
		}
		if c.readErr != nil {
			return 0, c.readErr
		}
		payload, err := c.readMessage()
		if err != nil {
			c.readErr = err
			return 0, err
		}
		if len(payload) == 0 {
			continue
		}
		c.buf = payload
	}
}

// readMessage reads one length-prefixed gRPC message. The caller holds rmu.
func (c *grpcConn) readMessage() ([]byte, error) {
	var hdr [grpcFrameHdrLen]byte
	if _, err := io.ReadFull(c.stream, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// A truncated message means the stream died mid-frame.
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length > grpcMaxMessage {
		return nil, fmt.Errorf("transport: grpc message too large (%d bytes)", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.stream, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// Close implements net.Conn.
func (c *grpcConn) Close() error {
	return c.stream.Close()
}

func (c *grpcConn) LocalAddr() net.Addr  { return c.raw.LocalAddr() }
func (c *grpcConn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// Deadline support: HTTP/2 has no per-stream deadline, so a deadline is applied
// to the underlying socket. An expired deadline therefore ends the whole stream
// (the reader goroutine sees the timeout and shuts the connection down), which
// is the behaviour callers expect from a proxy stream.
func (c *grpcConn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

func (c *grpcConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *grpcConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
