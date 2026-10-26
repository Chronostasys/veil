package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"veil/internal/logx"
)

// SOCKS5 wire constants (RFC 1928 / RFC 1929).
const (
	socks5Version = 0x05

	socks5AuthNone     = 0x00
	socks5AuthNoAccept = 0xFF

	socks5CmdConnect = 0x01
	socks5CmdBind    = 0x02
	socks5CmdUDP     = 0x03

	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	socks5RepSuccess          = 0x00
	socks5RepGeneralFailure   = 0x01
	socks5RepNotAllowed       = 0x02
	socks5RepNetUnreachable   = 0x03
	socks5RepHostUnreachable  = 0x04
	socks5RepConnRefused      = 0x05
	socks5RepTTLExpired       = 0x06
	socks5RepCmdNotSupported  = 0x07
	socks5RepAtypNotSupported = 0x08

	// handshakeTimeout bounds greeting + request parsing. It is cleared once
	// the request is understood, because after that the connection may relay
	// for an unbounded time.
	handshakeTimeout = 30 * time.Second

	// maxUDPDatagram is the largest UDP payload a relay can see.
	maxUDPDatagram = 65535
)

// errUnsupportedAtyp signals ATYP 0x08 in replies.
var errUnsupportedAtyp = errors.New("unsupported address type")

// listenerBase implements the Server lifecycle shared by every local listener:
// accept loop, connection tracking, idempotent Close and panic recovery.
//
// A handler must be safe to run concurrently; listenerBase starts one goroutine
// per accepted connection and untracks the connection when it returns. The
// handler is responsible for closing the connection (or handing it to the
// Handler, which then owns it).
type listenerBase struct {
	name string
	ln   net.Listener
	log  *logx.Logger

	closeOnce sync.Once
	serveOnce sync.Once
	closed    atomic.Bool
	started   atomic.Bool
	done      chan struct{}

	ctx    context.Context
	cancel context.CancelFunc

	mu   sync.Mutex
	live map[net.Conn]struct{}
}

func newListenerBase(name string, ln net.Listener, log *logx.Logger) listenerBase {
	if log == nil {
		log = logx.New(logx.Info, 128)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return listenerBase{
		name:   name,
		ln:     ln,
		log:    log,
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
		live:   make(map[net.Conn]struct{}),
	}
}

// Name implements Server.
func (b *listenerBase) Name() string { return b.name }

// Addr implements Server.
func (b *listenerBase) Addr() string { return b.ln.Addr().String() }

// Serve accepts connections until the listener fails or Close is called. It
// returns nil for a Close-induced shutdown, the accept error otherwise.
func (b *listenerBase) Serve(handle func(net.Conn)) error {
	b.started.Store(true)
	var err error
	b.serveOnce.Do(func() {
		defer close(b.done)
		err = b.acceptLoop(handle)
	})
	return err
}

func (b *listenerBase) acceptLoop(handle func(net.Conn)) error {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			if b.closed.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		b.track(c)
		go func() {
			defer b.untrack(c)
			defer func() {
				if r := recover(); r != nil {
					b.log.Errorf("%s: panic serving %v: %v", b.name, c.RemoteAddr(), r)
					_ = c.Close()
				}
			}()
			handle(c)
		}()
	}
}

func (b *listenerBase) track(c net.Conn) {
	b.mu.Lock()
	b.live[c] = struct{}{}
	b.mu.Unlock()
}

func (b *listenerBase) untrack(c net.Conn) {
	b.mu.Lock()
	delete(b.live, c)
	b.mu.Unlock()
}

// Close stops accepting, waits for Serve to return and closes every connection
// still tracked (which unblocks long-lived relays). Idempotent.
func (b *listenerBase) Close() error {
	var err error
	b.closeOnce.Do(func() {
		b.closed.Store(true)
		b.cancel()
		err = b.ln.Close()
	})
	if b.started.Load() {
		<-b.done
	}
	b.mu.Lock()
	for c := range b.live {
		_ = c.Close()
	}
	b.mu.Unlock()
	return err
}

// SOCKS5 is a local RFC 1928 listener supporting CONNECT and UDP ASSOCIATE.
type SOCKS5 struct {
	handler Handler
	log     *logx.Logger
	counter
	listenerBase
}

// NewSOCKS5 binds addr and returns a SOCKS5 listener. addr may use port 0.
func NewSOCKS5(addr string, h Handler, log *logx.Logger) (*SOCKS5, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("socks5 listen %s: %w", addr, err)
	}
	s := newSOCKS5(h, log)
	s.listenerBase = newListenerBase("socks", ln, log)
	return s, nil
}

// newSOCKS5 returns a SOCKS5 protocol handler without a listener (used by the
// mixed listener, which owns the accept loop itself).
func newSOCKS5(h Handler, log *logx.Logger) *SOCKS5 {
	if log == nil {
		log = logx.New(logx.Info, 128)
	}
	return &SOCKS5{handler: h, log: log, listenerBase: newListenerBase("socks", nil, log)}
}

// Serve implements Server.
func (s *SOCKS5) Serve() error { return s.listenerBase.Serve(s.serveConn) }

// Close implements Server.
func (s *SOCKS5) Close() error { return s.listenerBase.Close() }

// serveConn runs the SOCKS5 handshake on an already-accepted connection.
func (s *SOCKS5) serveConn(c net.Conn) {
	s.serveBuffered(c, bufio.NewReader(c))
}

// serveBuffered is serveConn with a pre-existing reader, so a mixed listener
// can sniff the first byte without losing it.
func (s *SOCKS5) serveBuffered(c net.Conn, br *bufio.Reader) {
	s.enter()
	defer s.leave()

	handoff := false
	defer func() {
		if !handoff {
			_ = c.Close()
		}
	}()
	if err := s.handle(c, br, &handoff); err != nil {
		s.log.Debugf("socks5 %s: %v", c.RemoteAddr(), err)
	}
}

// handle performs greeting + request and either hands the connection to the
// Handler (handoff=true) or terminates it. It sets *handoff only after the
// Handler took ownership.
func (s *SOCKS5) handle(c net.Conn, br *bufio.Reader, handoff *bool) error {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	source := c.RemoteAddr().String()

	if err := s.greet(c, br); err != nil {
		return err
	}
	cmd, target, rep, err := readRequest(br)
	if err != nil {
		_ = writeReply(c, rep, "", 0)
		return err
	}

	switch cmd {
	case socks5CmdConnect:
		// The Handler dials, so success is the best we can report; a dial
		// failure surfaces as an immediate EOF to the client.
		if err := writeReply(c, socks5RepSuccess, "", 0); err != nil {
			return err
		}
		_ = c.SetDeadline(time.Time{})
		*handoff = true
		if err := s.handler.HandleTCP(s.ctx, c, target, source); err != nil {
			s.log.Debugf("socks5 %s -> %s: %v", source, target, err)
		}
		return nil

	case socks5CmdUDP:
		_ = c.SetDeadline(time.Time{})
		return s.associateUDP(c, br, source)

	case socks5CmdBind:
		_ = writeReply(c, socks5RepCmdNotSupported, "", 0)
		return errors.New("BIND is not supported")

	default:
		_ = writeReply(c, socks5RepCmdNotSupported, "", 0)
		return fmt.Errorf("unsupported command 0x%02x", cmd)
	}
}

// greet performs the method negotiation, accepting only "no authentication".
func (s *SOCKS5) greet(c net.Conn, br *bufio.Reader) error {
	ver, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if ver != socks5Version {
		// Not SOCKS5: no reply is defined, just drop.
		return fmt.Errorf("bad version 0x%02x", ver)
	}
	n, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("read method count: %w", err)
	}
	if n == 0 {
		_ = writeRaw(c, []byte{socks5Version, socks5AuthNoAccept})
		return errors.New("empty method list")
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(br, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}
	if !bytes.Contains(methods, []byte{socks5AuthNone}) {
		_ = writeRaw(c, []byte{socks5Version, socks5AuthNoAccept})
		return errors.New("no acceptable auth method")
	}
	return writeRaw(c, []byte{socks5Version, socks5AuthNone})
}

// readRequest parses the SOCKS5 request header, returning the command, the
// target in host:port form and the reply code to send on failure.
func readRequest(r io.Reader) (cmd byte, target string, rep byte, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, "", socks5RepGeneralFailure, fmt.Errorf("read request: %w", err)
	}
	if hdr[0] != socks5Version {
		return 0, "", socks5RepGeneralFailure, fmt.Errorf("bad request version 0x%02x", hdr[0])
	}
	if hdr[2] != 0x00 {
		return 0, "", socks5RepGeneralFailure, fmt.Errorf("bad reserved byte 0x%02x", hdr[2])
	}
	host, port, err := readAddr(r, hdr[3])
	if err != nil {
		if errors.Is(err, errUnsupportedAtyp) {
			return hdr[1], "", socks5RepAtypNotSupported, err
		}
		return hdr[1], "", socks5RepGeneralFailure, err
	}
	return hdr[1], net.JoinHostPort(host, strconv.Itoa(port)), socks5RepSuccess, nil
}

// readAddr reads an ATYP-prefixed address (the ATYP itself is given) plus port.
func readAddr(r io.Reader, atyp byte) (host string, port int, err error) {
	switch atyp {
	case socks5AtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, fmt.Errorf("read ipv4: %w", err)
		}
		host = net.IP(b[:]).String()
	case socks5AtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, fmt.Errorf("read ipv6: %w", err)
		}
		host = net.IP(b[:]).String()
	case socks5AtypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", 0, fmt.Errorf("read domain length: %w", err)
		}
		if l[0] == 0 {
			return "", 0, errors.New("empty domain name")
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, fmt.Errorf("read domain: %w", err)
		}
		host = string(b)
	default:
		return "", 0, fmt.Errorf("%w 0x%02x", errUnsupportedAtyp, atyp)
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", 0, fmt.Errorf("read port: %w", err)
	}
	return host, int(binary.BigEndian.Uint16(p[:])), nil
}

// writeReply writes a SOCKS5 reply; host="" means 0.0.0.0:0 ("unknown").
func writeReply(w io.Writer, rep byte, host string, port int) error {
	buf := make([]byte, 0, 32)
	buf = append(buf, socks5Version, rep, 0x00)
	if host == "" {
		buf = append(buf, socks5AtypIPv4, 0, 0, 0, 0, 0, 0)
		return writeRaw(w, buf)
	}
	buf = appendAddr(buf, host, port)
	return writeRaw(w, buf)
}

// appendAddr appends an ATYP-tagged address + port to dst.
func appendAddr(dst []byte, host string, port int) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			dst = append(dst, socks5AtypIPv4)
			dst = append(dst, ip4...)
		} else {
			dst = append(dst, socks5AtypIPv6)
			dst = append(dst, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		dst = append(dst, socks5AtypDomain, byte(len(host)))
		dst = append(dst, host...)
	}
	return binary.BigEndian.AppendUint16(dst, uint16(port))
}

func writeRaw(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

// relayBindAddr picks the address the UDP relay should listen on: the local IP
// of the control connection (loopback when the listener is on a wildcard).
func relayBindAddr(local net.Addr) *net.UDPAddr {
	if ta, ok := local.(*net.TCPAddr); ok && ta.IP != nil && !ta.IP.IsUnspecified() {
		return &net.UDPAddr{IP: ta.IP}
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

// associateUDP implements UDP ASSOCIATE: bind a relay, tell the client where it
// is, and keep it alive until the control connection closes.
func (s *SOCKS5) associateUDP(c net.Conn, br *bufio.Reader, source string) error {
	uc, err := net.ListenUDP("udp", relayBindAddr(c.LocalAddr()))
	if err != nil {
		_ = writeReply(c, socks5RepGeneralFailure, "", 0)
		return fmt.Errorf("udp listen: %w", err)
	}
	relay := uc.LocalAddr().(*net.UDPAddr)
	if err := writeReply(c, socks5RepSuccess, relay.IP.String(), relay.Port); err != nil {
		_ = uc.Close()
		return err
	}

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	r := &udpRelay{
		conn:     uc,
		handler:  s.handler,
		log:      s.log,
		stats:    &s.counter,
		clientIP: remoteIP(c.RemoteAddr()),
	}
	go func() { _ = r.run(ctx) }()
	go func() {
		<-ctx.Done()
		_ = uc.Close()
	}()

	s.log.Debugf("socks5 %s: udp associate on %s", source, relay)
	// The association lives as long as the TCP control connection; clients send
	// nothing over it, so this blocks until they close.
	_, _ = io.Copy(io.Discard, br)
	_ = uc.Close()
	return nil
}

// udpRelay forwards SOCKS5-wrapped UDP datagrams between one client and the
// Handler.
type udpRelay struct {
	conn     *net.UDPConn
	handler  Handler
	log      *logx.Logger
	stats    *counter
	clientIP net.IP

	mu     sync.Mutex
	client *net.UDPAddr
}

func (r *udpRelay) run(ctx context.Context) error {
	buf := make([]byte, maxUDPDatagram)
	for {
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		r.handlePacket(ctx, pkt, src)
	}
}

func (r *udpRelay) clientAddr() *net.UDPAddr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.client
}

func (r *udpRelay) setClient(a *net.UDPAddr) {
	r.mu.Lock()
	r.client = a
	r.mu.Unlock()
}

// handlePacket classifies a datagram: from the client (SOCKS5-wrapped, needs a
// handler round-trip) or from a remote peer (forwarded to the client wrapped
// with the sender's address).
func (r *udpRelay) handlePacket(ctx context.Context, pkt []byte, src *net.UDPAddr) {
	client := r.clientAddr()
	if client == nil {
		// First datagram must come from the control connection's host.
		if r.clientIP == nil || !src.IP.Equal(r.clientIP) {
			return
		}
		client = src
		r.setClient(src)
	} else if !src.IP.Equal(client.IP) || src.Port != client.Port {
		out := appendAddr([]byte{0, 0, 0}, src.IP.String(), src.Port)
		out = append(out, pkt...)
		_, _ = r.conn.WriteToUDP(out, client)
		return
	}

	target, payload, err := parseUDPDatagram(pkt)
	if err != nil {
		r.log.Debugf("socks5 udp from %s: %v", src, err)
		return
	}
	reply, err := r.handler.HandleUDP(ctx, payload, target, src.String())
	if err != nil {
		r.log.Debugf("socks5 udp %s -> %s: %v", src, target, err)
		return
	}
	r.stats.udp.Add(1)
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return
	}
	out := appendAddr([]byte{0, 0, 0}, host, p)
	out = append(out, reply...)
	_, _ = r.conn.WriteToUDP(out, client)
}

// parseUDPDatagram strips the SOCKS5 UDP request header (RSV, FRAG, ATYP...).
// Fragmented datagrams are rejected: this relay never reassembles.
func parseUDPDatagram(b []byte) (target string, payload []byte, err error) {
	if len(b) < 4 {
		return "", nil, errors.New("short udp header")
	}
	if b[0] != 0 || b[1] != 0 {
		return "", nil, errors.New("bad udp reserved bytes")
	}
	if b[2] != 0 {
		return "", nil, fmt.Errorf("fragmentation (0x%02x) not supported", b[2])
	}
	rd := bytes.NewReader(b[4:])
	host, port, err := readAddr(rd, b[3])
	if err != nil {
		return "", nil, err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), b[len(b)-rd.Len():], nil
}

func remoteIP(a net.Addr) net.IP {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.IP
	}
	if ua, ok := a.(*net.UDPAddr); ok {
		return ua.IP
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
