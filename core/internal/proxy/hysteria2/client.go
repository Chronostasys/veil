package hysteria2

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"veil/internal/config"
	"veil/internal/outbound"
)

const (
	// dialTimeout bounds a fresh QUIC handshake plus authentication.
	dialTimeout = 10 * time.Second

	defaultIdleTimeout = 30 * time.Second
	keepAlivePeriod    = 10 * time.Second
)

// errClosed is returned once Close has been called.
var errClosed = errors.New("hysteria2: client closed")

// dialRefusedError means the server answered but refused the target. It is a
// per-request failure, not a connection failure, so the QUIC connection is kept.
type dialRefusedError struct{ msg string }

func (e *dialRefusedError) Error() string {
	return "hysteria2: server refused connection: " + e.msg
}

// Client is one Hysteria2 server. It owns a single lazily established QUIC
// connection shared by all streams and datagram sessions.
type Client struct {
	tag        string
	serverAddr string
	password   string

	tlsConfig  *tls.Config
	quicConfig *quic.Config

	mu      sync.Mutex
	dialMu  sync.Mutex // serialises handshakes so only one runs at a time
	conn    *quic.Conn
	tr      *quic.Transport
	pktConn net.PacketConn
	h3      *h3State
	closed  bool

	// udpDisabled is set when the server's auth response says it does not
	// relay UDP.
	udpDisabled bool

	sessions map[*packetConn]struct{}
}

var (
	_ outbound.Outbound       = (*Client)(nil)
	_ outbound.PacketOutbound = (*Client)(nil)
)

// New builds a Hysteria2 client for n.
//
// Obfuscation is not supported: config.Node has no obfs field, and while
// Hysteria2 deployments may use salamander, guessing the password from Remark
// would be worse than refusing. Nodes with obfs enabled will not work.
func New(n config.Node) (*Client, error) {
	if n.Password == "" {
		return nil, fmt.Errorf("hysteria2 %s: missing password", n.Tag)
	}
	return &Client{
		tag:        n.Tag,
		serverAddr: n.Addr(),
		password:   n.Password,
		tlsConfig:  buildTLSConfig(n),
		quicConfig: buildQUICConfig(),
		sessions:   make(map[*packetConn]struct{}),
	}, nil
}

func buildTLSConfig(n config.Node) *tls.Config {
	// Hysteria2 mandates QUIC + TLS 1.3 with ALPN "h3"; the certificate is
	// usually self-signed, hence the insecure flag.
	cfg := &tls.Config{
		ServerName: n.Server,
		NextProtos: []string{alpnH3},
		MinVersion: tls.VersionTLS13,
	}
	if n.TLS != nil {
		if n.TLS.ServerName != "" {
			cfg.ServerName = n.TLS.ServerName
		}
		cfg.InsecureSkipVerify = n.TLS.Insecure
		// ALPN must still offer h3 first; extra protocols are kept after it.
		cfg.NextProtos = []string{alpnH3}
		for _, p := range n.TLS.ALPN {
			if p != "" && p != alpnH3 {
				cfg.NextProtos = append(cfg.NextProtos, p)
			}
		}
	}
	return cfg
}

func buildQUICConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 defaultIdleTimeout,
		KeepAlivePeriod:                keepAlivePeriod,
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     4 << 20,
		MaxStreamReceiveWindow:         8 << 20,
		InitialConnectionReceiveWindow: 8 << 20,
		MaxConnectionReceiveWindow:     16 << 20,
	}
}

// Tag implements outbound.Outbound.
func (c *Client) Tag() string { return c.tag }

// Type implements outbound.Outbound.
func (c *Client) Type() string { return "hysteria2" }

// Close tears down the QUIC connection and every datagram session.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	sessions := make([]*packetConn, 0, len(c.sessions))
	for s := range c.sessions {
		sessions = append(sessions, s)
	}
	c.sessions = nil
	conn, tr, pkt := c.conn, c.tr, c.pktConn
	c.conn, c.tr, c.pktConn = nil, nil, nil
	c.mu.Unlock()

	for _, s := range sessions {
		_ = s.Close()
	}
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
	if tr != nil {
		_ = tr.Close()
	}
	if pkt != nil {
		_ = pkt.Close()
	}
	return nil
}

// invalidate drops conn if it is still the connection we are using, so the next
// call dials a fresh one.
func (c *Client) invalidate(conn *quic.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != conn {
		return
	}
	c.dropLocked()
}

func (c *Client) dropLocked() {
	conn, tr, pkt := c.conn, c.tr, c.pktConn
	c.conn, c.tr, c.pktConn = nil, nil, nil
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
	if tr != nil {
		_ = tr.Close()
	}
	if pkt != nil {
		_ = pkt.Close()
	}
}

// getConn returns the shared QUIC connection, dialing and authenticating it on
// first use or after a failure.
func (c *Client) getConn(ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errClosed
	}
	if c.conn != nil {
		select {
		case <-c.conn.Context().Done():
			c.dropLocked()
		default:
			conn := c.conn
			c.mu.Unlock()
			return conn, nil
		}
	}
	c.mu.Unlock()

	// Dial without holding the lock would race with other dialers; hold a
	// dedicated mutex so exactly one handshake happens at a time.
	c.dialMu.Lock()
	defer c.dialMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errClosed
	}
	if c.conn != nil {
		select {
		case <-c.conn.Context().Done():
			c.dropLocked()
		default:
			conn := c.conn
			c.mu.Unlock()
			return conn, nil
		}
	}
	c.mu.Unlock()

	conn, tr, pkt, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.CloseWithError(0, "")
		_ = tr.Close()
		_ = pkt.Close()
		return nil, errClosed
	}
	c.conn, c.tr, c.pktConn = conn, tr, pkt
	c.mu.Unlock()
	return conn, nil
}

func (c *Client) dial(ctx context.Context) (*quic.Conn, *quic.Transport, net.PacketConn, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dialTimeout)
		defer cancel()
	}
	serverAddr, err := c.resolveServer(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	pkt, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hysteria2 %s: %w", c.tag, err)
	}
	tr := &quic.Transport{Conn: pkt}
	// quic-go wants an address for the transport; listen on the unspecified
	// address of the same family as the server.
	conn, err := tr.Dial(ctx, serverAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		_ = tr.Close()
		_ = pkt.Close()
		return nil, nil, nil, fmt.Errorf("hysteria2 %s: quic dial %s: %w", c.tag, serverAddr, err)
	}
	if err := c.authenticate(ctx, conn); err != nil {
		_ = conn.CloseWithError(0, "")
		_ = tr.Close()
		_ = pkt.Close()
		return nil, nil, nil, err
	}
	return conn, tr, pkt, nil
}

func (c *Client) resolveServer(ctx context.Context) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(c.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 %s: %w", c.tag, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 %s: bad port %q", c.tag, portStr)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(port))), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 %s: resolve %s: %w", c.tag, host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("hysteria2 %s: no address for %s", c.tag, host)
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ips[0].Unmap(), uint16(port))), nil
}

// authenticate performs the HTTP/3 auth exchange on the freshly dialed
// connection. The request is a plain POST to https://hysteria/auth; the server
// answers 233 when the credential is accepted.
func (c *Client) authenticate(ctx context.Context, conn *quic.Conn) error {
	h3, err := openH3Streams(ctx, conn)
	if err != nil {
		return fmt.Errorf("hysteria2 %s: open h3 streams: %w", c.tag, err)
	}
	fields, err := h3Request(ctx, conn, authHost, authPath, []headerField{
		{headerAuth, c.password},
		// A receive rate of 0 means "unknown"; the server then reports the
		// bandwidth it measures, which we ignore.
		{headerCCRX, "0"},
		{headerPadding, randomPadding(authPaddingMin, authPaddingMax)},
	})
	if err != nil {
		return fmt.Errorf("hysteria2 %s: auth request: %w", c.tag, err)
	}
	status, err := statusOf(fields)
	if err != nil {
		return fmt.Errorf("hysteria2 %s: %w", c.tag, err)
	}
	if status != statusAuth {
		return fmt.Errorf("hysteria2 %s: authentication failed (status %d)", c.tag, status)
	}
	// The server tells us whether it relays UDP; absence means yes.
	if v := headerValue(fields, headerUDPEnabled); v != "" {
		if enabled, perr := strconv.ParseBool(v); perr == nil && !enabled {
			c.udpDisabled = true
		}
	}
	// The HTTP/3 control and QPACK streams must stay open for the lifetime of
	// the connection, so the client owns them.
	c.h3 = h3
	return nil
}

// DialContext opens a proxied TCP stream to address ("host:port").
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("hysteria2 %s: unsupported network %q", c.tag, network)
	}
	addr, err := normalizeAddr(address)
	if err != nil {
		return nil, err
	}
	stream, conn, err := c.openStream(ctx, addr)
	if err != nil {
		return nil, err
	}
	tc := &tcpConn{stream: stream, conn: conn}
	// Opening the stream and waiting for the server's answer can take a while;
	// do not hand out a connection whose caller already gave up.
	if err := ctx.Err(); err != nil {
		_ = tc.Close()
		return nil, err
	}
	return tc, nil
}

func (c *Client) openStream(ctx context.Context, addr string) (*quic.Stream, *quic.Conn, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.getConn(ctx)
		if err != nil {
			return nil, nil, err
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err == nil {
			if err = writeTCPRequest(stream, addr); err == nil {
				err = readTCPResponse(stream)
			}
			if err == nil {
				return stream, conn, nil
			}
			stream.CancelRead(0)
			stream.CancelWrite(0)
		}
		var refused *dialRefusedError
		if errors.As(err, &refused) {
			// The connection is healthy; the request itself was rejected.
			return nil, conn, err
		}
		lastErr = err
		c.invalidate(conn)
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
	}
	return nil, nil, fmt.Errorf("hysteria2 %s: open stream: %w", c.tag, lastErr)
}

// tcpConn adapts a QUIC stream to net.Conn.
type tcpConn struct {
	stream *quic.Stream
	conn   *quic.Conn
}

func (t *tcpConn) Read(p []byte) (int, error)  { return t.stream.Read(p) }
func (t *tcpConn) Write(p []byte) (int, error) { return t.stream.Write(p) }
func (t *tcpConn) Close() error {
	t.stream.CancelRead(0)
	return t.stream.Close()
}

func (t *tcpConn) LocalAddr() net.Addr  { return t.conn.LocalAddr() }
func (t *tcpConn) RemoteAddr() net.Addr { return t.conn.RemoteAddr() }

func (t *tcpConn) SetDeadline(deadline time.Time) error {
	return t.stream.SetDeadline(deadline)
}

func (t *tcpConn) SetReadDeadline(deadline time.Time) error {
	return t.stream.SetReadDeadline(deadline)
}

func (t *tcpConn) SetWriteDeadline(deadline time.Time) error {
	return t.stream.SetWriteDeadline(deadline)
}

// DialPacket opens a UDP session. address is the initial target; Hysteria2
// carries the destination in every datagram, so it is only advisory.
func (c *Client) DialPacket(ctx context.Context, address string) (outbound.PacketConn, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	session := uint32(0)
	for session == 0 {
		b := make([]byte, 4)
		if _, err := randRead(b); err != nil {
			return nil, err
		}
		session = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	pc := &packetConn{
		c:         c,
		conn:      conn,
		sessionID: session,
		frags:     make(map[uint16]*fragState),
		closed:    make(chan struct{}),
		buf:       make([]byte, maxUDPSize),
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errClosed
	}
	c.sessions[pc] = struct{}{}
	c.mu.Unlock()
	return pc, nil
}
