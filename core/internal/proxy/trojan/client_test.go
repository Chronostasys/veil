package trojan

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/transport"
)

// newTestClient builds a Client with an injected dialer so the tests can talk
// to the fake server over plain TCP or WebSocket (the real transport.Build adds
// TLS, which is exercised separately).
func newTestClient(t *testing.T, dialer transport.Dialer) *Client {
	t.Helper()
	return &Client{
		tag:      "test",
		password: "password",
		key:      passwordKey("password"),
		dialer:   dialer,
		udp:      true,
	}
}

// wsDialer dials the fake WebSocket server and returns the stream.
type wsDialer struct {
	url string
}

func (d wsDialer) Dial(ctx context.Context) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := websocket.Dial(d.url, "", "http://127.0.0.1/")
		ch <- result{conn, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

func TestClientInterface(t *testing.T) {
	c := newTestClient(t, transport.TCP("127.0.0.1:1"))
	if c.Tag() != "test" || c.Type() != "trojan" {
		t.Fatalf("Tag/Type = %q/%q", c.Tag(), c.Type())
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var _ outbound.PacketOutbound = c
}

func TestDialContextTCPRoundTrip(t *testing.T) {
	srv := startTCP(t, passwordKey("password"))
	c := newTestClient(t, transport.TCP(srv.Addr()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := c.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello trojan")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
	if err := srv.Err(); err != nil {
		t.Fatalf("server: %v", err)
	}
	reqs := srv.Requests()
	if len(reqs) != 1 {
		t.Fatalf("server saw %d requests, want 1", len(reqs))
	}
	if reqs[0].Command != commandTCP || reqs[0].Host != "example.com" || reqs[0].Port != 443 {
		t.Fatalf("server saw %+v", reqs[0])
	}
}

func TestDialContextTCPOverWebSocket(t *testing.T) {
	srv := startWS(t, passwordKey("password"))
	c := newTestClient(t, wsDialer{url: "ws://" + srv.Addr() + "/ws"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := c.DialContext(ctx, "tcp", "1.2.3.4:8080")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	payload := []byte("over websocket")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
	if err := srv.Err(); err != nil {
		t.Fatalf("server: %v", err)
	}
	if reqs := srv.Requests(); len(reqs) != 1 || reqs[0].Host != "1.2.3.4" || reqs[0].Port != 8080 {
		t.Fatalf("server saw %+v", reqs)
	}
}

func TestClientRejectsBadNetwork(t *testing.T) {
	c := newTestClient(t, transport.TCP("127.0.0.1:1"))
	if _, err := c.DialContext(context.Background(), "udp", "1.2.3.4:53"); err == nil {
		t.Fatal("expected error for udp network on DialContext")
	}
	if _, err := c.DialContext(context.Background(), "tcp", ""); err == nil {
		t.Fatal("expected error for empty destination")
	}
}

func TestDialContextDialFailure(t *testing.T) {
	// Nothing listens here.
	c := newTestClient(t, transport.TCP("127.0.0.1:1"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected dial error")
	}
}

// TestDialContextCanceled proves a dead context costs nothing: the dial fails
// before the header is even attempted.
func TestDialContextCanceled(t *testing.T) {
	c := newTestClient(t, transport.TCP("127.0.0.1:1"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected cancellation error")
	}
}

// stubConn records the deadlines the client applies while writing the header.
type stubConn struct {
	net.Conn // nil; only the methods below are used
	mu       sync.Mutex
	deadline []time.Time
	writes   int
}

func (c *stubConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	return len(p), nil
}

func (c *stubConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = append(c.deadline, t)
	return nil
}

func (c *stubConn) Close() error { return nil }

// TestHeaderWriteAppliesContextDeadline checks that ctx's deadline is pushed
// onto the stream for the header write and cleared afterwards, so a stalled
// server cannot wedge a dial.
func TestHeaderWriteAppliesContextDeadline(t *testing.T) {
	sc := &stubConn{}
	c := newTestClient(t, transport.DialerFunc(func(context.Context) (net.Conn, error) { return sc, nil }))

	deadline := time.Now().Add(3 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	if _, err := c.DialContext(ctx, "tcp", "example.com:443"); err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if sc.writes != 1 {
		t.Fatalf("writes = %d, want 1", sc.writes)
	}
	if len(sc.deadline) != 2 {
		t.Fatalf("SetDeadline calls = %d, want 2 (set + clear)", len(sc.deadline))
	}
	if !sc.deadline[0].Equal(deadline) {
		t.Fatalf("deadline = %v, want %v", sc.deadline[0], deadline)
	}
	if !sc.deadline[1].IsZero() {
		t.Fatalf("deadline was not cleared: %v", sc.deadline[1])
	}
}

func TestDialPacketUDPRoundTrip(t *testing.T) {
	srv := startTCP(t, passwordKey("password"))
	c := newTestClient(t, transport.TCP(srv.Addr()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pc, err := c.DialPacket(ctx, "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer pc.Close()

	targets := []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("9.9.9.9:5353"),
		netip.MustParseAddrPort("[2001:db8::1]:1234"),
	}
	for i, target := range targets {
		if err := pc.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
		payload := []byte{byte('a' + i), 0x00, 0xff}
		n, err := pc.WriteTo(payload, target)
		if err != nil {
			t.Fatalf("WriteTo(%v): %v", target, err)
		}
		if n != len(payload) {
			t.Fatalf("WriteTo = %d, want %d", n, len(payload))
		}

		buf := make([]byte, 64)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		if got, want := buf[:n], payload; string(got) != string(want) {
			t.Fatalf("echo = %x, want %x", got, want)
		}
		if src != target {
			t.Fatalf("source = %v, want %v", src, target)
		}
	}

	if err := srv.Err(); err != nil {
		t.Fatalf("server: %v", err)
	}
	reqs := srv.Requests()
	if len(reqs) != 1 || reqs[0].Command != commandUDP {
		t.Fatalf("server saw %+v", reqs)
	}
}

func TestDialPacketWithoutDestination(t *testing.T) {
	srv := startTCP(t, passwordKey("password"))
	c := newTestClient(t, transport.TCP(srv.Addr()))

	pc, err := c.DialPacket(context.Background(), "")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer pc.Close()

	target := netip.MustParseAddrPort("1.1.1.1:53")
	if _, err := pc.WriteTo([]byte("x"), target); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 8)
	if err := pc.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, _, err := pc.ReadFrom(buf); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	reqs := srv.Requests()
	if len(reqs) != 1 || reqs[0].Host != "0.0.0.0" || reqs[0].Port != 0 {
		t.Fatalf("header destination = %+v", reqs)
	}
}

func TestDialPacketUDPDisabled(t *testing.T) {
	c := newTestClient(t, transport.TCP("127.0.0.1:1"))
	c.udp = false
	if _, err := c.DialPacket(context.Background(), "1.1.1.1:53"); err == nil {
		t.Fatal("expected error when UDP is disabled")
	}
}

func TestPacketConnDeadlineAndClose(t *testing.T) {
	srv := startTCP(t, passwordKey("password"))
	c := newTestClient(t, transport.TCP(srv.Addr()))

	pc, err := c.DialPacket(context.Background(), "1.1.1.1:53")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}

	// A deadline in the past must surface as a timeout, not a hang.
	if err := pc.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	buf := make([]byte, 16)
	if _, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatal("expected read timeout")
	} else if !isTimeout(err) {
		t.Fatalf("expected timeout, got %v", err)
	}

	if err := pc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close: %v", err)
	}
	if err := pc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal("second Close should be a no-op")
	}
	if _, err := pc.WriteTo([]byte("x"), netip.MustParseAddrPort("1.1.1.1:53")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo after Close = %v, want net.ErrClosed", err)
	}
	if _, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatal("ReadFrom after Close should fail")
	}
}

func TestPacketConnTruncatesOversizedRead(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	pc := newPacketConn(clientSide)
	defer pc.Close()

	payload := []byte("0123456789")
	frame, err := appendAddrPort(nil, "1.1.1.1", 53)
	if err != nil {
		t.Fatalf("appendAddrPort: %v", err)
	}
	frame = append(frame, 0x00, byte(len(payload)), '\r', '\n')
	frame = append(frame, payload...)

	go func() {
		_, _ = serverSide.Write(frame)
	}()

	small := make([]byte, 4)
	n, addr, err := pc.ReadFrom(small)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != 4 || string(small) != "0123" {
		t.Fatalf("truncated read = %d %q", n, small)
	}
	if addr != netip.MustParseAddrPort("1.1.1.1:53") {
		t.Fatalf("addr = %v", addr)
	}
}

func TestPacketConnRejectsOversizeFrame(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	pc := newPacketConn(clientSide)
	defer pc.Close()

	frame, err := appendAddrPort(nil, "1.1.1.1", 53)
	if err != nil {
		t.Fatalf("appendAddrPort: %v", err)
	}
	frame = append(frame, 0xff, 0xff, '\r', '\n') // 65535 > maxPacketSize
	go func() {
		_, _ = serverSide.Write(frame)
	}()

	if _, _, err := pc.ReadFrom(make([]byte, 16)); !errors.Is(err, ErrOversizePacket) {
		t.Fatalf("err = %v, want ErrOversizePacket", err)
	}
}

func TestPacketConnRejectsBadCRLF(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	pc := newPacketConn(clientSide)
	defer pc.Close()

	frame, err := appendAddrPort(nil, "1.1.1.1", 53)
	if err != nil {
		t.Fatalf("appendAddrPort: %v", err)
	}
	frame = append(frame, 0x00, 0x01, 'x', 'y', 'z')
	go func() {
		_, _ = serverSide.Write(frame)
	}()

	if _, _, err := pc.ReadFrom(make([]byte, 16)); err == nil || !strings.Contains(err.Error(), "CRLF") {
		t.Fatalf("err = %v, want CRLF error", err)
	}
}

func TestNewValidatesNode(t *testing.T) {
	if _, err := New(config.Node{Tag: "t", Type: "trojan", Server: "example.com", Port: 443}); err == nil {
		t.Fatal("expected error for empty password")
	}
	if _, err := New(config.Node{Tag: "t", Type: "trojan", Password: "x", Port: 443}); err == nil {
		t.Fatal("expected error for empty server")
	}
	if _, err := New(config.Node{Tag: "t", Type: "trojan", Password: "x", Server: "h", Port: 0}); err == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestWithTLSDefaults(t *testing.T) {
	n := withTLSDefaults(config.Node{Server: "example.com", Port: 443})
	if n.TLS == nil || !n.TLS.Enabled || n.TLS.ServerName != "example.com" {
		t.Fatalf("nil TLS defaults = %+v", n.TLS)
	}

	n = withTLSDefaults(config.Node{Server: "example.com", TLS: &config.TLS{Enabled: false}})
	if !n.TLS.Enabled || n.TLS.ServerName != "example.com" {
		t.Fatalf("disabled TLS defaults = %+v", n.TLS)
	}

	n = withTLSDefaults(config.Node{Server: "example.com", TLS: &config.TLS{Enabled: true, ServerName: "cdn.example.org"}})
	if n.TLS.ServerName != "cdn.example.org" {
		t.Fatalf("explicit server name was overwritten: %+v", n.TLS)
	}
}

// TestNoGoroutineLeak asserts that a full TCP dial/close cycle leaves no
// goroutines behind. The client itself is goroutine-free, but the transport and
// the packet reader must not spawn any either.
func TestNoGoroutineLeak(t *testing.T) {
	base := runtime.NumGoroutine()

	srv := startTCP(t, passwordKey("password"))
	c := newTestClient(t, transport.TCP(srv.Addr()))

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := c.DialContext(ctx, "tcp", "example.com:443")
			if err != nil {
				t.Errorf("DialContext: %v", err)
				return
			}
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Errorf("write: %v", err)
				return
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Errorf("read: %v", err)
			}
			_ = conn.Close()
		}()
	}
	wg.Wait()

	waitForGoroutines(t, base+2)
}

func isTimeout(err error) bool {
	var ne net.Error
	if ok := errors.As(err, &ne); ok {
		return ne.Timeout()
	}
	return false
}

func waitForGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	t.Fatalf("goroutine leak: have %d, want <= %d\n%s", runtime.NumGoroutine(), want, buf[:n])
}
