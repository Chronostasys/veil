package vmess

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"veil/internal/config"
	"veil/internal/outbound"
	"veil/internal/transport"
)

// wsDialer dials the fake WebSocket server and hands back the stream.
type wsDialer struct{ url string }

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

// newTestClient builds a client with an injected dialer, so the tests can speak
// to the fake server over plain TCP or WebSocket (transport.Build would add TLS).
func newTestClient(t *testing.T, dialer transport.Dialer) *Client {
	t.Helper()
	id, err := parseUUID(testUUID)
	if err != nil {
		t.Fatalf("parseUUID: %v", err)
	}
	return &Client{
		tag:      "test",
		id:       id,
		key:      cmdKey(id),
		security: securityAES128GCM,
		dialer:   dialer,
		udp:      true,
	}
}

func TestClientInterface(t *testing.T) {
	c := newTestClient(t, transport.TCP("127.0.0.1:1"))
	if c.Tag() != "test" || c.Type() != "vmess" {
		t.Fatalf("Tag/Type = %q/%q", c.Tag(), c.Type())
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var _ outbound.PacketOutbound = c
}

func TestDialContextTCPRoundTrip(t *testing.T) {
	srv := newFakeServer(t, testUUID).startTCP(t)
	c := newTestClient(t, transport.TCP(srv.Addr()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := c.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello vmess aead")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}

	if err := srv.Err(); err != nil {
		t.Fatalf("server: %v", err)
	}
	reqs := srv.Requests()
	if len(reqs) != 1 {
		t.Fatalf("server saw %d requests", len(reqs))
	}
	if r := reqs[0]; r.Command != cmdTCP || r.Host != "example.com" || r.Port != 443 ||
		r.Security != securityAES128GCM || r.Option != optionChunkStream || r.Version != 1 {
		t.Fatalf("server saw %+v", r)
	}
}

func TestDialContextOverWebSocket(t *testing.T) {
	srv := newFakeServer(t, testUUID).startWS(t)
	c := newTestClient(t, wsDialer{url: "ws://" + srv.Addr() + "/vmess"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := c.DialContext(ctx, "tcp", "1.2.3.4:8080")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	payload := []byte("wrapped in websocket")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
	if err := srv.Err(); err != nil {
		t.Fatalf("server: %v", err)
	}
	if r := srv.Requests(); len(r) != 1 || r[0].Host != "1.2.3.4" || r[0].Port != 8080 {
		t.Fatalf("server saw %+v", r)
	}
}

// TestLargePayload exercises multi-chunk framing in both directions.
func TestLargePayload(t *testing.T) {
	srv := newFakeServer(t, testUUID).startTCP(t)
	c := newTestClient(t, transport.TCP(srv.Addr()))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 300*1024)
	for i := range payload {
		payload[i] = byte(i * 7)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := conn.Write(payload); err != nil {
			t.Errorf("write: %v", err)
		}
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	wg.Wait()
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch (%d bytes)", len(got))
	}
}

func TestSecurityChaCha20Poly1305RoundTrip(t *testing.T) {
	srv := newFakeServer(t, testUUID).startTCP(t)
	c := newTestClient(t, transport.TCP(srv.Addr()))
	c.security = securityChaCha20Poly1305

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("chacha")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len("chacha"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "chacha" {
		t.Fatalf("echo = %q", got)
	}
	if r := srv.Requests(); len(r) != 1 || r[0].Security != securityChaCha20Poly1305 {
		t.Fatalf("server saw %+v", r)
	}
}

func TestSecurityNoneRoundTrip(t *testing.T) {
	srv := newFakeServer(t, testUUID).startTCP(t)
	c := newTestClient(t, transport.TCP(srv.Addr()))
	c.security = securityNone

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("cleartext body")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len("cleartext body"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "cleartext body" {
		t.Fatalf("echo = %q", got)
	}
}

// TestServerRejectsWrongUUID proves the auth id really authenticates the user:
// a server configured with another UUID drops the session.
func TestServerRejectsWrongUUID(t *testing.T) {
	srv := newFakeServer(t, "11111111-2222-3333-4444-555555555555").startTCP(t)
	c := newTestClient(t, transport.TCP(srv.Addr()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte("should not arrive")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the session to be rejected")
	}
	if err := srv.Err(); err == nil {
		t.Fatal("server accepted the wrong uuid")
	}
}

func TestDialPacketUDPRoundTrip(t *testing.T) {
	srv := newFakeServer(t, testUUID).startTCP(t)
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
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("echo = %x, want %x", buf[:n], payload)
		}
		if src != target {
			t.Fatalf("source = %v, want %v", src, target)
		}
	}

	if err := srv.Err(); err != nil {
		t.Fatalf("server: %v", err)
	}
	if r := srv.Requests(); len(r) != 1 || r[0].Command != cmdUDP {
		t.Fatalf("server saw %+v", r)
	}
	dsts := srv.DatagramDestinations()
	if len(dsts) != 2 || dsts[0] != "1.1.1.1:53" || dsts[1] != "9.9.9.9:5353" {
		t.Fatalf("server saw datagrams to %v", dsts)
	}
}

func TestDialPacketUDPDisabled(t *testing.T) {
	c := newTestClient(t, transport.TCP("127.0.0.1:1"))
	c.udp = false
	if _, err := c.DialPacket(context.Background(), "1.1.1.1:53"); err == nil {
		t.Fatal("expected error when UDP is disabled")
	}
}

func TestConnDeadlineAndClose(t *testing.T) {
	srv := newFakeServer(t, testUUID).startTCP(t)
	c := newTestClient(t, transport.TCP(srv.Addr()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	// No response is coming: the read must time out instead of hanging.
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected a read timeout")
	} else if !isClosedErr(err) {
		t.Fatalf("expected timeout, got %v", err)
	}

	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close: %v", err)
	}
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("Read after Close should fail")
	}
}

func TestPacketConnClose(t *testing.T) {
	srv := newFakeServer(t, testUUID).startTCP(t)
	c := newTestClient(t, transport.TCP(srv.Addr()))

	pc, err := c.DialPacket(context.Background(), "1.1.1.1:53")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
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
	if _, _, err := pc.ReadFrom(make([]byte, 8)); err == nil {
		t.Fatal("ReadFrom after Close should fail")
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

func TestDialContextCanceled(t *testing.T) {
	c := newTestClient(t, transport.TCP("127.0.0.1:1"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestNewValidatesNode(t *testing.T) {
	base := config.Node{Tag: "v", Type: "vmess", Server: "example.com", Port: 443, UUID: testUUID}

	n := base
	n.UUID = ""
	if _, err := New(n); err == nil {
		t.Fatal("expected error for missing uuid")
	}

	n = base
	n.UUID = "not-a-uuid"
	if _, err := New(n); err == nil {
		t.Fatal("expected error for malformed uuid")
	}

	n = base
	n.Server = ""
	if _, err := New(n); err == nil {
		t.Fatal("expected error for missing server")
	}

	n = base
	n.AlterID = 32
	if _, err := New(n); err == nil {
		t.Fatal("expected error for non-zero alterId")
	}

	n = base
	n.Method = "rc4"
	if _, err := New(n); err == nil {
		t.Fatal("expected error for unsupported method")
	}
}

// TestNoGoroutineLeak asserts a full session lifecycle leaves nothing running.
func TestNoGoroutineLeak(t *testing.T) {
	base := runtime.NumGoroutine()

	srv := newFakeServer(t, testUUID).startTCP(t)
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
			defer conn.Close()
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Errorf("write: %v", err)
				return
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Errorf("read: %v", err)
			}
		}()
	}
	wg.Wait()

	waitForGoroutines(t, base+2)
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
