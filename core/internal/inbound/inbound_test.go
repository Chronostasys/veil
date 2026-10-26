package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"veil/internal/logx"
)

func testLogger() *logx.Logger { return logx.New(logx.Debug, 64) }

// testHandler relays TCP to the target with a real dial and echoes UDP through
// a real datagram round-trip, recording what it was asked to reach.
type testHandler struct {
	mu         sync.Mutex
	targets    []string
	udpTargets []string
	dialErr    error
}

func (h *testHandler) record(target, source string) {
	h.mu.Lock()
	h.targets = append(h.targets, target)
	h.mu.Unlock()
}

func (h *testHandler) lastTarget() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.targets) == 0 {
		return ""
	}
	return h.targets[len(h.targets)-1]
}

func (h *testHandler) HandleTCP(ctx context.Context, conn net.Conn, target, source string) error {
	h.record(target, source)
	if h.dialErr != nil {
		_ = conn.Close()
		return h.dialErr
	}
	up, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		_ = conn.Close()
		return err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, conn)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, up)
		_ = conn.Close()
	}()
	wg.Wait()
	_ = up.Close()
	return nil
}

func (h *testHandler) HandleUDP(ctx context.Context, payload []byte, target, source string) ([]byte, error) {
	h.mu.Lock()
	h.udpTargets = append(h.udpTargets, target)
	h.mu.Unlock()

	c, err := net.Dial("udp", target)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// startEchoTCP starts a local echo server and returns its address.
func startEchoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo tcp: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// startEchoUDP starts a local UDP echo server and returns its address.
func startEchoUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen echo udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

func dialProxy(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", addr, err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return b
}

// socksGreet performs the no-auth greeting.
func socksGreet(t *testing.T, c net.Conn) {
	t.Helper()
	if _, err := c.Write([]byte{socks5Version, 1, socks5AuthNone}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	if got := readN(t, c, 2); !bytes.Equal(got, []byte{socks5Version, socks5AuthNone}) {
		t.Fatalf("greeting reply = %v, want [5 0]", got)
	}
}

// socksRequest builds a request with the given command and address bytes.
func socksRequest(cmd byte, addr ...byte) []byte {
	req := []byte{socks5Version, cmd, 0x00}
	req = append(req, addr...)
	return req
}

func ipv4Addr(hostPort string) []byte {
	host, portStr, _ := net.SplitHostPort(hostPort)
	ip := net.ParseIP(host).To4()
	p, _ := net.LookupPort("tcp", portStr)
	b := []byte{socks5AtypIPv4}
	b = append(b, ip...)
	return binary.BigEndian.AppendUint16(b, uint16(p))
}

// readSocksReply reads a full reply and returns the code and bound address.
func readSocksReply(t *testing.T, c net.Conn) (rep byte, hostPort string) {
	t.Helper()
	hdr := readN(t, c, 4)
	host, port, err := readAddr(c, hdr[3])
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return hdr[1], net.JoinHostPort(host, fmt.Sprint(port))
}

func TestSOCKS5ConnectIPv4(t *testing.T) {
	echo := startEchoTCP(t)
	h := &testHandler{}
	srv, err := NewSOCKS5("127.0.0.1:0", h, testLogger())
	if err != nil {
		t.Fatalf("NewSOCKS5: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Close()

	c := dialProxy(t, srv.Addr())
	socksGreet(t, c)
	if _, err := c.Write(socksRequest(socks5CmdConnect, ipv4Addr(echo)...)); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	if rep, _ := readSocksReply(t, c); rep != socks5RepSuccess {
		t.Fatalf("connect reply = %d, want success", rep)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if got := readN(t, c, 5); string(got) != "hello" {
		t.Fatalf("echo = %q, want hello", got)
	}
	if got := h.lastTarget(); got != echo {
		t.Fatalf("handler target = %q, want %q", got, echo)
	}
}

func TestSOCKS5ConnectDomain(t *testing.T) {
	echo := startEchoTCP(t)
	_, portStr, _ := net.SplitHostPort(echo)
	port, _ := net.LookupPort("tcp", portStr)
	domain := []byte{socks5AtypDomain, byte(len("127.0.0.1"))}
	domain = append(domain, "127.0.0.1"...)
	domain = binary.BigEndian.AppendUint16(domain, uint16(port))

	h := &testHandler{}
	srv, err := NewSOCKS5("127.0.0.1:0", h, testLogger())
	if err != nil {
		t.Fatalf("NewSOCKS5: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Close()

	c := dialProxy(t, srv.Addr())
	socksGreet(t, c)
	if _, err := c.Write(socksRequest(socks5CmdConnect, domain...)); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	if rep, _ := readSocksReply(t, c); rep != socks5RepSuccess {
		t.Fatalf("connect reply = %d, want success", rep)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if got := readN(t, c, 4); string(got) != "ping" {
		t.Fatalf("echo = %q, want ping", got)
	}
	if got := h.lastTarget(); got != echo {
		t.Fatalf("handler target = %q, want %q", got, echo)
	}
}

func TestSOCKS5UDPAssociate(t *testing.T) {
	echoUDP := startEchoUDP(t)
	h := &testHandler{}
	srv, err := NewSOCKS5("127.0.0.1:0", h, testLogger())
	if err != nil {
		t.Fatalf("NewSOCKS5: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Close()

	c := dialProxy(t, srv.Addr())
	socksGreet(t, c)
	udpReq := []byte{socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(socksRequest(socks5CmdUDP, udpReq...)); err != nil {
		t.Fatalf("write udp associate: %v", err)
	}
	rep, relayAddr := readSocksReply(t, c)
	if rep != socks5RepSuccess {
		t.Fatalf("udp associate reply = %d, want success", rep)
	}

	uc, err := net.Dial("udp", relayAddr)
	if err != nil {
		t.Fatalf("dial relay %s: %v", relayAddr, err)
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(5 * time.Second))

	pkt := []byte{0, 0, 0}
	pkt = append(pkt, ipv4Addr(echoUDP)...)
	pkt = append(pkt, []byte("udp-payload")...)
	if _, err := uc.Write(pkt); err != nil {
		t.Fatalf("write datagram: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := uc.Read(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	gotTarget, payload, err := parseUDPDatagram(buf[:n])
	if err != nil {
		t.Fatalf("parse reply datagram: %v", err)
	}
	if gotTarget != echoUDP {
		t.Fatalf("reply target = %q, want %q", gotTarget, echoUDP)
	}
	if string(payload) != "udp-payload" {
		t.Fatalf("reply payload = %q, want udp-payload", payload)
	}
	h.mu.Lock()
	seen := len(h.udpTargets)
	h.mu.Unlock()
	if seen != 1 {
		t.Fatalf("handler saw %d udp datagrams, want 1", seen)
	}

	// Closing the control connection must tear the association down.
	_ = c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Active() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("udp association still active after control conn closed: %d", srv.Active())
}

func TestSOCKS5Malformed(t *testing.T) {
	h := &testHandler{}
	srv, err := NewSOCKS5("127.0.0.1:0", h, testLogger())
	if err != nil {
		t.Fatalf("NewSOCKS5: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Close()

	t.Run("no acceptable method", func(t *testing.T) {
		c := dialProxy(t, srv.Addr())
		if _, err := c.Write([]byte{socks5Version, 1, 0x02}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		if got := readN(t, c, 2); !bytes.Equal(got, []byte{socks5Version, socks5AuthNoAccept}) {
			t.Fatalf("reply = %v, want [5 255]", got)
		}
	})

	t.Run("wrong version", func(t *testing.T) {
		c := dialProxy(t, srv.Addr())
		if _, err := c.Write([]byte{0x04, 1, 0x00}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var one [1]byte
		if _, err := c.Read(one[:]); err == nil {
			t.Fatal("connection stayed open after bad version")
		}
	})

	t.Run("bind unsupported", func(t *testing.T) {
		c := dialProxy(t, srv.Addr())
		socksGreet(t, c)
		if _, err := c.Write(socksRequest(socks5CmdBind, ipv4Addr("127.0.0.1:80")...)); err != nil {
			t.Fatalf("write bind: %v", err)
		}
		if rep, _ := readSocksReply(t, c); rep != socks5RepCmdNotSupported {
			t.Fatalf("reply = %d, want %d", rep, socks5RepCmdNotSupported)
		}
	})

	t.Run("atyp unsupported", func(t *testing.T) {
		c := dialProxy(t, srv.Addr())
		socksGreet(t, c)
		bad := []byte{socks5Version, socks5CmdConnect, 0x00, 0x09, 0, 0}
		if _, err := c.Write(bad); err != nil {
			t.Fatalf("write request: %v", err)
		}
		hdr := readN(t, c, 4)
		if hdr[1] != socks5RepAtypNotSupported {
			t.Fatalf("reply = %d, want %d", hdr[1], socks5RepAtypNotSupported)
		}
	})
}

func TestHTTPConnect(t *testing.T) {
	echo := startEchoTCP(t)
	h := &testHandler{}
	srv, err := NewHTTP("127.0.0.1:0", h, testLogger())
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Close()

	c := dialProxy(t, srv.Addr())
	br := bufio.NewReader(c)
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo, echo)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read connect status: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("status line = %q, want 200", line)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	// The echo server must be reachable through the tunnel, with the reader
	// preserved across the handoff.
	if _, err := c.Write([]byte("tunnel")); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}
	if got := readN(t, c, 6); string(got) != "tunnel" {
		t.Fatalf("echo = %q, want tunnel", got)
	}
	if got := h.lastTarget(); got != echo {
		t.Fatalf("handler target = %q, want %q", got, echo)
	}
}

func TestHTTPAbsoluteForm(t *testing.T) {
	var (
		mu       sync.Mutex
		seenPath string
		seenHop  string
		seenHost string
	)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenPath = r.URL.Path
		seenHop = r.Header.Get("Proxy-Connection")
		seenHost = r.Host
		mu.Unlock()
		_, _ = io.WriteString(w, "hello-http")
	}))
	defer origin.Close()

	h := &testHandler{}
	srv, err := NewHTTP("127.0.0.1:0", h, testLogger())
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Close()

	c := dialProxy(t, srv.Addr())
	fmt.Fprintf(c, "GET %s/x?q=1 HTTP/1.1\r\nHost: %s\r\n"+
		"Proxy-Connection: keep-alive\r\nX-Test: 1\r\nAccept: */*\r\n\r\n",
		origin.URL, strings.TrimPrefix(origin.URL, "http://"))

	req, _ := http.NewRequest("GET", origin.URL+"/x?q=1", nil)
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "hello-http" {
		t.Fatalf("body = %q, want hello-http", body)
	}
	mu.Lock()
	defer mu.Unlock()
	if seenPath != "/x" {
		t.Fatalf("origin path = %q, want /x", seenPath)
	}
	if seenHop != "" {
		t.Fatalf("Proxy-Connection leaked to origin: %q", seenHop)
	}
	if seenHost == "" {
		t.Fatal("Host header missing at origin")
	}
}

func TestHTTPConnectDialFailure(t *testing.T) {
	// Reserve a port and close it so the dial is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	h := &testHandler{}
	srv, err := NewHTTP("127.0.0.1:0", h, testLogger())
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Close()

	c := dialProxy(t, srv.Addr())
	br := bufio.NewReader(c)
	fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", deadAddr, deadAddr)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestHTTPHeaderTooLarge(t *testing.T) {
	h := &testHandler{}
	srv, err := NewHTTP("127.0.0.1:0", h, testLogger())
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Close()

	c := dialProxy(t, srv.Addr())
	br := bufio.NewReader(c)
	fmt.Fprintf(c, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Big: %s\r\n\r\n",
		strings.Repeat("a", maxHeaderBytes))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want 431", resp.StatusCode)
	}
}

func TestMixedSniffing(t *testing.T) {
	echo := startEchoTCP(t)
	h := &testHandler{}
	srv, err := NewMixed("127.0.0.1:0", h, testLogger())
	if err != nil {
		t.Fatalf("NewMixed: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Close()

	if srv.Name() != "mixed" {
		t.Fatalf("name = %q, want mixed", srv.Name())
	}
	if srv.Addr() == "" || srv.Addr() != srv.Addr() {
		t.Fatal("mixed addr not stable")
	}

	t.Run("socks5", func(t *testing.T) {
		c := dialProxy(t, srv.Addr())
		socksGreet(t, c)
		if _, err := c.Write(socksRequest(socks5CmdConnect, ipv4Addr(echo)...)); err != nil {
			t.Fatalf("write connect: %v", err)
		}
		if rep, _ := readSocksReply(t, c); rep != socks5RepSuccess {
			t.Fatalf("connect reply = %d, want success", rep)
		}
		if _, err := c.Write([]byte("mixed")); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		if got := readN(t, c, 5); string(got) != "mixed" {
			t.Fatalf("echo = %q, want mixed", got)
		}
	})

	t.Run("http", func(t *testing.T) {
		c := dialProxy(t, srv.Addr())
		br := bufio.NewReader(c)
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo, echo)
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read status: %v", err)
		}
		if !strings.Contains(line, "200") {
			t.Fatalf("status line = %q, want 200", line)
		}
	})

	if got := srv.Accepted(); got < 2 {
		t.Fatalf("Accepted = %d, want >= 2", got)
	}
	if got := srv.Stats(); got < 2 {
		t.Fatalf("Stats = %d, want >= 2", got)
	}
}

func TestCloseUnblocksServe(t *testing.T) {
	h := &testHandler{}
	srv, err := NewSOCKS5("127.0.0.1:0", h, testLogger())
	if err != nil {
		t.Fatalf("NewSOCKS5: %v", err)
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve() }()

	// Make sure the accept loop is running.
	c := dialProxy(t, srv.Addr())
	_ = c.Close()

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
	// Idempotent.
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestConcurrentConnections(t *testing.T) {
	echo := startEchoTCP(t)
	h := &testHandler{}
	srv, err := NewMixed("127.0.0.1:0", h, testLogger())
	if err != nil {
		t.Fatalf("NewMixed: %v", err)
	}
	go func() { _ = srv.Serve() }()
	defer srv.Close()

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", srv.Addr(), 3*time.Second)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.Write([]byte{socks5Version, 1, socks5AuthNone}); err != nil {
				errs <- err
				return
			}
			if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
				errs <- err
				return
			}
			if _, err := c.Write(socksRequest(socks5CmdConnect, ipv4Addr(echo)...)); err != nil {
				errs <- err
				return
			}
			if _, err := io.ReadFull(c, make([]byte, 10)); err != nil {
				errs <- err
				return
			}
			msg := fmt.Sprintf("worker-%d", i)
			if _, err := c.Write([]byte(msg)); err != nil {
				errs <- err
				return
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(c, got); err != nil {
				errs <- err
				return
			}
			if string(got) != msg {
				errs <- fmt.Errorf("echo = %q, want %q", got, msg)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent connection: %v", err)
		}
	}
}
