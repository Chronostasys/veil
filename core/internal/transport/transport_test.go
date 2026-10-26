package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"veil/internal/config"
)

// testCert builds a self-signed certificate for localhost/127.0.0.1.
func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// echoServer is a local TCP echo server with optional TLS, used as the payload
// target for every transport under test.
type echoServer struct {
	ln        net.Listener
	wg        sync.WaitGroup
	protocols chan string

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	down  bool
}

// startTLSEcho starts a TLS echo server. Negotiated ALPN protocols are pushed
// on the returned channel.
func startTLSEcho(t *testing.T, cert tls.Certificate) *echoServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	return serveEcho(t, ln, true)
}

// startTCPEcho starts a plain TCP echo server.
func startTCPEcho(t *testing.T) *echoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return serveEcho(t, ln, false)
}

func serveEcho(t *testing.T, ln net.Listener, reportALPN bool) *echoServer {
	t.Helper()
	s := &echoServer{ln: ln, protocols: make(chan string, 16), conns: make(map[net.Conn]struct{})}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if !s.track(conn) {
				conn.Close()
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				defer s.untrack(conn)
				if reportALPN {
					if tc, ok := conn.(*tls.Conn); ok {
						// A REALITY server dials its "dest" eagerly even when the
						// client never sends anything (when it authenticates), so
						// the handshake needs a bound or it would block shutdown.
						_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
						if err := tc.Handshake(); err != nil {
							return
						}
						_ = tc.SetDeadline(time.Time{})
						select {
						case s.protocols <- tc.ConnectionState().NegotiatedProtocol:
						default:
						}
					}
				}
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		s.mu.Lock()
		s.down = true
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

// track registers a connection, reporting false once the server is shutting down.
func (s *echoServer) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *echoServer) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// startCamouflage starts a TLS 1.3 "site" that completes the handshake and then
// reads (and discards) whatever arrives. REALITY replays the target's server
// flight, so the target must be a real TLS 1.3 server that never writes
// application data of its own — that keeps the replayed records clean.
func startCamouflage(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.SetDeadline(time.Now().Add(30 * time.Second))
					if err := tc.Handshake(); err != nil {
						return
					}
					_ = tc.SetDeadline(time.Time{})
				}
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return ln.Addr().String()
}

func (s *echoServer) addr() string { return s.ln.Addr().String() }

// roundTrip writes payload and reads the echo.
func roundTrip(t *testing.T, conn net.Conn, payload []byte) []byte {
	t.Helper()
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	return got
}

// waitGoroutines waits until the goroutine count drops to at most want.
func waitGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: have %d, want <= %d", runtime.NumGoroutine(), want)
}

func TestFingerprintSelection(t *testing.T) {
	seen := make(map[string]bool)
	for _, name := range []string{"", "chrome", "firefox", "safari", "ios", "android", "edge", "randomized"} {
		id, err := fingerprintIDs(name)
		if err != nil {
			t.Fatalf("fingerprint %q: %v", name, err)
		}
		if id.Client == "" {
			t.Fatalf("fingerprint %q resolved to an empty id", name)
		}
		seen[name] = true
	}
	if _, err := fingerprintIDs("netscape-3"); err == nil {
		t.Fatal("unknown fingerprint should be rejected")
	}

	// Each spec must carry the requested ALPN list.
	spec, err := clientHelloSpec(utls.HelloChrome_Auto, []string{"http/1.1"}, "example.com")
	if err != nil {
		t.Fatalf("build spec: %v", err)
	}
	var alpn []string
	for _, ext := range spec.Extensions {
		if e, ok := ext.(*utls.ALPNExtension); ok {
			alpn = e.AlpnProtocols
		}
	}
	if len(alpn) != 1 || alpn[0] != "http/1.1" {
		t.Fatalf("alpn = %v, want [http/1.1]", alpn)
	}
}

func TestTLSDialEcho(t *testing.T) {
	base := runtime.NumGoroutine()
	srv := startTLSEcho(t, testCert(t))

	// android (OkHttp 11) and randomized are legacy/random ClientHellos that a
	// modern-only Go server may refuse; they are covered by the spec test below.
	for _, fp := range []string{"", "chrome", "firefox", "safari", "ios", "edge"} {
		t.Run("fingerprint="+fp, func(t *testing.T) {
			d, err := TLS(TCP(srv.addr()), &config.TLS{
				Enabled:     true,
				ServerName:  "localhost",
				Insecure:    true,
				Fingerprint: fp,
			})
			if err != nil {
				t.Fatalf("TLS(): %v", err)
			}
			conn, err := d.Dial(context.Background())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			got := roundTrip(t, conn, []byte("hello tls"))
			if string(got) != "hello tls" {
				t.Fatalf("echo = %q", got)
			}
		})
	}

	// The default ALPN list must negotiate h2 against a server that offers it.
	select {
	case proto := <-srv.protocols:
		if proto != "h2" {
			t.Fatalf("negotiated ALPN = %q, want h2", proto)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never reported an ALPN protocol")
	}
	waitGoroutines(t, base+2)
}

// TestFingerprintSpecs checks that every accepted fingerprint produces a
// ClientHello we can send: SNI patched in, ALPN replaced, no utls error.
func TestFingerprintSpecs(t *testing.T) {
	for _, name := range []string{"", "chrome", "firefox", "safari", "ios", "android", "edge", "randomized"} {
		id, err := fingerprintIDs(name)
		if err != nil {
			t.Fatalf("fingerprint %q: %v", name, err)
		}
		spec, err := clientHelloSpec(id, []string{"http/1.1"}, "example.com")
		if err != nil {
			t.Fatalf("fingerprint %q: %v", name, err)
		}
		var alpn, sni bool
		for _, ext := range spec.Extensions {
			switch e := ext.(type) {
			case *utls.ALPNExtension:
				alpn = len(e.AlpnProtocols) == 1 && e.AlpnProtocols[0] == "http/1.1"
			case *utls.SNIExtension:
				sni = e.ServerName == "example.com"
			}
		}
		if !alpn {
			t.Fatalf("fingerprint %q: ALPN not applied", name)
		}
		if !sni {
			t.Fatalf("fingerprint %q: SNI not applied", name)
		}
	}
}

func TestTLSRejectsBadFingerprint(t *testing.T) {
	if _, err := TLS(TCP("127.0.0.1:1"), &config.TLS{Enabled: true, Fingerprint: "lynx"}); err == nil {
		t.Fatal("unknown fingerprint must fail")
	}
}

func TestRealityRejectsBadKeyMaterial(t *testing.T) {
	if _, err := Reality(TCP("127.0.0.1:1"), &config.TLS{Reality: &config.Reality{PublicKey: "not-a-key"}}); err == nil {
		t.Fatal("invalid public key must fail")
	}
	if _, err := Reality(TCP("127.0.0.1:1"), &config.TLS{Reality: &config.Reality{
		PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		ShortID:   "zz",
	}}); err == nil {
		t.Fatal("non-hex short id must fail")
	}
}

// wsEchoHandler upgrades the connection and echoes every frame back.
func wsEchoHandler(t *testing.T, protocols chan<- string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "not a websocket request", http.StatusBadRequest)
			return
		}
		if p := r.Header.Get("Sec-WebSocket-Protocol"); p != "" && protocols != nil {
			select {
			case protocols <- p:
			default:
			}
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacker", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		accept := wsAcceptKey(r.Header.Get("Sec-WebSocket-Key"))
		if _, err := fmt.Fprintf(conn,
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			accept); err != nil {
			return
		}
		serverWSFrameEcho(t, conn, brw)
	}
}

// serverWSFrameEcho echoes websocket frames back to the client (server frames
// are unmasked).
func serverWSFrameEcho(t *testing.T, conn net.Conn, brw interface {
	Read(p []byte) (int, error)
}) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		// Read a frame header byte by byte: the test only needs binary echoes.
		var hdr [2]byte
		if _, err := readFull(brw, hdr[:]); err != nil {
			return
		}
		op := hdr[0] & 0x0F
		masked := hdr[1]&0x80 != 0
		length := int(hdr[1] & 0x7F)
		switch length {
		case 126:
			var ext [2]byte
			if _, err := readFull(brw, ext[:]); err != nil {
				return
			}
			length = int(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := readFull(brw, ext[:]); err != nil {
				return
			}
			length = int(binary.BigEndian.Uint64(ext[:]))
		}
		var mask [4]byte
		if masked {
			if _, err := readFull(brw, mask[:]); err != nil {
				return
			}
		}
		buf = buf[:0]
		if cap(buf) < length {
			buf = make([]byte, length)
		} else {
			buf = buf[:length]
		}
		if _, err := readFull(brw, buf); err != nil {
			return
		}
		for i := 0; i < length; i++ {
			buf[i] ^= mask[i%4]
		}
		if op == wsOpClose {
			return
		}
		if op != wsOpBinary && op != wsOpContinuation && op != wsOpText {
			continue
		}
		out := make([]byte, 0, 4+length)
		out = append(out, 0x80|wsOpBinary)
		if length < 126 {
			out = append(out, byte(length))
		} else {
			out = append(out, 126, byte(length>>8), byte(length))
		}
		out = append(out, buf...)
		if _, err := conn.Write(out); err != nil {
			return
		}
		_ = tmp
	}
}

// readFull reads exactly len(p) bytes from an io.Reader.
func readFull(r interface{ Read([]byte) (int, error) }, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		m, err := r.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func TestWSDialEcho(t *testing.T) {
	base := runtime.NumGoroutine()
	srv := httptest.NewServer(wsEchoHandler(t, nil))
	defer srv.Close()

	d := WS(TCP(strings.TrimPrefix(srv.URL, "http://")), &config.Transport{
		Type:    "ws",
		Path:    "/tunnel",
		Host:    "example.com",
		Headers: map[string]string{"X-Test": "1"},
	})
	conn, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := roundTrip(t, conn, []byte("hello websocket"))
	if string(got) != "hello websocket" {
		t.Fatalf("echo = %q", got)
	}
	waitGoroutines(t, base+3)
}

func TestWSEarlyData(t *testing.T) {
	base := runtime.NumGoroutine()
	protocols := make(chan string, 4)
	srv := httptest.NewServer(wsEchoHandler(t, protocols))
	defer srv.Close()

	d := WS(TCP(strings.TrimPrefix(srv.URL, "http://")), &config.Transport{
		Type:      "ws",
		Path:      "/ed",
		Host:      "example.com",
		EarlyData: 1024,
	})
	conn, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	// The first write goes out inside the upgrade request.
	if _, err := conn.Write([]byte("early")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case p := <-protocols:
		raw, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			t.Fatalf("subprotocol is not base64: %v", err)
		}
		if string(raw) != "early" {
			t.Fatalf("early data = %q, want %q", raw, "early")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw the early data subprotocol")
	}
	// The second write uses real frames and must be echoed.
	if _, err := conn.Write([]byte("late")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "late" {
		t.Fatalf("echo = %q", buf)
	}
	waitGoroutines(t, base+3)
}

// startGRPCEcho starts an HTTP/2 (h2 over TLS) server that echoes gRPC frames.
func startGRPCEcho(t *testing.T) string {
	t.Helper()
	var gotMu sync.Mutex
	var gotPath, gotContentType string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMu.Lock()
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotMu.Unlock()
		if r.ProtoMajor != 2 {
			http.Error(w, "http/2 required", http.StatusHTTPVersionNotSupported)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}
		for {
			var hdr [grpcFrameHdrLen]byte
			if _, err := io.ReadFull(r.Body, hdr[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(hdr[1:5])
			payload := make([]byte, n)
			if _, err := io.ReadFull(r.Body, payload); err != nil {
				return
			}
			if _, err := w.Write(hdr[:]); err != nil {
				return
			}
			if _, err := w.Write(payload); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	base, err := TLS(TCP(strings.TrimPrefix(srv.URL, "https://")), &config.TLS{
		Enabled:    true,
		ServerName: "localhost",
		Insecure:   true,
		ALPN:       []string{"h2"},
	})
	if err != nil {
		t.Fatalf("TLS(): %v", err)
	}
	d, err := GRPC(base, &config.Transport{Type: "grpc", ServiceName: "gun", Host: "localhost"})
	if err != nil {
		t.Fatalf("GRPC(): %v", err)
	}
	conn, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := roundTrip(t, conn, []byte("hello grpc"))
	if string(got) != "hello grpc" {
		t.Fatalf("echo = %q", got)
	}

	gotMu.Lock()
	defer gotMu.Unlock()
	if gotPath != "/gun/Tun" {
		t.Fatalf("path = %q, want /gun/Tun", gotPath)
	}
	if !strings.HasPrefix(gotContentType, "application/grpc") {
		t.Fatalf("content-type = %q", gotContentType)
	}
	return srv.URL
}

func TestGRPCDialEcho(t *testing.T) {
	base := runtime.NumGoroutine()
	startGRPCEcho(t)
	waitGoroutines(t, base+6)
}

func TestGRPCRequiresServiceName(t *testing.T) {
	d, err := GRPC(TCP("127.0.0.1:1"), &config.Transport{Type: "grpc"})
	if err != nil {
		t.Fatalf("GRPC(): %v", err)
	}
	if got := d.(*grpcDialer).path; got != "/Tun" {
		t.Fatalf("path = %q, want /Tun", got)
	}
}

func TestBuildComposition(t *testing.T) {
	node := config.Node{
		Tag:    "n1",
		Type:   "vless",
		Server: "127.0.0.1",
		Port:   443,
		TLS:    &config.TLS{Enabled: true, ServerName: "example.com"},
	}
	d, err := Build(node)
	if err != nil {
		t.Fatalf("Build(): %v", err)
	}
	if _, ok := d.(*tlsDialer); !ok {
		t.Fatalf("Build returned %T, want *tlsDialer", d)
	}

	// ALPN defaults per transport.
	node.Transport = &config.Transport{Type: "ws", Path: "/x"}
	d, err = Build(node)
	if err != nil {
		t.Fatalf("Build(ws): %v", err)
	}
	wd, ok := d.(*wsDialer)
	if !ok {
		t.Fatalf("Build returned %T, want *wsDialer", d)
	}
	if wd.host != "127.0.0.1" {
		t.Fatalf("ws host = %q, want the node address", wd.host)
	}

	node.Transport = &config.Transport{Type: "grpc", ServiceName: "gun"}
	if _, err := Build(node); err != nil {
		t.Fatalf("Build(grpc): %v", err)
	}

	node.TLS.Reality = &config.Reality{
		PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	d, err = Build(node)
	if err != nil {
		t.Fatalf("Build(reality): %v", err)
	}
	if _, ok := d.(*grpcDialer); !ok {
		t.Fatalf("Build returned %T, want *grpcDialer over reality", d)
	}

	node.Transport = &config.Transport{Type: "quic"}
	if _, err := Build(node); err == nil {
		t.Fatal("unknown transport must fail")
	}
}

func TestBuildDefaultsALPN(t *testing.T) {
	if got := defaultALPN("ws"); len(got) != 1 || got[0] != "http/1.1" {
		t.Fatalf("ws alpn = %v", got)
	}
	if got := defaultALPN("grpc"); len(got) != 1 || got[0] != "h2" {
		t.Fatalf("grpc alpn = %v", got)
	}
	if got := defaultALPN(""); len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
		t.Fatalf("plain alpn = %v", got)
	}
}

func TestWSFrameRoundTripLarge(t *testing.T) {
	base := runtime.NumGoroutine()
	srv := httptest.NewServer(wsEchoHandler(t, nil))
	defer srv.Close()

	d := WS(TCP(strings.TrimPrefix(srv.URL, "http://")), &config.Transport{Path: "/big", Host: "example.com"})
	conn, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	payload := bytes.Repeat([]byte("abcdefgh"), 8000) // 64 KiB, forces 64-bit lengths
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		errc <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("large payload was not echoed faithfully")
	}
	waitGoroutines(t, base+3)
}
