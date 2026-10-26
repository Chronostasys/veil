package hysteria2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"

	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2/hpack"

	"veil/internal/config"
)

// ---------------------------------------------------------------------------
// A small Hysteria2 server: HTTP/3 auth endpoint, TCP stream echo and datagram
// echo, all on one QUIC listener.
// ---------------------------------------------------------------------------

type testServer struct {
	t        *testing.T
	ln       *quic.Listener
	addr     string
	password string

	conns   atomic.Int32
	streams atomic.Int32
	auths   atomic.Int32
	authErr atomic.Int32
}

func newTestServer(t *testing.T, password string) *testServer {
	t.Helper()
	cert := selfSignedCert(t)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpnH3},
		MinVersion:   tls.VersionTLS13,
	}
	pkt, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ln, err := quic.Listen(pkt, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		_ = pkt.Close()
		t.Fatalf("quic listen: %v", err)
	}
	s := &testServer{t: t, ln: ln, addr: ln.Addr().String(), password: password}
	go s.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *testServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept(context.Background())
		if err != nil {
			return
		}
		s.conns.Add(1)
		go s.handleConn(conn)
	}
}

func (s *testServer) handleConn(conn *quic.Conn) {
	go func() {
		// Drain the client's unidirectional HTTP/3 streams.
		for {
			if _, err := conn.AcceptUniStream(context.Background()); err != nil {
				return
			}
		}
	}()
	go s.echoDatagrams(conn)
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		s.streams.Add(1)
		go s.handleStream(stream)
	}
}

func (s *testServer) handleStream(stream *quic.Stream) {
	defer stream.Close()
	vr := quicvarint.NewReader(stream)
	frameType, err := quicvarint.Read(vr)
	if err != nil {
		return
	}
	switch frameType {
	case frameTypeTCPRequest:
		addr, err := readTCPRequestFrom(stream)
		if err != nil {
			return
		}
		_ = addr
		if err := writeTCPResponse(stream, true, ""); err != nil {
			return
		}
		buf := make([]byte, 4096)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if _, werr := stream.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	case frameHeaders:
		s.handleAuthRequest(stream)
	default:
		s.t.Logf("test server: unexpected frame type %#x", frameType)
	}
}

// handleAuthRequest decodes the QPACK header block of the auth request and
// answers 233 when the credential matches.
func (s *testServer) handleAuthRequest(stream *quic.Stream) {
	vr := quicvarint.NewReader(stream)
	length, err := quicvarint.Read(vr)
	if err != nil {
		return
	}
	block := make([]byte, length)
	if _, err := io.ReadFull(stream, block); err != nil {
		return
	}
	fields, err := decodeFieldSection(block)
	if err != nil {
		s.t.Logf("test server: decode request headers: %v", err)
		return
	}
	var status int
	if headerValue(fields, ":path") == authPath && headerValue(fields, headerAuth) == s.password {
		status = statusAuth
		s.auths.Add(1)
	} else {
		status = 401
		s.authErr.Add(1)
	}
	resp := encodeFieldSection([]headerField{
		{":status", fmt.Sprint(status)},
		{headerUDPEnabled, "true"},
	})
	frame := quicvarint.Append(nil, frameHeaders)
	frame = quicvarint.Append(frame, uint64(len(resp)))
	frame = append(frame, resp...)
	_, _ = stream.Write(frame)
}

func readTCPRequestFrom(r io.Reader) (string, error) {
	vr := quicvarint.NewReader(r)
	addrLen, err := quicvarint.Read(vr)
	if err != nil {
		return "", err
	}
	if addrLen == 0 || addrLen > maxAddressLength {
		return "", fmt.Errorf("bad address length %d", addrLen)
	}
	addr := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addr); err != nil {
		return "", err
	}
	padLen, err := quicvarint.Read(vr)
	if err != nil {
		return "", err
	}
	if padLen > maxPaddingLength {
		return "", fmt.Errorf("bad padding length %d", padLen)
	}
	if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
		return "", err
	}
	return string(addr), nil
}

func writeTCPResponse(w io.Writer, ok bool, msg string) error {
	buf := make([]byte, 0, 8+len(msg))
	if ok {
		buf = append(buf, 0)
	} else {
		buf = append(buf, 1)
	}
	buf = quicvarint.Append(buf, uint64(len(msg)))
	buf = append(buf, msg...)
	buf = quicvarint.Append(buf, 0) // padding
	_, err := w.Write(buf)
	return err
}

func (s *testServer) echoDatagrams(conn *quic.Conn) {
	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if _, err := parseUDPMessage(data); err != nil {
			continue
		}
		_ = conn.SendDatagram(data)
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ---------------------------------------------------------------------------
// Client tests
// ---------------------------------------------------------------------------

func serverNode(t *testing.T, srv *testServer, password string) config.Node {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatalf("server addr: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("server port: %v", err)
	}
	return config.Node{
		Tag:      "hy2",
		Type:     "hysteria2",
		Server:   host,
		Port:     port,
		Password: password,
		TLS:      &config.TLS{Enabled: true, Insecure: true},
	}
}

func TestTCPEcho(t *testing.T) {
	srv := newTestServer(t, "s3cret")
	client, err := New(serverNode(t, srv, "s3cret"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello hysteria2")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
	if srv.auths.Load() != 1 {
		t.Fatalf("expected 1 successful auth, got %d", srv.auths.Load())
	}
}

func TestConnectionReuse(t *testing.T) {
	srv := newTestServer(t, "pw")
	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		conn, err := client.DialContext(ctx, "tcp", "1.2.3.4:80")
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		buf := make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		_ = conn.Close()
	}
	if n := srv.conns.Load(); n != 1 {
		t.Fatalf("expected a single QUIC connection, got %d", n)
	}
	if n := srv.auths.Load(); n != 1 {
		t.Fatalf("expected a single auth, got %d", n)
	}
}

func TestAuthFailure(t *testing.T) {
	srv := newTestServer(t, "right-password")
	client, err := New(serverNode(t, srv, "wrong-password"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err = client.DialContext(ctx, "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected an authentication error, got a connection")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("auth failure took too long: %v", elapsed)
	}
	if srv.authErr.Load() == 0 {
		t.Fatal("server never saw the rejected credential")
	}
	t.Logf("auth error: %v", err)
}

func TestCancelledContextFailsFast(t *testing.T) {
	srv := newTestServer(t, "pw")
	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	// An already-cancelled context must fail before any handshake work.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected a context error")
	}
	if srv.conns.Load() != 0 {
		t.Fatalf("expected no QUIC connection, got %d", srv.conns.Load())
	}
}

func TestUDPEcho(t *testing.T) {
	srv := newTestServer(t, "pw")
	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := client.DialPacket(ctx, "")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer pc.Close()

	dst := netip.MustParseAddrPort("8.8.8.8:53")
	if _, err := pc.WriteTo([]byte("dns query"), dst); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if err := pc.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "dns query" {
		t.Fatalf("unexpected payload %q", buf[:n])
	}
	if from != dst {
		t.Fatalf("unexpected source %s", from)
	}
}

func TestUDPFragmentation(t *testing.T) {
	srv := newTestServer(t, "pw")
	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := client.DialPacket(ctx, "")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer pc.Close()

	// 4 KiB definitely exceeds a single QUIC datagram, so the client has to
	// fragment and the server echoes the fragments back.
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	dst := netip.MustParseAddrPort("9.9.9.9:53")
	if _, err := pc.WriteTo(payload, dst); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if err := pc.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	got := make([]byte, 8192)
	n, _, err := pc.ReadFrom(got)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("reassembled %d bytes, want %d", n, len(payload))
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("byte %d mismatch: %d != %d", i, got[i], payload[i])
		}
	}
}

func TestUDPDeadline(t *testing.T) {
	srv := newTestServer(t, "pw")
	client, err := New(serverNode(t, srv, "pw"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := client.DialPacket(ctx, "")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer pc.Close()

	if err := pc.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	buf := make([]byte, 128)
	if _, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatal("expected a timeout")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected a timeout error, got %v", err)
	}
}

func TestInvalidNodes(t *testing.T) {
	cases := []struct {
		name string
		node config.Node
	}{
		{"missing password", config.Node{Tag: "a", Type: "hysteria2", Server: "127.0.0.1", Port: 443}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.node); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestNormalizeAddr(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"example.com:443", "example.com:443", false},
		{"1.2.3.4:80", "1.2.3.4:80", false},
		{"[::1]:8080", "[::1]:8080", false},
		{"::1:8080", "[::1]:8080", false}, // last colon is the port separator
		{"example.com", "", true},
		{"example.com:", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		got, err := normalizeAddr(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeAddr(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeAddr(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestQPackFieldSection pins the encoder/decoder agreement and checks the
// documented byte layout for a static-table match and a literal header.
func TestQPackFieldSection(t *testing.T) {
	fields := []headerField{
		{":method", "POST"},
		{":scheme", "https"},
		{":authority", "hysteria"},
		{":path", "/auth"},
		{headerAuth, "pw"},
		{headerCCRX, "0"},
	}
	block := encodeFieldSection(fields)
	got, err := decodeFieldSection(block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != len(fields) {
		t.Fatalf("field count %d, want %d", len(got), len(fields))
	}
	for i := range fields {
		if got[i] != fields[i] {
			t.Fatalf("field %d = %+v, want %+v", i, got[i], fields[i])
		}
	}
	// ":method: POST" is static entry 20, so it is one indexed field line.
	if block[0] != 0xD4 {
		t.Fatalf("expected indexed field line 0xD4, got %#x", block[0])
	}
	// ":authority" is static entry 0: name reference with a literal value.
	if block[2] != 0x50 {
		t.Fatalf("expected name reference 0x50, got %#x", block[2])
	}
}

func TestHuffmanValueDecoding(t *testing.T) {
	// ":status: 233" encoded as a literal with a Huffman-coded value. The bytes
	// come from x/net/http2/hpack's encoder so the decoder is exercised against
	// an independent implementation.
	var buf []byte
	buf = appendQPACKInt(buf, 25, 4, 0x50) // :status (static 25 = ":status 200")
	dst := hpack.AppendHuffmanString(nil, "233")
	buf = appendQPACKInt(buf, uint64(len(dst)), 7, 0x80)
	buf = append(buf, dst...)
	fields, err := decodeFieldSection(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(fields) != 1 || fields[0].name != ":status" || fields[0].value != "233" {
		t.Fatalf("decoded %+v", fields)
	}
}
