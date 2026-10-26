package vless

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
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
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"veil/internal/config"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// --- header unit tests -------------------------------------------------------

func TestRequestHeaderRoundTrip(t *testing.T) {
	user, err := parseUUID(testUUID)
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	cases := []struct {
		name    string
		header  requestHeader
		wantLen int
	}{
		{
			name:   "ipv4/tcp",
			header: requestHeader{User: user, Command: commandTCP, Address: netip.MustParseAddr("1.2.3.4"), Port: 443},
		},
		{
			name:   "domain/tcp",
			header: requestHeader{User: user, Command: commandTCP, Domain: "example.com", Port: 80},
		},
		{
			name:   "ipv6/tcp",
			header: requestHeader{User: user, Command: commandTCP, Address: netip.MustParseAddr("2001:db8::1"), Port: 8080},
		},
		{
			name:   "ipv4/udp",
			header: requestHeader{User: user, Command: commandUDP, Address: netip.MustParseAddr("8.8.8.8"), Port: 53},
		},
		{
			name:   "domain/udp",
			header: requestHeader{User: user, Command: commandUDP, Domain: "dns.example", Port: 5353},
		},
		{
			name:   "vision/domain",
			header: requestHeader{User: user, Flow: FlowVision, Command: commandTCP, Domain: "www.example.org", Port: 443},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.header.encode()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, err := decodeRequestHeader(encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.User != tc.header.User {
				t.Fatalf("user = %x", got.User)
			}
			if got.Command != tc.header.Command {
				t.Fatalf("command = %d, want %d", got.Command, tc.header.Command)
			}
			if got.Port != tc.header.Port {
				t.Fatalf("port = %d, want %d", got.Port, tc.header.Port)
			}
			if got.Domain != tc.header.Domain {
				t.Fatalf("domain = %q, want %q", got.Domain, tc.header.Domain)
			}
			if got.Address != tc.header.Address {
				t.Fatalf("address = %v, want %v", got.Address, tc.header.Address)
			}
			if got.Flow != tc.header.Flow {
				t.Fatalf("flow = %q, want %q", got.Flow, tc.header.Flow)
			}
		})
	}
}

func TestHeaderAddressEncoding(t *testing.T) {
	user, _ := parseUUID(testUUID)

	v4, err := requestHeader{User: user, Command: commandTCP, Address: netip.MustParseAddr("1.2.3.4"), Port: 443}.encode()
	if err != nil {
		t.Fatalf("encode ipv4: %v", err)
	}
	// version(1) + uuid(16) + addons len(1) + command(1) + port(2) = 21
	if got := v4[21]; got != addrIPv4 {
		t.Fatalf("address type = %d, want %d (IPv4)", got, addrIPv4)
	}
	if !bytes.Equal(v4[22:26], []byte{1, 2, 3, 4}) {
		t.Fatalf("ipv4 bytes = %v", v4[22:26])
	}

	v6, err := requestHeader{User: user, Command: commandTCP, Address: netip.MustParseAddr("2001:db8::1"), Port: 443}.encode()
	if err != nil {
		t.Fatalf("encode ipv6: %v", err)
	}
	if got := v6[21]; got != addrIPv6 {
		t.Fatalf("address type = %d, want %d (IPv6)", got, addrIPv6)
	}
	if len(v6) != 21+1+16 {
		t.Fatalf("ipv6 header length = %d", len(v6))
	}

	dom, err := requestHeader{User: user, Command: commandTCP, Domain: "example.com", Port: 443}.encode()
	if err != nil {
		t.Fatalf("encode domain: %v", err)
	}
	if got := dom[21]; got != addrDomain {
		t.Fatalf("address type = %d, want %d (domain)", got, addrDomain)
	}
	if got := int(dom[22]); got != len("example.com") {
		t.Fatalf("domain length = %d", got)
	}
	if string(dom[23:]) != "example.com" {
		t.Fatalf("domain = %q", dom[23:])
	}
}

func TestVisionFlowAddons(t *testing.T) {
	user, _ := parseUUID(testUUID)
	hdr, err := requestHeader{User: user, Flow: FlowVision, Command: commandTCP, Domain: "example.com", Port: 443}.encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	addonsLen := int(hdr[17])
	if addonsLen == 0 {
		t.Fatal("flow=vision must produce addons")
	}
	body := hdr[18 : 18+addonsLen]
	// protobuf: tag 0x0A (field 1, wire type 2), length, "xtls-rprx-vision"
	if body[0] != 0x0A {
		t.Fatalf("addons tag = %#x, want 0x0A", body[0])
	}
	if int(body[1]) != len(FlowVision) || string(body[2:]) != FlowVision {
		t.Fatalf("addons body = %q", body)
	}
	decoded, err := decodeRequestHeader(hdr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Flow != FlowVision {
		t.Fatalf("decoded flow = %q, want %q", decoded.Flow, FlowVision)
	}

	// Without a flow the addons section is a single zero byte.
	plain, err := requestHeader{User: user, Command: commandTCP, Domain: "example.com", Port: 443}.encode()
	if err != nil {
		t.Fatalf("encode plain: %v", err)
	}
	if plain[17] != 0 {
		t.Fatalf("addons length = %d, want 0", plain[17])
	}
	if plain[18] != commandTCP {
		t.Fatalf("command offset is wrong: %d", plain[18])
	}
}

func TestResponseHeader(t *testing.T) {
	enc, err := encodeResponseHeader(addons{})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(enc, []byte{0, 0}) {
		t.Fatalf("response header = %v, want [0 0]", enc)
	}
	if _, err := readResponseHeader(bytes.NewReader(enc)); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := readResponseHeader(bytes.NewReader([]byte{1, 0})); err == nil {
		t.Fatal("non-zero response version must fail")
	}
	if _, err := readResponseHeader(bytes.NewReader([]byte{0})); err == nil {
		t.Fatal("truncated response header must fail")
	}
}

func TestParseUUID(t *testing.T) {
	want, err := parseUUID(testUUID)
	if err != nil {
		t.Fatalf("dashed uuid: %v", err)
	}
	bare, err := parseUUID(strings.ReplaceAll(testUUID, "-", ""))
	if err != nil {
		t.Fatalf("bare uuid: %v", err)
	}
	if want != bare {
		t.Fatal("dashed and bare uuid must decode identically")
	}
	if _, err := parseUUID("nope"); err == nil {
		t.Fatal("invalid uuid must fail")
	}
	if _, err := parseUUID("zzzzzzzz-6324-4d53-ad4f-8cda48b30811"); err == nil {
		t.Fatal("non-hex uuid must fail")
	}
}

func TestDestination(t *testing.T) {
	ip, domain, port, err := destination("example.com:443")
	if err != nil || domain != "example.com" || port != 443 || ip.IsValid() {
		t.Fatalf("domain destination = %v %q %d %v", ip, domain, port, err)
	}
	ip, domain, port, err = destination("[2001:db8::1]:8080")
	if err != nil || domain != "" || port != 8080 || ip != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("ipv6 destination = %v %q %d %v", ip, domain, port, err)
	}
	if _, _, _, err := destination("example.com"); err == nil {
		t.Fatal("missing port must fail")
	}
	if _, _, _, err := destination("example.com:0"); err == nil {
		t.Fatal("port 0 must fail")
	}
}

// --- test VLESS server -------------------------------------------------------

// readHeaderStream parses a VLESS request header from a stream.
func readHeaderStream(r *bufio.Reader) (requestHeader, error) {
	var h requestHeader
	head := make([]byte, 18)
	if _, err := io.ReadFull(r, head); err != nil {
		return h, err
	}
	if head[0] != version {
		return h, fmt.Errorf("bad version %d", head[0])
	}
	copy(h.User[:], head[1:17])
	addonsLen := int(head[17])
	if addonsLen > 0 {
		body := make([]byte, addonsLen)
		if _, err := io.ReadFull(r, body); err != nil {
			return h, err
		}
		a, err := unmarshalAddons(body)
		if err != nil {
			return h, err
		}
		h.Flow = a.Flow
	}
	cmd, err := r.ReadByte()
	if err != nil {
		return h, err
	}
	h.Command = cmd
	if h.Command == commandMux {
		return h, nil
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return h, err
	}
	h.Port = binary.BigEndian.Uint16(portBuf[:])
	atype, err := r.ReadByte()
	if err != nil {
		return h, err
	}
	switch atype {
	case addrIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return h, err
		}
		h.Address = netip.AddrFrom4(b)
	case addrIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return h, err
		}
		h.Address = netip.AddrFrom16(b)
	case addrDomain:
		n, err := r.ReadByte()
		if err != nil {
			return h, err
		}
		b := make([]byte, int(n))
		if _, err := io.ReadFull(r, b); err != nil {
			return h, err
		}
		h.Domain = string(b)
	default:
		return h, fmt.Errorf("bad address type %d", atype)
	}
	return h, nil
}

// testServer is a minimal VLESS server: it echoes whatever the client sends.
type testServer struct {
	ln   net.Listener
	uuid [16]byte
	wg   sync.WaitGroup
}

// startTestServer serves VLESS over the given listener. serve, when non-nil,
// wraps the accepted connection (used for WebSocket).
func startTestServer(t *testing.T, ln net.Listener, uuid [16]byte, wrap func(net.Conn) net.Conn) *testServer {
	t.Helper()
	s := &testServer{ln: ln, uuid: uuid}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				if wrap != nil {
					if conn = wrap(conn); conn == nil {
						return
					}
				}
				s.serve(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *testServer) serve(conn net.Conn) {
	br := bufio.NewReaderSize(conn, 4096)
	hdr, err := readHeaderStream(br)
	if err != nil {
		return
	}
	if hdr.User != s.uuid {
		return
	}
	if _, err := conn.Write([]byte{version, 0}); err != nil {
		return
	}
	if hdr.Flow == FlowVision {
		s.serveVision(conn, br, hdr)
		return
	}
	switch hdr.Command {
	case commandTCP:
		_, _ = io.Copy(conn, br)
	case commandUDP:
		s.serveUDP(conn, br, hdr)
	}
}

// serveUDP echoes datagrams back with their destination address.
func (s *testServer) serveUDP(conn net.Conn, br *bufio.Reader, hdr requestHeader) {
	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		body := make([]byte, n)
		if _, err := io.ReadFull(br, body); err != nil {
			return
		}
		out := make([]byte, 2+len(body))
		binary.BigEndian.PutUint16(out[:2], uint16(len(body)))
		copy(out[2:], body)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// serveVision runs the server half of the Vision framing. The uplink is
// unpadded with an independent implementation of the documented format and the
// downlink pads the first frame with command=end, exactly like Xray's server.
func (s *testServer) serveVision(conn net.Conn, br *bufio.Reader, hdr requestHeader) {
	r := &serverVisionReader{r: br, uuid: hdr.User[:]}
	buf := make([]byte, 4096)
	first := true
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out := buf[:n]
			if first {
				first = false
				frame := serverVisionFrame(hdr.User[:], out)
				if _, werr := conn.Write(frame); werr != nil {
					return
				}
			} else if _, werr := conn.Write(out); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// serverVisionFrame builds a padded frame with command=end and no padding.
func serverVisionFrame(uuid, content []byte) []byte {
	frame := make([]byte, 0, len(uuid)+5+len(content))
	frame = append(frame, uuid...)
	frame = append(frame, commandPaddingEnd, byte(len(content)>>8), byte(len(content)), 0, 0)
	return append(frame, content...)
}

// serverVisionReader is an independent implementation of the Vision unpadding
// state machine (kept separate from the client code on purpose).
type serverVisionReader struct {
	r    *bufio.Reader
	uuid []byte

	started bool
	raw     bool

	needCmd bool
	cmd     byte
	remain  int
	skip    int
	header  [5]byte
	hdrPos  int
}

func (v *serverVisionReader) Read(p []byte) (int, error) {
	if !v.started {
		head, err := v.r.Peek(16)
		if len(head) < 16 {
			return 0, err
		}
		if bytes.Equal(head[:16], v.uuid) {
			_, _ = v.r.Discard(16)
			v.needCmd = true
		} else {
			v.raw = true
		}
		v.started = true
	}
	if v.raw {
		return v.r.Read(p)
	}

	written := 0
	for written < len(p) {
		switch {
		case v.needCmd:
			if v.hdrPos < 5 {
				b, err := v.r.ReadByte()
				if err != nil {
					return written, err
				}
				v.header[v.hdrPos] = b
				v.hdrPos++
				if v.hdrPos == 5 {
					v.cmd = v.header[0]
					v.remain = int(binary.BigEndian.Uint16(v.header[1:3]))
					v.skip = int(binary.BigEndian.Uint16(v.header[3:5]))
					v.hdrPos = 0
					v.needCmd = false
				}
				continue
			}
		case v.remain > 0:
			n := v.remain
			if n > len(p)-written {
				n = len(p) - written
			}
			read, err := io.ReadFull(v.r, p[written:written+n])
			written += read
			v.remain -= read
			if err != nil {
				return written, err
			}
		case v.skip > 0:
			n := v.skip
			if n > 4096 {
				n = 4096
			}
			discarded, err := v.r.Discard(n)
			v.skip -= discarded
			if err != nil {
				return written, err
			}
		default:
			if v.cmd == commandPaddingContinue {
				v.needCmd = true
				if written > 0 {
					// Return what we have: the client may be waiting for the echo
					// before sending the next frame.
					return written, nil
				}
				continue
			}
			v.raw = true
			return written, nil
		}
	}
	return written, nil
}

// --- test helpers for the transports -----------------------------------------

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

// startTCPEcho is the "dest" a REALITY server falls back to.
func startTCPEcho(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
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

// wsServerConn adapts a hijacked HTTP connection to a server-side websocket.
type wsServerConn struct {
	net.Conn
	br   *bufio.Reader
	buf  []byte
	rmu  sync.Mutex
	wmu  sync.Mutex
	dead time.Time
}

func (c *wsServerConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		if len(c.buf) > 0 {
			n := copy(p, c.buf)
			c.buf = c.buf[n:]
			return n, nil
		}
		var hdr [2]byte
		if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
			return 0, err
		}
		op := hdr[0] & 0x0F
		length := int(hdr[1] & 0x7F)
		switch length {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return 0, err
			}
			length = int(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return 0, err
			}
			length = int(binary.BigEndian.Uint64(ext[:]))
		}
		var mask [4]byte
		if hdr[1]&0x80 != 0 {
			if _, err := io.ReadFull(c.br, mask[:]); err != nil {
				return 0, err
			}
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return 0, err
		}
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		if op == 0x8 { // close
			return 0, io.EOF
		}
		if op == 0x9 { // ping
			continue
		}
		c.buf = payload
	}
}

func (c *wsServerConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	frame := make([]byte, 0, 10+len(p))
	frame = append(frame, 0x82) // FIN + binary
	n := len(p)
	switch {
	case n < 126:
		frame = append(frame, byte(n))
	case n <= 0xFFFF:
		frame = append(frame, 126, byte(n>>8), byte(n))
	default:
		frame = append(frame, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	frame = append(frame, p...)
	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// startWSServer runs an HTTP server that upgrades to websocket and hands the
// stream to the VLESS test server.
func startWSServer(t *testing.T, uuid [16]byte) string {
	t.Helper()
	var srv *testServer
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "upgrade required", http.StatusBadRequest)
			return
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
		key := r.Header.Get("Sec-WebSocket-Key")
		if _, err := fmt.Fprintf(conn,
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			wsAcceptForTest(key)); err != nil {
			conn.Close()
			return
		}
		srv.serve(&wsServerConn{Conn: conn, br: brw.Reader})
		conn.Close()
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpSrv := &http.Server{Handler: handler}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	srv = &testServer{ln: ln, uuid: uuid}
	return ln.Addr().String()
}

// wsAcceptForTest computes Sec-WebSocket-Accept (test-only duplicate).
func wsAcceptForTest(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func splitAddr(t *testing.T, address string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split %q: %v", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return host, port
}

// waitGoroutines waits until the goroutine count is back near want.
func waitGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, true)
	t.Fatalf("goroutine leak: have %d, want <= %d\n%s", runtime.NumGoroutine(), want, buf[:n])
}

// echoThrough dials address through client and round-trips payload.
func echoThrough(t *testing.T, c *Client, address string, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
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
}

// --- end-to-end tests --------------------------------------------------------

func TestEndToEndTCP(t *testing.T) {
	base := runtime.NumGoroutine()
	uuid, err := parseUUID(testUUID)
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	startTestServer(t, ln, uuid, nil)
	host, port := splitAddr(t, ln.Addr().String())

	client, err := New(config.Node{
		Tag:    "hk",
		Type:   "vless",
		Server: host,
		Port:   port,
		UUID:   testUUID,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if client.Type() != "vless" || client.Tag() != "hk" {
		t.Fatalf("client identity = %q/%q", client.Type(), client.Tag())
	}
	echoThrough(t, client, "example.com:443", []byte("hello vless"))
	waitGoroutines(t, base+1)
}

func TestEndToEndWS(t *testing.T) {
	base := runtime.NumGoroutine()
	uuid, err := parseUUID(testUUID)
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	addr := startWSServer(t, uuid)
	host, port := splitAddr(t, addr)

	client, err := New(config.Node{
		Tag:       "ws",
		Type:      "vless",
		Server:    host,
		Port:      port,
		UUID:      testUUID,
		Transport: &config.Transport{Type: "ws", Path: "/vl", Host: "example.com"},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	echoThrough(t, client, "example.com:443", []byte("hello over websocket"))
	waitGoroutines(t, base+2)
}

func TestEndToEndVision(t *testing.T) {
	base := runtime.NumGoroutine()
	uuid, err := parseUUID(testUUID)
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	startTestServer(t, ln, uuid, nil)
	host, port := splitAddr(t, ln.Addr().String())

	client, err := New(config.Node{
		Tag:    "vision",
		Type:   "vless",
		Server: host,
		Port:   port,
		UUID:   testUUID,
		Flow:   FlowVision,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		t.Fatalf("deadline: %v", err)
	}

	// The first payload travels inside a padded frame (command=continue).
	if _, err := conn.Write([]byte("hello vision")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len("hello vision"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello vision" {
		t.Fatalf("first echo = %q", got)
	}

	// Once the server ended padding the rest of the stream is raw.
	if _, err := conn.Write([]byte("second")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got = make([]byte, len("second"))
	if _, err := io.ReadFull(conn, got); err != nil {
		conn.Close()
		t.Fatalf("read: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("second echo = %q", got)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	waitGoroutines(t, base+1)
}

func TestEndToEndUDP(t *testing.T) {
	base := runtime.NumGoroutine()
	uuid, err := parseUUID(testUUID)
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	startTestServer(t, ln, uuid, nil)
	host, port := splitAddr(t, ln.Addr().String())

	client, err := New(config.Node{
		Tag:    "udp",
		Type:   "vless",
		Server: host,
		Port:   port,
		UUID:   testUUID,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := client.DialPacket(ctx, "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	if err := pc.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		pc.Close()
		t.Fatalf("deadline: %v", err)
	}

	payload := []byte("dns query")
	dst := netip.MustParseAddrPort("9.9.9.9:53")
	if n, err := pc.WriteTo(payload, dst); err != nil || n != len(payload) {
		t.Fatalf("WriteTo = %d, %v", n, err)
	}
	buf := make([]byte, 1500)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("packet = %q, want %q", buf[:n], payload)
	}
	if from != dst {
		t.Fatalf("from = %v, want %v", from, dst)
	}

	// A datagram that cannot fit in the 16-bit length prefix is rejected.
	if _, err := pc.WriteTo(make([]byte, maxDatagramPayload+1), dst); err == nil {
		t.Fatal("oversized datagram must be rejected")
	}
	if err := pc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitGoroutines(t, base+1)
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(config.Node{Type: "vmess", UUID: testUUID}); err == nil {
		t.Fatal("wrong type must fail")
	}
	if _, err := New(config.Node{Type: "vless", UUID: "not-a-uuid"}); err == nil {
		t.Fatal("invalid uuid must fail")
	}
	if _, err := New(config.Node{Type: "vless", UUID: testUUID, Flow: "xtls-rprx-origin"}); err == nil {
		t.Fatal("unsupported flow must fail")
	}
	if _, err := New(config.Node{Type: "vless", UUID: testUUID, Flow: FlowVision + "-udp443"}); err != nil {
		t.Fatalf("vision-udp443 should be accepted: %v", err)
	}
}

func TestDialContextRejectsBadNetwork(t *testing.T) {
	c, err := New(config.Node{Type: "vless", Server: "127.0.0.1", Port: 1, UUID: testUUID})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if _, err := c.DialContext(context.Background(), "udp", "example.com:53"); err == nil {
		t.Fatal("udp via DialContext must fail")
	}
	if _, err := c.DialContext(context.Background(), "tcp", "example.com"); err == nil {
		t.Fatal("address without port must fail")
	}
	// A closed port must produce a context-wrapped error, not a panic.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("dialing a closed port must fail")
	}
}
