package ss

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	"veil/internal/config"
	"veil/internal/proxy/ss/blake3"
)

// ---------------------------------------------------------------------------
// Reference codecs, written against the specs and independent of the package
// internals: the tests drive the real client against a real server socket.
// ---------------------------------------------------------------------------

func incLE(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

func randomN(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}

// legacySubkey is SIP004's HKDF-SHA1 derivation.
func legacySubkey(master, salt []byte, keyLen int) []byte {
	k := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdf.New(sha1.New, master, salt, []byte("ss-subkey")), k); err != nil {
		panic(err)
	}
	return k
}

// subkey2022 is SIP022's BLAKE3 derive_key over psk || salt.
func subkey2022(psk, salt []byte, keyLen int) []byte {
	material := append(append([]byte{}, psk...), salt...)
	out := make([]byte, keyLen)
	blake3.DeriveKey(out, "shadowsocks 2022 session subkey", material)
	return out
}

func readChunk(r io.Reader, aead cipher.AEAD, nonce []byte) ([]byte, error) {
	var encLen [2 + 16]byte
	if _, err := io.ReadFull(r, encLen[:]); err != nil {
		return nil, err
	}
	plainLen, err := aead.Open(encLen[:0], nonce, encLen[:], nil)
	if err != nil {
		return nil, fmt.Errorf("length tag: %w", err)
	}
	incLE(nonce)
	size := int(binary.BigEndian.Uint16(plainLen))
	if size == 0 {
		return nil, fmt.Errorf("zero chunk")
	}
	buf := make([]byte, size+16)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	plain, err := aead.Open(buf[:0], nonce, buf, nil)
	if err != nil {
		return nil, fmt.Errorf("payload tag: %w", err)
	}
	incLE(nonce)
	return plain, nil
}

func writeChunk(w io.Writer, aead cipher.AEAD, nonce []byte, p []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(p)))
	out := aead.Seal(nil, nonce, lenBuf[:], nil)
	incLE(nonce)
	out = aead.Seal(out, nonce, p, nil)
	incLE(nonce)
	_, err := w.Write(out)
	return err
}

// socks5Addr encodes an address the way Shadowsocks does.
func socks5Addr(host string, port uint16) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b := append([]byte{1}, v4...)
			return binary.BigEndian.AppendUint16(b, port)
		}
		b := append([]byte{4}, ip.To16()...)
		return binary.BigEndian.AppendUint16(b, port)
	}
	b := []byte{3, byte(len(host))}
	b = append(b, host...)
	return binary.BigEndian.AppendUint16(b, port)
}

// parseSocks5Addr decodes a SOCKS5 address and returns the destination string.
func parseSocks5Addr(b []byte) (string, int, error) {
	if len(b) < 1 {
		return "", 0, fmt.Errorf("short address")
	}
	switch b[0] {
	case 1:
		if len(b) < 7 {
			return "", 0, fmt.Errorf("short ipv4")
		}
		return net.JoinHostPort(net.IP(b[1:5]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(b[5:7])))), 7, nil
	case 4:
		if len(b) < 19 {
			return "", 0, fmt.Errorf("short ipv6")
		}
		return net.JoinHostPort(net.IP(b[1:17]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(b[17:19])))), 19, nil
	case 3:
		if len(b) < 2 || len(b) < 2+int(b[1])+2 {
			return "", 0, fmt.Errorf("short domain")
		}
		n := int(b[1])
		host := string(b[2 : 2+n])
		port := binary.BigEndian.Uint16(b[2+n : 2+n+2])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), 2 + n + 2, nil
	default:
		return "", 0, fmt.Errorf("unknown address type %d", b[0])
	}
}

// ---------------------------------------------------------------------------
// Test server
// ---------------------------------------------------------------------------

type testServer struct {
	t      *testing.T
	method *Cipher
	key    []byte

	tcpLn net.Listener
	udpPC *net.UDPConn
	addr  string // host:port, shared by TCP and UDP

	mu      sync.Mutex
	salts   []string
	targets []string
	// serverSession is the SIP022 UDP session id; the response header cipher
	// must be derived from it.
	udpServerSession uint64
}

func newTestServer(t *testing.T, methodName, password string) *testServer {
	t.Helper()
	m, err := CipherByName(methodName)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	var key []byte
	if m.Is2022 {
		key, err = m.ParseKey(password)
		if err != nil {
			t.Fatalf("parse key: %v", err)
		}
	} else {
		key = m.LegacyKey(password)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	udpPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		_ = ln.Close()
		t.Fatalf("listen udp: %v", err)
	}

	s := &testServer{
		t:      t,
		method: m,
		key:    key,
		tcpLn:  ln,
		udpPC:  udpPC,
		addr:   ln.Addr().String(),
	}
	s.udpServerSession = binary.BigEndian.Uint64(randomN(8)) | 1

	go s.acceptLoop()
	go s.udpLoop()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = udpPC.Close()
	})
	return s
}

func (s *testServer) port() int { return s.tcpLn.Addr().(*net.TCPAddr).Port }
func (s *testServer) host() string {
	host, _, _ := net.SplitHostPort(s.addr)
	return host
}

func (s *testServer) recordSalt(salt []byte) {
	s.mu.Lock()
	s.salts = append(s.salts, base64.StdEncoding.EncodeToString(salt))
	s.mu.Unlock()
}

func (s *testServer) recordTarget(target string) {
	s.mu.Lock()
	s.targets = append(s.targets, target)
	s.mu.Unlock()
}

func (s *testServer) lastTarget() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.targets) == 0 {
		return ""
	}
	return s.targets[len(s.targets)-1]
}

func (s *testServer) saltsCopy() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.salts...)
}

func (s *testServer) acceptLoop() {
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			if s.method.Is2022 {
				s.serve2022TCP(conn)
			} else {
				s.serveLegacyTCP(conn)
			}
		}()
	}
}

func (s *testServer) serveLegacyTCP(conn net.Conn) {
	salt := make([]byte, s.method.SaltSize)
	if _, err := io.ReadFull(conn, salt); err != nil {
		s.t.Logf("server: read salt: %v", err)
		return
	}
	s.recordSalt(salt)
	aead, err := s.method.NewAEAD(legacySubkey(s.key, salt, s.method.KeySize))
	if err != nil {
		s.t.Logf("server: aead: %v", err)
		return
	}
	nonce := make([]byte, aead.NonceSize())

	addrChunk, err := readChunk(conn, aead, nonce)
	if err != nil {
		s.t.Logf("server: read address chunk: %v", err)
		return
	}
	target, _, err := parseSocks5Addr(addrChunk)
	if err != nil {
		s.t.Logf("server: address: %v", err)
		return
	}
	s.recordTarget(target)

	// Respond on a fresh salt/subkey, like a real server does.
	respSalt := randomN(s.method.SaltSize)
	respAEAD, err := s.method.NewAEAD(legacySubkey(s.key, respSalt, s.method.KeySize))
	if err != nil {
		return
	}
	if _, err := conn.Write(respSalt); err != nil {
		return
	}
	respNonce := make([]byte, respAEAD.NonceSize())

	for {
		payload, err := readChunk(conn, aead, nonce)
		if err != nil {
			return
		}
		if err := writeChunk(conn, respAEAD, respNonce, payload); err != nil {
			return
		}
	}
}

func (s *testServer) serve2022TCP(conn net.Conn) {
	salt := make([]byte, s.method.SaltSize)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return
	}
	s.recordSalt(salt)
	aead, err := s.method.NewAEAD(subkey2022(s.key, salt, s.method.KeySize))
	if err != nil {
		s.t.Logf("server: 2022 aead: %v", err)
		return
	}
	nonce := make([]byte, aead.NonceSize())

	fixedCipher := make([]byte, 11+16)
	if _, err := io.ReadFull(conn, fixedCipher); err != nil {
		return
	}
	fixed, err := aead.Open(fixedCipher[:0], nonce, fixedCipher, nil)
	if err != nil {
		s.t.Logf("server: fixed header: %v", err)
		return
	}
	incLE(nonce)
	if fixed[0] != 0 {
		s.t.Logf("server: bad header type %d", fixed[0])
		return
	}
	varLen := int(binary.BigEndian.Uint16(fixed[9:11]))
	varCipher := make([]byte, varLen+16)
	if _, err := io.ReadFull(conn, varCipher); err != nil {
		return
	}
	varPlain, err := aead.Open(varCipher[:0], nonce, varCipher, nil)
	if err != nil {
		s.t.Logf("server: variable header: %v", err)
		return
	}
	incLE(nonce)

	target, consumed, err := parseSocks5Addr(varPlain)
	if err != nil {
		s.t.Logf("server: 2022 address: %v", err)
		return
	}
	padLen := int(binary.BigEndian.Uint16(varPlain[consumed : consumed+2]))
	if consumed+2+padLen > len(varPlain) {
		s.t.Logf("server: bad padding")
		return
	}
	s.recordTarget(target)
	early := varPlain[consumed+2+padLen:]

	// Server response: own salt, fixed header echoing the client salt, then the
	// first payload chunk (length carried in the fixed header).
	respSalt := randomN(s.method.SaltSize)
	respAEAD, err := s.method.NewAEAD(subkey2022(s.key, respSalt, s.method.KeySize))
	if err != nil {
		return
	}
	respNonce := make([]byte, respAEAD.NonceSize())

	fixedResp := make([]byte, 0, 1+8+s.method.SaltSize+2)
	fixedResp = append(fixedResp, 1)
	fixedResp = binary.BigEndian.AppendUint64(fixedResp, uint64(time.Now().Unix()))
	fixedResp = append(fixedResp, salt...)
	fixedResp = binary.BigEndian.AppendUint16(fixedResp, uint16(len(early)))

	out := append([]byte{}, respSalt...)
	out = respAEAD.Seal(out, respNonce, fixedResp, nil)
	incLE(respNonce)
	if len(early) > 0 {
		out = respAEAD.Seal(out, respNonce, early, nil)
		incLE(respNonce)
	}
	if _, err := conn.Write(out); err != nil {
		return
	}

	for {
		payload, err := readChunk(conn, aead, nonce)
		if err != nil {
			return
		}
		if err := writeChunk(conn, respAEAD, respNonce, payload); err != nil {
			return
		}
	}
}

func (s *testServer) udpLoop() {
	buf := make([]byte, 65536)
	for {
		n, from, err := s.udpPC.ReadFromUDP(buf)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buf[:n]...)
		resp, err := s.handleUDP(packet)
		if err != nil {
			s.t.Logf("server: udp: %v", err)
			continue
		}
		if _, err := s.udpPC.WriteToUDP(resp, from); err != nil {
			return
		}
	}
}

func (s *testServer) handleUDP(packet []byte) ([]byte, error) {
	if s.method.Is2022 {
		return s.handle2022UDP(packet)
	}
	if len(packet) < s.method.SaltSize+16 {
		return nil, fmt.Errorf("short packet")
	}
	salt := packet[:s.method.SaltSize]
	s.recordSalt(salt)
	aead, err := s.method.NewAEAD(legacySubkey(s.key, salt, s.method.KeySize))
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), packet[s.method.SaltSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	target, _, err := parseSocks5Addr(plain)
	if err != nil {
		return nil, err
	}
	s.recordTarget(target)

	respSalt := randomN(s.method.SaltSize)
	respAEAD, err := s.method.NewAEAD(legacySubkey(s.key, respSalt, s.method.KeySize))
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, respSalt...)
	return respAEAD.Seal(out, make([]byte, respAEAD.NonceSize()), plain, nil), nil
}

func (s *testServer) handle2022UDP(packet []byte) ([]byte, error) {
	var body []byte
	var clientSession uint64
	if s.method.IsChaCha {
		if len(packet) < 24+16 {
			return nil, fmt.Errorf("short packet")
		}
		aead, err := s.method.NewXAEAD(s.key)
		if err != nil {
			return nil, err
		}
		plain, err := aead.Open(nil, packet[:24], packet[24:], nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt: %w", err)
		}
		if len(plain) < 16 {
			return nil, fmt.Errorf("short body")
		}
		clientSession = binary.BigEndian.Uint64(plain[:8])
		body = plain[16:]
	} else {
		block, err := s.method.NewBlock(s.key)
		if err != nil {
			return nil, err
		}
		var raw [16]byte
		block.Decrypt(raw[:], packet[:16])
		clientSession = binary.BigEndian.Uint64(raw[:8])
		key := subkey2022(s.key, raw[:8], s.method.KeySize)
		aead, err := s.method.NewAEAD(key)
		if err != nil {
			return nil, err
		}
		body, err = aead.Open(nil, raw[4:16], packet[16:], nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt body: %w", err)
		}
	}
	if len(body) < 1+8+2 {
		return nil, fmt.Errorf("short body")
	}
	if body[0] != 0 {
		return nil, fmt.Errorf("bad header type %d", body[0])
	}
	padLen := int(binary.BigEndian.Uint16(body[9:11]))
	off := 11 + padLen
	if len(body) < off {
		return nil, fmt.Errorf("short padding")
	}
	target, consumed, err := parseSocks5Addr(body[off:])
	if err != nil {
		return nil, err
	}
	s.recordTarget(target)

	// Server -> client body: type 1, timestamp, client session id, padding,
	// address, payload.
	respBody := []byte{1}
	respBody = binary.BigEndian.AppendUint64(respBody, uint64(time.Now().Unix()))
	respBody = binary.BigEndian.AppendUint64(respBody, clientSession)
	respBody = binary.BigEndian.AppendUint16(respBody, 0)
	respBody = append(respBody, body[off:off+consumed]...)
	respBody = append(respBody, body[off+consumed:]...)

	packetID := uint16(randomN(1)[0])<<8 | uint16(randomN(1)[0])
	if s.method.IsChaCha {
		xaead, err := s.method.NewXAEAD(s.key)
		if err != nil {
			return nil, err
		}
		nonce := randomN(24)
		// The chacha packet prefix is session id (8) || packet id (8), both
		// big-endian, inside the AEAD.
		plain := binary.BigEndian.AppendUint64(nil, s.udpServerSession)
		plain = binary.BigEndian.AppendUint64(plain, uint64(packetID))
		plain = append(plain, respBody...)
		return xaead.Seal(nonce, nonce, plain, nil), nil
	}

	block, err := s.method.NewBlock(s.key)
	if err != nil {
		return nil, err
	}
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[:8], s.udpServerSession)
	binary.BigEndian.PutUint16(raw[8:10], packetID)
	var enc [16]byte
	block.Encrypt(enc[:], raw[:])
	bodyKey := subkey2022(s.key, raw[:8], s.method.KeySize)
	aead, err := s.method.NewAEAD(bodyKey)
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, enc[:]...)
	return aead.Seal(out, raw[4:16], respBody, nil), nil
}

// ---------------------------------------------------------------------------
// Client construction helpers
// ---------------------------------------------------------------------------

func (s *testServer) node(t *testing.T, password string) config.Node {
	t.Helper()
	return config.Node{
		Tag:      "ss-test",
		Type:     "ss",
		Server:   s.host(),
		Port:     s.port(),
		Method:   s.method.Name,
		Password: password,
	}
}

func newClient(t *testing.T, s *testServer, password string) *Client {
	t.Helper()
	c, err := New(s.node(t, password))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCipherByName(t *testing.T) {
	cases := []struct {
		name    string
		keySize int
		is2022  bool
		chacha  bool
		wantErr bool
	}{
		{"aes-128-gcm", 16, false, false, false},
		{"aes-256-gcm", 32, false, false, false},
		{"chacha20-ietf-poly1305", 32, false, true, false},
		{"2022-blake3-aes-128-gcm", 16, true, false, false},
		{"2022-blake3-aes-256-gcm", 32, true, false, false},
		{"2022-blake3-chacha20-poly1305", 32, true, true, false},
		{"AES-128-GCM", 16, false, false, false}, // case-insensitive
		{"rc4-md5", 0, false, false, true},
		{"", 0, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := CipherByName(tc.name)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("CipherByName: %v", err)
			}
			if m.KeySize != tc.keySize || m.Is2022 != tc.is2022 || m.IsChaCha != tc.chacha {
				t.Fatalf("got %+v", m)
			}
			if m.SaltSize != tc.keySize {
				t.Fatalf("salt size %d, want %d", m.SaltSize, tc.keySize)
			}
		})
	}
}

func TestParseKey2022(t *testing.T) {
	m, err := CipherByName("2022-blake3-aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	good := base64.StdEncoding.EncodeToString(randomN(16))
	key, err := m.ParseKey(good)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	if len(key) != 16 {
		t.Fatalf("key length %d", len(key))
	}

	bad := []struct {
		name string
		key  string
	}{
		{"wrong length", base64.StdEncoding.EncodeToString(randomN(32))},
		{"not base64", "definitely not base64 !!"},
		{"empty", ""},
		{"passphrase", "hunter2"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := m.ParseKey(tc.key); err == nil {
				t.Fatalf("expected an error for %q", tc.key)
			}
		})
	}
}

func TestLegacyKeyMatchesOpenSSL(t *testing.T) {
	// openssl enc -aes-128-cbc -md md5 -pass pass:test-password -nosalt -P
	cases := []struct {
		method string
		want   string
	}{
		{"aes-128-gcm", "dfb450efddbb5387197c84460623675b"},
		{"aes-256-gcm", "dfb450efddbb5387197c84460623675b69f2cebcd8ef520a3dfddef7c3d540b2"},
	}
	for _, tc := range cases {
		m, err := CipherByName(tc.method)
		if err != nil {
			t.Fatal(err)
		}
		got := fmt.Sprintf("%x", m.LegacyKey("test-password"))
		if got != tc.want {
			t.Errorf("%s: key %s, want %s", tc.method, got, tc.want)
		}
	}
}

func TestTCPRoundTrip(t *testing.T) {
	methods := []string{
		"aes-128-gcm",
		"aes-256-gcm",
		"chacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm",
		"2022-blake3-aes-256-gcm",
		"2022-blake3-chacha20-poly1305",
	}
	for _, name := range methods {
		t.Run(name, func(t *testing.T) {
			m, err := CipherByName(name)
			if err != nil {
				t.Fatal(err)
			}
			password := "passphrase"
			if m.Is2022 {
				password = base64.StdEncoding.EncodeToString(randomN(m.KeySize))
			}
			srv := newTestServer(t, name, password)
			client := newClient(t, srv, password)

			ctx := contextWithTimeout(t, 15*time.Second)
			conn, err := client.DialContext(ctx, "tcp", "example.com:443")
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer conn.Close()

			payload := []byte("hello shadowsocks over tcp")
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != string(payload) {
				t.Fatalf("echo mismatch: %q != %q", got, payload)
			}
			if target := srv.lastTarget(); target != "example.com:443" {
				t.Fatalf("server saw target %q, want example.com:443", target)
			}
		})
	}
}

func TestLegacyTCPLargeTransfer(t *testing.T) {
	// 100 KiB crosses many chunks (the legacy chunk limit is 0x3FFF).
	srv := newTestServer(t, "aes-256-gcm", "pw")
	client := newClient(t, srv, "pw")

	conn, err := client.DialContext(contextWithTimeout(t, 15*time.Second), "tcp", "10.0.0.1:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 100*1024)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	go func() {
		if _, err := conn.Write(payload); err != nil {
			t.Logf("write: %v", err)
		}
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("byte %d: %d != %d", i, got[i], payload[i])
		}
	}
}

func TestSaltsAreUniquePerConnection(t *testing.T) {
	for _, name := range []string{"aes-256-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(name, func(t *testing.T) {
			m, err := CipherByName(name)
			if err != nil {
				t.Fatal(err)
			}
			password := "pw"
			if m.Is2022 {
				password = base64.StdEncoding.EncodeToString(randomN(m.KeySize))
			}
			srv := newTestServer(t, name, password)
			client := newClient(t, srv, password)

			for i := 0; i < 3; i++ {
				conn, err := client.DialContext(contextWithTimeout(t, 15*time.Second), "tcp", "1.1.1.1:53")
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

			salts := srv.saltsCopy()
			seen := make(map[string]bool)
			for _, salt := range salts {
				if seen[salt] {
					t.Fatalf("salt reuse detected: %s", salt)
				}
				seen[salt] = true
			}
			if len(salts) < 3 {
				t.Fatalf("expected at least 3 salts, got %d", len(salts))
			}
		})
	}
}

func TestUDPRoundTrip(t *testing.T) {
	methods := []string{
		"aes-128-gcm",
		"aes-256-gcm",
		"chacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm",
		"2022-blake3-aes-256-gcm",
		"2022-blake3-chacha20-poly1305",
	}
	for _, name := range methods {
		t.Run(name, func(t *testing.T) {
			m, err := CipherByName(name)
			if err != nil {
				t.Fatal(err)
			}
			password := "pw"
			if m.Is2022 {
				password = base64.StdEncoding.EncodeToString(randomN(m.KeySize))
			}
			srv := newTestServer(t, name, password)
			client := newClient(t, srv, password)

			pc, err := client.DialPacket(contextWithTimeout(t, 15*time.Second), "")
			if err != nil {
				t.Fatalf("DialPacket: %v", err)
			}
			defer pc.Close()

			dst := netipMustParse(t, "8.8.4.4:53")
			if _, err := pc.WriteTo([]byte("query"), dst); err != nil {
				t.Fatalf("WriteTo: %v", err)
			}
			if err := pc.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatalf("SetDeadline: %v", err)
			}
			buf := make([]byte, 2048)
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				t.Fatalf("ReadFrom: %v", err)
			}
			if string(buf[:n]) != "query" {
				t.Fatalf("payload %q", buf[:n])
			}
			if from.String() != dst.String() {
				t.Fatalf("source %s, want %s", from, dst)
			}
			if target := srv.lastTarget(); target != dst.String() {
				t.Fatalf("server saw target %q, want %s", target, dst)
			}
		})
	}
}

func TestUDPUnsupportedMethodStillBuilds(t *testing.T) {
	// A 2022 node without a base64 key must be rejected at construction time.
	_, err := New(config.Node{
		Tag: "bad", Type: "ss", Server: "127.0.0.1", Port: 8388,
		Method: "2022-blake3-aes-128-gcm", Password: "not-base64!",
	})
	if err == nil {
		t.Fatal("expected an error for a non-base64 2022 key")
	}
	_, err = New(config.Node{
		Tag: "bad2", Type: "ss", Server: "127.0.0.1", Port: 8388,
		Method: "aes-128-gcm", Password: "",
	})
	if err == nil {
		t.Fatal("expected an error for an empty legacy password")
	}
}

func TestDialAfterClose(t *testing.T) {
	srv := newTestServer(t, "aes-128-gcm", "pw")
	client := newClient(t, srv, "pw")
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := client.DialContext(contextWithTimeout(t, time.Second), "tcp", "1.2.3.4:80"); err == nil {
		t.Fatal("expected an error after Close")
	}
	if _, err := client.DialPacket(contextWithTimeout(t, time.Second), ""); err == nil {
		t.Fatal("expected an error after Close")
	}
}

func TestUnsupportedNetwork(t *testing.T) {
	srv := newTestServer(t, "aes-128-gcm", "pw")
	client := newClient(t, srv, "pw")
	if _, err := client.DialContext(contextWithTimeout(t, time.Second), "udp", "1.2.3.4:80"); err == nil {
		t.Fatal("expected an error for the udp network")
	}
}

func TestTagAndType(t *testing.T) {
	srv := newTestServer(t, "aes-128-gcm", "pw")
	client := newClient(t, srv, "pw")
	if client.Tag() != "ss-test" || client.Type() != "ss" {
		t.Fatalf("Tag/Type = %q/%q", client.Tag(), client.Type())
	}
}

// ---------------------------------------------------------------------------
// Small test utilities
// ---------------------------------------------------------------------------

func contextWithTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func netipMustParse(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return addr
}
