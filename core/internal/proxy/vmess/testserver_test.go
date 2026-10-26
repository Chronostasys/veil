package vmess

// Server-side implementation of VMess AEAD, written only for tests. It is
// deliberately independent of the client code (its own address parser, its own
// selector for the body cipher) so that the round-trip tests really cross-check
// the wire format instead of testing the encoder against itself.

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/websocket"
)

// fakeServer is a minimal VMess AEAD server: it authenticates the request
// header, then echoes body chunks back.
type fakeServer struct {
	uuid     [16]byte
	key      [16]byte
	security byte

	mu           sync.Mutex
	requests     []serverRequest
	datagramDsts []string
	errs         []error
	wg           sync.WaitGroup

	ln     net.Listener
	http   *http.Server
	wsAddr string
	conns  atomic.Int64
}

type serverRequest struct {
	Version        byte
	Command        byte
	bodyKey        [16]byte
	bodyIV         [16]byte
	Host           string
	Port           uint16
	Security       byte
	Option         byte
	ResponseHeader byte
	PaddingLen     int
}

func newFakeServer(t *testing.T, uuidStr string) *fakeServer {
	t.Helper()
	id, err := parseUUID(uuidStr)
	if err != nil {
		t.Fatalf("parse uuid: %v", err)
	}
	return &fakeServer{uuid: id, key: cmdKey(id), security: securityAES128GCM}
}

// startTCP starts a plain-TCP listener running the fake server.
func (s *fakeServer) startTCP(t *testing.T) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.ln = ln
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				if err := s.serve(conn); err != nil && !isClosedErr(err) {
					s.recordErr(err)
				}
			}()
		}
	}()
	t.Cleanup(s.Close)
	return s
}

// startWS starts the fake server behind a WebSocket upgrade.
func (s *fakeServer) startWS(t *testing.T) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.ln = ln
	s.wsAddr = ln.Addr().String()
	mux := http.NewServeMux()
	mux.Handle("/vmess", websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		s.conns.Add(1)
		if err := s.serve(ws); err != nil && !isClosedErr(err) {
			s.recordErr(err)
		}
	}))
	s.http = &http.Server{Handler: mux}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = s.http.Serve(ln)
	}()
	t.Cleanup(s.Close)
	return s
}

func (s *fakeServer) Addr() string {
	if s.wsAddr != "" {
		return s.wsAddr
	}
	return s.ln.Addr().String()
}

func (s *fakeServer) Close() {
	if s.http != nil {
		_ = s.http.Close()
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.wg.Wait()
}

func (s *fakeServer) Requests() []serverRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]serverRequest, len(s.requests))
	copy(out, s.requests)
	return out
}

func (s *fakeServer) DatagramDestinations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.datagramDsts))
	copy(out, s.datagramDsts)
	return out
}

func (s *fakeServer) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.errs) == 0 {
		return nil
	}
	return s.errs[0]
}

func (s *fakeServer) recordErr(err error) {
	s.mu.Lock()
	s.errs = append(s.errs, err)
	s.mu.Unlock()
}

// serve authenticates one VMess session and echoes its payload.
func (s *fakeServer) serve(conn net.Conn) error {
	br := bufio.NewReader(conn)

	// --- request header -----------------------------------------------------
	var authID [16]byte
	if _, err := io.ReadFull(br, authID[:]); err != nil {
		return fmt.Errorf("read auth id: %w", err)
	}
	// The CRC inside the auth id only validates with the right cmd key, which
	// is derived from the server's UUID: this is the user check.
	ts, ok := decodeAuthID(s.key[:], authID)
	if !ok {
		return errors.New("auth id rejected: wrong uuid or corrupt header")
	}
	if d := time.Since(time.Unix(ts, 0)); d > 2*time.Minute || d < -2*time.Minute {
		return fmt.Errorf("auth id timestamp outside window: %v", d)
	}

	var sealedLen [18]byte
	if _, err := io.ReadFull(br, sealedLen[:]); err != nil {
		return fmt.Errorf("read sealed length: %w", err)
	}
	var connNonce [8]byte
	if _, err := io.ReadFull(br, connNonce[:]); err != nil {
		return fmt.Errorf("read connection nonce: %w", err)
	}

	lenAEAD, err := aesGCM(kdf16(s.key[:], saltHeaderPayloadLenKey, string(authID[:]), string(connNonce[:])))
	if err != nil {
		return err
	}
	lenNonce := kdf(s.key[:], saltHeaderPayloadLenIV, string(authID[:]), string(connNonce[:]))[:12]
	lenPlain, err := lenAEAD.Open(nil, lenNonce, sealedLen[:], authID[:])
	if err != nil {
		return fmt.Errorf("open header length: %w", err)
	}
	headerLen := int(binary.BigEndian.Uint16(lenPlain))
	if headerLen <= 0 || headerLen > 4096 {
		return fmt.Errorf("implausible header length %d", headerLen)
	}
	sealed := make([]byte, headerLen+16)
	if _, err := io.ReadFull(br, sealed); err != nil {
		return fmt.Errorf("read sealed header: %w", err)
	}
	payloadAEAD, err := aesGCM(kdf16(s.key[:], saltHeaderPayloadAEADKey, string(authID[:]), string(connNonce[:])))
	if err != nil {
		return err
	}
	payloadNonce := kdf(s.key[:], saltHeaderPayloadAEADIV, string(authID[:]), string(connNonce[:]))[:12]
	plain, err := payloadAEAD.Open(nil, payloadNonce, sealed, authID[:])
	if err != nil {
		return fmt.Errorf("open header: %w", err)
	}

	hdr, err := parseServerHeader(plain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.requests = append(s.requests, hdr)
	s.mu.Unlock()

	// --- response header ----------------------------------------------------
	respKeySum := sha256.Sum256(hdr.bodyKey[:])
	respIVSum := sha256.Sum256(hdr.bodyIV[:])
	var rk, riv [16]byte
	copy(rk[:], respKeySum[:16])
	copy(riv[:], respIVSum[:16])

	if err := writeServerResponseHeader(conn, hdr.ResponseHeader, rk, riv); err != nil {
		return err
	}

	respAEAD, err := serverAEAD(rk, hdr.Security)
	if err != nil {
		return err
	}
	reqAEAD, err := serverAEAD(hdr.bodyKey, hdr.Security)
	if err != nil {
		return err
	}

	rd := &serverChunkReader{aead: reqAEAD, nonce: hdr.bodyIV, r: br}
	wr := &serverChunkWriter{aead: respAEAD, nonce: riv, w: conn}

	switch hdr.Command {
	case cmdTCP:
		return echoStream(rd, wr)
	case cmdUDP:
		return s.echoPackets(rd, wr)
	default:
		return fmt.Errorf("unexpected command 0x%02x", hdr.Command)
	}
}

// parseServerHeader decodes the plaintext request header and verifies the FNV
// checksum, exactly like Xray's server does.
func parseServerHeader(b []byte) (serverRequest, error) {
	var out serverRequest
	if len(b) < 42 {
		return out, fmt.Errorf("header too short: %d bytes", len(b))
	}
	out.Version = b[0]
	if out.Version != 1 {
		return out, fmt.Errorf("bad version %d", out.Version)
	}
	copy(out.bodyIV[:], b[1:17])
	copy(out.bodyKey[:], b[17:33])
	_ = out.bodyIV
	out.ResponseHeader = b[33]
	out.Option = b[34]
	out.PaddingLen = int(b[35] >> 4)
	out.Security = b[35] & 0x0f
	if b[36] != 0 {
		return out, fmt.Errorf("reserved byte is not zero: %#x", b[36])
	}
	out.Command = b[37]

	body := b[:len(b)-4]
	h := fnv.New32a()
	h.Write(body)
	if h.Sum32() != binary.BigEndian.Uint32(b[len(b)-4:]) {
		return out, errors.New("header checksum mismatch")
	}

	addrPart := b[38 : len(b)-4-out.PaddingLen]
	host, port, used, err := readServerAddr(addrPart)
	if err != nil {
		return out, fmt.Errorf("address: %w", err)
	}
	if used != len(addrPart) {
		return out, fmt.Errorf("%d stray bytes between address and padding", len(addrPart)-used)
	}
	out.Host, out.Port = host, port
	return out, nil
}

// readServerAddr parses VMess's port-first [port][atyp][addr] encoding and
// returns how many bytes it consumed.
func readServerAddr(b []byte) (host string, port uint16, used int, err error) {
	if len(b) < 3 {
		return "", 0, 0, fmt.Errorf("address too short: %d bytes", len(b))
	}
	port = binary.BigEndian.Uint16(b[:2])
	switch b[2] {
	case atypIPv4:
		if len(b) < 7 {
			return "", 0, 0, errors.New("short ipv4 address")
		}
		return net.IP(b[3:7]).String(), port, 7, nil
	case atypIPv6:
		if len(b) < 19 {
			return "", 0, 0, errors.New("short ipv6 address")
		}
		return net.IP(b[3:19]).String(), port, 19, nil
	case atypDomain:
		if len(b) < 4 {
			return "", 0, 0, errors.New("short domain address")
		}
		l := int(b[3])
		if l == 0 || len(b) < 4+l {
			return "", 0, 0, errors.New("bad domain length")
		}
		return string(b[4 : 4+l]), port, 4 + l, nil
	default:
		return "", 0, 0, fmt.Errorf("unknown address type %d", b[2])
	}
}

// writeServerResponseHeader emits the AEAD-wrapped response preamble:
// AEAD(2-byte length) || AEAD([responseHeader, option, cmd, cmdLen]).
func writeServerResponseHeader(w io.Writer, responseHeader byte, key, iv [16]byte) error {
	headerPlain := []byte{responseHeader, 0x00, 0x00, 0x00}

	lenAEAD, err := aesGCM(kdf16(key[:], saltAEADRespHeaderLenKey))
	if err != nil {
		return err
	}
	lenNonce := kdf(iv[:], saltAEADRespHeaderLenIV)[:12]
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], uint16(len(headerPlain)))
	out := lenAEAD.Seal(nil, lenNonce, lenPlain[:], nil)

	payloadAEAD, err := aesGCM(kdf16(key[:], saltAEADRespHeaderKey))
	if err != nil {
		return err
	}
	payloadNonce := kdf(iv[:], saltAEADRespHeaderIV)[:12]
	out = payloadAEAD.Seal(out, payloadNonce, headerPlain, nil)

	_, err = w.Write(out)
	return err
}

// serverChunkReader decrypts the request body (or yields plaintext when the
// session uses security "none").
type serverChunkReader struct {
	aead  cipher.AEAD
	nonce [16]byte
	count uint16
	r     io.Reader
}

func (r *serverChunkReader) next() ([]byte, error) {
	var lb [2]byte
	if _, err := io.ReadFull(r.r, lb[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(lb[:]))

	if r.aead == nil {
		if size == 0 {
			return nil, io.EOF
		}
		b := make([]byte, size)
		_, err := io.ReadFull(r.r, b)
		return b, err
	}
	if size == 16 {
		return nil, io.EOF
	}
	if size < 16 {
		return nil, fmt.Errorf("chunk length %d is smaller than the tag", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r.r, body); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(r.nonce[:2], r.count)
	r.count++
	return r.aead.Open(body[:0], r.nonce[:12], body, nil)
}

type serverChunkWriter struct {
	aead  cipher.AEAD
	nonce [16]byte
	count uint16
	w     io.Writer
}

func (w *serverChunkWriter) write(p []byte) error {
	const chunk = 4096
	for len(p) > 0 {
		n := min(chunk, len(p))
		var out []byte
		if w.aead == nil {
			out = binary.BigEndian.AppendUint16(nil, uint16(n))
			out = append(out, p[:n]...)
		} else {
			out = binary.BigEndian.AppendUint16(nil, uint16(n+16))
			binary.BigEndian.PutUint16(w.nonce[:2], w.count)
			w.count++
			out = w.aead.Seal(out, w.nonce[:12], p[:n], nil)
		}
		if _, err := w.w.Write(out); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// echoStream copies request chunks to response chunks until the client closes
// its direction.
func echoStream(r *serverChunkReader, w *serverChunkWriter) error {
	for {
		chunk, err := r.next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := w.write(chunk); err != nil {
			return err
		}
	}
}

// echoPackets echoes UDP datagrams, preserving the [len][addr][payload] framing.
func (s *fakeServer) echoPackets(r *serverChunkReader, w *serverChunkWriter) error {
	for {
		chunk, err := r.next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(chunk) < 2 {
			return fmt.Errorf("short datagram: %d bytes", len(chunk))
		}
		declared := int(binary.BigEndian.Uint16(chunk[:2]))
		if declared != len(chunk)-2 {
			return fmt.Errorf("datagram length %d does not match chunk payload %d", declared, len(chunk)-2)
		}
		body := chunk[2:]
		host, port, used, err := readServerAddr(body)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.datagramDsts = append(s.datagramDsts, fmt.Sprintf("%s:%d", host, port))
		s.mu.Unlock()

		// Echo the frame unchanged: the address is the source the client knows.
		echoed := binary.BigEndian.AppendUint16(nil, uint16(used+(len(body)-used)))
		echoed = append(echoed, body...)
		if err := w.write(echoed); err != nil {
			return err
		}
	}
}

// serverAEAD builds the body cipher for a session security type. It is written
// independently of newChunkCipher so that a bug in the client's key expansion
// shows up as a decrypt failure instead of cancelling out.
func serverAEAD(key [16]byte, security byte) (cipher.AEAD, error) {
	switch security {
	case securityAES128GCM:
		return aesGCM(key[:])
	case securityChaCha20Poly1305:
		first := md5.Sum(key[:])
		second := md5.Sum(first[:])
		full := make([]byte, 0, 32)
		full = append(full, first[:]...)
		full = append(full, second[:]...)
		return chacha20poly1305.New(full)
	case securityNone:
		return nil, nil
	default:
		return nil, fmt.Errorf("server: unsupported security %d", security)
	}
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
