package ss

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"veil/internal/proxy/ss/blake3"
)

// SIP022 TCP framing:
//
//	client -> server: salt || AEAD(fixed header) || AEAD(variable header) || chunks
//	server -> client: salt || AEAD(fixed header) || [AEAD(initial payload)] || chunks
//
// The fixed header is 11 bytes (type, unix timestamp, length of the variable
// header). The variable header carries the address, optional padding and early
// payload. Every following chunk is a 2-byte length chunk followed by a payload
// chunk. All AEAD nonces are 12-byte little-endian counters starting at zero.
const (
	headerTypeClient = 0
	headerTypeServer = 1

	sip022FixedHeaderLen = 1 + 8 + 2
	sip022MaxPayload     = 0xFFFF
	sip022MaxPadding     = 900

	// sip022MaxClockSkew bounds the request/response timestamp we accept.
	sip022MaxClockSkew = 30 * time.Second
)

const (
	kdfContextSession  = "shadowsocks 2022 session subkey"
	kdfContextIdentity = "shadowsocks 2022 identity subkey"
)

// deriveSessionSubKey is SIP022's per-session key: BLAKE3 derive_key over
// psk || salt with a fixed context string.
func deriveSessionSubKey(psk, salt []byte, keyLen int) []byte {
	material := make([]byte, 0, len(psk)+len(salt))
	material = append(material, psk...)
	material = append(material, salt...)
	out := make([]byte, keyLen)
	blake3.DeriveKey(out, kdfContextSession, material)
	return out
}

// pskHash is the identity hash used by multi-user (identity header) setups.
func pskHash(psk []byte) [16]byte {
	sum := blake3.Sum512(psk)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("ss: crypto/rand failed: " + err.Error())
	}
	return b
}

func appendTimestamp(b []byte) []byte {
	return binary.BigEndian.AppendUint64(b, uint64(time.Now().Unix()))
}

func checkTimestamp(v uint64) error {
	diff := math.Abs(float64(time.Now().Unix() - int64(v)))
	if diff > sip022MaxClockSkew.Seconds() {
		return fmt.Errorf("ss: peer clock skew %.0fs exceeds %.0fs", diff, sip022MaxClockSkew.Seconds())
	}
	return nil
}

// sip022Writer frames payload chunks with an incrementing nonce.
type sip022Writer struct {
	mu    sync.Mutex
	w     io.Writer
	aead  cipher.AEAD
	nonce []byte
	buf   []byte
}

func newSIP022Writer(w io.Writer, aead cipher.AEAD, nonce []byte) *sip022Writer {
	return &sip022Writer{
		w:     w,
		aead:  aead,
		nonce: nonce,
		buf:   make([]byte, 0, sip022MaxPayload+2+2*aeadTagSize),
	}
}

func (sw *sip022Writer) Write(p []byte) (int, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	total := len(p)
	for len(p) > 0 {
		n := len(p)
		if n > sip022MaxPayload {
			n = sip022MaxPayload
		}
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		out := sw.aead.Seal(sw.buf[:0], sw.nonce, lenBuf[:], nil)
		incNonce(sw.nonce)
		out = sw.aead.Seal(out, sw.nonce, p[:n], nil)
		incNonce(sw.nonce)
		if _, err := sw.w.Write(out); err != nil {
			return total - len(p), err
		}
		p = p[n:]
	}
	return total, nil
}

// sip022Reader reads chunks produced by a sip022Writer.
type sip022Reader struct {
	r      io.Reader
	aead   cipher.AEAD
	nonce  []byte
	lenBuf [2 + aeadTagSize]byte
	buf    []byte
	cache  []byte
	err    error
}

func newSIP022Reader(r io.Reader, aead cipher.AEAD, nonce []byte) *sip022Reader {
	return &sip022Reader{
		r:     r,
		aead:  aead,
		nonce: nonce,
		buf:   make([]byte, sip022MaxPayload+aeadTagSize),
	}
}

func (sr *sip022Reader) Read(p []byte) (int, error) {
	if len(sr.cache) > 0 {
		n := copy(p, sr.cache)
		sr.cache = sr.cache[n:]
		return n, nil
	}
	if sr.err != nil {
		return 0, sr.err
	}
	if _, err := io.ReadFull(sr.r, sr.lenBuf[:]); err != nil {
		sr.err = err
		return 0, err
	}
	plainLen, err := sr.aead.Open(sr.lenBuf[:0], sr.nonce, sr.lenBuf[:], nil)
	if err != nil {
		sr.err = fmt.Errorf("ss: bad 2022 chunk length tag: %w", err)
		return 0, sr.err
	}
	incNonce(sr.nonce)

	size := int(binary.BigEndian.Uint16(plainLen))
	if size == 0 || size > sip022MaxPayload {
		sr.err = fmt.Errorf("ss: invalid 2022 chunk size %d", size)
		return 0, sr.err
	}
	if _, err := io.ReadFull(sr.r, sr.buf[:size+aeadTagSize]); err != nil {
		sr.err = err
		return 0, err
	}
	plain, err := sr.aead.Open(sr.buf[:0], sr.nonce, sr.buf[:size+aeadTagSize], nil)
	if err != nil {
		sr.err = fmt.Errorf("ss: bad 2022 chunk tag: %w", err)
		return 0, sr.err
	}
	incNonce(sr.nonce)

	sr.cache = plain
	n := copy(p, sr.cache)
	sr.cache = sr.cache[n:]
	return n, nil
}

// sip022ClientSession is the client half of one 2022 TCP session. The request
// header is written eagerly (so the server can start connecting immediately),
// the response header is read lazily on the first Read.
type sip022ClientSession struct {
	conn net_Conn
	c    *Cipher
	psk  []byte

	clientSalt []byte
	writer     *sip022Writer

	mu     sync.Mutex
	reader *sip022Reader
	rerr   error
	ready  bool
}

// net_Conn is a tiny alias so this file does not have to import net for one
// type; it keeps the framing code transport-agnostic.
type net_Conn interface {
	io.Reader
	io.Writer
}

func newSIP022ClientSession(conn net_Conn, c *Cipher, psk []byte, addrHeader []byte) (*sip022ClientSession, error) {
	s := &sip022ClientSession{conn: conn, c: c, psk: psk}
	// The salt doubles as the per-session nonce material and is echoed back by
	// the server, letting us verify we talk to someone who knows the PSK.
	s.clientSalt = randomBytes(c.SaltSize)
	subkey := deriveSessionSubKey(psk, s.clientSalt, c.KeySize)
	aead, err := c.NewAEAD(subkey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())

	// Padding must be non-zero: SIP022 rejects requests that carry neither
	// padding nor payload.
	paddingLen := int(randomBytes(1)[0])%sip022MaxPadding + 1
	varHeader := make([]byte, 0, len(addrHeader)+2+paddingLen)
	varHeader = append(varHeader, addrHeader...)
	varHeader = binary.BigEndian.AppendUint16(varHeader, uint16(paddingLen))
	varHeader = append(varHeader, make([]byte, paddingLen)...)

	fixed := make([]byte, 0, sip022FixedHeaderLen)
	fixed = append(fixed, headerTypeClient)
	fixed = appendTimestamp(fixed)
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(varHeader)))

	out := make([]byte, 0, c.SaltSize+sip022FixedHeaderLen+aeadTagSize+len(varHeader)+aeadTagSize)
	out = append(out, s.clientSalt...)
	out = aead.Seal(out, nonce, fixed, nil)
	incNonce(nonce)
	out = aead.Seal(out, nonce, varHeader, nil)
	incNonce(nonce)

	if _, err := conn.Write(out); err != nil {
		return nil, err
	}
	s.writer = newSIP022Writer(conn, aead, nonce)
	return s, nil
}

func (s *sip022ClientSession) Write(p []byte) (int, error) {
	if s.writer == nil {
		return 0, fmt.Errorf("ss: session not established")
	}
	return s.writer.Write(p)
}

// initReader reads and validates the server response header.
func (s *sip022ClientSession) initReader() error {
	// The response's fixed header echoes our salt:
	//   type(1) || timestamp(8) || request salt(SaltSize) || first payload len(2)
	headerLen := s.c.SaltSize + (sip022FixedHeaderLen + s.c.SaltSize) + aeadTagSize
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(s.conn, header); err != nil {
		return fmt.Errorf("ss: read 2022 response header: %w", err)
	}
	salt := header[:s.c.SaltSize]
	subkey := deriveSessionSubKey(s.psk, salt, s.c.KeySize)
	aead, err := s.c.NewAEAD(subkey)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	plain, err := aead.Open(nil, nonce, header[s.c.SaltSize:], nil)
	if err != nil {
		return fmt.Errorf("ss: decrypt 2022 response header: %w", err)
	}
	incNonce(nonce)

	if plain[0] != headerTypeServer {
		return fmt.Errorf("ss: bad response header type %d", plain[0])
	}
	if err := checkTimestamp(binary.BigEndian.Uint64(plain[1:9])); err != nil {
		return err
	}
	echoed := plain[9 : 9+s.c.SaltSize]
	if string(echoed) != string(s.clientSalt) {
		return fmt.Errorf("ss: server echoed a different request salt")
	}
	initialLen := int(binary.BigEndian.Uint16(plain[9+s.c.SaltSize:]))
	s.reader = newSIP022Reader(s.conn, aead, nonce)
	if initialLen > 0 {
		// The first payload chunk has no length prefix; its size is in the
		// fixed header. It is framed exactly like a normal chunk after that.
		buf := make([]byte, initialLen+aeadTagSize)
		if _, err := io.ReadFull(s.conn, buf); err != nil {
			return err
		}
		payload, err := aead.Open(buf[:0], nonce, buf, nil)
		if err != nil {
			return fmt.Errorf("ss: decrypt 2022 initial payload: %w", err)
		}
		incNonce(s.reader.nonce)
		s.reader.cache = payload
	}
	return nil
}

func (s *sip022ClientSession) Read(p []byte) (int, error) {
	s.mu.Lock()
	if !s.ready && s.rerr == nil {
		s.rerr = s.initReader()
		s.ready = true
	}
	err := s.rerr
	reader := s.reader
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return reader.Read(p)
}
