package vmess

// Wire-format vectors. These values are the protocol contract: if a refactor
// changes any of them, Veil stops talking to real Xray/sing-box servers. The
// expectations were produced by this implementation from the reference
// algorithm and are verified independently where possible (see the AES-GCM and
// HMAC cross-checks below).

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"testing"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// seq16 returns base, base+1, ... base+15; used to build deterministic IV/key
// material for the vectors.
func seq16(base byte) [16]byte {
	var b [16]byte
	for i := range b {
		b[i] = base + byte(i)
	}
	return b
}

// seqReader yields a repeating deterministic byte stream so header sealing is
// reproducible.
type seqReader struct {
	buf []byte
	pos int
}

func newSeqReader(b []byte) *seqReader { return &seqReader{buf: b} }

func (r *seqReader) Read(p []byte) (int, error) {
	for n := range p {
		if r.pos >= len(r.buf) {
			r.pos = 0
		}
		p[n] = r.buf[r.pos]
		r.pos++
	}
	return len(p), nil
}

func testSeq() []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// TestCmdKeyVector pins MD5(uuid || suffix), the root of every VMess AEAD key.
func TestCmdKeyVector(t *testing.T) {
	id, err := parseUUID(testUUID)
	if err != nil {
		t.Fatalf("parseUUID: %v", err)
	}
	key := cmdKey(id)
	if got := hex.EncodeToString(key[:]); got != "b50d916ac0cec067981af8e5f38a758f" {
		t.Fatalf("cmdKey = %s", got)
	}
}

// TestKDFLevelZero checks the first level of the chain against a plain
// HMAC-SHA256 keyed with the VMess salt — an independent expression of the same
// definition.
func TestKDFLevelZero(t *testing.T) {
	msg := []byte("veil kdf level zero")
	mac := hmac.New(sha256.New, []byte(saltVMessAEADKDF))
	mac.Write(msg)
	want := mac.Sum(nil)
	got := kdf(msg)
	if !bytes.Equal(got, want) {
		t.Fatalf("kdf() = %x, want %x", got, want)
	}
}

// TestAuthIDVector pins the AES-ECB auth id for a fixed timestamp and entropy.
// The timestamp is visible to a passive observer, so a wrong construction here
// would break authentication with every server.
func TestAuthIDVector(t *testing.T) {
	id, err := parseUUID(testUUID)
	if err != nil {
		t.Fatalf("parseUUID: %v", err)
	}
	key := cmdKey(id)

	if got := hex.EncodeToString(kdf16(key[:], saltAuthIDEncryptionKey)); got != "1415ba74ca8b3d041a8f583fb4116315" {
		t.Fatalf("auth id key = %s", got)
	}

	authID, err := createAuthID(key[:], 1700000000, newSeqReader(testSeq()))
	if err != nil {
		t.Fatalf("createAuthID: %v", err)
	}
	if got := hex.EncodeToString(authID[:]); got != "d9c0ed55b9e8a475049f4f675a131a85" {
		t.Fatalf("authID = %s", got)
	}

	// The server half must recover the same timestamp.
	ts, ok := decodeAuthID(key[:], authID)
	if !ok {
		t.Fatal("decodeAuthID rejected a valid auth id")
	}
	if ts != 1700000000 {
		t.Fatalf("timestamp = %d, want 1700000000", ts)
	}

	// A foreign key must be rejected rather than silently accepted.
	if _, ok := decodeAuthID(bytes.Repeat([]byte{0x42}, 16), authID); ok {
		t.Fatal("decodeAuthID accepted an auth id for the wrong key")
	}
}

func testHeader() *requestHeader {
	return &requestHeader{
		bodyIV:         seq16(0x10),
		bodyKey:        seq16(0x20),
		responseHeader: 0x5a,
		option:         optionChunkStream,
		security:       securityAES128GCM,
		command:        cmdTCP,
		host:           "example.com",
		port:           443,
	}
}

// TestRequestHeaderLayout spells out the plaintext header byte by byte. Each
// field offset is part of the protocol, so this test is written without calling
// the encoder's helpers.
func TestRequestHeaderLayout(t *testing.T) {
	plain, err := testHeader().marshal(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	iv, key := seq16(0x10), seq16(0x20)

	want := []byte{0x01}            // version
	want = append(want, iv[:]...)   // request body IV
	want = append(want, key[:]...)  // request body key
	want = append(want, 0x5a)       // response header byte
	want = append(want, 0x01)       // option: chunk stream
	want = append(want, 0x03)       // padding<<4 | security(aes-128-gcm)
	want = append(want, 0x00)       // reserved
	want = append(want, 0x01)       // command: TCP
	want = append(want, 0x01, 0xbb) // port 443 (port comes first!)
	want = append(want, 0x02, 11)   // atyp domain, length
	want = append(want, []byte("example.com")...)

	fnv1a := fnvTest(want)
	want = binary.BigEndian.AppendUint32(want, fnv1a)

	if !bytes.Equal(plain, want) {
		t.Fatalf("header mismatch\n got %x\nwant %x", plain, want)
	}
	if got := hex.EncodeToString(plain); got != "01101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f5a0103000101bb020b6578616d706c652e636f6df36802cb" {
		t.Fatalf("header hex drifted: %s", got)
	}
}

// TestSealedHeaderVector covers the whole AEAD envelope: auth id, KDF-derived
// length/payload keys, connection nonce and layout.
func TestSealedHeaderVector(t *testing.T) {
	id, err := parseUUID(testUUID)
	if err != nil {
		t.Fatalf("parseUUID: %v", err)
	}
	key := cmdKey(id)
	plain, err := testHeader().marshal(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sealed, err := sealRequestHeader(key, plain, newSeqReader(testSeq()), 1700000000)
	if err != nil {
		t.Fatalf("sealRequestHeader: %v", err)
	}

	const want = "d9c0ed55b9e8a475049f4f675a131a8522c1cd14eaae28a163cc7685ed0801ad07f30405060708090a0bbe3a7159bec3aefc066ebe879633df53b3604f1c9ff5622e90cb0d90ab55a80df2b61fe967a2d6414512f73542f98339e7b50f2838c32d5b5f8d0d522e0a0cda87573f44a54f4fbef5"
	if got := hex.EncodeToString(sealed); got != want {
		t.Fatalf("sealed header drifted\n got %s\nwant %s", got, want)
	}

	// Layout: authID(16) || sealed length(18) || connection nonce(8) || sealed payload.
	if len(sealed) != 16+18+8+len(plain)+16 {
		t.Fatalf("sealed length = %d", len(sealed))
	}
	if !bytes.Equal(sealed[34:42], []byte{0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}) {
		t.Fatalf("connection nonce = %x", sealed[34:42])
	}
}

// TestSealedHeaderRoundTrip proves the test server's opener (which never calls
// the client's seal path) accepts what the client produces.
func TestSealedHeaderRoundTrip(t *testing.T) {
	id, err := parseUUID(testUUID)
	if err != nil {
		t.Fatalf("parseUUID: %v", err)
	}
	key := cmdKey(id)
	want := testHeader()
	want.paddingLen = 7
	plain, err := want.marshal(newSeqReader(testSeq()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sealed, err := sealRequestHeader(key, plain, newSeqReader(testSeq()), 1700000000)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	got, authID, err := openRequestHeader(key, bytes.NewReader(sealed))
	if err != nil {
		t.Fatalf("openRequestHeader: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch\n got %x\nwant %x", got, plain)
	}
	if !bytes.Equal(authID[:], sealed[:16]) {
		t.Fatal("auth id was not the first 16 bytes")
	}

	hdr, err := parseServerHeader(got)
	if err != nil {
		t.Fatalf("parseServerHeader: %v", err)
	}
	if hdr.Command != cmdTCP || hdr.Host != "example.com" || hdr.Port != 443 ||
		hdr.Security != securityAES128GCM || hdr.Option != optionChunkStream ||
		hdr.ResponseHeader != 0x5a || hdr.PaddingLen != 7 {
		t.Fatalf("decoded header = %+v", hdr)
	}

	// A flipped bit anywhere must be rejected, not silently accepted.
	for _, i := range []int{0, 3, 20, 40, len(sealed) - 1} {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 0xff
		if _, _, err := openRequestHeader(key, bytes.NewReader(bad)); err == nil {
			t.Fatalf("corrupt byte %d was accepted", i)
		}
	}
}

// TestChunkVectors pins the body framing: 2-byte length (ciphertext+tag), tag,
// ciphertext, with the nonce derived from the IV and a per-chunk counter.
func TestChunkVectors(t *testing.T) {
	key := seq16(0x20)
	iv := seq16(0x10)
	c, err := newChunkCipher(key, iv, securityAES128GCM)
	if err != nil {
		t.Fatalf("newChunkCipher: %v", err)
	}
	payload := []byte("hello vmess")

	first := c.sealChunk(nil, payload)
	if got := hex.EncodeToString(first); got != "001b26aca2da20928569be59cdd21c0242afc3aad8f708734ee223de91" {
		t.Fatalf("chunk 1 drifted: %s", got)
	}
	second := c.sealChunk(nil, payload)
	if got := hex.EncodeToString(second); got != "001b992b717644fdd8d17087b47a661c15e063707e83706ea51da3365d" {
		t.Fatalf("chunk 2 drifted: %s", got)
	}
	end := c.sealChunk(nil, nil)
	if got := hex.EncodeToString(end); got != "0010a2a59ee76df01745231f2b034d37a6d1" {
		t.Fatalf("terminator drifted: %s", got)
	}

	// Cross-check chunk 1 against a plain AES-GCM computation: nonce is the IV
	// with the first two bytes replaced by the chunk counter (0 for chunk 1).
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, 16)
	copy(nonce, iv[:])
	binary.BigEndian.PutUint16(nonce[:2], 0)
	wantFirst := binary.BigEndian.AppendUint16(nil, uint16(len(payload)+gcm.Overhead()))
	wantFirst = gcm.Seal(wantFirst, nonce[:gcm.NonceSize()], payload, nil)
	if !bytes.Equal(first, wantFirst) {
		t.Fatalf("chunk 1 does not match plain AES-GCM\n got %x\nwant %x", first, wantFirst)
	}

	// Opening the vectors must give the payload back, then EOF twice (the
	// terminator is sticky).
	r := bytes.NewReader(append(append(append([]byte(nil), first...), second...), end...))
	opener, err := newChunkCipher(key, iv, securityAES128GCM)
	if err != nil {
		t.Fatalf("newChunkCipher: %v", err)
	}
	for i := 0; i < 2; i++ {
		got, err := opener.openChunk(r)
		if err != nil {
			t.Fatalf("openChunk %d: %v", i, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("openChunk %d = %q", i, got)
		}
	}
	if _, err := opener.openChunk(r); err == nil {
		t.Fatal("terminator was not detected")
	}
}

// TestChunkCipherChaChaVector pins the 32-byte key expansion used for
// ChaCha20-Poly1305.
func TestChunkCipherChaChaVector(t *testing.T) {
	key := seq16(0x20)
	if got := hex.EncodeToString(chachaKey(key[:])); got != "35ba6d08f0e34c15b9d0b09998960eb608192e2100960d3badb6175ebb26e7ab" {
		t.Fatalf("chacha key = %s", got)
	}
}

// TestChunkCipherRoundTrip exercises both AEAD choices, including multi-chunk
// payloads that cross the 8 KiB boundary.
func TestChunkCipherRoundTrip(t *testing.T) {
	for _, security := range []byte{securityAES128GCM, securityChaCha20Poly1305} {
		t.Run(securityName(security), func(t *testing.T) {
			key := seq16(0x20)
			iv := seq16(0x10)
			enc, err := newChunkCipher(key, iv, security)
			if err != nil {
				t.Fatalf("newChunkCipher: %v", err)
			}
			dec, err := newChunkCipher(key, iv, security)
			if err != nil {
				t.Fatalf("newChunkCipher: %v", err)
			}

			payload := bytes.Repeat([]byte{0x7e}, maxChunkPayload*2+13)
			var wire []byte
			wire = enc.sealChunk(wire, payload[:maxChunkPayload])
			wire = enc.sealChunk(wire, payload[maxChunkPayload:])
			wire = enc.sealChunk(wire, nil)

			r := bytes.NewReader(wire)
			var got []byte
			for {
				chunk, err := dec.openChunk(r)
				if err != nil {
					if err.Error() == "EOF" || err == io.EOF {
						break
					}
					t.Fatalf("openChunk: %v", err)
				}
				got = append(got, chunk...)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("decoded %d bytes, want %d", len(got), len(payload))
			}
		})
	}
}

func TestChunkCipherNone(t *testing.T) {
	enc, err := newChunkCipher(seq16(1), seq16(2), securityNone)
	if err != nil {
		t.Fatalf("newChunkCipher: %v", err)
	}
	wire := enc.sealChunk(nil, []byte("plaintext"))
	wire = enc.sealChunk(wire, nil)
	if want := []byte{0x00, 0x09, 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't', 0x00, 0x00}; !bytes.Equal(wire, want) {
		t.Fatalf("none framing = %x, want %x", wire, want)
	}

	dec, err := newChunkCipher(seq16(1), seq16(2), securityNone)
	if err != nil {
		t.Fatalf("newChunkCipher: %v", err)
	}
	r := bytes.NewReader(wire)
	got, err := dec.openChunk(r)
	if err != nil || string(got) != "plaintext" {
		t.Fatalf("openChunk = %q, %v", got, err)
	}
	if _, err := dec.openChunk(r); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

// TestParseUUID covers the spellings that appear in share links.
func TestParseUUID(t *testing.T) {
	want := testUUID
	for _, in := range []string{
		testUUID,
		"B831381D-6324-4D53-AD4F-8CDA48B30811",
		"b831381d63244d53ad4f8cda48b30811",
		"{b831381d-6324-4d53-ad4f-8cda48b30811}",
		"urn:uuid:b831381d-6324-4d53-ad4f-8cda48b30811",
		"  b831381d-6324-4d53-ad4f-8cda48b30811  ",
	} {
		id, err := parseUUID(in)
		if err != nil {
			t.Fatalf("parseUUID(%q): %v", in, err)
		}
		if got := uuidString(id); got != want {
			t.Fatalf("parseUUID(%q) = %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"", "b831381d", "zzzzzzzz-6324-4d53-ad4f-8cda48b30811", "b831381d-6324-4d53-ad4f-8cda48b3081"} {
		if _, err := parseUUID(bad); err == nil {
			t.Fatalf("parseUUID(%q) should fail", bad)
		}
	}
}

func TestAddressEncoding(t *testing.T) {
	cases := []struct {
		host string
		port uint16
		want string
	}{
		{"1.2.3.4", 53, "00350101020304"},
		{"example.com", 443, "01bb020b6578616d706c652e636f6d"},
		{"2001:db8::1", 8443, "20fb0320010db8000000000000000000000001"},
	}
	for _, tc := range cases {
		got, err := appendAddrPort(nil, tc.host, tc.port)
		if err != nil {
			t.Fatalf("appendAddrPort(%q): %v", tc.host, err)
		}
		if tc.want != "" && hex.EncodeToString(got) != tc.want {
			t.Errorf("appendAddrPort(%q) = %x, want %s", tc.host, got, tc.want)
		}
		host, port, used, err := readServerAddr(got)
		if err != nil {
			t.Fatalf("readServerAddr(%q): %v", tc.host, err)
		}
		if used != len(got) || port != tc.port {
			t.Errorf("readServerAddr(%q) used %d/%d port %d", tc.host, used, len(got), port)
		}
		if host != tc.host {
			t.Errorf("readServerAddr(%q) host = %q", tc.host, host)
		}
	}
}

func TestResolveSecurity(t *testing.T) {
	cases := map[string]byte{
		"":                       securityAES128GCM,
		"auto":                   securityAutoResolved(),
		"aes-128-gcm":            securityAES128GCM,
		"AES-128-GCM":            securityAES128GCM,
		"chacha20-poly1305":      securityChaCha20Poly1305,
		"chacha20-ietf-poly1305": securityChaCha20Poly1305,
		"none":                   securityNone,
	}
	for method, want := range cases {
		got, err := resolveSecurity(method)
		if err != nil {
			t.Fatalf("resolveSecurity(%q): %v", method, err)
		}
		if got != want {
			t.Fatalf("resolveSecurity(%q) = %d, want %d", method, got, want)
		}
	}
	if _, err := resolveSecurity("rc4"); err == nil {
		t.Fatal("expected error for an unknown security")
	}
}

func securityAutoResolved() byte {
	if hasAESGCMHardware() {
		return securityAES128GCM
	}
	return securityChaCha20Poly1305
}

func securityName(security byte) string {
	switch security {
	case securityAES128GCM:
		return "aes-128-gcm"
	case securityChaCha20Poly1305:
		return "chacha20-poly1305"
	default:
		return "none"
	}
}

func fnvTest(b []byte) uint32 {
	var h uint32 = 2166136261
	for _, c := range b {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}
