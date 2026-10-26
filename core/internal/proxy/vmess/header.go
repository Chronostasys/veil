package vmess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/netip"
)

// Protocol constants that appear on the wire.
const (
	protocolVersion byte = 0x01

	cmdTCP byte = 0x01
	cmdUDP byte = 0x02

	securityAES128GCM        byte = 0x03
	securityChaCha20Poly1305 byte = 0x04
	securityNone             byte = 0x05

	// optionChunkStream marks the body as the AEAD chunk stream. VMess AEAD
	// always frames the body this way; the byte is kept for compatibility with
	// servers that key on it.
	optionChunkStream byte = 0x01

	// VMess address types (port-first framing) differ from SOCKS5 numbering.
	atypIPv4   byte = 0x01
	atypDomain byte = 0x02
	atypIPv6   byte = 0x03

	// plainHeaderFixedLen is version + IV + key + response header byte +
	// option + security + reserved + command.
	plainHeaderFixedLen = 38
)

// requestHeader is the plaintext of a VMess request header, before the AEAD
// envelope is applied.
type requestHeader struct {
	bodyIV         [16]byte
	bodyKey        [16]byte
	responseHeader byte
	option         byte
	security       byte
	command        byte
	host           string
	port           uint16
	paddingLen     int
}

// marshal serialises the header and appends the FNV-1a checksum that the server
// verifies after decryption.
func (h *requestHeader) marshal(rnd io.Reader) ([]byte, error) {
	buf := make([]byte, 0, plainHeaderFixedLen+6+len(h.host)+h.paddingLen+4)
	buf = append(buf, protocolVersion)
	buf = append(buf, h.bodyIV[:]...)
	buf = append(buf, h.bodyKey[:]...)
	buf = append(buf, h.responseHeader)
	buf = append(buf, h.option)
	buf = append(buf, byte(h.paddingLen<<4)|h.security&0x0f)
	buf = append(buf, 0) // reserved
	buf = append(buf, h.command)

	var err error
	if buf, err = appendAddrPort(buf, h.host, h.port); err != nil {
		return nil, err
	}
	if h.paddingLen > 0 {
		if rnd == nil {
			return nil, errors.New("vmess: header padding needs an entropy source")
		}
		pad := make([]byte, h.paddingLen)
		if _, err := io.ReadFull(rnd, pad); err != nil {
			return nil, fmt.Errorf("vmess: read padding: %w", err)
		}
		buf = append(buf, pad...)
	}

	fnv1a := fnv.New32a()
	fnv1a.Write(buf)
	return binary.BigEndian.AppendUint32(buf, fnv1a.Sum32()), nil
}

// appendAddrPort appends VMess's address encoding: port first, then a
// VMess-specific address type byte and the address itself.
func appendAddrPort(dst []byte, host string, port uint16) ([]byte, error) {
	dst = binary.BigEndian.AppendUint16(dst, port)
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b := ip.As4()
			dst = append(dst, atypIPv4)
			return append(dst, b[:]...), nil
		}
		b := ip.As16()
		dst = append(dst, atypIPv6)
		return append(dst, b[:]...), nil
	}
	if host == "" || len(host) > 255 {
		return nil, fmt.Errorf("vmess: invalid domain %q", host)
	}
	dst = append(dst, atypDomain, byte(len(host)))
	return append(dst, host...), nil
}

// readAddrPort is the inverse of appendAddrPort. It is only used by the test
// server; clients never parse an address out of the stream.
func readAddrPort(r io.Reader) (host string, port uint16, err error) {
	var pb [2]byte
	if _, err = io.ReadFull(r, pb[:]); err != nil {
		return "", 0, err
	}
	port = binary.BigEndian.Uint16(pb[:])

	var atyp [1]byte
	if _, err = io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, err
	}
	switch atyp[0] {
	case atypIPv4:
		var b [4]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4(b).String()
	case atypIPv6:
		var b [16]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16(b).Unmap().String()
	case atypDomain:
		var l [1]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		if l[0] == 0 {
			return "", 0, errors.New("vmess: empty domain")
		}
		b := make([]byte, l[0])
		if _, err = io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, fmt.Errorf("vmess: unknown address type 0x%02x", atyp[0])
	}
	return host, port, nil
}

// sealRequestHeader wraps the serialised header in the VMess AEAD envelope:
//
//	authID(16) || AEAD-Seal(len)(18) || connectionNonce(8) || AEAD-Seal(header)
//
// The length and the payload use separate keys and nonces, both derived from
// the auth id and the connection nonce, and both authenticate the auth id as
// additional data. A server that cannot open the length block drops the
// connection immediately; that is the point of splitting them.
func sealRequestHeader(cmdKey [16]byte, header []byte, rnd io.Reader, timestamp int64) ([]byte, error) {
	authID, err := createAuthID(cmdKey[:], timestamp, rnd)
	if err != nil {
		return nil, err
	}

	var connNonce [8]byte
	if _, err := io.ReadFull(rnd, connNonce[:]); err != nil {
		return nil, fmt.Errorf("vmess: read connection nonce: %w", err)
	}

	lenKey := kdf16(cmdKey[:], saltHeaderPayloadLenKey, string(authID[:]), string(connNonce[:]))
	lenNonce := kdf(cmdKey[:], saltHeaderPayloadLenIV, string(authID[:]), string(connNonce[:]))[:12]
	lenAEAD, err := newGCM(lenKey)
	if err != nil {
		return nil, err
	}

	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], uint16(len(header)))
	sealedLen := lenAEAD.Seal(nil, lenNonce, lenPlain[:], authID[:])

	payloadKey := kdf16(cmdKey[:], saltHeaderPayloadAEADKey, string(authID[:]), string(connNonce[:]))
	payloadNonce := kdf(cmdKey[:], saltHeaderPayloadAEADIV, string(authID[:]), string(connNonce[:]))[:12]
	payloadAEAD, err := newGCM(payloadKey)
	if err != nil {
		return nil, err
	}
	sealedPayload := payloadAEAD.Seal(nil, payloadNonce, header, authID[:])

	out := make([]byte, 0, authIDSize+len(sealedLen)+len(connNonce)+len(sealedPayload))
	out = append(out, authID[:]...)
	out = append(out, sealedLen...)
	out = append(out, connNonce[:]...)
	out = append(out, sealedPayload...)
	return out, nil
}

// openRequestHeader is the server side of sealRequestHeader. Tests use it to
// prove the client is wire compatible; the client itself never calls it.
func openRequestHeader(cmdKey [16]byte, r io.Reader) ([]byte, [16]byte, error) {
	var authID [16]byte
	if _, err := io.ReadFull(r, authID[:]); err != nil {
		return nil, authID, fmt.Errorf("vmess: read auth id: %w", err)
	}
	var sealedLen [2 + 16]byte
	if _, err := io.ReadFull(r, sealedLen[:]); err != nil {
		return nil, authID, fmt.Errorf("vmess: read sealed header length: %w", err)
	}
	var connNonce [8]byte
	if _, err := io.ReadFull(r, connNonce[:]); err != nil {
		return nil, authID, fmt.Errorf("vmess: read connection nonce: %w", err)
	}

	lenKey := kdf16(cmdKey[:], saltHeaderPayloadLenKey, string(authID[:]), string(connNonce[:]))
	lenNonce := kdf(cmdKey[:], saltHeaderPayloadLenIV, string(authID[:]), string(connNonce[:]))[:12]
	lenAEAD, err := newGCM(lenKey)
	if err != nil {
		return nil, authID, err
	}
	lenPlain, err := lenAEAD.Open(nil, lenNonce, sealedLen[:], authID[:])
	if err != nil {
		return nil, authID, fmt.Errorf("vmess: open header length: %w", err)
	}
	headerLen := int(binary.BigEndian.Uint16(lenPlain))
	if headerLen == 0 || headerLen > 1<<14 {
		return nil, authID, fmt.Errorf("vmess: implausible header length %d", headerLen)
	}

	sealedPayload := make([]byte, headerLen+16)
	if _, err := io.ReadFull(r, sealedPayload); err != nil {
		return nil, authID, fmt.Errorf("vmess: read sealed header: %w", err)
	}
	payloadKey := kdf16(cmdKey[:], saltHeaderPayloadAEADKey, string(authID[:]), string(connNonce[:]))
	payloadNonce := kdf(cmdKey[:], saltHeaderPayloadAEADIV, string(authID[:]), string(connNonce[:]))[:12]
	payloadAEAD, err := newGCM(payloadKey)
	if err != nil {
		return nil, authID, err
	}
	header, err := payloadAEAD.Open(nil, payloadNonce, sealedPayload, authID[:])
	if err != nil {
		return nil, authID, fmt.Errorf("vmess: open header: %w", err)
	}
	return header, authID, nil
}

// parseRequestHeader decodes the plaintext header that openRequestHeader
// returned, validating the trailing FNV-1a checksum the same way Xray does.
func parseRequestHeader(plain []byte) (*requestHeader, error) {
	if len(plain) < plainHeaderFixedLen+4 {
		return nil, fmt.Errorf("vmess: header too short (%d bytes)", len(plain))
	}
	if plain[0] != protocolVersion {
		return nil, fmt.Errorf("vmess: unsupported version %d", plain[0])
	}
	h := &requestHeader{}
	copy(h.bodyIV[:], plain[1:17])
	copy(h.bodyKey[:], plain[17:33])
	h.responseHeader = plain[33]
	h.option = plain[34]
	h.paddingLen = int(plain[35] >> 4)
	h.security = plain[35] & 0x0f
	h.command = plain[37]

	body := plain[:len(plain)-4]
	fnv1a := fnv.New32a()
	fnv1a.Write(body)
	if fnv1a.Sum32() != binary.BigEndian.Uint32(plain[len(plain)-4:]) {
		return nil, errors.New("vmess: header checksum mismatch")
	}

	// The address sits between the fixed part and the padding; parse it out of
	// a reader that stops before the checksum.
	addrLen := len(plain) - 4 - plainHeaderFixedLen - h.paddingLen
	if addrLen < 0 {
		return nil, errors.New("vmess: header padding overflows header")
	}
	host, port, err := readAddrPort(bytes.NewReader(plain[plainHeaderFixedLen : plainHeaderFixedLen+addrLen]))
	if err != nil {
		return nil, err
	}
	h.host, h.port = host, port
	return h, nil
}

// responseHeader is the decrypted response preamble the server sends before any
// body chunk.
type responseHeader struct {
	option byte
	cmdID  byte
}

// decodeResponseHeader reads the AEAD-wrapped response header using the response
// body key material (SHA-256 of the request material, truncated to 16 bytes).
func decodeResponseHeader(r io.Reader, respKey, respIV [16]byte, wantResponseHeader byte) (*responseHeader, error) {
	lenKey := kdf16(respKey[:], saltAEADRespHeaderLenKey)
	lenNonce := kdf(respIV[:], saltAEADRespHeaderLenIV)[:12]
	lenAEAD, err := newGCM(lenKey)
	if err != nil {
		return nil, err
	}

	var sealedLen [2 + 16]byte
	if _, err := io.ReadFull(r, sealedLen[:]); err != nil {
		return nil, fmt.Errorf("vmess: read response header length: %w", err)
	}
	lenPlain, err := lenAEAD.Open(nil, lenNonce, sealedLen[:], nil)
	if err != nil {
		return nil, fmt.Errorf("vmess: open response header length: %w", err)
	}
	headerLen := int(binary.BigEndian.Uint16(lenPlain))
	if headerLen == 0 || headerLen > 1<<12 {
		return nil, fmt.Errorf("vmess: implausible response header length %d", headerLen)
	}

	sealed := make([]byte, headerLen+16)
	if _, err := io.ReadFull(r, sealed); err != nil {
		return nil, fmt.Errorf("vmess: read response header: %w", err)
	}
	payloadKey := kdf16(respKey[:], saltAEADRespHeaderKey)
	payloadNonce := kdf(respIV[:], saltAEADRespHeaderIV)[:12]
	payloadAEAD, err := newGCM(payloadKey)
	if err != nil {
		return nil, err
	}
	plain, err := payloadAEAD.Open(nil, payloadNonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("vmess: open response header: %w", err)
	}
	if len(plain) < 2 {
		return nil, errors.New("vmess: response header too short")
	}
	if plain[0] != wantResponseHeader {
		return nil, fmt.Errorf("vmess: unexpected response header byte 0x%02x (want 0x%02x)", plain[0], wantResponseHeader)
	}
	h := &responseHeader{option: plain[1]}
	if len(plain) >= 4 && plain[2] != 0 {
		h.cmdID = plain[2]
	}
	return h, nil
}

// newGCM builds AES-128-GCM, the primitive VMess AEAD uses for headers and for
// the aes-128-gcm body security.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vmess: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vmess: gcm: %w", err)
	}
	return aead, nil
}

// randomBytes fills dst from crypto/rand.
func randomBytes(dst []byte) error {
	if _, err := io.ReadFull(rand.Reader, dst); err != nil {
		return fmt.Errorf("vmess: entropy: %w", err)
	}
	return nil
}
