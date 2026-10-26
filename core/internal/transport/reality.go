package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"veil/internal/config"
)

// REALITY wire constants. The client authenticates by embedding an AEAD-sealed
// session ID in the ClientHello; the server answers with an Ed25519 certificate
// whose signature is HMAC-SHA512(authKey, pubkey). Nothing else identifies the
// client, which is why both sides must agree on these exact bytes.
const (
	randomLen       = 32
	sessionIDLen    = 32
	sessionIDOffset = 39 // 1 (type) + 3 (len) + 2 (version) + 32 (random) + 1 (sid len)
	authKeyLen      = 32
)

// ClientHello "compatibility" version bytes. Xray writes its own version here
// (x.y.z) so the server can enforce minClientVer. 1.8.24 is a real Xray
// release, so servers that apply a minimum version keep accepting us.
var realityClientVersion = [3]byte{1, 8, 24}

// realityDialer performs a REALITY client handshake over base.
type realityDialer struct {
	base       Dialer
	id         utls.ClientHelloID
	alpn       []string
	publicKey  []byte
	shortID    []byte
	serverName string
	spiderX    string
}

// Reality returns a Dialer that speaks REALITY (client side) to the server
// described by cfg.Reality. It follows Xray's client algorithm byte for byte.
func Reality(base Dialer, cfg *config.TLS) (Dialer, error) {
	if base == nil {
		return nil, errors.New("transport: reality needs a base dialer")
	}
	if cfg == nil || cfg.Reality == nil {
		return nil, errors.New("transport: reality needs reality settings")
	}
	pbk, err := decodeRealityKey(cfg.Reality.PublicKey)
	if err != nil {
		return nil, err
	}
	shortID, err := decodeShortID(cfg.Reality.ShortID)
	if err != nil {
		return nil, err
	}
	id, err := fingerprintIDs(cfg.Fingerprint)
	if err != nil {
		return nil, err
	}
	alpn := cfg.ALPN
	if len(alpn) == 0 {
		alpn = alpnPlain
	}
	// REALITY always skips the chain check: the certificate is either forged by
	// the server from our authKey (verified via VerifyPeerCertificate) or it is
	// a *real* certificate belonging to the masqueraded site, in which case we
	// reject the connection instead of talking to it.
	ucfg := utlsConfig(cfg, cfg.ServerName)
	ucfg.InsecureSkipVerify = true
	return &realityDialer{
		base:       base,
		id:         id,
		alpn:       append([]string(nil), alpn...),
		publicKey:  pbk,
		shortID:    shortID,
		serverName: cfg.ServerName,
		spiderX:    cfg.Reality.SpiderX,
	}, nil
}

// decodeRealityKey accepts the base64 (raw-url or std) form used by share links
// as well as a 32-byte hex key. Anything that is not 32 bytes is rejected: a
// wrong-length key would otherwise silently produce an unauthenticated stream.
func decodeRealityKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("transport: reality public key is empty")
	}
	var candidates [][]byte
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		candidates = append(candidates, b)
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		candidates = append(candidates, b)
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		candidates = append(candidates, b)
	}
	if b, err := hex.DecodeString(s); err == nil {
		candidates = append(candidates, b)
	}
	for _, b := range candidates {
		if len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("transport: reality public key %q is not a 32 byte x25519 key", s)
}

// decodeShortID hex-decodes the short id. Xray allows 0..8 bytes; the value is
// zero padded to 8 bytes inside the 32-byte session id.
func decodeShortID(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("transport: reality short id %q is not hex: %w", s, err)
	}
	if len(b) > 8 {
		return nil, fmt.Errorf("transport: reality short id %q is longer than 8 bytes", s)
	}
	return b, nil
}

func (d *realityDialer) Dial(ctx context.Context) (net.Conn, error) {
	raw, err := d.base.Dial(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := d.handshake(ctx, raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// authState carries the values that are computed before the handshake but only
// checked during it (the peer-certificate callback).
type authState struct {
	authKey    []byte
	serverName string
	verified   bool
}

// VerifyPeerCertificate implements utls.Config.VerifyPeerCertificate.
//
// The REALITY server forges an Ed25519 certificate and stores
// HMAC-SHA512(authKey, pubkey) in the certificate's signature field. Seeing that
// value proves the peer knows the x25519 private key matching our public key,
// i.e. it is the REALITY server and not a MITM. Anything else is treated as a
// normal certificate and must validate against the system roots.
func (a *authState) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	certs, err := parseCertificates(rawCerts)
	if err != nil {
		return err
	}
	if len(a.authKey) == 32 {
		if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
			h := hmac.New(sha512.New, a.authKey)
			h.Write(pub)
			if hmac.Equal(h.Sum(nil), certs[0].Signature) {
				a.verified = true
				return nil
			}
		}
	}
	// Not a REALITY certificate. Do NOT fall back to a normal x509 check: a
	// REALITY server that failed to authenticate us silently proxies the
	// connection to the masqueraded site, whose *valid* certificate would pass
	// that check and hide the real problem (we would then talk VLESS to Apple).
	// Failing here turns "mysterious EOF" into "wrong pbk/sid/sni".
	var intermediates [][]byte
	for _, der := range rawCerts[1:] {
		intermediates = append(intermediates, der)
	}
	return fmt.Errorf("transport: reality peer is not authenticated (wrong pbk/shortId/sni?)")
}

func (d *realityDialer) handshake(ctx context.Context, raw net.Conn) (*utls.UConn, error) {
	spec, err := clientHelloSpec(d.id, d.alpn, d.serverName)
	if err != nil {
		return nil, err
	}
	auth := &authState{serverName: d.serverName}
	// A fresh config per dial: utls.Config copies poorly (it embeds a mutex) and
	// each handshake needs its own VerifyPeerCertificate closure.
	cfg := &utls.Config{
		ServerName:             d.serverName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  auth.VerifyPeerCertificate,
	}

	uconn := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("transport: reality apply client hello: %w", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("transport: reality build handshake state: %w", err)
	}
	if err := d.authenticate(uconn, auth); err != nil {
		return nil, err
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("transport: reality handshake: %w", err)
	}
	if !auth.verified {
		// Xray logs this and lets the connection die later; we fail loudly so the
		// user sees "the server answered with a real certificate" instead of a
		// mysterious VLESS error. This never happens with a correct pbk/shortId.
		return nil, errors.New("transport: reality server presented a real certificate (wrong public key, or MITM)")
	}
	return uconn, nil
}

// authenticate computes the REALITY auth key and seals the session ID into the
// ClientHello, exactly like Xray's reality.UClient.
func (d *realityDialer) authenticate(uconn *utls.UConn, auth *authState) error {
	hello := uconn.HandshakeState.Hello
	if hello == nil || len(hello.Raw) < sessionIDOffset+sessionIDLen {
		return fmt.Errorf("transport: reality client hello too short (%d bytes)", len(hello.Raw))
	}

	// 32-byte session id: 3 version bytes, 1 reserved, 4 timestamp, short id.
	//
	// The wire layout is: zeroed session id in the ClientHello, sealed into the
	// first 16 bytes. The server zeroes the field before using the message as
	// AEAD additional data, so `Raw` must hold zeros while sealing.
	sessionID := make([]byte, sessionIDLen)
	hello.SessionId = sessionID
	copy(hello.Raw[sessionIDOffset:], sessionID)

	sessionID[0] = realityClientVersion[0]
	sessionID[1] = realityClientVersion[1]
	sessionID[2] = realityClientVersion[2]
	sessionID[3] = 0
	binary.BigEndian.PutUint32(sessionID[4:8], uint32(time.Now().Unix()))
	copy(sessionID[8:], d.shortID)

	pub, err := ecdh.X25519().NewPublicKey(d.publicKey)
	if err != nil {
		return fmt.Errorf("transport: reality public key: %w", err)
	}
	keys := uconn.HandshakeState.State13.KeyShareKeys
	var ecdhe *ecdh.PrivateKey
	if keys != nil {
		// The pinned REALITY server authenticates against a standalone X25519 key
		// share when the ClientHello carries one (Chrome sends both
		// X25519MLKEM768 and X25519); only a ClientHello without a plain X25519
		// share falls back to the X25519 half of the hybrid share, which uTLS
		// exposes as MlkemEcdhe.
		ecdhe = keys.Ecdhe
		if ecdhe == nil {
			ecdhe = keys.MlkemEcdhe
		}
	}
	if ecdhe == nil {
		return errors.New("transport: reality needs a TLS 1.3 fingerprint with an x25519 key share")
	}
	shared, err := ecdhe.ECDH(pub)
	if err != nil {
		return fmt.Errorf("transport: reality x25519: %w", err)
	}
	authKey, err := hkdf.Key(sha256.New, shared, hello.Random[:20], "REALITY", authKeyLen)
	if err != nil {
		return fmt.Errorf("transport: reality hkdf: %w", err)
	}
	auth.authKey = authKey

	aead, err := newAESGCM(authKey)
	if err != nil {
		return err
	}
	// Seal the plaintext session id in place with the second half of the random
	// as nonce, authenticating the ClientHello itself.
	aead.Seal(sessionID[:0], hello.Random[20:32], sessionID[:16], hello.Raw)
	copy(hello.Raw[sessionIDOffset:], sessionID)
	return nil
}

// newAESGCM builds the AES-256-GCM AEAD used by REALITY.
func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("transport: reality aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("transport: reality gcm: %w", err)
	}
	return aead, nil
}
