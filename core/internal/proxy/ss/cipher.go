package ss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Cipher describes one Shadowsocks method.
type Cipher struct {
	Name     string
	KeySize  int // master key size, also the session key size
	SaltSize int // per-session salt/IV size (== KeySize for both families)
	Is2022   bool
	IsChaCha bool // chacha20-poly1305 (legacy ietf or 2022 variant)
}

var ciphers = map[string]*Cipher{
	// Legacy AEAD (SIP004/SIP007).
	"aes-128-gcm":            {Name: "aes-128-gcm", KeySize: 16, SaltSize: 16},
	"aes-256-gcm":            {Name: "aes-256-gcm", KeySize: 32, SaltSize: 32},
	"chacha20-ietf-poly1305": {Name: "chacha20-ietf-poly1305", KeySize: 32, SaltSize: 32, IsChaCha: true},

	// Shadowsocks 2022 (SIP022).
	"2022-blake3-aes-128-gcm":       {Name: "2022-blake3-aes-128-gcm", KeySize: 16, SaltSize: 16, Is2022: true},
	"2022-blake3-aes-256-gcm":       {Name: "2022-blake3-aes-256-gcm", KeySize: 32, SaltSize: 32, Is2022: true},
	"2022-blake3-chacha20-poly1305": {Name: "2022-blake3-chacha20-poly1305", KeySize: 32, SaltSize: 32, Is2022: true, IsChaCha: true},
}

// CipherByName resolves a Shadowsocks method name.
func CipherByName(name string) (*Cipher, error) {
	c, ok := ciphers[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return nil, fmt.Errorf("unsupported shadowsocks method %q", name)
	}
	return c, nil
}

// ParseKey decodes a SIP022 PSK. Shadowsocks 2022 keys are always base64 of
// exactly KeySize bytes; a passphrase is not allowed.
func (c *Cipher) ParseKey(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%s: password is not valid base64: %w", c.Name, err)
	}
	if len(raw) != c.KeySize {
		return nil, fmt.Errorf("%s: key must decode to %d bytes, got %d", c.Name, c.KeySize, len(raw))
	}
	return raw, nil
}

// LegacyKey derives the master key of a pre-2022 method from a passphrase with
// OpenSSL's EVP_BytesToKey (MD5), which is what every Shadowsocks client uses.
func (c *Cipher) LegacyKey(password string) []byte {
	if c.Is2022 {
		return nil
	}
	return evpBytesToKey([]byte(password), c.KeySize)
}

func evpBytesToKey(password []byte, keyLen int) []byte {
	var out, prev []byte
	h := md5.New()
	for len(out) < keyLen {
		h.Reset()
		h.Write(prev)
		h.Write(password)
		out = h.Sum(out)
		prev = out[len(out)-h.Size():]
	}
	return out[:keyLen]
}

// NewAEAD builds the AEAD used for TCP chunks and (for 2022) UDP bodies.
func (c *Cipher) NewAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != c.KeySize {
		return nil, fmt.Errorf("%s: bad key length %d", c.Name, len(key))
	}
	if c.IsChaCha {
		return chacha20poly1305.New(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewXAEAD builds XChaCha20-Poly1305, used by the SIP022 chacha20 UDP format
// (it needs a 24-byte nonce).
func (c *Cipher) NewXAEAD(key []byte) (cipher.AEAD, error) {
	if !c.IsChaCha {
		return nil, fmt.Errorf("%s: 24-byte nonce AEAD is only available for chacha20", c.Name)
	}
	if len(key) != c.KeySize {
		return nil, fmt.Errorf("%s: bad key length %d", c.Name, len(key))
	}
	return chacha20poly1305.NewX(key)
}

// NewBlock builds the AES block cipher used by the SIP022 header formats.
func (c *Cipher) NewBlock(key []byte) (cipher.Block, error) {
	if c.IsChaCha {
		return nil, fmt.Errorf("%s: header block cipher is only available for aes methods", c.Name)
	}
	if len(key) != c.KeySize {
		return nil, fmt.Errorf("%s: bad key length %d", c.Name, len(key))
	}
	return aes.NewCipher(key)
}

// legacySubKey is SIP004's HKDF-SHA1("ss-subkey") used by pre-2022 AEAD.
func legacySubKey(master, salt []byte, keyLen int) ([]byte, error) {
	k := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdf.New(sha1.New, master, salt, []byte("ss-subkey")), k); err != nil {
		return nil, err
	}
	return k, nil
}
