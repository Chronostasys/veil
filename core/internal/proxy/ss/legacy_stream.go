package ss

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// Pre-2022 AEAD framing (SIP004): salt || (2-byte length chunk || payload chunk)+
// where every chunk is sealed with the session subkey and a 12-byte
// little-endian counter nonce starting at zero.
const (
	legacyMaxPayload = 0x3FFF
	aeadTagSize      = 16
	streamNonceSize  = 12
)

// incNonce increments a nonce as a little-endian integer, as specified by both
// SIP004 and SIP022 for AEAD chunk counters.
func incNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

type legacyWriter struct {
	w     io.Writer
	mast  []byte
	c     *Cipher
	aead  cipher.AEAD
	nonce []byte
	buf   []byte
}

func newLegacyWriter(w io.Writer, master []byte, c *Cipher) *legacyWriter {
	return &legacyWriter{w: w, mast: master, c: c, buf: make([]byte, 0, legacyMaxPayload+2+2*aeadTagSize)}
}

func (lw *legacyWriter) Write(p []byte) (int, error) {
	if lw.aead == nil {
		salt := make([]byte, lw.c.SaltSize)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return 0, err
		}
		subkey, err := legacySubKey(lw.mast, salt, lw.c.KeySize)
		if err != nil {
			return 0, err
		}
		aead, err := lw.c.NewAEAD(subkey)
		if err != nil {
			return 0, err
		}
		lw.aead = aead
		lw.nonce = make([]byte, aead.NonceSize())
		// The salt travels in the clear and is the first thing on the wire.
		if _, err := lw.w.Write(salt); err != nil {
			return 0, err
		}
	}

	total := len(p)
	for len(p) > 0 {
		n := len(p)
		if n > legacyMaxPayload {
			n = legacyMaxPayload
		}
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		out := lw.aead.Seal(lw.buf[:0], lw.nonce, lenBuf[:], nil)
		incNonce(lw.nonce)
		out = lw.aead.Seal(out, lw.nonce, p[:n], nil)
		incNonce(lw.nonce)
		if _, err := lw.w.Write(out); err != nil {
			return total - len(p), err
		}
		p = p[n:]
	}
	return total, nil
}

type legacyReader struct {
	r      io.Reader
	master []byte
	c      *Cipher
	aead   cipher.AEAD
	nonce  []byte
	lenBuf [2 + aeadTagSize]byte
	buf    []byte
	cache  []byte
	err    error
}

func newLegacyReader(r io.Reader, master []byte, c *Cipher) *legacyReader {
	return &legacyReader{r: r, master: master, c: c, buf: make([]byte, legacyMaxPayload+aeadTagSize)}
}

func (lr *legacyReader) init() error {
	salt := make([]byte, lr.c.SaltSize)
	if _, err := io.ReadFull(lr.r, salt); err != nil {
		return fmt.Errorf("ss: read salt: %w", err)
	}
	subkey, err := legacySubKey(lr.master, salt, lr.c.KeySize)
	if err != nil {
		return err
	}
	aead, err := lr.c.NewAEAD(subkey)
	if err != nil {
		return err
	}
	lr.aead = aead
	lr.nonce = make([]byte, aead.NonceSize())
	return nil
}

func (lr *legacyReader) Read(p []byte) (int, error) {
	if len(lr.cache) > 0 {
		n := copy(p, lr.cache)
		lr.cache = lr.cache[n:]
		return n, nil
	}
	if lr.err != nil {
		return 0, lr.err
	}
	if lr.aead == nil {
		if err := lr.init(); err != nil {
			lr.err = err
			return 0, err
		}
	}

	if _, err := io.ReadFull(lr.r, lr.lenBuf[:]); err != nil {
		lr.err = err
		return 0, err
	}
	plainLen, err := lr.aead.Open(lr.lenBuf[:0], lr.nonce, lr.lenBuf[:], nil)
	if err != nil {
		lr.err = fmt.Errorf("ss: bad chunk length tag: %w", err)
		return 0, lr.err
	}
	incNonce(lr.nonce)

	size := int(binary.BigEndian.Uint16(plainLen))
	if size == 0 || size > legacyMaxPayload {
		lr.err = fmt.Errorf("ss: invalid chunk size %d", size)
		return 0, lr.err
	}
	if _, err := io.ReadFull(lr.r, lr.buf[:size+aeadTagSize]); err != nil {
		lr.err = err
		return 0, err
	}
	plain, err := lr.aead.Open(lr.buf[:0], lr.nonce, lr.buf[:size+aeadTagSize], nil)
	if err != nil {
		lr.err = fmt.Errorf("ss: bad chunk tag: %w", err)
		return 0, lr.err
	}
	incNonce(lr.nonce)

	lr.cache = plain
	n := copy(p, lr.cache)
	lr.cache = lr.cache[n:]
	return n, nil
}

// legacySealPacket seals one legacy AEAD UDP datagram:
// salt || AEAD(addr || payload) with an all-zero nonce.
func legacySealPacket(c *Cipher, master []byte, plain []byte) ([]byte, error) {
	salt := make([]byte, c.SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	subkey, err := legacySubKey(master, salt, c.KeySize)
	if err != nil {
		return nil, err
	}
	aead, err := c.NewAEAD(subkey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(salt)+len(plain)+aeadTagSize)
	out = append(out, salt...)
	return aead.Seal(out, make([]byte, aead.NonceSize()), plain, nil), nil
}

// legacyOpenPacket opens one legacy AEAD UDP datagram.
func legacyOpenPacket(c *Cipher, master, packet []byte) ([]byte, error) {
	if len(packet) < c.SaltSize+aeadTagSize {
		return nil, fmt.Errorf("ss: short udp packet")
	}
	salt := packet[:c.SaltSize]
	subkey, err := legacySubKey(master, salt, c.KeySize)
	if err != nil {
		return nil, err
	}
	aead, err := c.NewAEAD(subkey)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), packet[c.SaltSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("ss: udp decrypt: %w", err)
	}
	return plain, nil
}
