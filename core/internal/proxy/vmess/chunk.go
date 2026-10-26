package vmess

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// chunkSizeFieldLen is the big-endian uint16 in front of every body chunk.
	chunkSizeFieldLen = 2
	// maxChunkPayload is how much plaintext we put in one chunk. Servers accept
	// any size that fits in the uint16 length field; keeping it small bounds the
	// per-chunk allocation and matches typical implementations.
	maxChunkPayload = 8192
)

// chunkCipher seals and opens one direction of a VMess body. The body is a
// stream of AEAD chunks:
//
//	uint16(len) || ciphertext || tag(16)
//
// where len counts ciphertext+tag. A chunk whose length equals the tag size
// carries no plaintext and marks end-of-stream. Nonces are the session IV with
// its first two bytes replaced by a chunk counter, which is why the counter
// lives here and not in the reader/writer.
type chunkCipher struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		Overhead() int
		NonceSize() int
	}
	nonce [16]byte
	count uint16
}

func newChunkCipher(key, iv [16]byte, security byte) (*chunkCipher, error) {
	c := &chunkCipher{nonce: iv}
	switch security {
	case securityAES128GCM:
		aead, err := newGCM(key[:])
		if err != nil {
			return nil, err
		}
		c.aead = aead
	case securityChaCha20Poly1305:
		aead, err := chacha20poly1305.New(chachaKey(key[:]))
		if err != nil {
			return nil, fmt.Errorf("vmess: chacha20poly1305: %w", err)
		}
		c.aead = aead
	case securityNone:
		// No body encryption: chunks are length-prefixed plaintext.
	default:
		return nil, fmt.Errorf("vmess: unsupported security type %d", security)
	}
	return c, nil
}

// chachaKey expands a 16-byte VMess key to the 32 bytes ChaCha20-Poly1305
// wants. The double-MD5 construction is part of the protocol.
func chachaKey(b []byte) []byte {
	key := make([]byte, 32)
	t := md5.Sum(b)
	copy(key, t[:])
	t = md5.Sum(key[:16])
	copy(key[16:], t[:])
	return key
}

func (c *chunkCipher) overhead() int {
	if c.aead == nil {
		return 0
	}
	return c.aead.Overhead()
}

// nextNonce returns the nonce for the next chunk and advances the counter. The
// counter wraps at 65536, exactly like the reference implementations; a session
// long enough to get there is already rekeyed in practice.
func (c *chunkCipher) nextNonce() []byte {
	if c.aead == nil {
		return nil
	}
	binary.BigEndian.PutUint16(c.nonce[:2], c.count)
	c.count++
	return c.nonce[:c.aead.NonceSize()]
}

// sealChunk appends one framed chunk to dst.
func (c *chunkCipher) sealChunk(dst, plain []byte) []byte {
	bodyLen := len(plain) + c.overhead()
	dst = binary.BigEndian.AppendUint16(dst, uint16(bodyLen))
	if c.aead == nil {
		return append(dst, plain...)
	}
	return c.aead.Seal(dst, c.nextNonce(), plain, nil)
}

// openChunk reads and decrypts one chunk. It returns io.EOF for the
// end-of-stream marker, which is a chunk with no plaintext.
func (c *chunkCipher) openChunk(r io.Reader) ([]byte, error) {
	var sizeBuf [chunkSizeFieldLen]byte
	if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(sizeBuf[:]))
	if size == c.overhead() {
		// Length + tag only: the sender closed its direction.
		return nil, io.EOF
	}
	if size < c.overhead() {
		return nil, fmt.Errorf("vmess: chunk length %d smaller than AEAD overhead %d", size, c.overhead())
	}

	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	if c.aead == nil {
		return body, nil
	}
	plain, err := c.aead.Open(body[:0], c.nextNonce(), body, nil)
	if err != nil {
		return nil, fmt.Errorf("vmess: open chunk: %w", err)
	}
	return plain, nil
}

// chunkWriter turns an io.Writer into a chunk stream.
type chunkWriter struct {
	w io.Writer
	c *chunkCipher
}

func newChunkWriter(w io.Writer, c *chunkCipher) *chunkWriter {
	return &chunkWriter{w: w, c: c}
}

// Write implements io.Writer. Each call produces one or more chunks; a partial
// write would desynchronise the stream, so a short write is reported as an
// error rather than a byte count.
func (w *chunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := len(p)
	buf := make([]byte, 0, total+2*(total/maxChunkPayload+1)+16*(total/maxChunkPayload+1))
	for len(p) > 0 {
		n := min(len(p), maxChunkPayload)
		buf = w.c.sealChunk(buf, p[:n])
		p = p[n:]
	}
	if _, err := w.w.Write(buf); err != nil {
		return 0, err
	}
	return total, nil
}
