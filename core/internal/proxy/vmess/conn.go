package vmess

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// responseReader owns the read direction of a VMess session: it consumes the
// AEAD response header on first use and then yields decrypted body chunks.
//
// The header is read lazily because servers write it together with their first
// body chunk; a client that waits for it eagerly deadlocks on protocols where
// the response only starts after the request body ends.
type responseReader struct {
	r          io.Reader
	cipher     *chunkCipher
	key, iv    [16]byte
	wantHeader byte

	started bool
	err     error
}

func (rr *responseReader) nextChunk() ([]byte, error) {
	if !rr.started {
		rr.started = true
		if _, err := decodeResponseHeader(rr.r, rr.key, rr.iv, rr.wantHeader); err != nil {
			rr.err = err
		}
	}
	if rr.err != nil {
		return nil, rr.err
	}
	return rr.cipher.openChunk(rr.r)
}

// Conn is a proxied stream. It behaves like the underlying net.Conn except that
// payloads are chunk-encrypted, so Read/Write translate between the two.
type Conn struct {
	net.Conn

	writeMu sync.Mutex
	writer  *chunkWriter

	readMu  sync.Mutex
	reader  *responseReader
	pending []byte // decrypted bytes not yet handed to the caller
	readErr error  // sticky read error
}

var _ net.Conn = (*Conn)(nil)

func newConn(conn net.Conn, sess *session) *Conn {
	return &Conn{
		Conn:   conn,
		writer: newChunkWriter(conn, sess.requestCipher),
		reader: &responseReader{
			r:          conn,
			cipher:     sess.responseCipher,
			key:        sess.responseKey,
			iv:         sess.responseIV,
			wantHeader: sess.responseHeaderByte,
		},
	}
}

// Read implements net.Conn. It returns one decrypted chunk at a time and only
// reports io.EOF for the protocol's end-of-stream marker (or a closed peer).
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.readErr != nil {
		return 0, c.readErr
	}
	for len(c.pending) == 0 {
		chunk, err := c.reader.nextChunk()
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.readErr = io.EOF
			} else {
				c.readErr = err
			}
			return 0, c.readErr
		}
		if len(chunk) == 0 {
			// A zero-length chunk that is not the terminator is legal but
			// carries nothing; keep looking rather than returning (0, nil).
			continue
		}
		c.pending = chunk
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// Write implements net.Conn. Every call is sealed as one or more chunks; a
// partial write would corrupt the stream, so failures are reported whole.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.writer.Write(p); err != nil {
		return 0, fmt.Errorf("vmess: write chunk: %w", err)
	}
	return len(p), nil
}

// Close shuts the stream down. The VMess end-of-stream chunk is deliberately not
// sent: it would need a blocking write, and a TCP FIN gives the server the same
// information without risking a Close that never returns.
func (c *Conn) Close() error {
	return c.Conn.Close()
}
