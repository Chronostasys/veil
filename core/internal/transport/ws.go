package transport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"veil/internal/config"
)

// WebSocket support is implemented directly on top of net.Conn instead of
// pulling in a WebSocket library: the client only needs the HTTP/1.1 Upgrade
// handshake plus masked binary frames, and owning the codec keeps early data
// (Xray's "ed") and deadline forwarding under our control.

const (
	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA

	wsMaxFramePayload = 64 << 20
)

// WS returns a Dialer that tunnels through a WebSocket upgrade on the stream
// produced by base. When cfg.EarlyData > 0 the first payload (up to EarlyData
// bytes) is smuggled in the Sec-WebSocket-Protocol header, exactly like Xray:
// the dial itself is deferred until the caller writes, so the VLESS header and
// the first request bytes reach the server in the same flight as the upgrade.
func WS(base Dialer, cfg *config.Transport) Dialer {
	c := config.Transport{}
	if cfg != nil {
		c = *cfg
	}
	d := &wsDialer{base: base, cfg: c}
	d.path = normalizePath(c.Path)
	d.host = c.Host
	if d.host == "" {
		d.host = headerValue(c.Headers, "Host")
	}
	return d
}

// normalizePath mirrors Xray's GetNormalizedPath.
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

// headerValue returns a header value case-insensitively.
func headerValue(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

type wsDialer struct {
	base Dialer
	cfg  config.Transport
	path string
	host string
}

// Dial implements Dialer.
func (d *wsDialer) Dial(ctx context.Context) (net.Conn, error) {
	if d.base == nil {
		return nil, errors.New("transport: ws needs a base dialer")
	}
	if d.cfg.EarlyData > 0 {
		dctx, cancel := context.WithCancel(ctx)
		return &wsEarlyConn{
			ctx:      dctx,
			cancel:   cancel,
			dialed:   make(chan struct{}),
			dialer:   d,
			maxEarly: d.cfg.EarlyData,
		}, nil
	}
	return d.dial(ctx, nil)
}

// dial performs the upgrade. early, when non-nil, is the payload carried in the
// Sec-WebSocket-Protocol header.
func (d *wsDialer) dial(ctx context.Context, early []byte) (net.Conn, error) {
	raw, err := d.base.Dial(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := d.upgrade(ctx, raw, early)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// upgrade writes the HTTP/1.1 upgrade request and validates the response.
func (d *wsDialer) upgrade(ctx context.Context, raw net.Conn, early []byte) (net.Conn, error) {
	if d.host == "" {
		return nil, errors.New("transport: ws needs a Host header")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("transport: ws key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	var b strings.Builder
	b.WriteString("GET ")
	b.WriteString(d.path)
	b.WriteString(" HTTP/1.1\r\n")
	b.WriteString("Host: " + d.host + "\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Key: " + key + "\r\n")
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	if len(early) > 0 {
		// RawURLEncoding without padding: the encoding both v2ray and Xray read.
		b.WriteString("Sec-WebSocket-Protocol: " + base64.RawURLEncoding.EncodeToString(early) + "\r\n")
	}
	for k, v := range d.cfg.Headers {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Upgrade") ||
			strings.EqualFold(k, "Connection") || strings.HasPrefix(strings.ToLower(k), "sec-websocket") {
			continue
		}
		b.WriteString(k + ": " + v + "\r\n")
	}
	b.WriteString("\r\n")

	if _, err := io.WriteString(raw, b.String()); err != nil {
		return nil, fmt.Errorf("transport: ws request: %w", err)
	}

	br := bufio.NewReaderSize(raw, 4096)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, fmt.Errorf("transport: ws response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("transport: ws upgrade rejected: %s", resp.Status)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!headerContainsToken(resp.Header.Get("Connection"), "upgrade") {
		return nil, fmt.Errorf("transport: ws upgrade response is not a websocket upgrade")
	}
	want := wsAcceptKey(key)
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != want {
		return nil, fmt.Errorf("transport: ws accept mismatch: got %q want %q", got, want)
	}

	// Clear the handshake deadline; the caller manages deadlines from here on.
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return newWSConn(raw, br), nil
}

// wsAcceptKey computes Sec-WebSocket-Accept for a client key.
func wsAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// headerContainsToken reports whether a comma separated header contains token.
func headerContainsToken(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// wsConn adapts a WebSocket connection to net.Conn.
type wsConn struct {
	conn net.Conn
	br   *bufio.Reader

	wmu sync.Mutex

	rmu       sync.Mutex
	remain    []byte // unread payload of the frame being consumed
	readErr   error
	closeOnce sync.Once
	closeErr  error
}

func newWSConn(conn net.Conn, br *bufio.Reader) *wsConn {
	if br == nil {
		br = bufio.NewReaderSize(conn, 4096)
	}
	return &wsConn{conn: conn, br: br}
}

// Read implements net.Conn.
func (c *wsConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		if len(c.remain) > 0 {
			n := copy(p, c.remain)
			c.remain = c.remain[n:]
			return n, nil
		}
		if c.readErr != nil {
			return 0, c.readErr
		}
		payload, op, err := c.readFrameLocked()
		if err != nil {
			c.readErr = err
			return 0, err
		}
		switch op {
		case wsOpBinary, wsOpText, wsOpContinuation:
			if len(payload) == 0 {
				continue
			}
			c.remain = payload
		case wsOpPing:
			if err := c.writeFrame(wsOpPong, payload); err != nil {
				c.readErr = err
				return 0, err
			}
		case wsOpPong:
			// ignore
		case wsOpClose:
			c.readErr = io.EOF
			return 0, io.EOF
		default:
			c.readErr = fmt.Errorf("transport: ws unexpected opcode %#x", op)
			return 0, c.readErr
		}
	}
}

// readFrameLocked reads one frame. The caller must hold rmu.
func (c *wsConn) readFrameLocked() ([]byte, byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return nil, 0, err
	}
	fin := hdr[0]&0x80 != 0
	op := hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, 0, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return nil, 0, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > wsMaxFramePayload {
		return nil, 0, fmt.Errorf("transport: ws frame too large (%d bytes)", length)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return nil, 0, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return nil, 0, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	_ = fin
	return payload, op, nil
}

// Write implements net.Conn. Every Write becomes one masked binary frame.
func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeFrame(wsOpBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeFrame writes a single masked frame (clients must mask).
func (c *wsConn) writeFrame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	header := make([]byte, 0, 14)
	header = append(header, 0x80|op) // FIN + opcode
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, 0x80|byte(n))
	case n <= 0xFFFF:
		header = append(header, 0x80|126, byte(n>>8), byte(n))
	default:
		header = append(header, 0x80|127,
			byte(uint64(n)>>56), byte(uint64(n)>>48), byte(uint64(n)>>40), byte(uint64(n)>>32),
			byte(uint64(n)>>24), byte(uint64(n)>>16), byte(uint64(n)>>8), byte(n))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header = append(header, mask[:]...)

	frame := make([]byte, 0, len(header)+n)
	frame = append(frame, header...)
	start := len(frame)
	frame = append(frame, payload...)
	for i := 0; i < n; i++ {
		frame[start+i] ^= mask[i%4]
	}
	_, err := c.conn.Write(frame)
	return err
}

// Close implements net.Conn. It sends a best-effort close frame then closes the
// underlying stream.
func (c *wsConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.writeFrame(wsOpClose, nil)
		c.closeErr = c.conn.Close()
	})
	return c.closeErr
}

func (c *wsConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// wsEarlyConn defers the WebSocket dial until the first Write so that the first
// payload can be embedded in the upgrade request (Xray's "early data"). Reads
// block until the dial has happened.
type wsEarlyConn struct {
	dialer   *wsDialer
	maxEarly int
	ctx      context.Context
	cancel   context.CancelFunc
	dialed   chan struct{}

	mu     sync.Mutex
	conn   net.Conn
	closed bool
	err    error

	rmu sync.Mutex
}

func (c *wsEarlyConn) ensure() (net.Conn, error) { return c.ensureWith(nil) }

func (c *wsEarlyConn) ensureWith(early []byte) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	if c.err != nil {
		return nil, c.err
	}
	if c.closed {
		return nil, io.ErrClosedPipe
	}
	conn, err := c.dialer.dial(c.ctx, early)
	if err != nil {
		c.err = err
		close(c.dialed)
		return nil, err
	}
	c.conn = conn
	close(c.dialed)
	return conn, nil
}

func (c *wsEarlyConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	dialed := c.conn != nil
	c.mu.Unlock()
	if !dialed {
		early := p
		if len(early) > c.maxEarly {
			early = nil
		}
		if _, err := c.ensureWith(early); err != nil {
			return 0, err
		}
		if early != nil {
			// The bytes travelled inside the upgrade request.
			return len(early), nil
		}
	}
	conn, err := c.ensure()
	if err != nil {
		return 0, err
	}
	return conn.Write(p)
}

func (c *wsEarlyConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	ready := c.conn != nil
	c.mu.Unlock()
	if !ready {
		// A read before the first write must still work: dial without early data.
		if _, err := c.ensure(); err != nil {
			return 0, err
		}
		select {
		case <-c.dialed:
		case <-c.ctx.Done():
			return 0, c.ctx.Err()
		}
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return 0, io.ErrClosedPipe
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return conn.Read(p)
}

func (c *wsEarlyConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	conn := c.conn
	c.mu.Unlock()
	c.cancel()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *wsEarlyConn) addr(local bool) net.Addr {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return nil
	}
	if local {
		return conn.LocalAddr()
	}
	return conn.RemoteAddr()
}

func (c *wsEarlyConn) LocalAddr() net.Addr  { return c.addr(true) }
func (c *wsEarlyConn) RemoteAddr() net.Addr { return c.addr(false) }

func (c *wsEarlyConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.SetDeadline(t)
}

func (c *wsEarlyConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.SetReadDeadline(t)
}

func (c *wsEarlyConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.SetWriteDeadline(t)
}
