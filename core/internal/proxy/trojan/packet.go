package trojan

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"veil/internal/outbound"
)

// packetConn is a trojan UDP association: one TCP stream carrying
//
//	[ATYP ADDR PORT][2-byte length][CRLF][payload]
//
// frames in both directions. The destination travels with every frame, so a
// single association reaches arbitrary peers (SOCKS5-style semantics). Reads
// and writes are independent; only the frame writes need the mutex so that
// concurrent datagrams cannot interleave.
type packetConn struct {
	conn   net.Conn
	br     *bufio.Reader
	wmu    sync.Mutex
	closed atomic.Bool
	once   sync.Once
}

var _ outbound.PacketConn = (*packetConn)(nil)

func newPacketConn(conn net.Conn) *packetConn {
	return &packetConn{conn: conn, br: bufio.NewReader(conn)}
}

// ReadFrom reads one UDP frame. A frame larger than p is truncated, matching
// net.PacketConn semantics.
func (c *packetConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	host, port, err := readAddrPort(c.br)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(c.br, lb[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	size := int(binary.BigEndian.Uint16(lb[:]))
	if size > maxPacketSize {
		return 0, netip.AddrPort{}, ErrOversizePacket
	}
	var delim [2]byte
	if _, err := io.ReadFull(c.br, delim[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if string(delim[:]) != crlf {
		return 0, netip.AddrPort{}, errors.New("trojan: missing CRLF after UDP length")
	}

	src, err := toAddrPort(host, port)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if size > len(p) {
		// Drain the whole frame so the stream stays framed, but only hand the
		// caller what fits.
		full := make([]byte, size)
		if _, err := io.ReadFull(c.br, full); err != nil {
			return 0, netip.AddrPort{}, err
		}
		return copy(p, full), src, nil
	}
	if _, err := io.ReadFull(c.br, p[:size]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	return size, src, nil
}

// WriteTo writes one UDP frame to addr.
func (c *packetConn) WriteTo(p []byte, addr netip.AddrPort) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > maxPacketSize {
		return 0, ErrOversizePacket
	}
	frame := make([]byte, 0, 1+16+2+2+len(p))
	frame, err := appendAddrPort(frame, addr.Addr().Unmap().String(), addr.Port())
	if err != nil {
		return 0, err
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(p)))
	frame = append(frame, crlf...)
	frame = append(frame, p...)

	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close tears down the underlying stream.
func (c *packetConn) Close() error {
	var err error
	c.once.Do(func() {
		c.closed.Store(true)
		err = c.conn.Close()
	})
	return err
}

// SetDeadline applies to both directions of the stream. A deadline in the past
// makes the next ReadFrom/WriteTo fail immediately, which is what the caller
// wants when it gives up on a datagram.
func (c *packetConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
