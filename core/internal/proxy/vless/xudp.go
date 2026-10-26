package vless

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"veil/internal/outbound"
)

// XUDP carries UDP over a MUX stream, which Xray requires when the flow is
// xtls-rprx-vision (proxy/vless/outbound rewrites command=UDP to
// command=Mux + v1.mux.cool:666). Frame layout (common/xudp):
//
//	2 bytes meta length
//	1 byte  status (1 = new destination, 2 = reuse previous)
//	1 byte  option
//	1 byte  network (2 = UDP, new destination only)
//	n bytes address + port (new destination only, VLESS order: port first)
//	2 bytes payload length
//	n bytes payload
const muxTarget = "v1.mux.cool"

type xudpConn struct {
	conn net.Conn
	dest netip.AddrPort
	mu   sync.Mutex
}

func newXUDP(conn net.Conn, dest netip.AddrPort) *xudpConn {
	return &xudpConn{conn: conn, dest: dest}
}

// WriteTo sends one datagram.
func (c *xudpConn) WriteTo(p []byte, addr netip.AddrPort) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	meta := make([]byte, 0, 21)
	if addr == c.dest {
		meta = append(meta, 2, 1)
	} else {
		meta = append(meta, 1, 1, 2)
		meta = appendAddrPort(meta, addr)
		c.dest = addr
	}
	frame := make([]byte, 2, 2+len(meta)+2+len(p))
	binary.BigEndian.PutUint16(frame, uint16(len(meta)))
	frame = append(frame, meta...)
	frame = append(frame, byte(len(p)>>8), byte(len(p)))
	frame = append(frame, p...)
	if _, err := c.conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom reads one datagram.
func (c *xudpConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var hdr [2]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	metaLen := int(binary.BigEndian.Uint16(hdr[:]))
	if metaLen < 2 || metaLen > 512 {
		return 0, netip.AddrPort{}, fmt.Errorf("vless xudp: bad meta length %d", metaLen)
	}
	meta := make([]byte, metaLen)
	if _, err := io.ReadFull(c.conn, meta); err != nil {
		return 0, netip.AddrPort{}, err
	}
	addr := c.dest
	if meta[0] == 1 && len(meta) > 2 {
		if a, n := parseAddrPort(meta[2:]); n > 0 {
			addr, c.dest = a, a
		}
	}
	var lp [2]byte
	if _, err := io.ReadFull(c.conn, lp[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	n := int(binary.BigEndian.Uint16(lp[:]))
	if n > len(p) {
		n = len(p)
	}
	if n > 0 {
		if _, err := io.ReadFull(c.conn, p[:n]); err != nil {
			return 0, netip.AddrPort{}, err
		}
	}
	return n, addr, nil
}

func (c *xudpConn) Close() error                  { return c.conn.Close() }
func (c *xudpConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

func appendAddrPort(b []byte, ap netip.AddrPort) []byte {
	if ap.Addr().Is4() {
		v := ap.Addr().As4()
		b = append(b, 1)
		b = append(b, v[:]...)
	} else {
		v := ap.Addr().As16()
		b = append(b, 3)
		b = append(b, v[:]...)
	}
	return append(b, byte(ap.Port()>>8), byte(ap.Port()))
}

func parseAddrPort(b []byte) (netip.AddrPort, int) {
	if len(b) < 1 {
		return netip.AddrPort{}, 0
	}
	switch b[0] {
	case 1:
		if len(b) < 7 {
			return netip.AddrPort{}, 0
		}
		ip, _ := netip.AddrFromSlice(b[1:5])
		return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[5:7])), 7
	case 3:
		if len(b) < 19 {
			return netip.AddrPort{}, 0
		}
		ip, _ := netip.AddrFromSlice(b[1:17])
		return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[17:19])), 19
	}
	return netip.AddrPort{}, 0
}

var _ outbound.PacketConn = (*xudpConn)(nil)
