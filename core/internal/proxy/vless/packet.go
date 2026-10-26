package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"veil/internal/outbound"
)

// UDP over VLESS: with command=UDP every datagram travels as
//
//	2 byte length (of port+address+payload)
//	2 byte port
//	1 byte address type
//	n byte address
//	n byte payload
//
// so one TCP stream can carry packets to many destinations.
const maxDatagramPayload = maxPacketLen - 2 - 2 - 1 - 16

// packetConn is an outbound.PacketConn over a VLESS UDP association.
type packetConn struct {
	conn net.Conn

	rmu sync.Mutex
	wmu sync.Mutex

	readErr error
}

// ReadFrom implements outbound.PacketConn.
func (p *packetConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	if p.readErr != nil {
		return 0, netip.AddrPort{}, p.readErr
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(p.conn, lenBuf[:]); err != nil {
		p.readErr = err
		return 0, netip.AddrPort{}, err
	}
	length := int(binary.BigEndian.Uint16(lenBuf[:]))
	if length < 2+1 {
		p.readErr = fmt.Errorf("vless: invalid udp frame length %d", length)
		return 0, netip.AddrPort{}, p.readErr
	}
	frame := make([]byte, length)
	if _, err := io.ReadFull(p.conn, frame); err != nil {
		p.readErr = err
		return 0, netip.AddrPort{}, err
	}

	port := binary.BigEndian.Uint16(frame[:2])
	frame = frame[2:]
	addr, domain, rest, err := parseAddress(frame)
	if err != nil {
		p.readErr = err
		return 0, netip.AddrPort{}, err
	}
	if domain != "" {
		if ip, err := netip.ParseAddr(domain); err == nil {
			addr = ip
		} else {
			// outbound.PacketConn only carries netip.AddrPort; a domain target can
			// only be reported as an invalid address.
			copy(b, rest)
			return len(rest), netip.AddrPort{}, nil
		}
	}
	if !addr.IsValid() {
		p.readErr = errors.New("vless: udp frame without a destination")
		return 0, netip.AddrPort{}, p.readErr
	}
	if len(rest) > len(b) {
		p.readErr = io.ErrShortBuffer
		return 0, netip.AddrPort{}, p.readErr
	}
	n := copy(b, rest)
	return n, netip.AddrPortFrom(addr, port), nil
}

// WriteTo implements outbound.PacketConn.
func (p *packetConn) WriteTo(b []byte, addr netip.AddrPort) (int, error) {
	if len(b) > maxDatagramPayload {
		return 0, fmt.Errorf("vless: datagram of %d bytes exceeds the maximum (%d)", len(b), maxDatagramPayload)
	}
	if !addr.IsValid() {
		return 0, errors.New("vless: udp write with an invalid destination")
	}
	target := addr.Addr().Unmap()
	frame := make([]byte, 0, 2+2+1+16+len(b))
	frame = append(frame, 0, 0) // length placeholder
	frame = appendPort(frame, addr.Port())
	frame, err := appendAddress(frame, target, "")
	if err != nil {
		return 0, err
	}
	frame = append(frame, b...)
	if len(frame)-2 > maxPacketLen {
		return 0, fmt.Errorf("vless: udp frame of %d bytes exceeds the maximum", len(frame)-2)
	}
	binary.BigEndian.PutUint16(frame[:2], uint16(len(frame)-2))

	p.wmu.Lock()
	defer p.wmu.Unlock()
	if _, err := p.conn.Write(frame); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close implements outbound.PacketConn.
func (p *packetConn) Close() error { return p.conn.Close() }

// SetDeadline implements outbound.PacketConn.
func (p *packetConn) SetDeadline(t time.Time) error { return p.conn.SetDeadline(t) }

var _ outbound.PacketConn = (*packetConn)(nil)
