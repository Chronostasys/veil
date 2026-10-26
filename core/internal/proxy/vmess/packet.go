package vmess

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"veil/internal/outbound"
)

// packetConn is the UDP half of a VMess session: one chunk stream where every
// chunk is a datagram framed as
//
//	uint16(len(addr+payload)) || ATYP ADDR PORT || payload
//
// The destination travels with the datagram, so a single association reaches
// arbitrary peers.
type packetConn struct {
	conn net.Conn

	writeMu sync.Mutex
	writer  *chunkWriter

	readMu sync.Mutex
	reader *responseReader

	closeOnce sync.Once
	closed    atomic.Bool
}

var _ outbound.PacketConn = (*packetConn)(nil)

// WriteTo sends one datagram to addr.
func (p *packetConn) WriteTo(b []byte, addr netip.AddrPort) (int, error) {
	if len(b) > maxDatagramSize {
		return 0, fmt.Errorf("vmess: datagram of %d bytes exceeds %d", len(b), maxDatagramSize)
	}

	frame, err := appendAddrPort(nil, addr.Addr().Unmap().String(), addr.Port())
	if err != nil {
		return 0, err
	}
	bodyLen := len(frame) + len(b)
	if bodyLen > 0xffff {
		return 0, fmt.Errorf("vmess: datagram too large (%d bytes)", bodyLen)
	}
	// Length field first, then the address+payload it describes.
	out := make([]byte, 0, chunkSizeFieldLen+4+bodyLen)
	out = binary.BigEndian.AppendUint16(out, uint16(bodyLen))
	out = append(out, frame...)
	out = append(out, b...)

	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.closed.Load() {
		return 0, net.ErrClosed
	}
	if _, err := p.writer.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom receives one datagram.
func (p *packetConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()

	if p.closed.Load() {
		return 0, netip.AddrPort{}, net.ErrClosed
	}

	chunk, err := p.reader.nextChunk()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if len(chunk) < chunkSizeFieldLen {
		return 0, netip.AddrPort{}, errors.New("vmess: short datagram")
	}
	declared := int(binary.BigEndian.Uint16(chunk[:chunkSizeFieldLen]))
	if declared > len(chunk)-chunkSizeFieldLen {
		return 0, netip.AddrPort{}, fmt.Errorf("vmess: datagram length %d exceeds chunk payload %d", declared, len(chunk)-chunkSizeFieldLen)
	}
	body := chunk[chunkSizeFieldLen : chunkSizeFieldLen+declared]

	br := bytes.NewReader(body)
	host, port, err := readAddrPort(br)
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("vmess: datagram address: %w", err)
	}
	addr, err := addrPortFrom(host, port)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	payload := body[len(body)-br.Len():]
	return copy(b, payload), addr, nil
}

// Close closes the association.
func (p *packetConn) Close() error {
	var err error
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		err = p.conn.Close()
	})
	return err
}

// SetDeadline applies to the underlying stream in both directions.
func (p *packetConn) SetDeadline(t time.Time) error {
	return p.conn.SetDeadline(t)
}

func addrPortFrom(host string, port uint16) (netip.AddrPort, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), port), nil
	}
	return netip.AddrPort{}, fmt.Errorf("vmess: datagram source %q is not an IP address", host)
}

// maxDatagramSize bounds what we accept from WriteTo; the chunk length field
// caps a frame at 64 KiB anyway.
const maxDatagramSize = 8192
