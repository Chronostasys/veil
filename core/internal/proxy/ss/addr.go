package ss

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// SOCKS5 address types, as used by Shadowsocks for the request header and by
// the legacy UDP packet body.
const (
	addrTypeIPv4   = 1
	addrTypeDomain = 3
	addrTypeIPv6   = 4
)

// AddrSize returns the size of the SOCKS5 encoding of addr.
func addrSize(addr netip.AddrPort) int {
	ip := addr.Addr().Unmap()
	switch {
	case ip.Is4():
		return 1 + 4 + 2
	case ip.Is6():
		return 1 + 16 + 2
	default:
		return 0
	}
}

// appendAddr appends the SOCKS5 encoding of addr to b.
func appendAddr(b []byte, addr netip.AddrPort) []byte {
	ip := addr.Addr().Unmap()
	port := addr.Port()
	switch {
	case ip.Is4():
		a := ip.As4()
		b = append(b, addrTypeIPv4)
		b = append(b, a[:]...)
	case ip.Is6():
		a := ip.As16()
		b = append(b, addrTypeIPv6)
		b = append(b, a[:]...)
	default:
		// Unreachable for a valid AddrPort; keep the encoder total.
		b = append(b, addrTypeIPv4, 0, 0, 0, 0)
	}
	return binary.BigEndian.AppendUint16(b, port)
}

// appendDomainAddr appends a SOCKS5 domain-address encoding, used when the
// destination was configured as a hostname (no DNS resolution on our side).
func appendDomainAddr(b []byte, host string, port uint16) ([]byte, error) {
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("ss: invalid domain length %d", len(host))
	}
	b = append(b, addrTypeDomain, byte(len(host)))
	b = append(b, host...)
	return binary.BigEndian.AppendUint16(b, port), nil
}

// parseAddr decodes one SOCKS5 address from b and returns it with the number of
// bytes consumed.
func parseAddr(b []byte) (netip.AddrPort, int, error) {
	if len(b) < 1 {
		return netip.AddrPort{}, 0, fmt.Errorf("ss: truncated address")
	}
	switch b[0] {
	case addrTypeIPv4:
		if len(b) < 1+4+2 {
			return netip.AddrPort{}, 0, fmt.Errorf("ss: truncated ipv4 address")
		}
		var a [4]byte
		copy(a[:], b[1:5])
		port := binary.BigEndian.Uint16(b[5:7])
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), 7, nil
	case addrTypeIPv6:
		if len(b) < 1+16+2 {
			return netip.AddrPort{}, 0, fmt.Errorf("ss: truncated ipv6 address")
		}
		var a [16]byte
		copy(a[:], b[1:17])
		port := binary.BigEndian.Uint16(b[17:19])
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), 19, nil
	case addrTypeDomain:
		if len(b) < 2 {
			return netip.AddrPort{}, 0, fmt.Errorf("ss: truncated domain address")
		}
		n := int(b[1])
		if len(b) < 2+n+2 {
			return netip.AddrPort{}, 0, fmt.Errorf("ss: truncated domain address")
		}
		host := string(b[2 : 2+n])
		port := binary.BigEndian.Uint16(b[2+n : 2+n+2])
		addr, err := netip.ParseAddr(host)
		if err != nil {
			// Fall back to resolving; netip.AddrPort cannot carry a name.
			ips, lerr := net.LookupIP(host)
			if lerr != nil || len(ips) == 0 {
				return netip.AddrPort{}, 0, fmt.Errorf("ss: cannot resolve %q from peer", host)
			}
			addr, _ = netip.AddrFromSlice(ips[0])
		}
		return netip.AddrPortFrom(addr, port), 2 + n + 2, nil
	default:
		return netip.AddrPort{}, 0, fmt.Errorf("ss: unknown address type %d", b[0])
	}
}

// parseHostPort splits a "host:port" destination, letting the SOCKS5 domain
// form survive to the server instead of resolving it locally.
func parseHostPort(address string) (host string, port uint16, isDomain bool, err error) {
	h, p, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, false, fmt.Errorf("ss: bad destination %q: %w", address, err)
	}
	pn, err := strconv.ParseUint(p, 10, 16)
	if err != nil || pn == 0 {
		return "", 0, false, fmt.Errorf("ss: bad destination port %q", p)
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return h, uint16(pn), false, nil
	}
	return h, uint16(pn), true, nil
}
