// Package trojan implements the Trojan client protocol.
//
// Trojan hides a SOCKS5-ish handshake inside a TLS stream: the client sends
// hex(SHA-224(password)) + CRLF + command + address + CRLF and then talks
// plaintext. There is no response header — the server replies with the raw
// application stream (or, for UDP, with trojan UDP frames).
//
// The wire format matches Xray-core's proxy/trojan package byte for byte.
package trojan

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Commands. Note that UDP is 0x03, not 0x02 (0x02 is unused in trojan).
const (
	commandTCP byte = 0x01
	commandUDP byte = 0x03
)

// Address types (SOCKS5 numbering, unlike VMess).
const (
	atypIPv4   byte = 0x01
	atypDomain byte = 0x03
	atypIPv6   byte = 0x04
)

const (
	// maxPacketSize is the largest UDP payload a trojan peer may send. It
	// mirrors the limit enforced by Xray's packet reader; anything above is a
	// protocol violation rather than ordinary truncation.
	maxPacketSize = 8192

	// keyHexLen is the length of hex(SHA-224(password)).
	keyHexLen = 56

	crlf     = "\r\n"
	crlfLen  = len(crlf)
	headerSZ = keyHexLen + crlfLen
)

// ErrOversizePacket is returned when a peer announces a UDP frame larger than
// the protocol allows.
var ErrOversizePacket = errors.New("trojan: oversize UDP packet")

// passwordKey returns the 56-byte hex(SHA-224(password)) that identifies the
// user on the wire. Trojan deliberately uses a truncated hash so that the
// header prefix is fixed-size.
func passwordKey(password string) []byte {
	sum := sha256.Sum224([]byte(password))
	out := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(out, sum[:])
	return out
}

// appendAddrPort appends a SOCKS5-style [ATYP ADDR PORT] to dst.
func appendAddrPort(dst []byte, host string, port uint16) ([]byte, error) {
	host = trimBrackets(host)
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b := ip.As4()
			dst = append(dst, atypIPv4)
			dst = append(dst, b[:]...)
		} else {
			b := ip.As16()
			dst = append(dst, atypIPv6)
			dst = append(dst, b[:]...)
		}
		return binary.BigEndian.AppendUint16(dst, port), nil
	}
	if host == "" || len(host) > 255 {
		return nil, fmt.Errorf("trojan: invalid domain %q", host)
	}
	dst = append(dst, atypDomain, byte(len(host)))
	dst = append(dst, host...)
	return binary.BigEndian.AppendUint16(dst, port), nil
}

// readAddrPort reads a SOCKS5-style [ATYP ADDR PORT] from r. The host comes
// back as a string so domains survive; use toAddrPort for a numeric form.
func readAddrPort(r io.Reader) (host string, port uint16, err error) {
	var atyp [1]byte
	if _, err = io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, err
	}
	switch atyp[0] {
	case atypIPv4:
		var b [4]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4(b).String()
	case atypIPv6:
		var b [16]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16(b).Unmap().String()
	case atypDomain:
		var l [1]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		if l[0] == 0 {
			return "", 0, errors.New("trojan: empty domain")
		}
		b := make([]byte, l[0])
		if _, err = io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, fmt.Errorf("trojan: unknown address type 0x%02x", atyp[0])
	}
	var pb [2]byte
	if _, err = io.ReadFull(r, pb[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(pb[:]), nil
}

// toAddrPort converts a host string to a netip.AddrPort. Domains are resolved
// because outbound.PacketConn can only report numeric addresses; in practice
// servers reply from IPs, so this path is rare.
func toAddrPort(host string, port uint16) (netip.AddrPort, error) {
	if ip, err := netip.ParseAddr(trimBrackets(host)); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), port), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("trojan: unresolvable datagram source %q", host)
	}
	return netip.AddrPortFrom(ips[0].Unmap(), port), nil
}

func trimBrackets(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

// splitHostPort is a lenient net.SplitHostPort: a bare host yields port 0.
func splitHostPort(address string) (string, uint16, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", 0, nil
	}
	if h, p, err := net.SplitHostPort(address); err == nil {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return "", 0, fmt.Errorf("trojan: invalid port in %q", address)
		}
		return trimBrackets(h), uint16(n), nil
	}
	if _, err := netip.ParseAddr(trimBrackets(address)); err == nil {
		return trimBrackets(address), 0, nil
	}
	// No port and not an IP literal: treat the whole string as a domain.
	if strings.Contains(address, ":") {
		return "", 0, fmt.Errorf("trojan: invalid address %q", address)
	}
	return address, 0, nil
}

// buildHeader appends the full trojan request header to dst:
//
//	hex(SHA-224(password)) CRLF command ATYP ADDR PORT CRLF
func buildHeader(dst []byte, key []byte, command byte, host string, port uint16) ([]byte, error) {
	dst = append(dst, key...)
	dst = append(dst, crlf...)
	dst = append(dst, command)
	var err error
	if dst, err = appendAddrPort(dst, host, port); err != nil {
		return nil, err
	}
	return append(dst, crlf...), nil
}
