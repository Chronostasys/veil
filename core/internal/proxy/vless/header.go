package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// VLESS wire format (Xray compatible).
//
// Request:
//
//	1 byte  protocol version (0x00)
//	16 byte user id
//	1 byte  addons length
//	n byte  addons (protobuf, used for the flow)
//	1 byte  command (1 TCP, 2 UDP, 3 Mux)
//	2 byte  port, big endian
//	1 byte  address type (1 IPv4, 2 domain, 3 IPv6)
//	n byte  address
//
// Response:
//
//	1 byte  version (0x00)
//	1 byte  addons length
//	n byte  addons
const (
	version = byte(0)

	commandTCP = byte(1)
	commandUDP = byte(2)
	commandMux = byte(3)

	addrIPv4   = byte(1)
	addrDomain = byte(2)
	addrIPv6   = byte(3)

	// FlowVision is the XTLS-Vision flow name.
	FlowVision = "xtls-rprx-vision"

	maxAddonsLen = 255
	maxPacketLen = 1<<16 - 1
)

// addons is the protobuf message Xray sends in the request header:
//
//	message Addons { string Flow = 1; }
type addons struct {
	Flow string
}

// marshal encodes the addons message the way proto.Marshal would for a single
// string field: tag 0x0A (field 1, wire type 2) + varint length + bytes.
func (a addons) marshal() ([]byte, error) {
	if a.Flow == "" {
		return nil, nil
	}
	if len(a.Flow) > maxAddonsLen-2 {
		return nil, fmt.Errorf("vless: flow name too long (%d bytes)", len(a.Flow))
	}
	out := make([]byte, 0, 2+len(a.Flow))
	out = append(out, 0x0A, byte(len(a.Flow)))
	out = append(out, a.Flow...)
	return out, nil
}

// unmarshalAddons decodes the protobuf body, skipping fields it does not know.
func unmarshalAddons(b []byte) (addons, error) {
	var a addons
	for len(b) > 0 {
		tag := b[0]
		field := tag >> 3
		wire := tag & 0x07
		b = b[1:]
		switch wire {
		case 0: // varint
			for len(b) > 0 && b[0]&0x80 != 0 {
				b = b[1:]
			}
			if len(b) == 0 {
				return a, errors.New("vless: truncated addons varint")
			}
			b = b[1:]
		case 1: // 64-bit
			if len(b) < 8 {
				return a, errors.New("vless: truncated addons fixed64")
			}
			b = b[8:]
		case 2: // length delimited
			if len(b) == 0 {
				return a, errors.New("vless: truncated addons length")
			}
			n, m := binary.Uvarint(b)
			if m <= 0 || uint64(len(b)-m) < n {
				return a, errors.New("vless: truncated addons field")
			}
			value := b[m : m+int(n)]
			if field == 1 {
				a.Flow = string(value)
			}
			b = b[m+int(n):]
		case 5: // 32-bit
			if len(b) < 4 {
				return a, errors.New("vless: truncated addons fixed32")
			}
			b = b[4:]
		default:
			return a, fmt.Errorf("vless: unsupported addons wire type %d", wire)
		}
	}
	return a, nil
}

// requestHeader is the decoded form of the bytes we send before any payload.
type requestHeader struct {
	User    [16]byte
	Flow    string
	Command byte
	Address netip.Addr // invalid for a domain
	Domain  string
	Port    uint16
}

// encode serialises the header.
func (h requestHeader) encode() ([]byte, error) {
	body, err := addons{Flow: h.Flow}.marshal()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 1+16+1+len(body)+1+2+1+len(h.Domain)+16)
	buf = append(buf, version)
	buf = append(buf, h.User[:]...)
	buf = append(buf, byte(len(body)))
	buf = append(buf, body...)
	buf = append(buf, h.Command)
	if h.Command != commandMux {
		// VLESS spec order: command, port (2 bytes BE), address type + address.
		buf = appendPort(buf, h.Port)
		var err error
		if buf, err = appendAddress(buf, h.Address, h.Domain); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// decodeRequestHeader parses a header. It is used by the test server and by
// interoperability tests; the client only ever encodes.
func decodeRequestHeader(b []byte) (requestHeader, error) {
	var h requestHeader
	if len(b) < 1+16+1 {
		return h, errors.New("vless: header too short")
	}
	if b[0] != version {
		return h, fmt.Errorf("vless: unsupported request version %d", b[0])
	}
	copy(h.User[:], b[1:17])
	b = b[17:]
	addonsLen := int(b[0])
	b = b[1:]
	if len(b) < addonsLen+1 {
		return h, errors.New("vless: truncated addons")
	}
	if addonsLen > 0 {
		a, err := unmarshalAddons(b[:addonsLen])
		if err != nil {
			return h, err
		}
		h.Flow = a.Flow
	}
	b = b[addonsLen:]
	h.Command = b[0]
	b = b[1:]
	if h.Command == commandMux {
		return h, nil
	}
	if len(b) < 2 {
		return h, errors.New("vless: truncated port")
	}
	h.Port = binary.BigEndian.Uint16(b[:2])
	b = b[2:]
	addr, domain, rest, err := parseAddress(b)
	if err != nil {
		return h, err
	}
	if len(rest) != 0 {
		return h, errors.New("vless: trailing bytes in header")
	}
	h.Address, h.Domain = addr, domain
	return h, nil
}

// encodeResponseHeader builds the two-byte response prefix plus addons.
func encodeResponseHeader(a addons) ([]byte, error) {
	body, err := a.marshal()
	if err != nil {
		return nil, err
	}
	if len(body) > maxAddonsLen {
		return nil, fmt.Errorf("vless: response addons too long (%d bytes)", len(body))
	}
	// version + addons length, always present even when there are no addons.
	buf := make([]byte, 0, 2+len(body))
	buf = append(buf, version, byte(len(body)))
	return append(buf, body...), nil
}

// readResponseHeader consumes the server's response prefix and validates the
// version. Addons (unused by Xray today) are skipped.
func readResponseHeader(r io.Reader) (addons, error) {
	var a addons
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return a, fmt.Errorf("vless: read response header: %w", err)
	}
	if head[0] != version {
		return a, fmt.Errorf("vless: unexpected response version %d", head[0])
	}
	n := int(head[1])
	if n == 0 {
		return a, nil
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return a, fmt.Errorf("vless: read response addons: %w", err)
	}
	return unmarshalAddons(body)
}

// appendPort writes the port.
func appendPort(buf []byte, port uint16) []byte {
	return append(buf, byte(port>>8), byte(port))
}

// appendAddress writes the address type byte and the address.
func appendAddress(buf []byte, addr netip.Addr, domain string) ([]byte, error) {
	if domain != "" {
		if len(domain) > 255 {
			return nil, fmt.Errorf("vless: domain name too long (%d bytes)", len(domain))
		}
		buf = append(buf, addrDomain, byte(len(domain)))
		return append(buf, domain...), nil
	}
	if !addr.IsValid() {
		return nil, errors.New("vless: no address")
	}
	if addr.Is4() {
		ip := addr.As4()
		buf = append(buf, addrIPv4)
		return append(buf, ip[:]...), nil
	}
	ip := addr.As16()
	buf = append(buf, addrIPv6)
	return append(buf, ip[:]...), nil
}

// parseAddress reads an address (type byte + body) and returns the remaining
// bytes.
func parseAddress(b []byte) (netip.Addr, string, []byte, error) {
	if len(b) < 1 {
		return netip.Addr{}, "", nil, errors.New("vless: missing address type")
	}
	atype := b[0]
	b = b[1:]
	switch atype {
	case addrIPv4:
		if len(b) < 4 {
			return netip.Addr{}, "", nil, errors.New("vless: truncated IPv4 address")
		}
		return netip.AddrFrom4([4]byte(b[:4])), "", b[4:], nil
	case addrIPv6:
		if len(b) < 16 {
			return netip.Addr{}, "", nil, errors.New("vless: truncated IPv6 address")
		}
		return netip.AddrFrom16([16]byte(b[:16])), "", b[16:], nil
	case addrDomain:
		if len(b) < 1 {
			return netip.Addr{}, "", nil, errors.New("vless: truncated domain length")
		}
		n := int(b[0])
		b = b[1:]
		if len(b) < n {
			return netip.Addr{}, "", nil, errors.New("vless: truncated domain")
		}
		return netip.Addr{}, string(b[:n]), b[n:], nil
	default:
		return netip.Addr{}, "", nil, fmt.Errorf("vless: unknown address type %d", atype)
	}
}

// destination splits a "host:port" address into its VLESS parts. IPv6 literals
// arrive bracketed from net.SplitHostPort.
func destination(address string) (netip.Addr, string, uint16, error) {
	host, portStr, err := splitHostPort(address)
	if err != nil {
		return netip.Addr{}, "", 0, err
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || p == 0 {
		return netip.Addr{}, "", 0, fmt.Errorf("vless: invalid port %q", portStr)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), "", uint16(p), nil
	}
	if host == "" {
		return netip.Addr{}, "", 0, errors.New("vless: empty host")
	}
	return netip.Addr{}, host, uint16(p), nil
}

// splitHostPort is net.SplitHostPort with a friendlier error.
func splitHostPort(address string) (string, string, error) {
	i := strings.LastIndexByte(address, ':')
	if i < 0 {
		return "", "", fmt.Errorf("vless: address %q has no port", address)
	}
	host := address[:i]
	port := address[i+1:]
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" || port == "" {
		return "", "", fmt.Errorf("vless: invalid address %q", address)
	}
	return host, port, nil
}

// parseUUID accepts the canonical dashed form and the bare 32-hex form.
func parseUUID(s string) ([16]byte, error) {
	var id [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != 32 {
		return id, fmt.Errorf("vless: invalid uuid %q", s)
	}
	decoded, err := decodeHex(clean)
	if err != nil {
		return id, fmt.Errorf("vless: invalid uuid %q: %w", s, err)
	}
	copy(id[:], decoded)
	return id, nil
}

// decodeHex decodes a lowercase or uppercase hex string.
func decodeHex(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, err := hexVal(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexVal(s[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex digit %q", string(c))
	}
}
