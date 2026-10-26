// Package hysteria2 implements the Hysteria2 client protocol.
//
// Hysteria2 rides on QUIC with ALPN "h3". The first thing a client does is an
// HTTP/3 POST to https://hysteria/auth carrying the credential in the
// Hysteria-Auth header; a 233 response means the connection may be used.
// Afterwards:
//
//   - TCP: each stream starts with a varint 0x401 request frame carrying the
//     destination as a "host:port" string, then raw bytes flow in both
//     directions (the server answers with a status frame first).
//   - UDP: QUIC datagrams carrying session id, packet id, fragment info, the
//     destination address and the payload.
//
// The QUIC connection is shared by every stream and datagram session and is
// dialed lazily, then redialed on failure. Close() tears it down.
package hysteria2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

// Wire constants, mirroring hysteria's internal/protocol package.
const (
	alpnH3     = "h3"
	authHost   = "hysteria"
	authPath   = "/auth"
	statusAuth = 233

	headerAuth       = "Hysteria-Auth"
	headerCCRX       = "Hysteria-CC-RX"
	headerPadding    = "Hysteria-Padding"
	headerUDPEnabled = "Hysteria-UDP"

	frameTypeTCPRequest = 0x401

	maxAddressLength = 2048
	maxMessageLength = 2048
	maxPaddingLength = 4096

	// maxDatagramSize is the datagram size hysteria2 servers are tuned for.
	// quic-go derives the actual limit from the path MTU, so this is only used
	// as documentation and to size the fragment headers.
	maxDatagramSize = 1200
	// maxUDPSize bounds what we accept from the server.
	maxUDPSize = 4096

	tcpRequestPaddingMin = 64
	tcpRequestPaddingMax = 512
	authPaddingMin       = 256
	authPaddingMax       = 2048
)

var paddingChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// randomPadding returns a random-length random ASCII string. Hysteria uses it
// to keep the auth request and TCP request headers from having a fixed size.
func randomPadding(minLen, maxLen int) string {
	n := minLen + rand.Intn(maxLen-minLen)
	b := make([]byte, n)
	for i := range b {
		b[i] = paddingChars[rand.Intn(len(paddingChars))]
	}
	return string(b)
}

// addrString renders a destination the way hysteria expects it: "host:port",
// with IPv6 in brackets.
func addrString(addr netip.AddrPort) string {
	return addr.String()
}

// normalizeAddr validates a destination string and returns it in canonical
// "host:port" form. The server resolves names, so this does not touch DNS.
func normalizeAddr(address string) (string, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return "", err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, port).String(), nil
	}
	if len(host) == 0 || len(host) > 255 {
		return "", fmt.Errorf("hysteria2: invalid host %q", host)
	}
	return host + ":" + strconv.FormatUint(uint64(port), 10), nil
}

func splitHostPort(address string) (string, uint16, error) {
	if len(address) == 0 {
		return "", 0, errors.New("hysteria2: empty destination")
	}
	if addr, err := netip.ParseAddrPort(address); err == nil {
		return addr.Addr().String(), addr.Port(), nil
	}
	i := strings.LastIndexByte(address, ':')
	if i <= 0 || i == len(address)-1 {
		return "", 0, fmt.Errorf("hysteria2: destination %q is not host:port", address)
	}
	host := strings.TrimSuffix(strings.TrimPrefix(address[:i], "["), "]")
	p, err := strconv.ParseUint(address[i+1:], 10, 16)
	if err != nil || p == 0 {
		return "", 0, fmt.Errorf("hysteria2: bad port in %q", address)
	}
	return host, uint16(p), nil
}

// writeTCPRequest writes the 0x401 request frame:
//
//	varint(0x401) || varint(len(addr)) || addr || varint(len(padding)) || padding
func writeTCPRequest(w io.Writer, addr string) error {
	padding := randomPadding(tcpRequestPaddingMin, tcpRequestPaddingMax)
	buf := make([]byte, 0, 8+len(addr)+len(padding))
	buf = quicvarint.Append(buf, frameTypeTCPRequest)
	buf = quicvarint.Append(buf, uint64(len(addr)))
	buf = append(buf, addr...)
	buf = quicvarint.Append(buf, uint64(len(padding)))
	buf = append(buf, padding...)
	_, err := w.Write(buf)
	return err
}

// readTCPResponse reads the server's status frame:
//
//	status(1) || varint(len(msg)) || msg || varint(len(padding)) || padding
func readTCPResponse(r io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return fmt.Errorf("hysteria2: read response: %w", err)
	}
	vr := quicvarint.NewReader(r)
	msgLen, err := quicvarint.Read(vr)
	if err != nil {
		return fmt.Errorf("hysteria2: read response message length: %w", err)
	}
	if msgLen > maxMessageLength {
		return fmt.Errorf("hysteria2: response message too long (%d)", msgLen)
	}
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(r, msg); err != nil {
		return fmt.Errorf("hysteria2: read response message: %w", err)
	}
	padLen, err := quicvarint.Read(vr)
	if err != nil {
		return fmt.Errorf("hysteria2: read response padding length: %w", err)
	}
	if padLen > maxPaddingLength {
		return fmt.Errorf("hysteria2: response padding too long (%d)", padLen)
	}
	if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
		return fmt.Errorf("hysteria2: read response padding: %w", err)
	}
	if status[0] != 0 {
		if len(msg) == 0 {
			return errors.New("hysteria2: server refused the connection")
		}
		return fmt.Errorf("hysteria2: server refused the connection: %s", msg)
	}
	return nil
}

// udpMessage is one Hysteria2 datagram:
//
//	session id (4) || packet id (2) || fragment id (1) || fragment count (1)
//	|| varint(len(addr)) || addr || payload
type udpMessage struct {
	sessionID uint32
	packetID  uint16
	fragID    uint8
	fragCount uint8
	addr      string
	data      []byte
}

func (m *udpMessage) headerSize() int {
	return 4 + 2 + 1 + 1 + quicvarint.Len(uint64(len(m.addr))) + len(m.addr)
}

func (m *udpMessage) size() int { return m.headerSize() + len(m.data) }

func (m *udpMessage) appendTo(buf []byte) []byte {
	buf = binary.BigEndian.AppendUint32(buf, m.sessionID)
	buf = binary.BigEndian.AppendUint16(buf, m.packetID)
	buf = append(buf, m.fragID, m.fragCount)
	buf = quicvarint.Append(buf, uint64(len(m.addr)))
	buf = append(buf, m.addr...)
	return append(buf, m.data...)
}

func parseUDPMessage(b []byte) (*udpMessage, error) {
	if len(b) < 8 {
		return nil, errors.New("hysteria2: short udp message")
	}
	m := &udpMessage{
		sessionID: binary.BigEndian.Uint32(b[0:4]),
		packetID:  binary.BigEndian.Uint16(b[4:6]),
		fragID:    b[6],
		fragCount: b[7],
	}
	addrLen, n, err := quicvarint.Parse(b[8:])
	if err != nil || n <= 0 {
		return nil, errors.New("hysteria2: bad udp address length")
	}
	if addrLen == 0 || addrLen > maxAddressLength {
		return nil, fmt.Errorf("hysteria2: invalid udp address length %d", addrLen)
	}
	rest := b[8+n:]
	if len(rest) <= int(addrLen) {
		return nil, errors.New("hysteria2: truncated udp message")
	}
	m.addr = string(rest[:addrLen])
	m.data = rest[addrLen:]
	if m.fragCount == 0 {
		return nil, errors.New("hysteria2: zero fragment count")
	}
	if m.fragID >= m.fragCount {
		return nil, errors.New("hysteria2: fragment id out of range")
	}
	return m, nil
}

// fragState reassembles one fragmented datagram.
type fragState struct {
	frags  [][]byte
	filled int
	total  int
	seen   time.Time
}

// commit assembles the fragments; it returns nil until every fragment arrived.
func (f *fragState) commit() []byte {
	if f.filled < f.total {
		return nil
	}
	n := 0
	for _, p := range f.frags {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range f.frags {
		out = append(out, p...)
	}
	return out
}

// deadlineError is a net.Error with Timeout() == true, matching what callers
// expect from a PacketConn past its deadline.
type deadlineError struct{}

func (deadlineError) Error() string   { return "hysteria2: i/o timeout" }
func (deadlineError) Timeout() bool   { return true }
func (deadlineError) Temporary() bool { return true }
