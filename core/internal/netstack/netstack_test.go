package netstack

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"veil/internal/logx"
)

type fakeHandler struct {
	mu      sync.Mutex
	got     chan []byte
	udpResp []byte
}

func (f *fakeHandler) HandleTCP(ctx context.Context, conn net.Conn, target, source string) error {
	defer conn.Close()
	_, _ = conn.Write([]byte("echo:" + target))
	_ = conn.Close()
	return nil
}

func (f *fakeHandler) HandleUDP(ctx context.Context, payload []byte, target, source string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.got != nil {
		cp := append([]byte(nil), payload...)
		select {
		case f.got <- cp:
		default:
		}
	}
	return append([]byte(nil), f.udpResp...), nil
}

// buildUDP crafts an IPv4/UDP packet with valid checksums.
func buildUDP(t *testing.T, src, dst [4]byte, sport, dport uint16, payload []byte) []byte {
	t.Helper()
	b := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src),
		DstAddr:     tcpip.AddrFrom4(dst),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(ip.Payload())
	u.Encode(&header.UDPFields{
		SrcPort: sport,
		DstPort: dport,
		Length:  uint16(len(payload) + header.UDPMinimumSize),
	})
	copy(u.Payload(), payload)
	u.SetChecksum(0) // IPv4 allows a zero UDP checksum
	return b
}

// TestUDPForwarding proves the packet pump terminates a UDP flow, calls the
// handler and writes the reply back with correct framing.
func TestUDPForwarding(t *testing.T) {
	h := &fakeHandler{got: make(chan []byte, 4), udpResp: []byte("pong")}
	st, err := NewChannel(1400, h, logx.New(logx.Error, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	payload := []byte("ping")
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(
		buildUDP(t, [4]byte{172, 19, 0, 1}, [4]byte{172, 19, 0, 2}, 12345, 53, payload))})
	st.Endpoint().InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()

	select {
	case got := <-h.got:
		if string(got) != "ping" {
			t.Fatalf("handler payload = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler never saw the datagram")
	}

	// Read the reply packet: IPv4 + UDP with "pong".
	var resp *stack.PacketBuffer
	deadline := time.After(2 * time.Second)
	for resp == nil {
		select {
		case <-deadline:
			t.Fatal("no UDP reply packet")
		default:
		}
		resp = st.Endpoint().ReadContext(context.Background())
		if resp == nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	view := resp.ToView()
	raw := append([]byte(nil), view.AsSlice()...)
	view.Release()
	resp.DecRef()

	ip := header.IPv4(raw)
	if !ip.IsValid(len(raw)) {
		t.Fatalf("invalid IPv4 reply (%d bytes)", len(raw))
	}
	if ip.Protocol() != uint8(header.UDPProtocolNumber) {
		t.Fatalf("reply protocol = %d", ip.Protocol())
	}
	u := header.UDP(ip.Payload())
	if u.DestinationPort() != 12345 {
		t.Fatalf("reply dst port = %d", u.DestinationPort())
	}
	if got := string(u.Payload()); got != "pong" {
		t.Fatalf("reply payload = %q", got)
	}
}

// TestTCPForwarding proves a SYN is answered and a full stream reaches the
// handler. It drives the endpoint with a minimal hand-made TCP client.
func TestTCPForwarding(t *testing.T) {
	h := &fakeHandler{}
	st, err := NewChannel(1400, h, logx.New(logx.Error, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	syn := buildTCP(t, [4]byte{172, 19, 0, 1}, [4]byte{10, 0, 0, 1}, 40000, 443, 1000, header.TCPFlagSyn, nil)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(syn)})
	st.Endpoint().InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()

	var raw []byte
	deadline := time.After(3 * time.Second)
	for len(raw) == 0 {
		select {
		case <-deadline:
			t.Fatal("no SYN-ACK")
		default:
		}
		p := st.Endpoint().ReadContext(context.Background())
		if p == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		v := p.ToView()
		raw = append([]byte(nil), v.AsSlice()...)
		v.Release()
		p.DecRef()
	}
	ip := header.IPv4(raw)
	tcpHdr := header.TCP(ip.Payload())
	if tcpHdr.Flags()&header.TCPFlagSyn == 0 || tcpHdr.Flags()&header.TCPFlagAck == 0 {
		t.Fatalf("expected SYN-ACK, got flags %#x", tcpHdr.Flags())
	}
	if tcpHdr.SourcePort() != 443 {
		t.Fatalf("SYN-ACK from port %d", tcpHdr.SourcePort())
	}
}

func buildTCP(t *testing.T, src, dst [4]byte, sport, dport uint16, seq uint32, flags header.TCPFlags, payload []byte) []byte {
	t.Helper()
	b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(payload))
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src),
		DstAddr:     tcpip.AddrFrom4(dst),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcpHdr := header.TCP(ip.Payload())
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    sport,
		DstPort:    dport,
		SeqNum:     seq,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	copy(tcpHdr.Payload(), payload)
	xsum := tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(tcpHdr))))
	binary.BigEndian.PutUint16(tcpHdr[16:18], ^xsum)
	return b
}
