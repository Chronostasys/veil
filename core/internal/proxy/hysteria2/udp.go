package hysteria2

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// randRead fills b with cryptographically random bytes.
func randRead(b []byte) (int, error) { return io.ReadFull(rand.Reader, b) }

// fragLifetime bounds how long an incomplete fragmented datagram is kept.
const fragLifetime = 10 * time.Second

// packetConn is one Hysteria2 UDP session. Every datagram carries the session
// id, so a single QUIC connection can multiplex independent UDP associations.
type packetConn struct {
	c         *Client
	conn      *quic.Conn
	sessionID uint32
	packetID  atomic.Uint32

	mu       sync.Mutex // guards deadline and the cancel of the pending read
	deadline time.Time
	cancel   context.CancelFunc

	fragMu sync.Mutex
	frags  map[uint16]*fragState

	wmu  sync.Mutex
	wbuf []byte

	buf []byte // scratch for ReceiveDatagram

	closeOnce sync.Once
	closed    chan struct{}
}

func (p *packetConn) nextPacketID() uint16 {
	return uint16(p.packetID.Add(1) - 1)
}

// ReadFrom implements outbound.PacketConn.
func (p *packetConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	for {
		msg, err := p.receive()
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		if msg.sessionID != p.sessionID {
			// Another session on the same connection; not ours.
			continue
		}
		if msg.fragCount > 1 {
			data := p.addFragment(msg)
			if data == nil {
				continue
			}
			msg.data = data
		}
		addr, err := netip.ParseAddrPort(msg.addr)
		if err != nil {
			// Hysteria2 always answers with an IP:port; a name would be a
			// protocol violation, so drop it rather than guess.
			continue
		}
		return copy(b, msg.data), addr, nil
	}
}

func (p *packetConn) receive() (*udpMessage, error) {
	for {
		ctx, cancel, err := p.readContext()
		if err != nil {
			return nil, err
		}
		data, err := p.conn.ReceiveDatagram(ctx)
		cancel()
		p.clearCancel()
		if err != nil {
			select {
			case <-p.closed:
				return nil, net.ErrClosed
			default:
			}
			if p.conn.Context().Err() != nil {
				return nil, errors.New("hysteria2: quic connection closed")
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				if p.deadlineExpired() {
					return nil, deadlineError{}
				}
				// Woken up by SetDeadline: re-evaluate the new deadline.
				continue
			}
			return nil, err
		}
		msg, err := parseUDPMessage(data)
		if err != nil {
			// A malformed datagram must not kill the session.
			continue
		}
		return msg, nil
	}
}

func (p *packetConn) deadlineExpired() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.deadline.IsZero() && !time.Now().Before(p.deadline)
}

func (p *packetConn) clearCancel() {
	p.mu.Lock()
	p.cancel = nil
	p.mu.Unlock()
}

// readContext builds the context for one ReceiveDatagram call, honouring the
// current deadline and letting SetDeadline/Close interrupt a blocked read.
func (p *packetConn) readContext() (context.Context, context.CancelFunc, error) {
	select {
	case <-p.closed:
		return nil, nil, net.ErrClosed
	default:
	}
	p.mu.Lock()
	dl := p.deadline
	p.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	if dl.IsZero() {
		p.mu.Lock()
		p.cancel = cancel
		p.mu.Unlock()
		return ctx, cancel, nil
	}
	d := time.Until(dl)
	if d <= 0 {
		cancel()
		return nil, nil, deadlineError{}
	}
	timer := time.AfterFunc(d, cancel)
	p.mu.Lock()
	p.cancel = func() { timer.Stop(); cancel() }
	p.mu.Unlock()
	return ctx, func() { timer.Stop(); cancel() }, nil
}

// addFragment collects fragments and returns the reassembled payload once it is
// complete.
func (p *packetConn) addFragment(msg *udpMessage) []byte {
	p.fragMu.Lock()
	defer p.fragMu.Unlock()

	now := time.Now()
	for id, st := range p.frags {
		if now.Sub(st.seen) > fragLifetime {
			delete(p.frags, id)
		}
	}
	st, ok := p.frags[msg.packetID]
	if !ok || st.total != int(msg.fragCount) {
		st = &fragState{
			frags: make([][]byte, msg.fragCount),
			total: int(msg.fragCount),
		}
		p.frags[msg.packetID] = st
	}
	if st.frags[msg.fragID] == nil {
		st.frags[msg.fragID] = append([]byte(nil), msg.data...)
		st.filled++
	}
	st.seen = now
	data := st.commit()
	if data != nil {
		delete(p.frags, msg.packetID)
	}
	return data
}

// WriteTo implements outbound.PacketConn.
func (p *packetConn) WriteTo(b []byte, addr netip.AddrPort) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}

	if addr.Port() == 0 || !addr.Addr().IsValid() {
		return 0, fmt.Errorf("hysteria2: invalid destination %s", addr)
	}
	target := addrString(addr)

	msg := &udpMessage{
		sessionID: p.sessionID,
		packetID:  p.nextPacketID(),
		fragID:    0,
		fragCount: 1,
		addr:      target,
		data:      b,
	}

	p.wmu.Lock()
	defer p.wmu.Unlock()

	packet := msg.appendTo(p.wbuf[:0])
	err := p.conn.SendDatagram(packet)
	var tooLarge *quic.DatagramTooLargeError
	if err == nil || !errors.As(err, &tooLarge) {
		if err != nil {
			return 0, err
		}
		return len(b), nil
	}

	// The datagram does not fit: split it, keeping the same packet id so the
	// receiver can reassemble.
	maxPayload := int(tooLarge.MaxDatagramPayloadSize)
	if maxPayload <= 0 {
		return 0, fmt.Errorf("hysteria2: datagram too large and cannot be fragmented")
	}
	header := 4 + 2 + 1 + 1 + quicvarintLen(uint64(len(target))) + len(target)
	chunk := maxPayload - header
	if chunk <= 0 {
		return 0, fmt.Errorf("hysteria2: datagram header leaves no room for payload")
	}
	count := (len(b) + chunk - 1) / chunk
	if count > 255 {
		return 0, fmt.Errorf("hysteria2: payload %d bytes needs %d fragments (max 255)", len(b), count)
	}
	for i := 0; i < count; i++ {
		start := i * chunk
		end := min(start+chunk, len(b))
		frag := &udpMessage{
			sessionID: msg.sessionID,
			packetID:  msg.packetID,
			fragID:    uint8(i),
			fragCount: uint8(count),
			addr:      target,
			data:      b[start:end],
		}
		if err := p.conn.SendDatagram(frag.appendTo(p.wbuf[:0])); err != nil {
			return start, err
		}
	}
	return len(b), nil
}

// SetDeadline implements outbound.PacketConn. It applies to reads that have not
// started yet and also interrupts a read already blocked in ReceiveDatagram.
func (p *packetConn) SetDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	cancel := p.cancel
	p.cancel = nil
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// Close implements outbound.PacketConn.
func (p *packetConn) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.mu.Lock()
		cancel := p.cancel
		p.cancel = nil
		p.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		p.c.mu.Lock()
		delete(p.c.sessions, p)
		p.c.mu.Unlock()
	})
	return nil
}

func quicvarintLen(v uint64) int {
	switch {
	case v < 64:
		return 1
	case v < 16384:
		return 2
	case v < 1073741824:
		return 4
	default:
		return 8
	}
}

var _ = binary.BigEndian // keep the import for future framing changes
