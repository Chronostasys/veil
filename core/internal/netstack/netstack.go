// Package netstack terminates the IP packets that arrive on the VPN tun file
// descriptor and turns them into ordinary TCP/UDP flows.
//
// The netstack is deliberately small: gVisor owns TCP/IP, this package owns the
// file descriptor pump, the forwarders, and the contract with the engine.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"veil/internal/logx"
)

const nicID = 1

// Handler receives terminated flows. The engine implements it.
type Handler interface {
	HandleTCP(ctx context.Context, conn net.Conn, target, source string) error
	HandleUDP(ctx context.Context, payload []byte, target, source string) ([]byte, error)
}

// Stack is a running userspace network stack bound to a tun device.
type Stack struct {
	f   *os.File
	ep  *channel.Endpoint
	s   *stack.Stack
	log *logx.Logger
	h   Handler

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// Start wires a packet stack to fd.
func Start(fd, mtu int, h Handler, log *logx.Logger) (*Stack, error) {
	if fd < 0 {
		return nil, errors.New("invalid tun fd")
	}
	f := os.NewFile(uintptr(fd), "veil-tun")
	if f == nil {
		return nil, errors.New("cannot wrap tun fd")
	}
	st, err := newStack(mtu, h, log)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	st.f = f
	st.startPump()
	return st, nil
}

// NewChannel builds a stack fed by an in-memory endpoint. It exists for tests.
func NewChannel(mtu int, h Handler, log *logx.Logger) (*Stack, error) {
	return newStack(mtu, h, log)
}

func newStack(mtu int, h Handler, log *logx.Logger) (*Stack, error) {
	if mtu <= 0 {
		mtu = 1400
	}
	if mtu > 65535 {
		mtu = 65535
	}
	if log == nil {
		log = logx.New(logx.Info, 128)
	}
	ep := channel.New(1024, uint32(mtu), "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	})
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create nic: %v", err)
	}
	// The tun has no meaningful assigned address: accept every destination and
	// let routing rules decide where it goes.
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	ctx, cancel := context.WithCancel(context.Background())
	st := &Stack{f: nil, ep: ep, s: s, log: log, h: h, ctx: ctx, cancel: cancel}

	tcpFwd := tcp.NewForwarder(s, 65535, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		target := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		source := net.JoinHostPort(id.RemoteAddress.String(), strconv.Itoa(int(id.RemotePort)))
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, ep)
		st.wg.Add(1)
		go func() {
			defer st.wg.Done()
			defer conn.Close()
			if err := h.HandleTCP(ctx, conn, target, source); err != nil {
				log.Debugf("tun tcp %s <- %s: %v", target, source, err)
			}
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		id := r.ID()
		target := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		source := net.JoinHostPort(id.RemoteAddress.String(), strconv.Itoa(int(id.RemotePort)))
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}
		conn := gonet.NewUDPConn(&wq, ep)
		st.wg.Add(1)
		go func() {
			defer st.wg.Done()
			defer conn.Close()
			st.serveUDP(conn, target, source)
		}()
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return st, nil
}

// serveUDP relays datagrams for one flow until it goes idle.
func (st *Stack) serveUDP(conn *gonet.UDPConn, target, source string) {
	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		ctx, cancel := context.WithTimeout(st.ctx, 10*time.Second)
		resp, err := st.h.HandleUDP(ctx, payload, target, source)
		cancel()
		if err != nil {
			st.log.Debugf("tun udp %s: %v", target, err)
			continue
		}
		if len(resp) == 0 {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

// startPump moves packets between the tun fd and the endpoint.
//
// The tun fd is non-blocking: a plain os.File.Read returns EAGAIN immediately
// after the first packet (or before any), and a read loop that treats that as
// EOF dies silently — which is exactly the "VPN is up but every counter stays
// zero" failure. So we poll the descriptor and retry.
func (st *Stack) startPump() {
	st.wg.Add(1)
	go func() {
		defer st.wg.Done()
		fd := int(st.f.Fd())
		buf := make([]byte, 65535)
		for {
			n, err := unix.Read(fd, buf)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				// Block until a packet arrives (timeout -1): an idle tunnel must
				// not wake the CPU at all. Close() closes the fd, which makes
				// Poll return an error and stops the loop.
				pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				if _, perr := unix.Poll(pfd, -1); perr != nil && perr != unix.EINTR {
					st.log.Debugf("tun poll stopped: %v", perr)
					return
				}
				continue
			}
			if err != nil {
				if st.ctx.Err() == nil && err != unix.EBADF {
					st.log.Debugf("tun read stopped: %v", err)
				}
				return
			}
			if n == 0 {
				continue
			}
			version := buf[0] >> 4
			var proto tcpip.NetworkProtocolNumber
			switch version {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			payload := append([]byte(nil), buf[:n]...)
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(payload),
			})
			st.ep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}()

	st.wg.Add(1)
	go func() {
		defer st.wg.Done()
		fd := int(st.f.Fd())
		for {
			pkt := st.ep.ReadContext(st.ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			data := view.AsSlice()
			// Write may be partial or EAGAIN; both are retried.
			off := 0
			for off < len(data) {
				n, err := unix.Write(fd, data[off:])
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
					if _, perr := unix.Poll(pfd, -1); perr != nil && perr != unix.EINTR {
						view.Release()
						pkt.DecRef()
						return
					}
					continue
				}
				if err != nil {
					if st.ctx.Err() == nil && err != unix.EBADF {
						st.log.Debugf("tun write stopped: %v", err)
					}
					view.Release()
					pkt.DecRef()
					return
				}
				off += n
			}
			view.Release()
			pkt.DecRef()
		}
	}()
}

// Endpoint exposes the in-memory endpoint for tests.
func (st *Stack) Endpoint() *channel.Endpoint { return st.ep }

// Close tears the stack down. It is idempotent.
func (st *Stack) Close() error {
	st.once.Do(func() {
		st.cancel()
		if st.f != nil {
			_ = st.f.Close()
		} else {
			// Tests drive the endpoint directly; unblock ReadContext.
			st.ep.Close()
		}
		st.s.Destroy()
	})
	done := make(chan struct{})
	go func() { st.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		return errors.New("netstack shutdown timed out")
	}
	return nil
}
