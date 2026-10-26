package inbound

import (
	"bufio"
	"fmt"
	"net"
	"time"

	"veil/internal/logx"
)

// Mixed is a listener that speaks both SOCKS5 and HTTP on the same port. The
// protocol is chosen by sniffing the first byte: 0x05 is a SOCKS5 greeting,
// anything else is treated as an HTTP request line.
type Mixed struct {
	handler Handler
	log     *logx.Logger
	listenerBase

	socks *SOCKS5
	http  *HTTP
}

// NewMixed binds addr and returns a mixed listener. addr may use port 0.
func NewMixed(addr string, h Handler, log *logx.Logger) (*Mixed, error) {
	if log == nil {
		log = logx.New(logx.Info, 128)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("mixed listen %s: %w", addr, err)
	}
	m := &Mixed{
		handler: h,
		log:     log,
		socks:   newSOCKS5(h, log),
		http:    newHTTP(h, log),
	}
	m.listenerBase = newListenerBase("mixed", ln, log)
	return m, nil
}

// Serve implements Server.
func (m *Mixed) Serve() error { return m.listenerBase.Serve(m.serveConn) }

// Close implements Server.
func (m *Mixed) Close() error { return m.listenerBase.Close() }

// Name implements Server. It is explicit because both sub-handlers carry a
// Name, which would otherwise make the selector ambiguous.
func (m *Mixed) Name() string { return "mixed" }

// Addr implements Server.
func (m *Mixed) Addr() string { return m.listenerBase.Addr() }

// Stats reports accepted connections seen by either protocol handler.
func (m *Mixed) Stats() (conns int64) {
	return m.socks.conns.Load() + m.http.conns.Load()
}

// Accepted is an alias of Stats.
func (m *Mixed) Accepted() int64 { return m.Stats() }

// Active reports connections currently being served.
func (m *Mixed) Active() int64 {
	return m.socks.active.Load() + m.http.active.Load()
}

// UDPDatagrams reports relayed UDP payloads (SOCKS5 UDP ASSOCIATE only).
func (m *Mixed) UDPDatagrams() int64 { return m.socks.udp.Load() }

func (m *Mixed) serveConn(c net.Conn) {
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(handshakeTimeout))
	first, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		m.log.Debugf("mixed %s: sniff first byte: %v", c.RemoteAddr(), err)
		_ = c.Close()
		return
	}
	// br still holds the peeked byte, so the sub-handler re-reads it.
	if first[0] == socks5Version {
		m.socks.serveBuffered(c, br)
		return
	}
	m.http.serveBuffered(c, br)
}
