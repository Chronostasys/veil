// Package inbound implements local proxy listeners (SOCKS5 + HTTP) that hand
// accepted connections to the engine.
package inbound

import (
	"context"
	"net"
)

// Handler receives fully-parsed proxy requests from a listener.
type Handler interface {
	// HandleTCP relays conn (already accepted, protocol handshake done) to
	// target. It takes ownership of conn and returns when the relay ends.
	HandleTCP(ctx context.Context, conn net.Conn, target, source string) error
	// HandleUDP relays one datagram. Implementations may keep state; a fresh
	// call is made per datagram only when the protocol has no association.
	HandleUDP(ctx context.Context, payload []byte, target, source string) ([]byte, error)
}

// Server is a local listener.
type Server interface {
	// Serve blocks until Close is called or the listener fails.
	Serve() error
	// Close stops the listener and waits for Serve to return.
	Close() error
	// Addr is the bound address (useful when the config used port 0).
	Addr() string
	// Name is "mixed", "socks", "http" or "dns".
	Name() string
}
