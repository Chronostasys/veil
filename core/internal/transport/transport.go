// Package transport provides the stream layer beneath proxy protocols:
// TCP, TLS (uTLS fingerprints), REALITY, WebSocket and gRPC.
package transport

import (
	"context"
	"net"
)

// Dialer opens a single stream to a fixed remote endpoint.
type Dialer interface {
	Dial(ctx context.Context) (net.Conn, error)
}

// DialerFunc adapts a function to Dialer.
type DialerFunc func(ctx context.Context) (net.Conn, error)

// Dial implements Dialer.
func (f DialerFunc) Dial(ctx context.Context) (net.Conn, error) { return f(ctx) }

// TCP returns a dialer that opens a plain TCP connection to address.
//
// It uses the protect-aware dialer so that on HarmonyOS the socket is handed to
// VpnConnection.protect() before connect and never loops back into the tun.
func TCP(address string) Dialer {
	d := NewDialer()
	return DialerFunc(func(ctx context.Context) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", address)
	})
}

// TCPWith returns a dialer using the supplied net.Dialer.
func TCPWith(d *net.Dialer, address string) Dialer {
	return DialerFunc(func(ctx context.Context) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", address)
	})
}
