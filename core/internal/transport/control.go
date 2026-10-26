package transport

import (
	"net"
	"sync"
	"syscall"
	"time"
)

var (
	protectMu sync.RWMutex
	protectFn func(fd uintptr) error
)

// SetProtector installs a hook called for every socket before connect.
//
// On HarmonyOS the VPN captures all traffic; sockets created by the core must
// call VpnConnection.protect(fd) first or they would loop back into the tun and
// take the whole tunnel down. On other platforms the hook stays nil and costs
// nothing.
func SetProtector(fn func(fd uintptr) error) {
	protectMu.Lock()
	protectFn = fn
	protectMu.Unlock()
}

// NewDialer returns the net.Dialer every transport should use.
func NewDialer() *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	protectMu.RLock()
	fn := protectFn
	protectMu.RUnlock()
	if fn == nil {
		return d
	}
	d.Control = func(network, address string, c syscall.RawConn) error {
		var perr error
		if err := c.Control(func(fd uintptr) {
			perr = fn(fd)
		}); err != nil {
			return err
		}
		return perr
	}
	return d
}

// ProtectFD protects an already-created descriptor (QUIC sockets, tun-side
// helpers). It is a no-op when no protector is installed.
func ProtectFD(fd uintptr) error {
	protectMu.RLock()
	fn := protectFn
	protectMu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(fd)
}
