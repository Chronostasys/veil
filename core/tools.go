//go:build tools

package veil

import (
	_ "github.com/miekg/dns"
	_ "github.com/quic-go/quic-go"
	_ "github.com/refraction-networking/utls"
	_ "golang.org/x/crypto/chacha20poly1305"
	_ "golang.org/x/net/http2"
	_ "golang.org/x/sys/unix"
	_ "gopkg.in/yaml.v3"
	_ "gvisor.dev/gvisor/pkg/tcpip/link/channel"
)
