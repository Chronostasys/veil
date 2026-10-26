package dns

import (
	"context"
	"errors"
	"net"
	"time"

	mdns "github.com/miekg/dns"
)

// handler adapts Resolver.Exchange to miekg/dns's Handler interface.
type handler struct {
	r *Resolver
}

// ServeDNS answers one query. Malformed messages never reach here (miekg/dns
// drops them), so a handler panic would only come from our own bugs; we keep
// this path allocation-light and defensive anyway.
func (h *handler) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	if req == nil {
		return
	}
	query, err := req.Pack()
	if err != nil {
		resp := new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeFormatError)
		_ = w.WriteMsg(resp)
		return
	}

	raw, exErr := h.r.Exchange(context.Background(), query)
	if exErr != nil || raw == nil {
		resp := new(mdns.Msg)
		resp.SetRcode(req, mdns.RcodeServerFailure)
		resp.RecursionAvailable = true
		_ = w.WriteMsg(resp)
		return
	}

	resp := new(mdns.Msg)
	if err := resp.Unpack(raw); err != nil {
		fb := new(mdns.Msg)
		fb.SetRcode(req, mdns.RcodeServerFailure)
		fb.RecursionAvailable = true
		_ = w.WriteMsg(fb)
		return
	}
	_ = w.WriteMsg(resp)
}

func newServer(r *Resolver) *mdns.Server {
	return &mdns.Server{
		Handler:     &handler{r: r},
		UDPSize:     4096,
		ReadTimeout: 5 * time.Second,
		// WriteTimeout is intentionally left at the library default so that a
		// slow tunnel does not turn large answers into truncated replies.
	}
}

// ServePacket serves DNS over an existing packet connection (the tun device).
// It blocks until the connection is closed.
func (r *Resolver) ServePacket(pc net.PacketConn) error {
	if pc == nil {
		return errors.New("dns: nil packet conn")
	}
	srv := newServer(r)
	srv.PacketConn = pc
	return srv.ActivateAndServe()
}

// ServeTCP serves DNS over an existing stream listener. It blocks until the
// listener is closed.
func (r *Resolver) ServeTCP(l net.Listener) error {
	if l == nil {
		return errors.New("dns: nil listener")
	}
	srv := newServer(r)
	srv.Listener = l
	return srv.ActivateAndServe()
}
