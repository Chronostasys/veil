package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"veil/internal/outbound"
	"veil/internal/version"
)

// probeHTTP measures the time to a complete HTTP response through ob.
//
// A TCP handshake alone would flatter a broken node; requiring a real 2xx/204
// response through the tunnel is what the user actually cares about.
func probeHTTP(ctx context.Context, ob outbound.Outbound, url string, timeout time.Duration) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return ob.DialContext(ctx, network, address)
	}
	tr := &http.Transport{
		DialContext:         dial,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return -1, err
	}
	req.Header.Set("User-Agent", version.UserAgent)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	head, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ms := int(time.Since(start).Milliseconds())
	if ms <= 0 {
		ms = 1
	}
	// Only 2xx counts: an injected 302/403 is what a censored path returns, and
	// treating it as success is how "the tunnel works" lies were born.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return -1, fmt.Errorf("http %d (body %q)", resp.StatusCode, trim(head))
	}
	return ms, nil
}

func trim(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// netipAddrPort converts "host:port" to an AddrPort, resolving a domain via
// the engine resolver when necessary.
func netipAddrPort(target string) (netip.AddrPort, error) {
	return netip.ParseAddrPort(target)
}
