package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"veil/internal/config"
)

// testUpstream is a local UDP DNS server used by the tests.
type testUpstream struct {
	pc     net.PacketConn
	srv    *mdns.Server
	total  atomic.Int64 // all queries
	aCount atomic.Int64 // A queries only
	nx     atomic.Bool
	delay  time.Duration
}

func newTestUpstream(t *testing.T) *testUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	u := &testUpstream{pc: pc}
	u.srv = &mdns.Server{PacketConn: pc, Handler: u, UDPSize: 4096}
	t.Cleanup(func() { _ = pc.Close() })
	return u
}

// start launches the server; call it after all fields are configured so the
// handler goroutine never races with test setup.
func (u *testUpstream) start() {
	go func() { _ = u.srv.ActivateAndServe() }()
}

func (u *testUpstream) addr() string { return u.pc.LocalAddr().String() }

func (u *testUpstream) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	u.total.Add(1)
	if u.delay > 0 {
		time.Sleep(u.delay)
	}
	m := new(mdns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	if len(req.Question) != 1 {
		m.Rcode = mdns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	if u.nx.Load() || q.Name != "example.com." {
		m.Rcode = mdns.RcodeNameError
		_ = w.WriteMsg(m)
		return
	}
	switch q.Qtype {
	case mdns.TypeA:
		u.aCount.Add(1)
		m.Answer = append(m.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.IPv4(93, 184, 216, 34).To4(),
		})
	case mdns.TypeAAAA:
		m.Answer = append(m.Answer, &mdns.AAAA{
			Hdr:  mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
		})
	default:
		m.Rcode = mdns.RcodeNameError
	}
	_ = w.WriteMsg(m)
}

func newResolver(t *testing.T, servers ...config.DNSServer) *Resolver {
	t.Helper()
	r, err := New(config.DNSConfig{Enable: true, Cache: true, Servers: servers}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// These tests exercise the upstream/cache path; fake-IP answers are covered
	// by TestFakeIPAnswersLocally.
	r.DisableFakeIP()
	return r
}

func TestLookupUDPAndCache(t *testing.T) {
	up := newTestUpstream(t)
	up.start()
	r := newResolver(t, config.DNSServer{Tag: "local", Addr: up.addr()})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := r.Lookup(ctx, "example.com.")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("want 2 addresses (A+AAAA), got %v", addrs)
	}
	var has4, has6 bool
	for _, a := range addrs {
		has4 = has4 || a.Is4()
		has6 = has6 || a.Is6()
	}
	if !has4 || !has6 {
		t.Fatalf("expected both A and AAAA, got %v", addrs)
	}

	before := up.total.Load()
	if _, err := r.Lookup(ctx, "Example.COM"); err != nil {
		t.Fatalf("cached Lookup: %v", err)
	}
	if after := up.total.Load(); after != before {
		t.Fatalf("cache miss: upstream queries %d -> %d", before, after)
	}
	if n := r.state().cacheLen(); n != 1 {
		t.Fatalf("cache length = %d, want 1", n)
	}
}

func TestSingleFlight(t *testing.T) {
	up := newTestUpstream(t)
	up.delay = 50 * time.Millisecond
	up.start()
	r := newResolver(t, config.DNSServer{Addr: up.addr()})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const n = 20
	var (
		wg    sync.WaitGroup
		errCh = make(chan error, n)
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := r.Lookup(ctx, "example.com"); err != nil {
				errCh <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent Lookup: %v", err)
	}

	if got := up.aCount.Load(); got != 1 {
		t.Fatalf("A queries = %d, want 1 (single-flight)", got)
	}
	if got := up.total.Load(); got != 2 {
		t.Fatalf("total upstream queries = %d, want 2 (one A + one AAAA round)", got)
	}
}

func TestDoH(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if ct := req.Header.Get("Content-Type"); ct != "application/dns-message" {
			http.Error(w, "bad content-type "+ct, http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		var query mdns.Msg
		if err := query.Unpack(body); err != nil {
			http.Error(w, "unpack", http.StatusBadRequest)
			return
		}
		hits.Add(1)
		resp := new(mdns.Msg)
		resp.SetReply(&query)
		resp.RecursionAvailable = true
		if q := query.Question[0]; q.Qtype == mdns.TypeA {
			resp.Answer = append(resp.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 30},
				A:   net.IPv4(203, 0, 113, 7).To4(),
			})
		}
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	defer srv.Close()

	r := newResolver(t, config.DNSServer{Tag: "doh", Addr: srv.URL + "/dns-query"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := r.Lookup(ctx, "doh.example")
	if err != nil {
		t.Fatalf("DoH Lookup: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "203.0.113.7" {
		t.Fatalf("unexpected DoH answers: %v", addrs)
	}
	if hits.Load() == 0 {
		t.Fatal("DoH server was never hit")
	}
}

func TestServePacket(t *testing.T) {
	up := newTestUpstream(t)
	up.start()
	r := newResolver(t, config.DNSServer{Addr: up.addr()})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	go func() { _ = r.ServePacket(pc) }()

	client := &mdns.Client{Net: "udp", Timeout: 3 * time.Second}
	query := new(mdns.Msg)
	query.SetQuestion("example.com.", mdns.TypeA)

	resp, _, err := client.Exchange(query, pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("rcode = %s", mdns.RcodeToString[resp.Rcode])
	}
	if !resp.RecursionAvailable || !resp.Response {
		t.Fatalf("flags not set: RA=%v response=%v", resp.RecursionAvailable, resp.Response)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %v", resp.Answer)
	}
	if ip, ok := resp.Answer[0].(*mdns.A); !ok || ip.A.String() != "93.184.216.34" {
		t.Fatalf("unexpected answer: %v", resp.Answer[0])
	}

	// Malformed packet must not panic the server.
	raw, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial raw: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := raw.Write([]byte{0x00, 0x01, 0xff, 0xff, 0x00}); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	buf := make([]byte, 512)
	_, _ = raw.Read(buf) // response or timeout; either way we must survive

	// And the server still answers afterwards.
	resp2, _, err := client.Exchange(query, pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("exchange after garbage: %v", err)
	}
	if len(resp2.Answer) != 1 {
		t.Fatalf("answers after garbage = %v", resp2.Answer)
	}
}

func TestExchangeMalformed(t *testing.T) {
	up := newTestUpstream(t)
	up.start()
	r := newResolver(t, config.DNSServer{Addr: up.addr()})
	ctx := context.Background()

	for _, in := range [][]byte{
		nil,
		{},
		{0x12, 0x34},
		[]byte("not a dns packet at all"),
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		out, err := r.Exchange(ctx, in)
		if err != nil {
			t.Fatalf("Exchange(%q) returned error: %v", in, err)
		}
		if len(out) < 12 {
			t.Fatalf("Exchange(%q) returned short reply %v", in, out)
		}
		var m mdns.Msg
		if err := m.Unpack(out); err != nil {
			t.Fatalf("Exchange(%q) reply does not unpack: %v", in, err)
		}
		if m.Rcode != mdns.RcodeFormatError {
			t.Fatalf("Exchange(%q) rcode = %s, want FORMERR", in, mdns.RcodeToString[m.Rcode])
		}
		if len(in) >= 2 && m.Id != binary.BigEndian.Uint16(in[:2]) {
			t.Fatalf("Exchange(%q) lost query ID", in)
		}
	}

	// Unsupported type -> NXDOMAIN, ID preserved.
	q := new(mdns.Msg)
	q.SetQuestion("example.com.", mdns.TypeMX)
	q.Id = 4242
	raw, _ := q.Pack()
	out, err := r.Exchange(ctx, raw)
	if err != nil {
		t.Fatalf("MX Exchange: %v", err)
	}
	var m mdns.Msg
	if err := m.Unpack(out); err != nil {
		t.Fatalf("MX reply unpack: %v", err)
	}
	if m.Id != 4242 || m.Rcode != mdns.RcodeNameError || !m.Response {
		t.Fatalf("MX reply id=%d rcode=%s response=%v", m.Id, mdns.RcodeToString[m.Rcode], m.Response)
	}
}

func TestLookupUnknownHost(t *testing.T) {
	up := newTestUpstream(t)
	up.nx.Store(true)
	up.start()
	r := newResolver(t, config.DNSServer{Addr: up.addr()})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if addrs, err := r.Lookup(ctx, "nope.example"); err == nil {
		t.Fatalf("expected error for unknown host, got %v", addrs)
	}
	// Negative result is cached for a short while.
	before := up.total.Load()
	if _, err := r.Lookup(ctx, "nope.example"); err == nil {
		t.Fatal("expected cached error")
	}
	if after := up.total.Load(); after != before {
		t.Fatalf("negative cache miss: %d -> %d", before, after)
	}
}

func TestLookupPlainIP(t *testing.T) {
	r := newResolver(t) // no upstreams at all
	ctx := context.Background()
	addrs, err := r.Lookup(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("literal lookup: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1" {
		t.Fatalf("literal lookup = %v", addrs)
	}
	if _, err := r.Lookup(ctx, "::1"); err != nil {
		t.Fatalf("v6 literal lookup: %v", err)
	}
}

func TestDomainRouting(t *testing.T) {
	// Parse-level check that suffix lists and the final server are honoured.
	r := newResolver(t,
		config.DNSServer{Tag: "local", Addr: "udp://223.5.5.5:53", Domains: []string{"cn", ".example.com"}},
		config.DNSServer{Tag: "remote", Addr: "tls://1.1.1.1:853"},
	)
	r.cfg.Final = "remote"

	got := r.upstreamsFor("www.example.com")
	if len(got) != 2 || got[0].addr != "223.5.5.5:53" || got[1].addr != "1.1.1.1:853" {
		t.Fatalf("routing order = %+v", got)
	}
	if got := r.upstreamsFor("unrelated.org"); len(got) != 2 || got[0].addr != "1.1.1.1:853" {
		t.Fatalf("final server not first: %+v", got)
	}
}

// TestFakeIPAnswersLocally pins the proxy-side-DNS design: an A query is
// answered from the synthetic pool without any upstream query, and the address
// maps back to the same domain.
func TestFakeIPAnswersLocally(t *testing.T) {
	up := newTestUpstream(t)
	up.start()
	r, err := New(config.DNSConfig{Enable: true, Servers: []config.DNSServer{{Addr: up.addr()}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := new(mdns.Msg)
	q.SetQuestion("www.google.com.", mdns.TypeA)
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.Exchange(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	var msg mdns.Msg
	if err := msg.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(msg.Answer))
	}
	a, ok := msg.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("answer type %T", msg.Answer[0])
	}
	ip, ok := netip.AddrFromSlice(a.A)
	if !ok || !r.IsFake(ip) {
		t.Fatalf("expected synthetic address, got %v", a.A)
	}
	host, ok := r.HostFor(ip)
	if !ok || host != "www.google.com" {
		t.Fatalf("HostFor(%v) = %q,%v", ip, host, ok)
	}
	// No upstream traffic: it must be answered locally.
	if n := up.total.Load(); n != 0 {
		t.Fatalf("upstream queried %d times", n)
	}
}
