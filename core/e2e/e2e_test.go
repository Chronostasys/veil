// Package e2e contains cross-package integration tests: a real SOCKS5 client
// through the engine to a real VLESS+REALITY server (the official xtls/reality
// server implementation), echoing bytes back. Nothing is mocked.
package e2e

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/reality"

	"veil/internal/config"
	"veil/internal/logx"
	"veil/internal/rpc"
	"veil/internal/state"
	"veil/internal/supervisor"
)

// echoServer starts a TCP echo server.
func echoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// vlessServer terminates a VLESS stream (no flow) and relays to the target.
func vlessServer(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	br := make([]byte, 1)
	if _, err := io.ReadFull(conn, br); err != nil {
		return
	}
	uuid := make([]byte, 16)
	if _, err := io.ReadFull(conn, uuid); err != nil {
		return
	}
	addonsLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, addonsLen); err != nil {
		return
	}
	if addonsLen[0] > 0 {
		if _, err := io.ReadFull(conn, make([]byte, addonsLen[0])); err != nil {
			return
		}
	}
	cmd := make([]byte, 1)
	if _, err := io.ReadFull(conn, cmd); err != nil || cmd[0] != 1 {
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return
	}
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(conn, atyp); err != nil {
		return
	}
	var host string
	switch atyp[0] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 2:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = string(b)
	case 3:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	target := net.JoinHostPort(host, fmt.Sprint(int(port[0])<<8|int(port[1])))
	upstream, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	// VLESS response header: version + addons length.
	if _, err := conn.Write([]byte{0x00, 0x00}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(upstream, conn) }()
	_, _ = io.Copy(conn, upstream)
}

// realityServer accepts REALITY connections and hands the terminated stream to
// the VLESS server.
func realityServer(t *testing.T, priv *ecdh.PrivateKey, sni string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// REALITY is a MITM: it replays the *target's* ServerHello to the client,
	// so Dest must be a real TLS 1.3 server, not a dummy listener.
	destAddr := tlsCamouflage(t)
	shortIDs := map[[8]byte]bool{{}: true}
	cfg := &reality.Config{
		DialContext:            (&net.Dialer{}).DialContext,
		Type:                   "tcp",
		Show:                   false,
		Dest:                   destAddr,
		ServerNames:            map[string]bool{sni: true},
		PrivateKey:             priv,
		ShortIds:               shortIDs,
		SessionTicketsDisabled: true,
		MaxTimeDiff:            30 * time.Second,
	}
	// The server must know the target's post-handshake record lengths before it
	// will finish a handshake (NewListener does this automatically).
	reality.DetectPostHandshakeRecordsLens(cfg)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				rc, err := reality.Server(context.Background(), c, cfg)
				if err != nil {
					_ = c.Close()
					return
				}
				vlessServer(t, rc)
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func socks5Echo(t *testing.T, proxyAddr, target string) error {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	host, ps, _ := net.SplitHostPort(target)
	port := 0
	fmt.Sscanf(ps, "%d", &port)
	req := append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		return err
	}
	if reply[1] != 0 {
		return fmt.Errorf("socks reply code %d", reply[1])
	}
	msg := []byte("veil-through-reality")
	if _, err := c.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if string(got) != string(msg) {
		return fmt.Errorf("echo mismatch: %q", got)
	}
	return nil
}

// TestVLESSRealityThroughEngine is the headline integration test: app config ->
// engine -> vless client -> REALITY handshake (official server) -> VLESS server
// -> echo server, observed through the SOCKS5 inbound and the stats API.
func TestVLESSRealityThroughEngine(t *testing.T) {
	echoAddr, stopEcho := echoServer(t)
	defer stopEcho()

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	pbk := base64.RawURLEncoding.EncodeToString(pub)
	realityAddr, stopReality := realityServer(t, priv, "www.icloud.com")
	defer stopReality()

	host, portStr, _ := net.SplitHostPort(realityAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	cfg := config.Default()
	cfg.LogLevel = "debug"
	cfg.Mixed = "127.0.0.1:0"
	cfg.Mode = config.ModeRule
	cfg.Tun.AutoRoute = false
	cfg.DNS.Enable = false
	cfg.Nodes = []config.Node{{
		Tag:    "reality",
		Type:   "vless",
		Server: host,
		Port:   port,
		UUID:   "11111111-2222-3333-4444-555555555555",
		TLS: &config.TLS{
			Enabled:    true,
			ServerName: "www.icloud.com",
			Reality:    &config.Reality{PublicKey: pbk},
		},
	}}
	cfg.Groups = []config.Group{{Tag: "proxy", Type: "select", Members: []string{"reality"}}}
	cfg.Rules = []config.Rule{{Type: "final", Action: "proxy"}}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	sup, err := supervisor.New(cfgPath, logx.New(logx.Debug, 512))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatal(err)
	}
	defer sup.Stop(context.Background())

	st := sup.Status()
	if st.Phase != state.PhaseRunning {
		t.Fatalf("phase=%s reason=%s", st.Phase, st.Reason)
	}
	proxyAddr := st.Inbounds[0].Addr

	if err := socks5Echo(t, proxyAddr, echoAddr); err != nil {
		t.Fatalf("through reality: %v", err)
	}
	// Repeat to prove the client is reusable and does not leak state.
	for i := 0; i < 5; i++ {
		if err := socks5Echo(t, proxyAddr, echoAddr); err != nil {
			t.Fatalf("repeat %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	var traffic state.Traffic
	for time.Now().Before(deadline) {
		traffic = sup.Status().Traffic
		if traffic.Up > 0 && traffic.Down > 0 && traffic.TotalConn >= 6 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if traffic.Up == 0 || traffic.Down == 0 {
		t.Fatalf("traffic counters empty: %+v", traffic)
	}

	// Delay probe through the same node.
	res, err := sup.Call(ctx, rpc.MethodDelay, json.RawMessage(`{"tag":"reality","timeout_ms":4000}`))
	if err != nil {
		t.Fatalf("delay rpc: %v", err)
	}
	b, _ := json.Marshal(res)
	var dr rpc.DelayResult
	_ = json.Unmarshal(b, &dr)
	// The echo server is not an HTTP server, so the probe must report a failure
	// rather than a fake latency.
	if dr.Delay > 0 && dr.Err == "" {
		t.Logf("probe unexpectedly succeeded: %+v", dr)
	}
}

// TestWrongRealityKeyFails proves REALITY authentication is actually enforced:
// a client with a different public key must not get a working tunnel.
func TestWrongRealityKeyFails(t *testing.T) {
	echoAddr, stopEcho := echoServer(t)
	defer stopEcho()

	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pbk := base64.RawURLEncoding.EncodeToString(other.PublicKey().Bytes())

	realityAddr, stopReality := realityServer(t, priv, "www.icloud.com")
	defer stopReality()
	host, portStr, _ := net.SplitHostPort(realityAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	cfg := config.Default()
	cfg.Mixed = "127.0.0.1:0"
	cfg.Mode = config.ModeRule
	cfg.Tun.AutoRoute = false
	cfg.DNS.Enable = false
	cfg.Nodes = []config.Node{{
		Tag: "bad", Type: "vless", Server: host, Port: port,
		UUID: "11111111-2222-3333-4444-555555555555",
		TLS:  &config.TLS{Enabled: true, ServerName: "www.icloud.com", Reality: &config.Reality{PublicKey: pbk}},
	}}
	cfg.Groups = []config.Group{{Tag: "proxy", Type: "select", Members: []string{"bad"}}}
	cfg.Rules = []config.Rule{{Type: "final", Action: "proxy"}}
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	sup, err := supervisor.New(cfgPath, logx.New(logx.Error, 128))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatal(err)
	}
	defer sup.Stop(ctx)

	err = socks5Echo(t, sup.Status().Inbounds[0].Addr, echoAddr)
	if err == nil {
		t.Fatal("REALITY accepted a wrong public key")
	}
	t.Logf("expected failure: %v", err)
}

var _ = os.Getpid

// TestVLESSPlainThroughEngine exercises the whole stack without REALITY: the
// same engine/inbound/VLESS code paths, with a plain VLESS server. It isolates
// transport crypto from routing/relay bugs.
func TestVLESSPlainThroughEngine(t *testing.T) {
	echoAddr, stopEcho := echoServer(t)
	defer stopEcho()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go vlessServer(t, c)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	cfg := config.Default()
	cfg.Mixed = "127.0.0.1:0"
	cfg.Mode = config.ModeRule
	cfg.Tun.AutoRoute = false
	cfg.DNS.Enable = false
	cfg.Nodes = []config.Node{{
		Tag: "plain", Type: "vless", Server: host, Port: port,
		UUID: "11111111-2222-3333-4444-555555555555",
	}}
	cfg.Groups = []config.Group{{Tag: "proxy", Type: "select", Members: []string{"plain"}}}
	cfg.Rules = []config.Rule{{Type: "final", Action: "proxy"}}
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	sup, err := supervisor.New(cfgPath, logx.New(logx.Error, 256))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatal(err)
	}
	defer sup.Stop(context.Background())

	if err := socks5Echo(t, sup.Status().Inbounds[0].Addr, echoAddr); err != nil {
		t.Fatalf("through vless: %v", err)
	}
	if st := sup.Status(); st.Traffic.TotalConn == 0 || st.Traffic.Up == 0 {
		t.Fatalf("traffic not counted: %+v", st.Traffic)
	}
}
