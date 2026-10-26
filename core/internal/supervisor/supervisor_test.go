package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"veil/internal/config"
	"veil/internal/logx"
	"veil/internal/rpc"
	"veil/internal/state"
)

// startEcho runs a TCP echo server and returns its address.
func startEcho(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	}
}

// socksConnect performs a SOCKS5 CONNECT through addr.
func socksConnect(t *testing.T, addr, target string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 5 || buf[1] != 0 {
		t.Fatalf("greeting reply %v", buf)
	}
	host, portStr, _ := net.SplitHostPort(target)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{5, 1, 0, 1}
	ip := net.ParseIP(host).To4()
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("connect reply code %d", reply[1])
	}
	return c
}

func newTestSupervisor(t *testing.T) (*Supervisor, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	cfg.Mixed = "127.0.0.1:0"
	cfg.Mode = config.ModeDirect
	cfg.Tun.AutoRoute = false
	cfg.DNS.Enable = true
	cfg.DNS.Servers = []config.DNSServer{{Tag: "local", Addr: "127.0.0.1:53535"}}
	cfg.DNS.Final = "local"
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	sup, err := New(cfgPath, logx.New(logx.Error, 256))
	if err != nil {
		t.Fatal(err)
	}
	return sup, cfgPath
}

// TestLifecycleAndStatus asserts the state machine tells the truth.
func TestLifecycleAndStatus(t *testing.T) {
	sup, _ := newTestSupervisor(t)
	if got := sup.Status().Phase; got != state.PhaseStopped {
		t.Fatalf("initial phase = %s", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatal(err)
	}
	defer sup.Stop(context.Background())
	st := sup.Status()
	if st.Phase != state.PhaseRunning {
		t.Fatalf("phase after start = %s (%s)", st.Phase, st.Reason)
	}
	if len(st.Inbounds) == 0 || !st.Inbounds[0].Up {
		t.Fatalf("mixed inbound not reported: %+v", st.Inbounds)
	}
	if st.Version == "" {
		t.Fatal("version missing")
	}
	// Status must be a live probe, not a snapshot: the uptime advances.
	time.Sleep(1100 * time.Millisecond)
	if st2 := sup.Status(); st2.UptimeSec < 1 {
		t.Fatalf("uptime did not advance: %d", st2.UptimeSec)
	}
	if err := sup.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := sup.Status().Phase; got != state.PhaseStopped {
		t.Fatalf("phase after stop = %s", got)
	}
}

// TestSoakNoLeaks is the regression test for the original client's worst bug:
// a long-running process that slowly leaks connections, goroutines and file
// descriptors until it dies in the background.
func TestSoakNoLeaks(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test skipped in -short")
	}
	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	sup, _ := newTestSupervisor(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatal(err)
	}
	defer sup.Stop(context.Background())

	addr := sup.Status().Inbounds[0].Addr
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()

	const workers = 24
	const perWorker = 60
	var okCount atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				conn := socksConnect(t, addr, echoAddr)
				msg := []byte(fmt.Sprintf("hello-%d", i))
				if _, err := conn.Write(msg); err != nil {
					conn.Close()
					continue
				}
				buf := make([]byte, len(msg))
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, err := io.ReadFull(conn, buf); err == nil && string(buf) == string(msg) {
					okCount.Add(1)
				}
				_ = conn.Close()
			}
		}()
	}
	wg.Wait()

	if got := okCount.Load(); got != workers*perWorker {
		t.Fatalf("echoed %d/%d connections", got, workers*perWorker)
	}

	// Connections must drain from the registry.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n := len(sup.Conns()); n == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := len(sup.Conns()); n != 0 {
		t.Fatalf("%d connections still tracked after close", n)
	}
	st := sup.Status()
	if st.Traffic.TotalConn < workers*perWorker {
		t.Fatalf("traffic counter missed connections: %d", st.Traffic.TotalConn)
	}
	if st.Traffic.Up == 0 || st.Traffic.Down == 0 {
		t.Fatalf("byte counters did not move: up=%d down=%d", st.Traffic.Up, st.Traffic.Down)
	}

	// And goroutines must come back to baseline (allow a small slack for
	// runtime internals and the still-running supervisor loops).
	time.Sleep(1500 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()
	if after > baseGoroutines+12 {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutines leaked: before=%d after=%d\n%s", baseGoroutines, after, buf[:n])
	}
}

// TestRPCStatusShape pins the JSON the UI consumes.
func TestRPCStatusShape(t *testing.T) {
	sup, _ := newTestSupervisor(t)
	ctx := context.Background()
	if _, err := sup.Call(ctx, rpc.MethodStart, json.RawMessage(`{"tun_fd":-1}`)); err != nil {
		t.Fatal(err)
	}
	defer sup.Stop(ctx)

	raw, err := sup.Call(ctx, rpc.MethodStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var st state.Status
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if st.Phase != state.PhaseRunning {
		t.Fatalf("phase = %q", st.Phase)
	}
	if st.Health.Goroutines == 0 || st.Health.OpenFDs == 0 {
		t.Fatalf("health not populated: %+v", st.Health)
	}
	if st.Health.HeartbeatAgoMS > 5000 {
		t.Fatalf("heartbeat stale: %d ms", st.Health.HeartbeatAgoMS)
	}

	if _, err := sup.Call(ctx, rpc.MethodConfig, nil); err != nil {
		t.Fatal(err)
	}
	// Unknown methods must error, not panic.
	if _, err := sup.Call(ctx, "definitely_not_a_method", nil); err == nil {
		t.Fatal("unknown method did not error")
	}
}

// TestStopIsIdempotent guards against double-stop crashes during app teardown.
func TestStopIsIdempotent(t *testing.T) {
	sup, _ := newTestSupervisor(t)
	ctx := context.Background()
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatal(err)
	}
	if err := sup.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sup.Stop(ctx); err != nil {
		t.Fatalf("second stop: %v", err)
	}
	if err := sup.Start(ctx, -1); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if err := sup.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

var _ = os.Getpid
