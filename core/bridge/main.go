// Package main builds libveilcore.so, the native core of the Veil HarmonyOS
// app. It is a C shared library, loaded through the NAPI shim and driven over
// the control socket described in internal/ctl.
package main

/*
#include <stdlib.h>

// Implemented in entry/src/main/cpp/napi_init.cpp (linked into the same
// library); lets the core log reach hilog, which is readable from hdc.

*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"veil/internal/config"
	"veil/internal/ctl"
	"veil/internal/logx"
	"veil/internal/supervisor"
	"veil/internal/transport"
	"veil/internal/version"
)

var (
	mu     sync.Mutex
	sup    *supervisor.Supervisor
	srv    *ctl.Server
	log    *logx.Logger
	result string // last returned C string, kept alive until the next call
)

// VeilStart boots the core: config is loaded/created at configPath, the control
// socket is bound at socketPath. Returns a JSON envelope.
//
//export VeilStart
func VeilStart(configPath, socketPath *C.char) *C.char {
	mu.Lock()
	defer mu.Unlock()
	if sup != nil {
		return ret(map[string]any{"ok": true, "result": map[string]any{"version": version.Version, "already": true}})
	}
	cfgPath := C.GoString(configPath)
	sockPath := C.GoString(socketPath)
	if cfgPath == "" {
		cfgPath = filepath.Join(os.TempDir(), "veil", "config.json")
	}
	if sockPath == "" {
		sockPath = filepath.Join(filepath.Dir(cfgPath), "veil.sock")
	}
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfg := config.Default()
		_ = config.Save(cfgPath, cfg)
	}
	// The first cgo call initialises the whole Go runtime, which can take
	// seconds on device. Doing that inline blocks the ArkTS main thread long
	// enough for the system to log THREAD_BLOCK_3S and reap the ability, so the
	// heavy part runs on a Go goroutine and this call returns immediately.
	// Callers wait for the control socket (the extension retries for 60s).
	go func() {
		// Fewer GC cycles = fewer idle wakeups. The core allocates little in
		// steady state (relay buffers are pooled), so a high GOGC is free.
		debug.SetGCPercent(400)
		// The engine shares its process with the ArkTS main thread (the VPN
		// extension host). Letting Go run on every core starves that thread and
		// the system kills the process with THREAD_BLOCK_3S (observed on device
		// ~1 minute after connect). Two Ps are plenty for a tunnel.
		runtime.GOMAXPROCS(2)
		level := logx.Info
		if c, err := config.Load(cfgPath); err == nil {
			level = logx.ParseLevel(c.LogLevel)
		}
		lg := logx.New(level, 1024)
		// Mirror the engine log to stderr so HarmonyOS hilog carries it: without
		// this the core is a black box on device ("import failed" with no reason).
		// Mirror to a file next to the config: HarmonyOS discards app stderr, so
		// a log file is the only way to read the core's own diagnosis.
		logPath := filepath.Join(filepath.Dir(cfgPath), "veil.log")
		var lf *os.File
		if f, ferr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); ferr == nil {
			lf = f
		}
		s, err := supervisor.New(cfgPath, lg)
		if err != nil {
			lg.Errorf("load config: %v", err)
			return
		}
		server := ctl.NewServer(s, sockPath, lg)
		s.SetHost(server)
		s.SetProtector(func(fd uintptr) error { return server.Protect(fd) })
		transport.SetProtector(func(fd uintptr) error { return server.Protect(fd) })

		mu.Lock()
		sup, srv, log = s, server, lg
		mu.Unlock()

		lg.SetSink(func(e logx.Entry) {
			line := fmt.Sprintf("%s %-5s %s", time.UnixMilli(e.Time).Format("15:04:05.000"), e.Level, e.Msg)
			// Three sinks on purpose: the file survives restarts, hilog is what
			// an outside observer (hdc) can read, and the socket copy feeds the
			// in-app log view.
			if lf != nil {
				fmt.Fprintln(lf, line)
				_ = lf.Sync()
			}
			hilogWrite(e.Level, line)
			server.BroadcastLog(line)
		})

		lg.Infof("build=%s starting (config %s)", version.Build, cfgPath)
		if err := server.ListenAndServe(); err != nil {
			lg.Errorf("control socket: %v", err)
		}
	}()

	return ret(map[string]any{"ok": true, "result": map[string]any{
		"version":  version.Version,
		"build":    version.Build,
		"socket":   sockPath,
		"config":   cfgPath,
		"starting": true,
	}})
}

// VeilCall executes one RPC in-process (used by tools and tests; the app uses
// the control socket).
//
//export VeilCall
func VeilCall(method, params *C.char) *C.char {
	s, lg := waitReady(5 * time.Second)
	if s == nil {
		return ret(map[string]any{"ok": false, "error": "core still starting"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw := json.RawMessage(C.GoString(params))
	res, err := s.Call(ctx, C.GoString(method), raw)
	if err != nil {
		if lg != nil {
			lg.Debugf("rpc %s failed: %v", C.GoString(method), err)
		}
		return ret(map[string]any{"ok": false, "error": err.Error()})
	}
	return ret(map[string]any{"ok": true, "result": res})
}

// VeilShutdown stops the engine and releases the socket.
//
//export VeilShutdown
func VeilShutdown() *C.char {
	mu.Lock()
	s, server := sup, srv
	sup, srv = nil, nil
	mu.Unlock()
	if s != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		_ = s.Stop(ctx)
		cancel()
	}
	if server != nil {
		_ = server.Close()
	}
	return ret(map[string]any{"ok": true})
}

// waitReady blocks until the background initialiser published the supervisor.
func waitReady(timeout time.Duration) (*supervisor.Supervisor, *logx.Logger) {
	deadline := time.Now().Add(timeout)
	for {
		mu.Lock()
		s, lg := sup, log
		mu.Unlock()
		if s != nil {
			return s, lg
		}
		if time.Now().After(deadline) {
			return nil, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func ret(v any) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"ok":false,"error":"encode"}`)
	}
	// Keep the buffer alive until the next call: the NAPI shim copies it
	// immediately, and avoiding C.malloc keeps cgo simple.
	result = string(b)
	return C.CString(result)
}

func errJSON(err error) *C.char {
	return ret(map[string]any{"ok": false, "error": err.Error()})
}

func main() {}
