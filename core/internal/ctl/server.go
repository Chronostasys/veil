// Package ctl exposes the supervisor over a line-delimited JSON socket.
//
// Two kinds of connections are accepted:
//
//   - The VPN extension ("host") opens one connection, announces itself with
//     {"role":"host"} and then serves tunnel requests (tun_up, tun_down,
//     protect) that the core sends to it.
//   - The UI opens ordinary RPC connections and calls the methods in
//     internal/rpc.
//
// Keeping the host channel separate makes the fd-protection handshake explicit
// and testable instead of a hidden global.
package ctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"veil/internal/logx"
	"veil/internal/supervisor"
)

// Server is the control socket.
type Server struct {
	sup      *supervisor.Supervisor
	sockPath string
	log      *logx.Logger

	ln   net.Listener
	seq  atomic.Uint64
	done chan struct{}
	once sync.Once

	hostMu sync.Mutex
	host   *hostConn

	connMu  sync.Mutex
	clients map[net.Conn]struct{}

	wg sync.WaitGroup
}

// hostConn is the platform channel.
type hostConn struct {
	conn net.Conn
	enc  *bufio.Writer
	mu   sync.Mutex // serialises writes
	pend sync.Map   // id -> chan hostReply
}

type hostReply struct {
	ok     bool
	result map[string]any
	err    string
}

// NewServer creates a server bound to sockPath. It does not listen yet.
func NewServer(sup *supervisor.Supervisor, sockPath string, log *logx.Logger) *Server {
	return &Server{
		sup:      sup,
		sockPath: sockPath,
		log:      log,
		done:     make(chan struct{}),
		clients:  make(map[net.Conn]struct{}),
	}
}

// ListenAndServe removes a stale socket, binds and serves until Close.
func (s *Server) ListenAndServe() error {
	if err := os.MkdirAll(dirOf(s.sockPath), 0o700); err != nil {
		return err
	}
	// A stale socket after a crash would otherwise make the app unstartable.
	if _, err := os.Stat(s.sockPath); err == nil {
		_ = os.Remove(s.sockPath)
	}
	ln, err := net.Listen("unix", s.sockPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(s.sockPath, 0o600)
	s.ln = ln
	s.log.Infof("control socket listening on %s", s.sockPath)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warnf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.connMu.Lock()
		s.clients[conn] = struct{}{}
		s.connMu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.connMu.Lock()
				delete(s.clients, conn)
				s.connMu.Unlock()
			}()
			s.serveConn(conn)
		}()
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			s.log.Errorf("control connection panic: %v", r)
		}
	}()

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	w := bufio.NewWriter(conn)
	var writeMu sync.Mutex
	reply := func(v any) {
		writeMu.Lock()
		defer writeMu.Unlock()
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		b = append(b, '\n')
		_, _ = w.Write(b)
		_ = w.Flush()
	}

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var probe struct {
			Role   string          `json:"role"`
			Host   bool            `json:"host"`
			ID     uint64          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			OK     *bool           `json:"ok"`
			Result map[string]any  `json:"result"`
			Error  string          `json:"error"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			reply(map[string]any{"id": probe.ID, "ok": false, "error": "bad json: " + err.Error()})
			continue
		}

		switch {
		case probe.Role == "host":
			hc := &hostConn{conn: conn, enc: w}
			s.hostMu.Lock()
			old := s.host
			s.host = hc
			s.hostMu.Unlock()
			if old != nil {
				_ = old.conn.Close()
			}
			s.log.Infof("host connected")
			reply(map[string]any{"ok": true, "result": map[string]any{"role": "host"}})

		case probe.Host && probe.Method != "":
			// A request from the core is answered by the host; this branch only
			// runs if the host itself sends requests (not used).
			reply(map[string]any{"id": probe.ID, "ok": false, "error": "unexpected host request"})

		case probe.Method == "" && probe.OK != nil:
			s.deliverHostReply(probe.ID, probe.OK != nil && *probe.OK, probe.Result, probe.Error)

		default:
			s.handleRPC(conn, probe.ID, probe.Method, probe.Params, reply)
		}
	}
	s.hostMu.Lock()
	if s.host != nil && s.host.conn == conn {
		s.host = nil
		s.log.Warnf("host disconnected")
	}
	s.hostMu.Unlock()
}

func (s *Server) handleRPC(conn net.Conn, id uint64, method string, params json.RawMessage, reply func(any)) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := s.sup.Call(ctx, method, params)
	if err != nil {
		reply(map[string]any{"id": id, "ok": false, "error": err.Error()})
		return
	}
	reply(map[string]any{"id": id, "ok": true, "result": res})
}

func (s *Server) deliverHostReply(id uint64, ok bool, result map[string]any, errMsg string) {
	s.hostMu.Lock()
	h := s.host
	s.hostMu.Unlock()
	if h == nil {
		return
	}
	if v, found := h.pend.Load(id); found {
		ch := v.(chan hostReply)
		h.pend.Delete(id)
		select {
		case ch <- hostReply{ok: ok, result: result, err: errMsg}:
		default:
		}
	}
}

// BroadcastLog pushes one core log line to the host connection so the ArkTS
// side can mirror it into hilog. Go's stderr is discarded on HarmonyOS and the
// C hilog call proved unreliable, so this is the dependable channel.
func (s *Server) BroadcastLog(line string) {
	s.hostMu.Lock()
	h := s.host
	s.hostMu.Unlock()
	if h == nil {
		return
	}
	b, err := json.Marshal(map[string]any{"event": "log", "line": line})
	if err != nil {
		return
	}
	b = append(b, '\n')
	h.mu.Lock()
	_, _ = h.enc.Write(b)
	_ = h.enc.Flush()
	h.mu.Unlock()
}

// Request implements supervisor.Host.
func (s *Server) Request(ctx context.Context, method string, params map[string]any) (map[string]any, error) {
	s.hostMu.Lock()
	h := s.host
	s.hostMu.Unlock()
	if h == nil {
		return nil, errors.New("vpn host is not connected")
	}
	id := s.seq.Add(1)
	ch := make(chan hostReply, 1)
	h.pend.Store(id, ch)
	defer h.pend.Delete(id)

	msg := map[string]any{"host": true, "id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	h.mu.Lock()
	_, err = h.enc.Write(b)
	if err == nil {
		err = h.enc.Flush()
	}
	h.mu.Unlock()
	if err != nil {
		return nil, err
	}

	select {
	case r := <-ch:
		if !r.ok {
			if r.err == "" {
				r.err = "host request failed"
			}
			return r.result, errors.New(r.err)
		}
		return r.result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, errors.New("control server closed")
	}
}

// Protect implements the socket protection hook: it asks the host to protect
// one file descriptor. The host runs in the VPN extension and owns the
// VpnConnection object.
func (s *Server) Protect(fd uintptr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err := s.Request(ctx, "protect", map[string]any{"fd": int64(fd)})
	return err
}

// Close stops the listener and closes client connections.
func (s *Server) Close() error {
	s.once.Do(func() {
		close(s.done)
		if s.ln != nil {
			_ = s.ln.Close()
		}
		s.hostMu.Lock()
		if s.host != nil {
			_ = s.host.conn.Close()
			s.host = nil
		}
		s.hostMu.Unlock()
		// Idle UI connections would otherwise keep Close (and therefore the VPN
		// extension's onDestroy) waiting.
		s.connMu.Lock()
		for c := range s.clients {
			_ = c.Close()
		}
		s.connMu.Unlock()
	})
	s.wg.Wait()
	_ = os.Remove(s.sockPath)
	return nil
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

// Client is a tiny RPC client used by veild and tests.
type Client struct {
	conn net.Conn
	enc  *bufio.Writer
	dec  *bufio.Scanner
	mu   sync.Mutex
	seq  uint64
}

// Dial connects to a control socket.
func Dial(sockPath string) (*Client, error) {
	conn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	return &Client{conn: conn, enc: bufio.NewWriter(conn), dec: sc}, nil
}

// Call performs one RPC.
func (c *Client) Call(method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	id := c.seq
	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	if _, err := c.enc.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	if err := c.enc.Flush(); err != nil {
		return nil, err
	}
	if !c.dec.Scan() {
		if err := c.dec.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("control socket closed")
	}
	var resp struct {
		ID     uint64          `json:"id"`
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(c.dec.Bytes(), &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	return resp.Result, nil
}

// Close closes the client connection.
func (c *Client) Close() error { return c.conn.Close() }
