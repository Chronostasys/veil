package trojan

// Server-side implementation of trojan, written only for tests. It verifies the
// password hash, parses the request header and echoes the payload back, which
// lets the client tests prove wire compatibility without a real trojan server.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"

	"golang.org/x/net/websocket"
)

// seenRequest records what the server side decoded from a client header.
type seenRequest struct {
	Key     string
	Command byte
	Host    string
	Port    uint16
}

type fakeServer struct {
	t        *testing.T
	key      []byte
	mu       sync.Mutex
	requests []seenRequest
	errs     []error
	wg       sync.WaitGroup

	ln     net.Listener
	http   *http.Server
	wsAddr string
}

// startTCP starts a plain-TCP fake trojan server (no TLS: the client's
// transport dialer is injected in tests).
func startTCP(t *testing.T, key []byte) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeServer{t: t, key: key, ln: ln}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				if err := s.serve(conn); err != nil && !isClosedErr(err) {
					s.recordErr(err)
				}
			}()
		}
	}()
	t.Cleanup(s.Close)
	return s
}

// startWS starts a fake trojan server behind a WebSocket upgrade.
func startWS(t *testing.T, key []byte) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeServer{t: t, key: key, ln: ln, wsAddr: ln.Addr().String()}
	mux := http.NewServeMux()
	mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		if err := s.serve(ws); err != nil && !isClosedErr(err) {
			s.recordErr(err)
		}
	}))
	s.http = &http.Server{Handler: mux}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = s.http.Serve(ln)
	}()
	t.Cleanup(s.Close)
	return s
}

// Addr returns the listening address of the fake server.
func (s *fakeServer) Addr() string {
	if s.wsAddr != "" {
		return s.wsAddr
	}
	return s.ln.Addr().String()
}

// Close stops the server and waits for its goroutines.
func (s *fakeServer) Close() {
	if s.http != nil {
		_ = s.http.Close()
	}
	_ = s.ln.Close()
	s.wg.Wait()
}

// Requests returns the headers the server decoded so far.
func (s *fakeServer) Requests() []seenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]seenRequest, len(s.requests))
	copy(out, s.requests)
	return out
}

// Err returns the first error the server hit, if any.
func (s *fakeServer) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.errs) == 0 {
		return nil
	}
	return s.errs[0]
}

func (s *fakeServer) recordErr(err error) {
	s.mu.Lock()
	s.errs = append(s.errs, err)
	s.mu.Unlock()
}

// serve parses one trojan request and echoes the payload.
func (s *fakeServer) serve(conn net.Conn) error {
	br := bufio.NewReader(conn)

	key := make([]byte, keyHexLen)
	if _, err := io.ReadFull(br, key); err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	var crlfBuf [2]byte
	if _, err := io.ReadFull(br, crlfBuf[:]); err != nil {
		return fmt.Errorf("read crlf: %w", err)
	}
	if string(crlfBuf[:]) != "\r\n" {
		return fmt.Errorf("bad crlf after key: %x", crlfBuf)
	}
	var cmd [1]byte
	if _, err := io.ReadFull(br, cmd[:]); err != nil {
		return fmt.Errorf("read command: %w", err)
	}
	host, port, err := readAddrPort(br)
	if err != nil {
		return fmt.Errorf("read address: %w", err)
	}
	if _, err := io.ReadFull(br, crlfBuf[:]); err != nil {
		return fmt.Errorf("read trailing crlf: %w", err)
	}
	if string(crlfBuf[:]) != "\r\n" {
		return fmt.Errorf("bad trailing crlf: %x", crlfBuf)
	}
	if string(key) != string(s.key) {
		return fmt.Errorf("bad password hash: got %q want %q", key, s.key)
	}

	s.mu.Lock()
	s.requests = append(s.requests, seenRequest{Key: string(key), Command: cmd[0], Host: host, Port: port})
	s.mu.Unlock()

	switch cmd[0] {
	case commandTCP:
		_, err := io.Copy(conn, br)
		return err
	case commandUDP:
		return s.serveUDP(conn, br)
	default:
		return fmt.Errorf("unexpected command 0x%02x", cmd[0])
	}
}

// serveUDP echoes every UDP frame back to its sender.
func (s *fakeServer) serveUDP(conn net.Conn, br *bufio.Reader) error {
	for {
		host, port, err := readAddrPort(br)
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			return err
		}
		var lb [2]byte
		if _, err := io.ReadFull(br, lb[:]); err != nil {
			return err
		}
		size := int(binary.BigEndian.Uint16(lb[:]))
		if size > maxPacketSize {
			return ErrOversizePacket
		}
		var delim [2]byte
		if _, err := io.ReadFull(br, delim[:]); err != nil {
			return err
		}
		if string(delim[:]) != "\r\n" {
			return fmt.Errorf("missing crlf in udp frame: %x", delim)
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(br, payload); err != nil {
			return err
		}

		frame, err := appendAddrPort(nil, host, port)
		if err != nil {
			return err
		}
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
		frame = append(frame, "\r\n"...)
		frame = append(frame, payload...)
		if _, err := conn.Write(frame); err != nil {
			return err
		}
	}
}

// isClosedErr reports errors that are expected when a test tears a connection
// down (peer closed, listener closed, deadline forced during cleanup).
func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
