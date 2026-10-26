package transport

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2/hpack"
)

// A minimal HTTP/2 client, enough for the gRPC carrier: one stream per
// connection, request headers, DATA frames, flow control and reading response
// headers. We do not use golang.org/x/net/http2 because that package pulls
// golang.org/x/net/idna -> golang.org/x/text, a dependency this module does not
// vendor; the framing layer is small and self-contained.
const (
	h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FrameRSTStream    = 0x3
	h2FrameSettings     = 0x4
	h2FramePushPromise  = 0x5
	h2FramePing         = 0x6
	h2FrameGoAway       = 0x7
	h2FrameWindowUpdate = 0x8
	h2FrameContinuation = 0x9

	h2FlagEndStream  = 0x1
	h2FlagAck        = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20

	h2SettingHeaderTableSize   = 0x1
	h2SettingEnablePush        = 0x2
	h2SettingInitialWindowSize = 0x4
	h2SettingMaxFrameSize      = 0x5
	h2SettingMaxHeaderListSize = 0x6

	h2DefaultWindow    = 65535
	h2DefaultFrameSize = 16384
	h2MaxFrameSize     = 1 << 24
	h2WindowIncrement  = 8 << 20 // extra receive window granted to the peer
)

// h2Frame is one parsed HTTP/2 frame.
type h2Frame struct {
	typ      byte
	flags    byte
	streamID uint32
	payload  []byte
}

// readH2Frame reads one frame from r.
func readH2Frame(r io.Reader) (h2Frame, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return h2Frame{}, err
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	if length > h2MaxFrameSize {
		return h2Frame{}, fmt.Errorf("http2: frame too large: %d", length)
	}
	f := h2Frame{
		typ:      hdr[3],
		flags:    hdr[4],
		streamID: binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff,
	}
	if length > 0 {
		f.payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return h2Frame{}, err
		}
	}
	return f, nil
}

// h2Stream is a single HTTP/2 stream on its own connection.
type h2Stream struct {
	conn     net.Conn
	br       *bufio.Reader
	streamID uint32

	maxFrameSize atomic.Uint32

	// write side
	wmu sync.Mutex

	// send flow control
	fmu              sync.Mutex
	connSendWindow   int64
	streamSendWindow int64
	winSig           chan struct{}

	// receive side
	dmu     sync.Mutex
	data    []byte
	readErr error
	credit  int
	dataSig chan struct{}
	eofSeen bool

	// response headers
	hmu     sync.Mutex
	headers http.Header
	status  int
	hdrSig  chan struct{}
	hdrDone bool

	closeOnce sync.Once
	closeErr  error
	closedSig chan struct{}
}

// dialH2Stream opens an HTTP/2 stream and sends the request headers. It returns
// once the response headers have been received and validated.
func dialH2Stream(conn net.Conn, method, authority, path string, extra http.Header) (*h2Stream, error) {
	s := &h2Stream{
		conn:             conn,
		br:               bufio.NewReaderSize(conn, 16*1024),
		streamID:         1,
		connSendWindow:   h2DefaultWindow,
		streamSendWindow: h2DefaultWindow,
		winSig:           make(chan struct{}, 1),
		dataSig:          make(chan struct{}, 1),
		hdrSig:           make(chan struct{}, 1),
		closedSig:        make(chan struct{}),
	}
	s.maxFrameSize.Store(h2DefaultFrameSize)

	if _, err := io.WriteString(conn, h2Preface); err != nil {
		return nil, fmt.Errorf("http2: preface: %w", err)
	}
	if err := s.writeSettings(); err != nil {
		return nil, err
	}
	go s.readLoop()

	fields := []hpack.HeaderField{
		{Name: ":method", Value: method},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}
	for k, vs := range extra {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, ":") || strings.EqualFold(k, "Host") || strings.EqualFold(k, "Connection") {
			continue
		}
		for _, v := range vs {
			fields = append(fields, hpack.HeaderField{Name: lk, Value: v})
		}
	}
	if err := s.writeHeaders(fields); err != nil {
		s.Close()
		return nil, err
	}

	select {
	case <-s.hdrSig:
	case <-s.closedSig:
	}
	s.hmu.Lock()
	status, err := s.status, s.readErr
	s.hmu.Unlock()
	if err != nil {
		s.Close()
		return nil, err
	}
	if status != http.StatusOK && status != 0 {
		s.Close()
		return nil, fmt.Errorf("http2: unexpected status %d", status)
	}
	return s, nil
}

// writeSettings sends our SETTINGS frame.
func (s *h2Stream) writeSettings() error {
	payload := make([]byte, 0, 24)
	put := func(id uint16, v uint32) {
		var b [6]byte
		binary.BigEndian.PutUint16(b[0:2], id)
		binary.BigEndian.PutUint32(b[2:6], v)
		payload = append(payload, b[:]...)
	}
	put(h2SettingEnablePush, 0)
	put(h2SettingInitialWindowSize, 1<<20)
	put(h2SettingMaxFrameSize, h2DefaultFrameSize)
	if err := s.writeFrame(h2FrameSettings, 0, 0, payload); err != nil {
		return err
	}
	// Grant the peer more room than the protocol default so bulk transfers do not
	// ping-pong on WINDOW_UPDATE frames for every 64 KiB.
	return s.writeWindowUpdate(0, h2WindowIncrement)
}

// writeHeaders writes the request HEADERS frame (EndHeaders, no EndStream).
func (s *h2Stream) writeHeaders(fields []hpack.HeaderField) error {
	var buf []byte
	enc := hpack.NewEncoder(&bufWriter{&buf})
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			return fmt.Errorf("http2: encode headers: %w", err)
		}
	}
	return s.writeFrame(h2FrameHeaders, h2FlagEndHeaders, s.streamID, buf)
}

// bufWriter adapts a byte slice to io.Writer.
type bufWriter struct{ p *[]byte }

func (w *bufWriter) Write(b []byte) (int, error) {
	*w.p = append(*w.p, b...)
	return len(b), nil
}

// writeFrame serialises and writes one frame.
func (s *h2Stream) writeFrame(typ, flags byte, streamID uint32, payload []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	hdr := make([]byte, 9, 9+len(payload))
	n := len(payload)
	hdr[0] = byte(n >> 16)
	hdr[1] = byte(n >> 8)
	hdr[2] = byte(n)
	hdr[3] = typ
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:9], streamID&0x7fffffff)
	bufs := net.Buffers{hdr, payload}
	_, err := bufs.WriteTo(s.conn)
	if err != nil {
		return fmt.Errorf("http2: write frame: %w", err)
	}
	return nil
}

// writeWindowUpdate grants n bytes of receive window.
func (s *h2Stream) writeWindowUpdate(streamID uint32, n uint32) error {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], n&0x7fffffff)
	return s.writeFrame(h2FrameWindowUpdate, 0, streamID, p[:])
}

// readLoop owns all reads from the connection and dispatches frames.
func (s *h2Stream) readLoop() {
	var hdrBlock []byte
	for {
		f, err := readH2Frame(s.br)
		if err != nil {
			s.fail(err)
			return
		}
		switch f.typ {
		case h2FrameData:
			if len(f.payload) > 0 {
				s.dmu.Lock()
				s.data = append(s.data, f.payload...)
				s.dmu.Unlock()
				s.signal(s.dataSig)
			}
			if f.flags&h2FlagEndStream != 0 {
				s.dmu.Lock()
				s.eofSeen = true
				s.dmu.Unlock()
				s.signal(s.dataSig)
			}
		case h2FrameHeaders:
			payload, _ := stripPadding(f)
			hdrBlock = append(hdrBlock, payload...)
			if f.flags&h2FlagEndHeaders != 0 {
				s.decodeHeaders(hdrBlock)
				hdrBlock = nil
			}
			if f.flags&h2FlagEndStream != 0 {
				s.dmu.Lock()
				s.eofSeen = true
				s.dmu.Unlock()
				s.signal(s.dataSig)
			}
		case h2FrameContinuation:
			payload, _ := stripPadding(f)
			hdrBlock = append(hdrBlock, payload...)
			if f.flags&h2FlagEndHeaders != 0 {
				s.decodeHeaders(hdrBlock)
				hdrBlock = nil
			}
		case h2FrameSettings:
			if f.flags&h2FlagAck == 0 {
				s.applySettings(f.payload)
				_ = s.writeFrame(h2FrameSettings, h2FlagAck, 0, nil)
			}
		case h2FramePing:
			if f.flags&h2FlagAck == 0 {
				_ = s.writeFrame(h2FramePing, h2FlagAck, 0, f.payload)
			}
		case h2FrameWindowUpdate:
			if len(f.payload) >= 4 {
				inc := int64(binary.BigEndian.Uint32(f.payload[:4]) & 0x7fffffff)
				s.fmu.Lock()
				if f.streamID == 0 {
					s.connSendWindow += inc
				} else if f.streamID == s.streamID {
					s.streamSendWindow += inc
				}
				s.fmu.Unlock()
				s.signal(s.winSig)
			}
		case h2FrameRSTStream:
			code := uint32(0)
			if len(f.payload) >= 4 {
				code = binary.BigEndian.Uint32(f.payload[:4])
			}
			s.fail(fmt.Errorf("http2: stream reset by peer (code %d)", code))
			return
		case h2FrameGoAway:
			s.fail(io.EOF)
			return
		case h2FramePushPromise:
			// Server push is disabled in our SETTINGS; ignore defensively.
		}
	}
}

// stripPadding removes the pad length byte and padding from a frame payload.
func stripPadding(f h2Frame) ([]byte, bool) {
	payload := f.payload
	if f.flags&h2FlagPadded != 0 {
		if len(payload) < 1 {
			return nil, false
		}
		pad := int(payload[0])
		payload = payload[1:]
		if pad > len(payload) {
			return nil, false
		}
		payload = payload[:len(payload)-pad]
	}
	if f.typ == h2FrameHeaders && f.flags&h2FlagPriority != 0 {
		if len(payload) < 5 {
			return nil, false
		}
		payload = payload[5:]
	}
	return payload, true
}

// decodeHeaders runs HPACK decoding over a complete header block.
func (s *h2Stream) decodeHeaders(block []byte) {
	headers := make(http.Header)
	status := 0
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			status = atoi(f.Value)
			return
		}
		if strings.HasPrefix(f.Name, ":") {
			return
		}
		headers.Add(f.Name, f.Value)
	})
	if _, err := dec.Write(block); err != nil {
		s.fail(fmt.Errorf("http2: decode headers: %w", err))
		return
	}
	s.hmu.Lock()
	s.headers = headers
	if s.status == 0 {
		s.status = status
	}
	s.hdrDone = true
	s.hmu.Unlock()
	s.signal(s.hdrSig)
}

// applySettings honours the peer's SETTINGS frame.
func (s *h2Stream) applySettings(payload []byte) {
	for len(payload) >= 6 {
		id := binary.BigEndian.Uint16(payload[0:2])
		v := binary.BigEndian.Uint32(payload[2:6])
		payload = payload[6:]
		switch id {
		case h2SettingMaxFrameSize:
			if v >= 16384 && v <= h2MaxFrameSize {
				s.maxFrameSize.Store(v)
			}
		case h2SettingInitialWindowSize:
			delta := int64(int32(v)) - h2DefaultWindow
			s.fmu.Lock()
			s.streamSendWindow += delta
			s.fmu.Unlock()
			s.signal(s.winSig)
		}
	}
}

// signal wakes one waiter without blocking.
func (s *h2Stream) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// fail records a terminal error for reads and wakes every waiter.
func (s *h2Stream) fail(err error) {
	if err == nil {
		err = io.EOF
	}
	s.dmu.Lock()
	if s.readErr == nil {
		s.readErr = err
	}
	s.dmu.Unlock()
	s.hmu.Lock()
	if !s.hdrDone {
		s.hdrDone = true
		if s.readErr == nil {
			s.readErr = err
		}
	}
	s.hmu.Unlock()
	s.signal(s.dataSig)
	s.signal(s.hdrSig)
	s.signal(s.winSig)
	s.closeOnce.Do(func() {
		close(s.closedSig)
		_ = s.conn.Close()
	})
}

// Read implements io.Reader over the stream's DATA frames.
func (s *h2Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		s.dmu.Lock()
		if len(s.data) > 0 {
			n := copy(p, s.data)
			s.data = s.data[n:]
			s.credit += n
			grant := 0
			if s.credit >= 16*1024 {
				grant = s.credit
				s.credit = 0
			}
			s.dmu.Unlock()
			if grant > 0 {
				// Return window credit for both the connection and this stream.
				_ = s.writeWindowUpdate(0, uint32(grant))
				_ = s.writeWindowUpdate(s.streamID, uint32(grant))
			}
			return n, nil
		}
		if s.readErr != nil {
			err := s.readErr
			s.dmu.Unlock()
			return 0, err
		}
		if s.eofSeen {
			s.dmu.Unlock()
			return 0, io.EOF
		}
		s.dmu.Unlock()
		select {
		case <-s.dataSig:
		case <-s.closedSig:
			s.dmu.Lock()
			err := s.readErr
			s.dmu.Unlock()
			if err == nil {
				err = io.ErrClosedPipe
			}
			return 0, err
		}
	}
}

// Write implements io.Writer by emitting DATA frames that respect flow control.
func (s *h2Stream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		s.fmu.Lock()
		for s.connSendWindow <= 0 || s.streamSendWindow <= 0 {
			s.fmu.Unlock()
			select {
			case <-s.winSig:
			case <-s.closedSig:
				return written, io.ErrClosedPipe
			}
			s.fmu.Lock()
		}
		n := int64(len(p))
		if n > s.connSendWindow {
			n = s.connSendWindow
		}
		if n > s.streamSendWindow {
			n = s.streamSendWindow
		}
		if max := int64(s.maxFrameSize.Load()); n > max {
			n = max
		}
		s.connSendWindow -= n
		s.streamSendWindow -= n
		s.fmu.Unlock()

		if err := s.writeFrame(h2FrameData, 0, s.streamID, p[:n]); err != nil {
			return written, err
		}
		written += int(n)
		p = p[n:]
	}
	return written, nil
}

// Close implements io.Closer. It resets the stream and closes the connection.
func (s *h2Stream) Close() error {
	s.closeOnce.Do(func() {
		var p [4]byte
		binary.BigEndian.PutUint32(p[:], 0) // NO_ERROR
		_ = s.writeFrame(h2FrameRSTStream, 0, s.streamID, p[:])
		_ = s.writeFrame(h2FrameGoAway, 0, 0, nil)
		close(s.closedSig)
		s.dmu.Lock()
		if s.readErr == nil {
			s.readErr = io.ErrClosedPipe
		}
		s.dmu.Unlock()
		s.closeErr = s.conn.Close()
	})
	return s.closeErr
}

// Headers returns the response headers (after the stream opened).
func (s *h2Stream) Headers() http.Header {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	return s.headers
}

// atoi parses a small decimal number, returning 0 on error.
func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// static assertions
var (
	_ io.ReadWriteCloser = (*h2Stream)(nil)
	_                    = errors.Is
	_                    = time.Now
)
