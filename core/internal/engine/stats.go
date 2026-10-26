package engine

import (
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"veil/internal/state"
)

// Stats owns traffic counters and the live connection registry.
//
// All counters are atomic. Rates are computed lazily in Snapshot, so an idle
// engine never wakes up on a timer (battery: zero periodic wakeups).
type Stats struct {
	up   atomic.Int64
	down atomic.Int64

	totalConn atomic.Int64
	active    atomic.Int64

	upRate   atomic.Uint64 // float64 bits
	downRate atomic.Uint64

	// lazy rate sampling state, guarded by rmu
	rmu      sync.Mutex
	lastUp   int64
	lastDown int64
	lastAt   time.Time

	conns *Registry
}

// NewStats returns an empty Stats.
func NewStats() *Stats {
	return &Stats{conns: NewRegistry(4096)}
}

// AddUp records uploaded bytes.
func (s *Stats) AddUp(n int64) { s.up.Add(n) }

// AddDown records downloaded bytes.
func (s *Stats) AddDown(n int64) { s.down.Add(n) }

// Snapshot returns a consistent view for the UI.
func (s *Stats) Snapshot() state.Traffic {
	up, down := s.up.Load(), s.down.Load()
	s.refreshRates(up, down)
	return state.Traffic{
		Up:        up,
		Down:      down,
		UpRate:    float64frombits(s.upRate.Load()),
		DownRate:  float64frombits(s.downRate.Load()),
		Active:    int(s.active.Load()),
		TotalConn: s.totalConn.Load(),
	}
}

// refreshRates recomputes the byte rates from the elapsed time since the last
// call. It runs only when status is read; the numbers are measured, not guessed,
// and an idle process pays nothing.
func (s *Stats) refreshRates(up, down int64) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	now := time.Now()
	if s.lastAt.IsZero() {
		s.lastAt, s.lastUp, s.lastDown = now, up, down
		return
	}
	el := now.Sub(s.lastAt)
	if el < 200*time.Millisecond {
		return
	}
	secs := el.Seconds()
	s.upRate.Store(float64bits(float64(up-s.lastUp) / secs))
	s.downRate.Store(float64bits(float64(down-s.lastDown) / secs))
	s.lastAt, s.lastUp, s.lastDown = now, up, down
}

// Reset zeroes the traffic counters.
func (s *Stats) Reset() {
	s.up.Store(0)
	s.down.Store(0)
	s.upRate.Store(0)
	s.downRate.Store(0)
	s.totalConn.Store(0)
	s.rmu.Lock()
	s.lastAt = time.Time{}
	s.lastUp, s.lastDown = 0, 0
	s.rmu.Unlock()
}

func float64bits(f float64) uint64 { return math.Float64bits(f) }

func float64frombits(b uint64) float64 { return math.Float64frombits(b) }

// Conn is one tracked proxied connection.
type Conn struct {
	ID       uint64
	Start    time.Time
	Network  string
	Source   string
	Dest     string
	Outbound string
	Rule     string
	Chain    string

	up   atomic.Int64
	down atomic.Int64

	closer io.Closer
	once   sync.Once
}

// Close closes the underlying transport once.
func (c *Conn) Close() error {
	var err error
	c.once.Do(func() {
		if c.closer != nil {
			err = c.closer.Close()
		}
	})
	return err
}

// Snapshot renders the connection for the UI.
func (c *Conn) Snapshot() state.Conn {
	return state.Conn{
		ID:       c.ID,
		Start:    c.Start.Unix(),
		Network:  c.Network,
		Source:   c.Source,
		Dest:     c.Dest,
		Outbound: c.Outbound,
		Rule:     c.Rule,
		Up:       c.up.Load(),
		Down:     c.down.Load(),
		Chain:    c.Chain,
	}
}

// Registry tracks live connections with a hard cap.
type Registry struct {
	mu    sync.RWMutex
	byID  map[uint64]*Conn
	order []uint64
	max   int
	seq   atomic.Uint64
}

// NewRegistry returns a registry capped at max connections.
func NewRegistry(max int) *Registry {
	if max <= 0 {
		max = 1024
	}
	return &Registry{byID: make(map[uint64]*Conn), max: max}
}

// Add registers a connection. It returns nil when the cap is reached.
func (r *Registry) Add(c *Conn) *Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.byID) >= r.max {
		return nil
	}
	c.ID = r.seq.Add(1)
	if c.Start.IsZero() {
		c.Start = time.Now()
	}
	r.byID[c.ID] = c
	r.order = append(r.order, c.ID)
	return c
}

// Remove forgets a connection.
func (r *Registry) Remove(id uint64) {
	r.mu.Lock()
	delete(r.byID, id)
	for i, v := range r.order {
		if v == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	r.mu.Unlock()
}

// Get returns a tracked connection.
func (r *Registry) Get(id uint64) *Conn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}

// Len reports the number of live connections.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// List returns snapshots, newest last.
func (r *Registry) List() []state.Conn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]state.Conn, 0, len(r.order))
	for _, id := range r.order {
		if c := r.byID[id]; c != nil {
			out = append(out, c.Snapshot())
		}
	}
	return out
}

// CloseAll closes every tracked connection.
func (r *Registry) CloseAll() {
	r.mu.Lock()
	conns := make([]*Conn, 0, len(r.byID))
	for _, c := range r.byID {
		conns = append(conns, c)
	}
	r.byID = make(map[uint64]*Conn)
	r.order = r.order[:0]
	r.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// countingConn counts bytes in both directions and forwards deadlines.
type countingConn struct {
	net.Conn
	up   *atomic.Int64
	down *atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.down != nil {
		c.down.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 && c.up != nil {
		c.up.Add(int64(n))
	}
	return n, err
}
