// Package logx is a tiny structured logger with an in-memory ring buffer so the
// UI can show logs without touching the filesystem.
package logx

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level is a log severity.
type Level int32

// Levels, ordered.
const (
	Debug Level = iota
	Info
	Warn
	Error
)

// ParseLevel maps a config string to a Level.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return Debug
	case "warn", "warning":
		return Warn
	case "error":
		return Error
	default:
		return Info
	}
}

func (l Level) String() string {
	switch l {
	case Debug:
		return "debug"
	case Warn:
		return "warn"
	case Error:
		return "error"
	default:
		return "info"
	}
}

// Entry is one buffered record.
type Entry struct {
	ID    uint64 `json:"id"`
	Time  int64  `json:"time"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// Logger writes to the platform sink and keeps the last size entries.
type Logger struct {
	level atomic.Int32
	seq   atomic.Uint64

	mu     sync.RWMutex
	buf    []Entry
	size   int
	start  int
	frozen bool

	sink func(Entry)
}

// New returns a logger keeping the last size entries.
func New(level Level, size int) *Logger {
	if size <= 0 {
		size = 512
	}
	return &Logger{level: atomic.Int32{}, buf: make([]Entry, size), size: size}
}

// SetLevel changes the level at runtime.
func (l *Logger) SetLevel(level Level) { l.level.Store(int32(level)) }

// SetSink installs a callback invoked for every accepted entry.
func (l *Logger) SetSink(fn func(Entry)) {
	l.mu.Lock()
	l.sink = fn
	l.mu.Unlock()
}

func (l *Logger) log(level Level, format string, args ...any) {
	if level < Level(l.level.Load()) {
		return
	}
	e := Entry{
		ID:    l.seq.Add(1),
		Time:  time.Now().UnixMilli(),
		Level: level.String(),
		Msg:   fmt.Sprintf(format, args...),
	}
	l.mu.Lock()
	l.buf[l.start] = e
	l.start = (l.start + 1) % l.size
	sink := l.sink
	l.mu.Unlock()
	if sink != nil {
		sink(e)
	}
}

// Debugf logs at debug level.
func (l *Logger) Debugf(format string, args ...any) { l.log(Debug, format, args...) }

// Infof logs at info level.
func (l *Logger) Infof(format string, args ...any) { l.log(Info, format, args...) }

// Warnf logs at warn level.
func (l *Logger) Warnf(format string, args ...any) { l.log(Warn, format, args...) }

// Errorf logs at error level.
func (l *Logger) Errorf(format string, args ...any) { l.log(Error, format, args...) }

// Snapshot returns up to limit entries newer than afterID in chronological
// order.
func (l *Logger) Snapshot(afterID uint64, limit int) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if limit <= 0 || limit > l.size {
		limit = l.size
	}
	out := make([]Entry, 0, limit)
	for i := 0; i < l.size; i++ {
		e := l.buf[(l.start+i)%l.size]
		if e.ID == 0 || e.ID <= afterID {
			continue
		}
		out = append(out, e)
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
