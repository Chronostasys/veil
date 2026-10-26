package inbound

import "sync/atomic"

// counter holds listener statistics. It is embedded by every concrete Server
// so the implementations expose Stats and Accepted without extra code.
//
// All methods are safe for concurrent use.
type counter struct {
	conns  atomic.Int64 // accepted connections since start
	active atomic.Int64 // connections currently being served
	udp    atomic.Int64 // UDP datagrams relayed
}

// Stats reports the number of accepted connections since the listener started.
func (c *counter) Stats() (conns int64) { return c.conns.Load() }

// Accepted is an alias of Stats.
func (c *counter) Accepted() int64 { return c.conns.Load() }

// Active reports how many connections are being served right now.
func (c *counter) Active() int64 { return c.active.Load() }

// UDPDatagrams reports how many UDP payloads were relayed.
func (c *counter) UDPDatagrams() int64 { return c.udp.Load() }

// enter records one accepted connection.
func (c *counter) enter() {
	c.conns.Add(1)
	c.active.Add(1)
}

// leave records that a connection finished.
func (c *counter) leave() { c.active.Add(-1) }
