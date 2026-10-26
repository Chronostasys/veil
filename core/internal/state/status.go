// Package state defines the live status model reported to the UI.
//
// Every field is derived from a live probe or an atomic counter; nothing here
// is a cached "is it connected" boolean, because that is exactly how proxy UIs
// end up lying to their users.
package state

// Phase is the supervisor lifecycle state.
type Phase string

const (
	PhaseStopped  Phase = "stopped"
	PhaseStarting Phase = "starting"
	PhaseRunning  Phase = "running"
	PhaseDegraded Phase = "degraded" // core traffic works, one subsystem is down
	PhaseStopping Phase = "stopping"
	PhaseFailed   Phase = "failed"
)

// Status is the single source of truth handed to the UI.
type Status struct {
	Phase     Phase           `json:"phase"`
	Reason    string          `json:"reason,omitempty"`
	SinceUnix int64           `json:"since_unix"` // when Phase was entered
	UptimeSec int64           `json:"uptime_sec"`
	Version   string          `json:"version"`
	Mode      string          `json:"mode"`
	Tun       TunStatus       `json:"tun"`
	Inbounds  []InboundStatus `json:"inbounds"`
	Health    Health          `json:"health"`
	Traffic   Traffic         `json:"traffic"`
	Groups    []GroupStatus   `json:"groups"`
	DNS       DNSStatus       `json:"dns"`
}

// TunStatus describes the VPN tun device.
type TunStatus struct {
	Enabled bool   `json:"enabled"`
	FD      int    `json:"fd"`
	MTU     int    `json:"mtu"`
	Up      bool   `json:"up"`
	Err     string `json:"err,omitempty"`
}

// InboundStatus describes one local listener.
type InboundStatus struct {
	Name string `json:"name"` // mixed | dns | api
	Addr string `json:"addr"`
	Up   bool   `json:"up"`
	Conn int64  `json:"conn"` // accepted connections since start
	Err  string `json:"err,omitempty"`
}

// Health is the supervisor's view of the process itself.
type Health struct {
	HeartbeatAgoMS int64   `json:"heartbeat_ago_ms"` // age of the newest watchdog tick
	Goroutines     int     `json:"goroutines"`
	OpenFDs        int     `json:"open_fds"`
	HeapMB         float64 `json:"heap_mb"`
	Restarts       int     `json:"restarts"`
	LastError      string  `json:"last_error,omitempty"`
	StartedUnix    int64   `json:"started_unix"`
}

// Traffic holds counters and sampled rates (bytes/second).
type Traffic struct {
	Up        int64   `json:"up"`
	Down      int64   `json:"down"`
	UpRate    float64 `json:"up_rate"`
	DownRate  float64 `json:"down_rate"`
	Active    int     `json:"active"`
	TotalConn int64   `json:"total_conn"`
}

// GroupStatus is one policy group with its member latencies.
type GroupStatus struct {
	Tag     string       `json:"tag"`
	Type    string       `json:"type"`
	Now     string       `json:"now"`
	Members []NodeStatus `json:"members"`
}

// NodeStatus is the live health of one outbound.
type NodeStatus struct {
	Tag      string `json:"tag"`
	Type     string `json:"type"`
	Remark   string `json:"remark,omitempty"`
	DelayMS  int    `json:"delay_ms"` // -1 unknown
	Alive    bool   `json:"alive"`
	TestedAt int64  `json:"tested_at,omitempty"`
}

// DNSStatus describes the resolver.
type DNSStatus struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen,omitempty"`
	Err     string `json:"err,omitempty"`
}

// Conn is one tracked live connection.
type Conn struct {
	ID       uint64 `json:"id"`
	Start    int64  `json:"start"`
	Network  string `json:"network"`
	Source   string `json:"source"`
	Dest     string `json:"dest"`
	Outbound string `json:"outbound"`
	Rule     string `json:"rule,omitempty"`
	Up       int64  `json:"up"`
	Down     int64  `json:"down"`
	Chain    string `json:"chain,omitempty"`
}
