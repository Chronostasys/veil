// Package rules implements Veil's routing rule matcher.
package rules

import (
	"net/netip"

	"veil/internal/config"
)

// Meta is the per-connection information available to the matcher.
type Meta struct {
	Network string // tcp | udp
	Host    string // requested domain, empty when the client sent an IP
	Dst     netip.Addr
	Port    uint16
	Process string
}

// Action is the routing decision.
type Action struct {
	Outbound string // node or group tag; "direct" / "reject" are built-ins
	Reject   bool
	Rule     string // matched rule, for display; empty when the default applied
}

// Engine matches Meta values against an ordered rule list.
type Engine struct {
	rules []compiled
	mode  string
	final string
}

// New compiles rs. mode is config.ModeRule/Global/Direct; final is the fallback
// outbound tag.
func New(rs []config.Rule, mode, final string) (*Engine, error) {
	e := &Engine{mode: mode, final: final}
	compiledRules, err := compile(rs)
	if err != nil {
		return nil, err
	}
	e.rules = compiledRules
	return e, nil
}

// Match returns the first matching action. It never blocks and never performs
// DNS lookups.
func (e *Engine) Match(m Meta) Action {
	switch e.mode {
	case config.ModeGlobal:
		return Action{Outbound: e.final, Rule: "global"}
	case config.ModeDirect:
		return Action{Outbound: "direct", Rule: "direct"}
	}
	for i := range e.rules {
		if e.rules[i].match(m) {
			return e.rules[i].action
		}
	}
	return Action{Outbound: e.final}
}
