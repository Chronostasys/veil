package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"veil/internal/config"
	"veil/internal/rpc"
	"veil/internal/share"
	"veil/internal/state"
	"veil/internal/version"
)

// Call dispatches one RPC method.
func (s *Supervisor) Call(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case rpc.MethodStart:
		var p rpc.StartParams
		_ = decode(params, &p)
		return s.Status(), s.Start(ctx, p.TunFD)
	case rpc.MethodStop:
		return s.Status(), s.Stop(ctx)
	case rpc.MethodStatus:
		return s.Status(), nil
	case rpc.MethodVersion:
		return rpc.VersionResult{Version: version.Version, Commit: version.Commit}, nil
	case rpc.MethodNodes:
		return s.nodeStatuses(), nil
	case rpc.MethodGroups:
		return s.Groups(), nil
	case rpc.MethodImport:
		var p rpc.ImportParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.Import(p)
	case rpc.MethodSelect:
		var p rpc.SelectParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.Select(p)
	case rpc.MethodDelay:
		var p rpc.DelayParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.Delay(ctx, p)
	case rpc.MethodDelete:
		var p rpc.DeleteParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return struct{}{}, s.Delete(p.Tag)
	case rpc.MethodSetMode:
		var p rpc.ModeParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		s.mu.Lock()
		if s.eng != nil {
			s.mu.Unlock()
			if err := s.eng.SetMode(p.Mode); err != nil {
				return nil, err
			}
			s.mu.Lock()
		}
		s.cfg.Mode = p.Mode
		cfg := s.cfg
		s.mu.Unlock()
		return s.Status(), s.persist(cfg)
	case rpc.MethodSubAdd:
		var p rpc.SubParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.addSubscription(p)
	case rpc.MethodSubUpdate:
		var p rpc.SubUpdateParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.updateSubscription(ctx, p.Name)
	case rpc.MethodSubDelete:
		var p rpc.SubUpdateParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return struct{}{}, s.deleteSubscription(p.Name)
	case rpc.MethodConns:
		return s.Conns(), nil
	case rpc.MethodCloseConn:
		var p rpc.ConnParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		s.mu.Lock()
		eng := s.eng
		s.mu.Unlock()
		if eng == nil {
			return struct{}{}, nil
		}
		eng.CloseConn(p.ID)
		return struct{}{}, nil
	case rpc.MethodCloseAll:
		s.mu.Lock()
		eng := s.eng
		s.mu.Unlock()
		if eng != nil {
			eng.CloseAllConns()
		}
		return struct{}{}, nil
	case rpc.MethodLogs:
		var p rpc.LogsParams
		_ = decode(params, &p)
		if p.Limit <= 0 {
			p.Limit = 200
		}
		entries := s.log.Snapshot(p.AfterID, p.Limit)
		out := rpc.LogsResult{Lines: make([]rpc.LogLine, 0, len(entries))}
		for _, e := range entries {
			out.Lines = append(out.Lines, rpc.LogLine{ID: e.ID, Time: e.Time, Level: e.Level, Msg: e.Msg})
			if e.ID > out.Last {
				out.Last = e.ID
			}
		}
		return out, nil
	case rpc.MethodConfig:
		return s.Config(), nil
	case rpc.MethodSetConfig:
		var p rpc.SetConfigParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		var cfg config.Config
		if err := json.Unmarshal(p.Config, &cfg); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		return s.SetConfig(cfg)
	case rpc.MethodSetTunFD:
		var p rpc.TunParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		s.mu.Lock()
		eng := s.eng
		s.mu.Unlock()
		if eng == nil {
			return nil, errNotRunning
		}
		if err := eng.AttachTun(p.FD, p.MTU); err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.tunFD = p.FD
		s.mu.Unlock()
		s.setPhase(state.PhaseRunning, "")
		return s.Status(), nil
	case rpc.MethodClearTun:
		s.mu.Lock()
		eng := s.eng
		s.mu.Unlock()
		if eng != nil {
			_ = eng.DetachTun()
		}
		s.setPhase(state.PhaseDegraded, "tun detached")
		return s.Status(), nil
	case rpc.MethodResetStats:
		s.mu.Lock()
		eng := s.eng
		s.mu.Unlock()
		if eng != nil {
			eng.Stats().Reset()
		}
		return struct{}{}, nil
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

var errNotRunning = fmt.Errorf("core is not running")

func decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// Conns returns live connections.
func (s *Supervisor) Conns() []state.Conn {
	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()
	if eng == nil {
		return []state.Conn{}
	}
	return eng.Conns()
}

// Groups returns policy groups.
func (s *Supervisor) Groups() []state.GroupStatus {
	s.mu.Lock()
	eng := s.eng
	cfg := s.cfg
	s.mu.Unlock()
	if eng != nil {
		if g := eng.Groups(); len(g) > 0 {
			return g
		}
	}
	// Engine stopped: report the configured nodes with unknown latency so the UI
	// can still browse and edit them.
	out := make([]state.GroupStatus, 0, len(cfg.Nodes)+len(cfg.Groups))
	if len(cfg.Groups) > 0 {
		for _, g := range cfg.Groups {
			gs := state.GroupStatus{Tag: g.Tag, Type: g.Type, Now: g.Selected}
			for _, m := range g.Members {
				gs.Members = append(gs.Members, state.NodeStatus{Tag: m, Type: nodeType(cfg, m), DelayMS: -1})
			}
			out = append(out, gs)
		}
		return out
	}
	gs := state.GroupStatus{Tag: "proxy", Type: "select"}
	for _, n := range cfg.Nodes {
		gs.Members = append(gs.Members, state.NodeStatus{Tag: n.Tag, Type: n.Type, Remark: n.Remark, DelayMS: -1})
	}
	return append(out, gs)
}

func nodeType(cfg config.Config, tag string) string {
	for _, n := range cfg.Nodes {
		if n.Tag == tag {
			return n.Type
		}
	}
	return ""
}

// nodeStatuses flattens groups into nodes.
func (s *Supervisor) nodeStatuses() []state.NodeStatus {
	out := []state.NodeStatus{}
	seen := map[string]bool{}
	for _, g := range s.Groups() {
		for _, n := range g.Members {
			if !seen[n.Tag] {
				seen[n.Tag] = true
				out = append(out, n)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}

// Select pins a group member.
func (s *Supervisor) Select(p rpc.SelectParams) (any, error) {
	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()
	if eng != nil {
		if err := eng.Select(p.Group, p.Tag); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	for i := range s.cfg.Groups {
		if s.cfg.Groups[i].Tag == p.Group {
			s.cfg.Groups[i].Selected = p.Tag
		}
	}
	cfg := s.cfg
	s.mu.Unlock()
	if err := s.persist(cfg); err != nil {
		return nil, err
	}
	return s.Groups(), nil
}

// Delay probes one node.
func (s *Supervisor) Delay(ctx context.Context, p rpc.DelayParams) (rpc.DelayResult, error) {
	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()
	if eng == nil {
		return rpc.DelayResult{Tag: p.Tag, Delay: -1}, errNotRunning
	}
	done := make(chan struct{})
	var ms int
	var err error
	go func() {
		ms, err = eng.ProbeTag(p.Tag)
		close(done)
	}()
	timeout := 10 * time.Second
	if p.Timeout > 0 {
		timeout = time.Duration(p.Timeout) * time.Millisecond
	}
	select {
	case <-done:
	case <-time.After(timeout):
		return rpc.DelayResult{Tag: p.Tag, Delay: -1}, fmt.Errorf("probe timed out")
	case <-ctx.Done():
		return rpc.DelayResult{Tag: p.Tag, Delay: -1}, ctx.Err()
	}
	res := rpc.DelayResult{Tag: p.Tag, Delay: ms}
	if err != nil {
		res.Delay = -1
		res.Err = err.Error()
	}
	return res, nil
}

// Import accepts pasted links, subscription bodies or Clash YAML.
func (s *Supervisor) Import(p rpc.ImportParams) (rpc.ImportResult, error) {
	res := rpc.ImportResult{}
	var nodes []config.Node
	var errs []error
	text := strings.TrimSpace(p.Text)
	if text != "" {
		nodes, errs = share.ParseText(text)
		if len(nodes) == 0 {
			if n2, e2 := share.ParseClashYAML([]byte(text), p.Source); len(n2) > 0 {
				nodes, errs = n2, e2
			}
		}
	}
	for _, url := range p.URLs {
		n, err := s.fetchSubscription(url, p.Source)
		if err != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", url, err))
			continue
		}
		nodes = append(nodes, n...)
	}
	for _, e := range errs {
		if e != nil {
			res.Failed++
			if len(res.Errors) < 20 {
				res.Errors = append(res.Errors, e.Error())
			}
		}
	}
	if len(nodes) == 0 {
		return res, fmt.Errorf("no nodes found in input")
	}
	source := p.Source
	if source == "" {
		source = p.Name
	}
	for i := range nodes {
		if nodes[i].Source == "" {
			nodes[i].Source = source
		}
	}
	added, updated := s.mergeNodes(nodes)
	res.Added, res.Updated = added, updated
	s.mu.Lock()
	for _, n := range nodes {
		res.Tags = append(res.Tags, n.Tag)
	}
	cfg := s.cfg
	s.mu.Unlock()
	if err := s.persist(cfg); err != nil {
		return res, err
	}
	if err := s.reload(); err != nil {
		return res, err
	}
	s.log.Infof("imported %d new and %d updated node(s)", added, updated)
	return res, nil
}

// mergeNodes inserts or replaces nodes by tag and ensures a default group.
func (s *Supervisor) mergeNodes(nodes []config.Node) (added, updated int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := make(map[string]int, len(s.cfg.Nodes))
	for i, n := range s.cfg.Nodes {
		idx[n.Tag] = i
	}
	for _, n := range nodes {
		if i, ok := idx[n.Tag]; ok {
			s.cfg.Nodes[i] = n
			updated++
			continue
		}
		idx[n.Tag] = len(s.cfg.Nodes)
		s.cfg.Nodes = append(s.cfg.Nodes, n)
		added++
	}
	// Keep exactly one "proxy" select group containing every node, unless the
	// user already defined groups explicitly.
	if len(s.cfg.Groups) == 0 {
		tags := make([]string, 0, len(s.cfg.Nodes))
		for _, n := range s.cfg.Nodes {
			tags = append(tags, n.Tag)
		}
		s.cfg.Groups = []config.Group{{
			Tag:     "proxy",
			Type:    "select",
			Members: tags,
			URL:     "http://cp.cloudflare.com/generate_204",
		}}
	} else {
		for gi := range s.cfg.Groups {
			for _, n := range nodes {
				if !contains(s.cfg.Groups[gi].Members, n.Tag) {
					s.cfg.Groups[gi].Members = append(s.cfg.Groups[gi].Members, n.Tag)
				}
			}
		}
	}
	return added, updated
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Delete removes a manually added node.
func (s *Supervisor) Delete(tag string) error {
	s.mu.Lock()
	out := s.cfg.Nodes[:0]
	found := false
	for _, n := range s.cfg.Nodes {
		if n.Tag == tag {
			found = true
			continue
		}
		out = append(out, n)
	}
	if !found {
		s.mu.Unlock()
		return fmt.Errorf("node %q not found", tag)
	}
	s.cfg.Nodes = out
	for gi := range s.cfg.Groups {
		members := s.cfg.Groups[gi].Members[:0]
		for _, m := range s.cfg.Groups[gi].Members {
			if m != tag {
				members = append(members, m)
			}
		}
		s.cfg.Groups[gi].Members = members
	}
	cfg := s.cfg
	s.mu.Unlock()
	if err := s.persist(cfg); err != nil {
		return err
	}
	return s.reload()
}

// SetConfig replaces the whole configuration.
func (s *Supervisor) SetConfig(cfg config.Config) (state.Status, error) {
	if err := cfg.Validate(); err != nil {
		return s.Status(), err
	}
	s.mu.Lock()
	s.cfg = cfg
	running := s.eng != nil
	s.mu.Unlock()
	if err := s.persist(cfg); err != nil {
		return s.Status(), err
	}
	if running {
		if err := s.reload(); err != nil {
			return s.Status(), err
		}
	}
	if lvl := cfg.LogLevel; lvl != "" {
		s.log.SetLevel(logLevel(lvl))
	}
	return s.Status(), nil
}

// addSubscription registers a subscription and imports it immediately.
func (s *Supervisor) addSubscription(p rpc.SubParams) (any, error) {
	if p.URL == "" {
		return nil, fmt.Errorf("subscription url is empty")
	}
	name := p.Name
	if name == "" {
		name = p.URL
	}
	s.mu.Lock()
	for _, sub := range s.cfg.Subscriptions {
		if sub.URL == p.URL {
			s.mu.Unlock()
			return nil, fmt.Errorf("subscription already exists")
		}
	}
	s.cfg.Subscriptions = append(s.cfg.Subscriptions, config.Subscription{
		Name:     name,
		URL:      p.URL,
		Interval: 86400,
	})
	cfg := s.cfg
	s.mu.Unlock()
	if err := s.persist(cfg); err != nil {
		return nil, err
	}
	if _, err := s.updateSubscription(context.Background(), name); err != nil {
		return nil, err
	}
	return s.Groups(), nil
}

// updateSubscription re-fetches a subscription and replaces its nodes.
func (s *Supervisor) updateSubscription(ctx context.Context, name string) ([]state.NodeStatus, error) {
	s.mu.Lock()
	var sub *config.Subscription
	for i := range s.cfg.Subscriptions {
		if s.cfg.Subscriptions[i].Name == name {
			sub = &s.cfg.Subscriptions[i]
		}
	}
	s.mu.Unlock()
	if sub == nil {
		return nil, fmt.Errorf("subscription %q not found", name)
	}
	nodes, err := s.fetchSubscription(sub.URL, name)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("subscription %q returned no nodes", name)
	}

	s.mu.Lock()
	kept := s.cfg.Nodes[:0]
	for _, n := range s.cfg.Nodes {
		if n.Source != name {
			kept = append(kept, n)
		}
	}
	s.cfg.Nodes = append(kept, nodes...)
	for i := range s.cfg.Subscriptions {
		if s.cfg.Subscriptions[i].Name == name {
			s.cfg.Subscriptions[i].Updated = time.Now().Unix()
		}
	}
	// Rebuild group membership for the refreshed subscription.
	for gi := range s.cfg.Groups {
		members := make([]string, 0, len(s.cfg.Groups[gi].Members)+len(nodes))
		for _, m := range s.cfg.Groups[gi].Members {
			if nodeSource(s.cfg.Nodes, m) != name || contains(tagsOf(nodes), m) {
				members = append(members, m)
			}
		}
		for _, n := range nodes {
			if !contains(members, n.Tag) {
				members = append(members, n.Tag)
			}
		}
		s.cfg.Groups[gi].Members = members
	}
	cfg := s.cfg
	s.mu.Unlock()
	if err := s.persist(cfg); err != nil {
		return nil, err
	}
	if err := s.reload(); err != nil {
		return nil, err
	}
	s.log.Infof("subscription %s updated: %d node(s)", name, len(nodes))
	return s.nodeStatuses(), nil
}

func tagsOf(nodes []config.Node) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Tag
	}
	return out
}

func nodeSource(nodes []config.Node, tag string) string {
	for _, n := range nodes {
		if n.Tag == tag {
			return n.Source
		}
	}
	return ""
}

func (s *Supervisor) deleteSubscription(name string) error {
	s.mu.Lock()
	subs := s.cfg.Subscriptions[:0]
	found := false
	for _, sub := range s.cfg.Subscriptions {
		if sub.Name == name {
			found = true
			continue
		}
		subs = append(subs, sub)
	}
	if !found {
		s.mu.Unlock()
		return fmt.Errorf("subscription %q not found", name)
	}
	s.cfg.Subscriptions = subs
	nodes := s.cfg.Nodes[:0]
	for _, n := range s.cfg.Nodes {
		if n.Source != name {
			nodes = append(nodes, n)
		}
	}
	s.cfg.Nodes = nodes
	for gi := range s.cfg.Groups {
		members := s.cfg.Groups[gi].Members[:0]
		for _, m := range s.cfg.Groups[gi].Members {
			if nodeSource(s.cfg.Nodes, m) != name {
				members = append(members, m)
			}
		}
		s.cfg.Groups[gi].Members = members
	}
	cfg := s.cfg
	s.mu.Unlock()
	if err := s.persist(cfg); err != nil {
		return err
	}
	return s.reload()
}

// fetchSubscription downloads and parses one subscription URL.
func (s *Supervisor) fetchSubscription(url, name string) ([]config.Node, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", version.UserAgent)
	req.Header.Set("Accept", "*/*")
	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	nodes, errs := share.ParseSubscription(body, name)
	if len(nodes) == 0 {
		if n2, _ := share.ParseClashYAML(body, name); len(n2) > 0 {
			return n2, nil
		}
		if len(errs) > 0 {
			return nil, errs[0]
		}
		return nil, fmt.Errorf("empty subscription")
	}
	return nodes, nil
}

// persist writes the configuration atomically.
func (s *Supervisor) persist(cfg config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	return config.Save(s.cfgPath, cfg)
}
