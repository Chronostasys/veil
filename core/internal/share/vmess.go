package share

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"veil/internal/config"
)

// flexInt accepts JSON numbers and quoted numbers (vmess JSON is inconsistent
// about "port": 443 vs "port": "443").
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("share: vmess: invalid integer %q", s)
	}
	*f = flexInt(v)
	return nil
}

// vmessJSON is the standard vmess://base64(JSON) payload.
type vmessJSON struct {
	V    string  `json:"v"`
	PS   string  `json:"ps"`
	Add  string  `json:"add"`
	Port flexInt `json:"port"`
	ID   string  `json:"id"`
	Aid  flexInt `json:"aid"`
	Net  string  `json:"net"`
	Type string  `json:"type"`
	Host string  `json:"host"`
	Path string  `json:"path"`
	TLS  string  `json:"tls"`
	SNI  string  `json:"sni"`
	Scy  string  `json:"scy"`
	Alpn string  `json:"alpn"`
	Fp   string  `json:"fp"`
	// Insecure is a non-standard extension the exporter emits so that
	// allowInsecure survives a Link -> Parse round-trip.
	Insecure bool `json:"insecure"`
}

// parseVMess handles both the standard base64(JSON) form and the legacy
// v2rayN form: vmess://base64(auto:uuid@host:port)?remarks=&obfs=websocket...
func parseVMess(body string) (config.Node, error) {
	body, frag := splitFragment(body)
	body, rawQuery := splitQuery(body)
	q := parseQuery(rawQuery)
	outerQ := q

	decoded := b64Text(body)
	if decoded == "" {
		return config.Node{}, fmt.Errorf("share: vmess: invalid base64 payload")
	}
	decoded = percentDecode(decoded)
	// The legacy payload may carry its own query string.
	payload, innerQuery := splitQuery(decoded)
	if innerQuery != "" {
		q = parseQuery(innerQuery)
		for k, vv := range outerQ {
			q[k] = vv
		}
	}

	if strings.HasPrefix(strings.TrimSpace(payload), "{") {
		return parseVMessJSON(payload, frag, q)
	}

	// Legacy: encryption:uuid@host:port (the fragment/query may hold the tag).
	userinfo, hostport, err := splitUserInfo(payload)
	if err != nil {
		return config.Node{}, fmt.Errorf("share: vmess: %w", err)
	}
	server, port, err := splitHostPort(hostport)
	if err != nil {
		return config.Node{}, fmt.Errorf("share: vmess: %w", err)
	}
	n := config.Node{
		Type:   "vmess",
		Server: server,
		Port:   port,
		UUID:   extractUUID(userinfo),
	}
	if err := validateUUID(n.UUID); err != nil {
		return config.Node{}, err
	}
	if v := qget(q, "alterId", "aid"); v != "" {
		if aid, err := strconv.Atoi(v); err == nil {
			n.AlterID = aid
		}
	}

	network := qget(q, "obfs", "network", "type")
	switch strings.ToLower(network) {
	case "websocket", "ws":
		network = "ws"
	case "none", "":
		network = "tcp"
	}
	tr := ensureTransport(&n, normalizeNetwork(network))
	tr.Type = normalizeNetwork(network)
	switch tr.Type {
	case "ws":
		tr.Path = qget(q, "path", "wspath")
		if host := qget(q, "obfsParam", "host", "ws-host"); host != "" {
			tr.Host = host
			if tr.Headers == nil {
				tr.Headers = map[string]string{}
			}
			tr.Headers["Host"] = host
		}
	case "grpc":
		tr.ServiceName = qget(q, "path", "serviceName")
		tr.Path = ""
	case "h2":
		tr.Path = qget(q, "path")
		if host := qget(q, "obfsParam", "host"); host != "" {
			tr.Host = host
			if tr.Headers == nil {
				tr.Headers = map[string]string{}
			}
			tr.Headers["Host"] = host
		}
	}

	if truthy(qget(q, "tls")) || qget(q, "tls") == "tls" {
		t := ensureTLS(&n)
		t.Enabled = true
		if sni := qget(q, "peer", "sni", "servername"); sni != "" {
			t.ServerName = sni
		}
		t.Insecure = truthy(qget(q, "allowInsecure", "insecure", "skipVerify"))
	}

	switch {
	case frag != "":
		n.Remark = frag
	default:
		n.Remark = NormalizeTag(qget(q, "remarks", "remark", "ps"))
	}
	return n, nil
}

// parseVMessJSON fills a node from the standard vmess JSON payload.
func parseVMessJSON(payload, frag string, q url.Values) (config.Node, error) {
	var m vmessJSON
	if err := json.Unmarshal([]byte(payload), &m); err != nil {
		return config.Node{}, fmt.Errorf("share: vmess: invalid json: %w", err)
	}
	server := strings.TrimSpace(m.Add)
	port := int(m.Port)
	if port == 0 {
		if v := qget(q, "port"); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				port = p
			}
		}
	}
	if server == "" || port <= 0 || port > 65535 {
		return config.Node{}, fmt.Errorf("share: vmess: invalid address %q:%d", server, port)
	}
	n := config.Node{
		Type:    "vmess",
		Server:  server,
		Port:    port,
		UUID:    strings.TrimSpace(m.ID),
		AlterID: int(m.Aid),
	}
	if err := validateUUID(n.UUID); err != nil {
		return config.Node{}, err
	}

	tr := ensureTransport(&n, normalizeNetwork(m.Net))
	tr.Type = normalizeNetwork(m.Net)
	switch tr.Type {
	case "ws":
		tr.Path = m.Path
		if m.Host != "" {
			tr.Host = m.Host
			if tr.Headers == nil {
				tr.Headers = map[string]string{}
			}
			tr.Headers["Host"] = m.Host
		}
	case "grpc":
		tr.ServiceName = m.Path
		tr.Path = ""
	case "h2":
		tr.Path = m.Path
		if m.Host != "" {
			tr.Host = m.Host
			if tr.Headers == nil {
				tr.Headers = map[string]string{}
			}
			tr.Headers["Host"] = m.Host
		}
	}

	if m.TLS != "" && !strings.EqualFold(m.TLS, "none") {
		t := ensureTLS(&n)
		t.Enabled = true
		t.ServerName = strings.TrimSpace(m.SNI)
		if t.ServerName == "" {
			t.ServerName = strings.TrimSpace(m.Host)
		}
		if m.Fp != "" {
			t.Fingerprint = m.Fp
		}
		t.Insecure = m.Insecure
		if m.Alpn != "" {
			for _, a := range strings.Split(m.Alpn, ",") {
				if a = strings.TrimSpace(a); a != "" {
					t.ALPN = append(t.ALPN, a)
				}
			}
		}
	}

	switch {
	case frag != "":
		n.Remark = frag
	default:
		n.Remark = NormalizeTag(m.PS)
	}
	return n, nil
}
