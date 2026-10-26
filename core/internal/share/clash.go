package share

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"veil/internal/config"
)

// clashDocument is the subset of a Clash config we care about.
type clashDocument struct {
	Proxies []clashProxy `yaml:"proxies"`
}

type clashProxy struct {
	Name           string            `yaml:"name"`
	Type           string            `yaml:"type"`
	Server         string            `yaml:"server"`
	Port           any               `yaml:"port"`
	UUID           string            `yaml:"uuid"`
	Password       string            `yaml:"password"`
	Cipher         string            `yaml:"cipher"`
	AlterID        any               `yaml:"alterId"`
	Network        string            `yaml:"network"`
	TLS            bool              `yaml:"tls"`
	ServerName     string            `yaml:"servername"`
	SNI            string            `yaml:"sni"`
	SkipCertVerify bool              `yaml:"skip-cert-verify"`
	Fingerprint    string            `yaml:"client-fingerprint"`
	Flow           string            `yaml:"flow"`
	Obfs           string            `yaml:"obfs"`
	ObfsPassword   string            `yaml:"obfs-password"`
	ALPN           []string          `yaml:"alpn"`
	UDP            *bool             `yaml:"udp"`
	WSOpts         *clashWSOpts      `yaml:"ws-opts"`
	GRPCOpts       *clashGRPCOpts    `yaml:"grpc-opts"`
	RealityOpts    *clashRealityOpts `yaml:"reality-opts"`
}

type clashWSOpts struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

type clashGRPCOpts struct {
	ServiceName string `yaml:"grpc-service-name"`
}

type clashRealityOpts struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

// asInt converts a YAML scalar (int or quoted string) to int.
func asInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return i
		}
	}
	return 0
}

// ParseClashYAML parses the `proxies:` list of a Clash/Clash.Meta config.
// Unsupported proxy types (direct, reject, dns, ...) are skipped silently;
// malformed proxies are reported in the error slice.
func ParseClashYAML(doc []byte, source string) ([]config.Node, []error) {
	var d clashDocument
	if err := yaml.Unmarshal(doc, &d); err != nil {
		return nil, []error{fmt.Errorf("share: clash yaml: %w", err)}
	}
	var nodes []config.Node
	var errs []error
	for i, p := range d.Proxies {
		n, err := p.node()
		if err != nil {
			errs = append(errs, fmt.Errorf("share: clash proxy %d (%q): %w", i, p.Name, err))
			continue
		}
		if n.Type == "" {
			continue // unsupported type
		}
		n.Remark = NormalizeTag(p.Name)
		n.Source = source
		nodes = append(nodes, n)
	}
	return finalize(nodes), errs
}

// node converts one Clash proxy entry into a config.Node. A zero Type means
// "unsupported, skip".
func (p clashProxy) node() (config.Node, error) {
	typ := strings.ToLower(strings.TrimSpace(p.Type))
	server := strings.TrimSpace(p.Server)
	port := asInt(p.Port)

	n := config.Node{
		Server:   server,
		Port:     port,
		AlterID:  asInt(p.AlterID),
		Flow:     strings.TrimSpace(p.Flow),
		Password: p.Password,
		Method:   p.Cipher,
		UDP:      p.UDP,
	}

	switch typ {
	case "vless", "vmess":
		n.Type = typ
		n.UUID = strings.TrimSpace(p.UUID)
		if n.Type == "vless" {
			n.AlterID = 0
		}
	case "trojan":
		n.Type = "trojan"
	case "ss", "shadowsocks":
		n.Type = "ss"
		n.Method = p.Cipher
	case "hysteria2", "hy2":
		n.Type = "hysteria2"
	case "", "direct", "reject", "dns", "selector", "urltest":
		return config.Node{}, nil
	default:
		return config.Node{}, nil // unsupported but not an error
	}

	if server == "" || port <= 0 || port > 65535 {
		return config.Node{}, fmt.Errorf("invalid address %q:%d", server, port)
	}
	switch n.Type {
	case "vless", "vmess":
		if err := validateUUID(n.UUID); err != nil {
			return config.Node{}, err
		}
	case "trojan", "hysteria2":
		if n.Password == "" {
			return config.Node{}, fmt.Errorf("missing password")
		}
	case "ss":
		if n.Method == "" || n.Password == "" {
			return config.Node{}, fmt.Errorf("missing cipher/password")
		}
	}

	// Transport.
	switch normalizeNetwork(p.Network) {
	case "ws":
		tr := ensureTransport(&n, "ws")
		tr.Type = "ws"
		if p.WSOpts != nil {
			tr.Path = p.WSOpts.Path
			for k, v := range p.WSOpts.Headers {
				if tr.Headers == nil {
					tr.Headers = map[string]string{}
				}
				tr.Headers[k] = v
				if strings.EqualFold(k, "host") {
					tr.Host = v
				}
			}
		}
	case "grpc":
		tr := ensureTransport(&n, "grpc")
		tr.Type = "grpc"
		if p.GRPCOpts != nil {
			tr.ServiceName = p.GRPCOpts.ServiceName
		}
	case "h2":
		tr := ensureTransport(&n, "h2")
		tr.Type = "h2"
		if p.WSOpts != nil {
			tr.Path = p.WSOpts.Path
		}
	}

	// TLS / REALITY.
	tlsOn := p.TLS || p.RealityOpts != nil || n.Type == "hysteria2" || n.Type == "trojan"
	if tlsOn {
		t := ensureTLS(&n)
		t.Enabled = true
		t.ServerName = strings.TrimSpace(p.SNI)
		if t.ServerName == "" {
			t.ServerName = strings.TrimSpace(p.ServerName)
		}
		if t.ServerName == "" && (n.Type == "hysteria2" || n.Type == "trojan") {
			t.ServerName = server
		}
		t.Insecure = p.SkipCertVerify
		if p.Fingerprint != "" {
			t.Fingerprint = p.Fingerprint
		}
		if len(p.ALPN) > 0 {
			t.ALPN = append(t.ALPN, p.ALPN...)
		}
		if p.RealityOpts != nil {
			t.Reality = &config.Reality{
				PublicKey: strings.TrimSpace(p.RealityOpts.PublicKey),
				ShortID:   strings.TrimSpace(p.RealityOpts.ShortID),
			}
			if t.Fingerprint == "" {
				t.Fingerprint = "chrome"
			}
		}
	}

	// Hysteria2 obfs travels in transport headers (see hysteria2.go).
	if p.Obfs != "" && !strings.EqualFold(p.Obfs, "none") {
		if n.Transport == nil {
			n.Transport = &config.Transport{}
		}
		if n.Transport.Headers == nil {
			n.Transport.Headers = map[string]string{}
		}
		n.Transport.Headers["obfs"] = p.Obfs
		if p.ObfsPassword != "" {
			n.Transport.Headers["obfs-password"] = p.ObfsPassword
		}
	}
	return n, nil
}
