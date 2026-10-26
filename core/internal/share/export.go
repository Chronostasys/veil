package share

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"veil/internal/config"
)

// Link renders n as a share URI. The output is the modern (non-base64) form
// for every supported protocol and round-trips through Parse.
func Link(n config.Node) (string, error) {
	switch n.Type {
	case "vless":
		return linkVLESS(n)
	case "vmess":
		return linkVMess(n)
	case "trojan":
		return linkTrojan(n)
	case "ss":
		return linkSS(n)
	case "hysteria2", "hy2":
		return linkHysteria2(n)
	default:
		return "", fmt.Errorf("share: cannot export node type %q", n.Type)
	}
}

// escape renders s as a URI component safe for userinfo and query values.
func escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// frag appends "#tag" when the node carries a tag or remark.
func frag(n config.Node) string {
	tag := NormalizeTag(n.Tag)
	if tag == "" {
		tag = NormalizeTag(n.Remark)
	}
	if tag == "" {
		return ""
	}
	return "#" + escape(tag)
}

// authority builds "[userinfo@]host:port".
func authority(userinfo, server string, port int) string {
	host := server
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	hp := host + ":" + strconv.Itoa(port)
	if userinfo == "" {
		return hp
	}
	return userinfo + "@" + hp
}

// queryBuilder accumulates non-empty query parameters in insertion order.
type queryBuilder struct {
	parts []string
}

func (b *queryBuilder) add(k, v string) {
	if v == "" {
		return
	}
	b.parts = append(b.parts, k+"="+escape(v))
}

func (b *queryBuilder) addBool(k string, v bool) {
	if v {
		b.parts = append(b.parts, k+"=1")
	}
}

func (b *queryBuilder) String() string {
	if len(b.parts) == 0 {
		return ""
	}
	return "?" + strings.Join(b.parts, "&")
}

func linkVLESS(n config.Node) (string, error) {
	if err := validateUUID(n.UUID); err != nil {
		return "", err
	}
	q := &queryBuilder{}
	q.add("encryption", "none")

	tlsOn := n.TLS != nil && n.TLS.Enabled
	reality := tlsOn && n.TLS.Reality != nil
	switch {
	case reality:
		q.add("security", "reality")
	case tlsOn:
		q.add("security", "tls")
	}

	if tlsOn {
		sni := n.TLS.ServerName
		if sni == "" {
			sni = n.Server
		}
		q.add("sni", sni)
		q.add("fp", n.TLS.Fingerprint)
		q.addBool("allowInsecure", n.TLS.Insecure)
		if len(n.TLS.ALPN) > 0 {
			q.add("alpn", strings.Join(n.TLS.ALPN, ","))
		}
	}
	if reality {
		q.add("pbk", n.TLS.Reality.PublicKey)
		q.add("sid", n.TLS.Reality.ShortID)
		q.add("spx", n.TLS.Reality.SpiderX)
	}
	q.add("flow", n.Flow)

	if t := n.Transport; t != nil {
		if t.Type != "" && t.Type != "tcp" {
			q.add("type", t.Type)
		}
		switch t.Type {
		case "ws":
			q.add("path", t.Path)
			q.add("host", t.Host)
		case "grpc":
			q.add("serviceName", t.ServiceName)
		case "h2":
			q.add("path", t.Path)
			q.add("host", t.Host)
		}
	}

	return "vless://" + authority(escape(n.UUID), n.Server, n.Port) + q.String() + frag(n), nil
}

// vmessJSONOut mirrors the standard vmess JSON payload.
type vmessJSONOut struct {
	V        string `json:"v"`
	PS       string `json:"ps"`
	Add      string `json:"add"`
	Port     string `json:"port"`
	ID       string `json:"id"`
	Aid      string `json:"aid"`
	Net      string `json:"net"`
	Type     string `json:"type"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	TLS      string `json:"tls,omitempty"`
	SNI      string `json:"sni,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
	Fp       string `json:"fp,omitempty"`
	Alpn     string `json:"alpn,omitempty"`
}

func linkVMess(n config.Node) (string, error) {
	if err := validateUUID(n.UUID); err != nil {
		return "", err
	}
	m := vmessJSONOut{
		V:    "2",
		PS:   NormalizeTag(n.Remark),
		Add:  n.Server,
		Port: strconv.Itoa(n.Port),
		ID:   n.UUID,
		Aid:  strconv.Itoa(n.AlterID),
		Net:  "tcp",
		Type: "none",
	}
	if t := n.Transport; t != nil && t.Type != "" {
		m.Net = t.Type
		if t.Type == "grpc" {
			m.Path = t.ServiceName
		} else {
			m.Path = t.Path
			m.Host = t.Host
		}
	}
	if m.Net == "tcp" {
		m.Host, m.Path = "", ""
	}
	if n.TLS != nil && n.TLS.Enabled {
		m.TLS = "tls"
		m.SNI = n.TLS.ServerName
		m.Insecure = n.TLS.Insecure
		m.Fp = n.TLS.Fingerprint
		if len(n.TLS.ALPN) > 0 {
			m.Alpn = strings.Join(n.TLS.ALPN, ",")
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("share: vmess: %w", err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b) + frag(n), nil
}

func linkTrojan(n config.Node) (string, error) {
	if n.Password == "" {
		return "", fmt.Errorf("share: trojan: missing password")
	}
	q := &queryBuilder{}
	if n.TLS != nil {
		sni := n.TLS.ServerName
		if sni == "" {
			sni = n.Server
		}
		q.add("sni", sni)
		q.add("fp", n.TLS.Fingerprint)
		if len(n.TLS.ALPN) > 0 {
			q.add("alpn", strings.Join(n.TLS.ALPN, ","))
		}
		q.addBool("allowInsecure", n.TLS.Insecure)
	}
	if t := n.Transport; t != nil {
		if t.Type != "" && t.Type != "tcp" {
			q.add("type", t.Type)
		}
		switch t.Type {
		case "ws", "h2":
			q.add("path", t.Path)
			q.add("host", t.Host)
		case "grpc":
			q.add("serviceName", t.ServiceName)
		}
	}
	return "trojan://" + authority(escape(n.Password), n.Server, n.Port) + q.String() + frag(n), nil
}

func linkSS(n config.Node) (string, error) {
	if n.Method == "" || n.Password == "" {
		return "", fmt.Errorf("share: ss: missing method/password")
	}
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(ssLinkPassword(n)))
	q := &queryBuilder{}
	q.add("plugin", pluginQuery(n))
	return "ss://" + authority(userinfo, n.Server, n.Port) + q.String() + frag(n), nil
}

func linkHysteria2(n config.Node) (string, error) {
	if n.Password == "" {
		return "", fmt.Errorf("share: hysteria2: missing password")
	}
	q := &queryBuilder{}
	if n.TLS != nil {
		sni := n.TLS.ServerName
		if sni == "" {
			sni = n.Server
		}
		q.add("sni", sni)
		q.addBool("insecure", n.TLS.Insecure)
	}
	if n.Transport != nil {
		if obfs := n.Transport.Headers["obfs"]; obfs != "" {
			q.add("obfs", obfs)
			q.add("obfs-password", n.Transport.Headers["obfs-password"])
		}
	}
	return "hysteria2://" + authority(escape(n.Password), n.Server, n.Port) + q.String() + frag(n), nil
}
