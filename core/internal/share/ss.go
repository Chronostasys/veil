package share

import (
	"fmt"
	"strings"

	"veil/internal/config"
)

// parseSS parses shadowsocks SIP002 links. Three dialects are accepted:
//
//	ss://base64(method:password)@host:port?plugin=...#tag   (SIP002)
//	ss://base64(method:password@host:port)#tag              (legacy whole-blob)
//	ss://method:password@host:port#tag                      (plain, non-standard)
func parseSS(body, raw string) (config.Node, error) {
	body, frag := splitFragment(body)
	body, rawQuery := splitQuery(body)
	q := parseQuery(rawQuery)
	body = strings.TrimSuffix(body, "/")

	var userinfo, hostport string
	if strings.Contains(body, "@") {
		ui, hp, _ := strings.Cut(body, "@")
		userinfo, hostport = ui, hp
	} else {
		decoded := b64Text(body)
		if decoded == "" {
			return config.Node{}, fmt.Errorf("share: ss: cannot decode payload")
		}
		decoded, innerQuery := splitQuery(decoded)
		for k, vv := range parseQuery(innerQuery) {
			if _, exists := q[k]; !exists {
				q[k] = vv
			}
		}
		decoded = strings.TrimSuffix(decoded, "/")
		ui, hp, err := splitUserInfo(decoded)
		if err != nil {
			return config.Node{}, fmt.Errorf("share: ss: %w", err)
		}
		userinfo, hostport = ui, hp
	}

	// userinfo is base64(method:password) in SIP002, but may already be plain.
	method, password := splitSSUserInfo(userinfo)
	if method == "" || password == "" {
		return config.Node{}, fmt.Errorf("share: ss: missing method/password")
	}
	server, port, err := splitHostPort(hostport)
	if err != nil {
		return config.Node{}, fmt.Errorf("share: ss: %w", err)
	}

	n := config.Node{
		Type:     "ss",
		Server:   server,
		Port:     port,
		Method:   method,
		Password: password,
	}

	if plugin := qget(q, "plugin"); plugin != "" {
		applySSPlugin(&n, plugin)
	}

	n.Remark = frag
	if n.Remark == "" {
		n.Remark = NormalizeTag(qget(q, "remark", "remarks"))
	}
	return n, nil
}

// splitSSUserInfo decodes "base64(method:password)" or "method:password".
func splitSSUserInfo(userinfo string) (string, string) {
	userinfo = percentDecode(strings.TrimSpace(userinfo))
	if decoded := b64Text(userinfo); decoded != "" && strings.Contains(decoded, ":") {
		userinfo = decoded
	}
	method, password, ok := strings.Cut(userinfo, ":")
	if !ok {
		return "", ""
	}
	return strings.TrimSpace(method), password
}

// applySSPlugin maps SIP002 plugin strings onto transport/TLS settings.
// v2ray-plugin and simple-obfs are the ones that exist in the wild.
func applySSPlugin(n *config.Node, plugin string) {
	parts := strings.Split(plugin, ";")
	name := strings.ToLower(parts[0])
	opts := map[string]string{}
	for _, p := range parts[1:] {
		k, v, _ := strings.Cut(p, "=")
		opts[strings.ToLower(strings.TrimSpace(k))] = v
	}

	switch name {
	case "v2ray-plugin", "xray-plugin":
		tr := ensureTransport(n, "ws")
		tr.Type = "ws"
		mode := strings.ToLower(opts["mode"])
		if mode == "" || mode == "websocket" {
			tr.Path = opts["path"]
			if host := opts["host"]; host != "" {
				tr.Host = host
				if tr.Headers == nil {
					tr.Headers = map[string]string{}
				}
				tr.Headers["Host"] = host
			}
		}
		if _, ok := opts["tls"]; ok {
			t := ensureTLS(n)
			t.Enabled = true
			if host := opts["host"]; host != "" {
				t.ServerName = host
			}
		}
	case "obfs-local", "simple-obfs", "obfs":
		obfs := strings.ToLower(opts["obfs"])
		if obfs == "" {
			obfs = "http"
		}
		tr := ensureTransport(n, "tcp")
		tr.Type = "tcp"
		if tr.Headers == nil {
			tr.Headers = map[string]string{}
		}
		tr.Headers["obfs"] = obfs
		if host := opts["obfs-host"]; host != "" {
			tr.Headers["obfs-host"] = host
			tr.Host = host
		}
	}
}

// ssLinkPassword builds the credential part of a SIP002 link.
func ssLinkPassword(n config.Node) string {
	return n.Method + ":" + n.Password
}

// pluginQuery renders the plugin parameter for a node, or "" when the node
// carries no shadowsocks plugin settings.
func pluginQuery(n config.Node) string {
	if n.Transport == nil {
		return ""
	}
	if obfs := n.Transport.Headers["obfs"]; obfs != "" {
		v := "obfs-local;obfs=" + obfs
		if host := n.Transport.Headers["obfs-host"]; host != "" {
			v += ";obfs-host=" + host
		}
		return v
	}
	if n.Transport.Type == "ws" {
		v := "v2ray-plugin;mode=websocket"
		if n.Transport.Path != "" {
			v += ";path=" + n.Transport.Path
		}
		if host := n.Transport.Host; host != "" {
			v += ";host=" + host
		}
		if n.TLS != nil && n.TLS.Enabled {
			v += ";tls"
		}
		return v
	}
	return ""
}
