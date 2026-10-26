package share

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"veil/internal/config"
)

// parseVLESS parses both the modern form
//
//	vless://<uuid>@<host>:<port>?type=ws&security=reality&pbk=...&sid=...#tag
//
// and the legacy form where the authority is base64-encoded:
//
//	vless://<b64(encryption:uuid@host:port)>?obfs=&tls=1&peer=&xtls=2&pbk=&sid=
//
// In the legacy form the query may sit inside or outside the encoded payload;
// the outer query wins on conflicts.
func parseVLESS(body, raw string) (config.Node, error) {
	body, frag := splitFragment(body)
	body, rawQuery := splitQuery(body)
	q := parseQuery(rawQuery)

	authority := body
	// Legacy: the authority is not directly readable, so try base64 first.
	if !strings.Contains(body, "@") {
		decoded := b64Text(body)
		if decoded == "" {
			return config.Node{}, fmt.Errorf("share: vless: cannot decode authority")
		}
		decoded, innerQuery := splitQuery(decoded)
		// Outer query takes precedence: merge inner values only for new keys.
		for k, vv := range parseQuery(innerQuery) {
			if _, exists := q[k]; !exists {
				q[k] = vv
			}
		}
		authority = decoded
	}

	userinfo, hostport, err := splitUserInfo(authority)
	if err != nil {
		return config.Node{}, fmt.Errorf("share: vless: %w", err)
	}
	server, port, err := splitHostPort(hostport)
	if err != nil {
		return config.Node{}, fmt.Errorf("share: vless: %w", err)
	}

	n := config.Node{
		Type:   "vless",
		Server: server,
		Port:   port,
		UUID:   extractUUID(userinfo),
	}
	if err := validateUUID(n.UUID); err != nil {
		return config.Node{}, err
	}

	applyVLESSQuery(&n, q)
	if frag != "" {
		n.Remark = frag
	}
	if n.Remark == "" {
		n.Remark = qget(q, "remark", "remarks", "remarks", "ps")
	}
	return n, nil
}

// extractUUID picks the UUID out of "uuid", "encryption:uuid" or
// "auto:uuid" style userinfo. Falls back to the last colon-separated token.
func extractUUID(userinfo string) string {
	userinfo = strings.TrimSpace(userinfo)
	if isValidUUID(userinfo) {
		return userinfo
	}
	parts := strings.Split(userinfo, ":")
	for _, p := range parts {
		if isValidUUID(p) {
			return p
		}
	}
	// Some links carry extra parameters in userinfo, e.g. "uuid:ext".
	if len(parts) > 0 {
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return ""
}

// applyVLESSQuery maps vless query parameters onto n (shared by vless/vmess
// legacy dialects that use the same key names).
func applyVLESSQuery(n *config.Node, q url.Values) {
	network := strings.ToLower(qget(q, "type", "network", "obfs-type"))
	transportType := normalizeNetwork(network)

	security := strings.ToLower(qget(q, "security", "encryption-security"))
	tlsOn := truthy(qget(q, "tls", "tlsEnabled"))
	if security == "tls" || security == "reality" || security == "xtls" {
		tlsOn = true
	}
	pbk := qget(q, "pbk", "publicKey", "public-key")
	if pbk != "" {
		tlsOn = true
	}

	if tlsOn {
		t := ensureTLS(n)
		t.Enabled = true
		if sni := qget(q, "sni", "peer", "servername", "serverName", "host-tls"); sni != "" {
			t.ServerName = sni
		}
		if fp := qget(q, "fp", "fingerprint"); fp != "" {
			t.Fingerprint = fp
		}
		if truthy(qget(q, "allowInsecure", "insecure", "skipVerify", "allow_insecure")) {
			t.Insecure = true
		}
		if alpn := qget(q, "alpn"); alpn != "" {
			for _, a := range strings.Split(alpn, ",") {
				if a = strings.TrimSpace(a); a != "" {
					t.ALPN = append(t.ALPN, a)
				}
			}
		}
		if pbk != "" {
			re := &config.Reality{PublicKey: pbk}
			re.ShortID = qget(q, "sid", "shortId", "short-id")
			re.SpiderX = qget(q, "spx", "spiderX", "spider-x")
			t.Reality = re
			if t.Fingerprint == "" {
				t.Fingerprint = "chrome"
			}
		}
	}

	// Flow: explicit flow= wins, legacy xtls=2 means vision.
	if flow := qget(q, "flow"); flow != "" {
		n.Flow = flow
	} else if qget(q, "xtls") == "2" {
		n.Flow = "xtls-rprx-vision"
	}

	tr := ensureTransport(n, transportType)
	if t := qget(q, "type", "network", "obfs-type"); t != "" {
		tr.Type = normalizeNetwork(t)
	}

	switch tr.Type {
	case "ws":
		tr.Path = qget(q, "path", "wspath", "ws-path")
		if host := qget(q, "host", "obfsParam", "ws-host"); host != "" {
			tr.Host = host
			if tr.Headers == nil {
				tr.Headers = map[string]string{}
			}
			tr.Headers["Host"] = host
		}
		if ed := qget(q, "ed", "eh", "earlyData", "early-data"); ed != "" {
			if v, err := strconv.Atoi(ed); err == nil {
				tr.EarlyData = v
			}
		}
	case "grpc":
		tr.ServiceName = qget(q, "serviceName", "service_name", "grpc-service-name", "path")
		tr.Path = ""
	case "h2":
		tr.Path = qget(q, "path")
		if host := qget(q, "host"); host != "" {
			tr.Host = host
			if tr.Headers == nil {
				tr.Headers = map[string]string{}
			}
			tr.Headers["Host"] = host
		}
	default:
		// tcp: no transport-specific fields.
	}
}

// normalizeNetwork maps subscription network names onto config.Transport types.
func normalizeNetwork(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "tcp", "raw", "none", "original":
		return "tcp"
	case "ws", "websocket":
		return "ws"
	case "grpc", "gun":
		return "grpc"
	case "h2", "http", "http2":
		return "h2"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}
