package share

import (
	"fmt"
	"strings"

	"veil/internal/config"
)

// parseTrojan parses trojan://password@host:port?params#tag.
// The password is percent-decoded; trojan always runs over TLS, so TLS is
// enabled even when the link omits tls=1 (trojan-go links often do).
func parseTrojan(body, raw string) (config.Node, error) {
	body, frag := splitFragment(body)
	body, rawQuery := splitQuery(body)
	q := parseQuery(rawQuery)

	userinfo, hostport, err := splitUserInfo(body)
	if err != nil {
		return config.Node{}, fmt.Errorf("share: trojan: %w", err)
	}
	server, port, err := splitHostPort(hostport)
	if err != nil {
		return config.Node{}, fmt.Errorf("share: trojan: %w", err)
	}
	password := percentDecode(userinfo)
	if password == "" {
		return config.Node{}, fmt.Errorf("share: trojan: missing password")
	}

	n := config.Node{
		Type:     "trojan",
		Server:   server,
		Port:     port,
		Password: password,
	}

	t := ensureTLS(&n)
	t.Enabled = true
	if sni := qget(q, "sni", "peer", "servername"); sni != "" {
		t.ServerName = sni
	}
	t.Insecure = truthy(qget(q, "allowInsecure", "insecure", "skipVerify", "allow_insecure"))
	if fp := qget(q, "fp", "fingerprint"); fp != "" {
		t.Fingerprint = fp
	}
	if alpn := qget(q, "alpn"); alpn != "" {
		for _, a := range strings.Split(alpn, ",") {
			if a = strings.TrimSpace(a); a != "" {
				t.ALPN = append(t.ALPN, a)
			}
		}
	}

	tr := ensureTransport(&n, normalizeNetwork(qget(q, "type", "network")))
	tr.Type = normalizeNetwork(qget(q, "type", "network"))
	switch tr.Type {
	case "ws":
		tr.Path = qget(q, "path", "wspath")
		if host := qget(q, "host", "ws-host"); host != "" {
			tr.Host = host
			if tr.Headers == nil {
				tr.Headers = map[string]string{}
			}
			tr.Headers["Host"] = host
		}
	case "grpc":
		tr.ServiceName = qget(q, "serviceName", "service_name", "path")
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
	}

	n.Remark = frag
	if n.Remark == "" {
		n.Remark = NormalizeTag(qget(q, "remark", "remarks"))
	}
	return n, nil
}
