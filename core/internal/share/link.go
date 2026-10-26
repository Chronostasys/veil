// Package share parses and formats proxy share links (vless, vmess, trojan,
// shadowsocks, hysteria2), subscription bodies and Clash proxy lists into
// config.Node values, and renders config.Node values back to share links.
//
// The parsers are deliberately forgiving: real-world subscriptions are full of
// hand-edited links, markdown-mangled URLs and non-canonical base64. A parser
// here never panics; malformed input yields an error.
package share

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"veil/internal/config"
)

// ErrEmpty is returned when a link is empty or only whitespace/comments.
var ErrEmpty = errors.New("share: empty link")

// ErrUnknownScheme is returned for unrecognised URI schemes.
var ErrUnknownScheme = errors.New("share: unknown scheme")

var (
	// mdLink matches markdown links such as [www.icloud.com](http://www.icloud.com).
	mdLinkRe = regexp.MustCompile(`\[([^\[\]]*)\]\((?:[^()\n]*)\)`)
	uuidRe   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// NormalizeTag cleans a human readable tag/remark: markdown links are reduced
// to their label, control characters dropped, surrounding and repeated
// whitespace collapsed.
func NormalizeTag(s string) string {
	s = normalizeMarkdown(s)
	s = percentDecode(s)
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	s = strings.TrimSpace(b.String())
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// Parse parses one share link into a config.Node. The returned node has Type,
// Server, Port and credentials populated; Tag is empty so the caller can apply
// de-duplication and subscription tagging.
func Parse(uri string) (config.Node, error) {
	raw := normalizeMarkdown(strings.TrimSpace(uri))
	if raw == "" {
		return config.Node{}, ErrEmpty
	}
	i := strings.Index(raw, "://")
	if i <= 0 {
		return config.Node{}, fmt.Errorf("%w: %q", ErrUnknownScheme, truncate(raw, 32))
	}
	scheme := strings.ToLower(raw[:i])
	body := raw[i+3:]

	switch scheme {
	case "vless":
		return parseVLESS(body, raw)
	case "vmess":
		return parseVMess(body)
	case "trojan", "trojan-go":
		return parseTrojan(body, raw)
	case "ss":
		return parseSS(body, raw)
	case "hysteria2", "hy2":
		return parseHysteria2(body, raw)
	default:
		return config.Node{}, fmt.Errorf("%w: %q", ErrUnknownScheme, scheme)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// normalizeMarkdown rewrites every markdown link to just its label. This is
// applied to the whole URI before parsing because subscriptions rendered by
// chat clients glue markdown into query values.
func normalizeMarkdown(s string) string {
	if !strings.Contains(s, "](") {
		return s
	}
	return mdLinkRe.ReplaceAllString(s, "$1")
}

// percentDecode decodes %XX escapes; on malformed input it returns s unchanged
// (plus-decoding is applied as a fallback since some generators use it).
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if out, err := url.PathUnescape(s); err == nil {
		return out
	}
	if out, err := url.QueryUnescape(s); err == nil {
		return out
	}
	return s
}

// decodeBase64 decodes raw, standard or URL-safe base64, with or without
// padding, ignoring embedded whitespace and newlines.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', ' ':
			return -1
		}
		return r
	}, s)
	if s == "" {
		return nil, errors.New("share: empty base64 payload")
	}
	// Normalise URL-safe alphabet and padding, then try both alphabets.
	norm := strings.NewReplacer("-", "+", "_", "/").Replace(s)
	norm = strings.TrimRight(norm, "=")
	if pad := len(norm) % 4; pad != 0 {
		if pad == 1 {
			return nil, errors.New("share: invalid base64 length")
		}
		norm += strings.Repeat("=", 4-pad)
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(norm); err == nil {
			return b, nil
		}
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("share: invalid base64 payload")
}

// b64Text decodes s and returns it as a string, or "" when undecodable.
func b64Text(s string) string {
	b, err := decodeBase64(s)
	if err != nil {
		return ""
	}
	return string(b)
}

// parseQuery parses a query string tolerantly: a bad escape never fails the
// whole link, the raw value is kept instead.
func parseQuery(raw string) url.Values {
	raw = strings.TrimPrefix(raw, "?")
	q := url.Values{}
	if raw == "" {
		return q
	}
	for _, pair := range strings.FieldsFunc(raw, func(r rune) bool { return r == '&' || r == ';' }) {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		k = percentDecode(k)
		if k == "" {
			continue
		}
		if _, dup := q[k]; !dup {
			q.Set(k, percentDecode(v))
		}
	}
	return q
}

// qget returns the first non-empty value among keys (case-insensitive).
func qget(q url.Values, keys ...string) string {
	for _, k := range keys {
		for qk, vv := range q {
			if strings.EqualFold(qk, k) && len(vv) > 0 && vv[0] != "" {
				return vv[0]
			}
		}
	}
	return ""
}

// truthy interprets boolean-ish query values.
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on", "t", "y":
		return true
	}
	return false
}

// isValidUUID reports whether s is a canonical 8-4-4-4-12 hex UUID.
func isValidUUID(s string) bool { return uuidRe.MatchString(strings.TrimSpace(s)) }

// validateUUID returns an error when s is not a valid UUID. Empty input is
// rejected as well, since every vless/vmess node needs a credential.
func validateUUID(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("share: missing uuid")
	}
	if !isValidUUID(s) {
		return fmt.Errorf("share: invalid uuid %q", s)
	}
	return nil
}

// splitHostPort splits "host:port", "host" (port 0) and "[v6]:port" forms.
func splitHostPort(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "/")
	if s == "" {
		return "", 0, errors.New("share: missing host")
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		// No port present (or bare IPv6/host): fall through to the checks below.
		switch {
		case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
			host, portStr = strings.Trim(s, "[]"), ""
		case strings.LastIndex(s, ":") > 0 && !strings.Contains(s[:strings.LastIndex(s, ":")], ":"):
			i := strings.LastIndex(s, ":")
			host, portStr = s[:i], s[i+1:]
		default:
			host, portStr = s, ""
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", 0, errors.New("share: missing host")
	}
	port := 0
	if portStr != "" {
		p, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil {
			return "", 0, fmt.Errorf("share: invalid port %q", portStr)
		}
		if p < 1 || p > 65535 {
			return "", 0, fmt.Errorf("share: port %d out of range", p)
		}
		port = p
	}
	if port == 0 {
		return "", 0, fmt.Errorf("share: missing port for host %q", host)
	}
	return host, port, nil
}

// splitUserInfo separates "userinfo@hostport" into its two halves.
func splitUserInfo(s string) (string, string, error) {
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return "", "", errors.New("share: missing userinfo@host")
	}
	return s[:at], s[at+1:], nil
}

// ensureTLS returns a non-nil TLS block with enabled set.
func ensureTLS(n *config.Node) *config.TLS {
	if n.TLS == nil {
		n.TLS = &config.TLS{}
	}
	return n.TLS
}

// ensureTransport returns a non-nil transport of typ (keeping existing fields).
func ensureTransport(n *config.Node, typ string) *config.Transport {
	if typ == "" {
		typ = "tcp"
	}
	if n.Transport == nil {
		n.Transport = &config.Transport{}
	}
	if n.Transport.Type == "" {
		n.Transport.Type = typ
	}
	return n.Transport
}

// splitFragment splits "body#fragment" returning the decoded fragment.
func splitFragment(s string) (string, string) {
	body, frag, ok := strings.Cut(s, "#")
	if !ok {
		return s, ""
	}
	return body, NormalizeTag(frag)
}

// splitQuery splits "body?query" returning the raw query (no '?').
func splitQuery(s string) (string, string) {
	body, q, ok := strings.Cut(s, "?")
	if !ok {
		return s, ""
	}
	return body, q
}
