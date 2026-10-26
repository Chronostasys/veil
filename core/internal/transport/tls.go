package transport

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"

	"veil/internal/config"
)

// alpnPlain is the ALPN advertisement used for a plain TLS carrier. It matches
// what browsers offer so that a TLS-with-fingerprint stream looks like a normal
// HTTPS connection. WebSocket needs "http/1.1" and gRPC needs "h2"; callers
// (see Build) override the list for those transports.
var alpnPlain = []string{"h2", "http/1.1"}

// Fingerprint names accepted by TLS and Reality. The empty name maps to Chrome
// (Xray's default) so a configuration without a fingerprint still produces a
// browser-shaped ClientHello.
const (
	FingerprintChrome     = "chrome"
	FingerprintFirefox    = "firefox"
	FingerprintSafari     = "safari"
	FingerprintIOS        = "ios"
	FingerprintAndroid    = "android"
	FingerprintEdge       = "edge"
	FingerprintRandomized = "randomized"
)

// fingerprintIDs resolves a fingerprint name to a uTLS ClientHelloID. Unknown
// names are an error rather than a silent fallback: a typo in a node must be
// visible, not turn into "chrome".
func fingerprintIDs(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", FingerprintChrome, "hellochrome":
		return utls.HelloChrome_Auto, nil
	case FingerprintFirefox, "hellofirefox":
		return utls.HelloFirefox_Auto, nil
	case FingerprintSafari, "hellosafari":
		return utls.HelloSafari_Auto, nil
	case FingerprintIOS, "helloios":
		return utls.HelloIOS_Auto, nil
	case FingerprintAndroid, "helloandroid":
		return utls.HelloAndroid_11_OkHttp, nil
	case FingerprintEdge, "helloedge":
		return utls.HelloEdge_Auto, nil
	case FingerprintRandomized, "random", "hellorandomized":
		return utls.HelloRandomizedALPN, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("transport: unknown tls fingerprint %q", name)
	}
}

// clientHelloSpec builds a fresh ClientHello template for id with the given
// ALPN list and SNI. It is called once per connection so that randomized
// fingerprints actually differ per dial and so that no mutable extension state
// is shared between concurrent handshakes.
//
// ServerName is patched into the SNI extension here: with HelloCustom +
// ApplyPreset, utls.Config.ServerName alone does not make it into the
// ClientHello, and REALITY servers reject a hello without SNI.
func clientHelloSpec(id utls.ClientHelloID, alpn []string, serverName string) (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, fmt.Errorf("transport: build client hello for %q: %w", id.Client, err)
	}
	setALPN(&spec, alpn)
	setSNI(&spec, serverName)
	return &spec, nil
}

// setSNI overrides the SNI extension in spec.
func setSNI(spec *utls.ClientHelloSpec, serverName string) {
	if serverName == "" {
		return
	}
	for _, ext := range spec.Extensions {
		if e, ok := ext.(*utls.SNIExtension); ok {
			e.ServerName = serverName
			return
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.SNIExtension{ServerName: serverName})
}

// setALPN replaces (or inserts) the ALPN extension in spec.
func setALPN(spec *utls.ClientHelloSpec, alpn []string) {
	if len(alpn) == 0 {
		return
	}
	for _, ext := range spec.Extensions {
		if e, ok := ext.(*utls.ALPNExtension); ok {
			e.AlpnProtocols = append([]string(nil), alpn...)
			return
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: append([]string(nil), alpn...)})
}

// utlsConfig converts a config.TLS into a uTLS client configuration.
func utlsConfig(cfg *config.TLS, serverName string) *utls.Config {
	return &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: cfg.Insecure,
		// A proxy client never resumes a session: every dial is a fresh
		// handshake, which keeps the fingerprint identical to a first visit.
		SessionTicketsDisabled: true,
	}
}

// tlsDialer performs a uTLS handshake over the stream produced by base.
type tlsDialer struct {
	base        Dialer
	id          utls.ClientHelloID
	cfg         *utls.Config
	alpn        []string
	fingerprint string
}

// TLS returns a Dialer that wraps base with a uTLS handshake using the
// configured browser fingerprint. ALPN defaults to h2,http/1.1 when the
// configuration does not name protocols.
func TLS(base Dialer, cfg *config.TLS) (Dialer, error) {
	if base == nil {
		return nil, errors.New("transport: tls needs a base dialer")
	}
	if cfg == nil {
		return nil, errors.New("transport: tls needs a configuration")
	}
	id, err := fingerprintIDs(cfg.Fingerprint)
	if err != nil {
		return nil, err
	}
	alpn := cfg.ALPN
	if len(alpn) == 0 {
		alpn = alpnPlain
	}
	return &tlsDialer{
		base:        base,
		id:          id,
		cfg:         utlsConfig(cfg, cfg.ServerName),
		alpn:        append([]string(nil), alpn...),
		fingerprint: cfg.Fingerprint,
	}, nil
}

// Dial implements Dialer.
func (d *tlsDialer) Dial(ctx context.Context) (net.Conn, error) {
	raw, err := d.base.Dial(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := d.handshake(ctx, raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// handshake upgrades raw to TLS using a freshly built ClientHello template.
func (d *tlsDialer) handshake(ctx context.Context, raw net.Conn) (*utls.UConn, error) {
	spec, err := clientHelloSpec(d.id, d.alpn, d.cfg.ServerName)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(raw, d.cfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("transport: apply %s client hello: %w", d.fingerprintName(), err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("transport: tls handshake (%s): %w", d.fingerprintName(), err)
	}
	return uconn, nil
}

func (d *tlsDialer) fingerprintName() string {
	if d.fingerprint == "" {
		return FingerprintChrome
	}
	return d.fingerprint
}

// verifyHostname is the manual hostname check used when the handshake was done
// with InsecureSkipVerify (REALITY always is). It mirrors crypto/tls.
func verifyHostname(rawCerts [][]byte, serverName string, intermediates [][]byte) error {
	certs, err := parseCertificates(rawCerts)
	if err != nil {
		return err
	}
	opts := x509.VerifyOptions{DNSName: serverName, Intermediates: x509.NewCertPool()}
	for _, der := range intermediates {
		if c, err := x509.ParseCertificate(der); err == nil {
			opts.Intermediates.AddCert(c)
		}
	}
	_, err = certs[0].Verify(opts)
	return err
}

// parseCertificates decodes raw certificate DER blobs. It returns at least one
// certificate or an error.
func parseCertificates(rawCerts [][]byte) ([]*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, errors.New("transport: peer presented no certificates")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, der := range rawCerts {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("transport: parse peer certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}
