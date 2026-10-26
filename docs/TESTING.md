# Testing

Everything below runs on a normal machine (macOS or Linux); nothing needs a
phone except the final HAP install.

```bash
cd core
GOTOOLCHAIN=go1.27.3 go test ./... -count=1          # unit + integration
GOTOOLCHAIN=go1.27.3 go test ./... -race -count=1    # race detector
GOTOOLCHAIN=go1.27.3 go vet ./...
```

## What is actually verified

| Area | Test | What it proves |
| --- | --- | --- |
| Share links | `internal/share/share_test.go` | the two legacy links from the bug report parse field-by-field; modern vless/vmess/trojan/ss/hy2, subscriptions, Clash YAML, `Link()` round-trips |
| REALITY | `internal/transport/*_test.go` + `e2e/e2e_test.go` | a **real handshake against the official `github.com/xtls/reality` server**, including the post-quantum hybrid key share, session-id sealing and certificate HMAC; a wrong `pbk` must fail |
| VLESS | `internal/proxy/vless/*_test.go` | header encode/decode for IPv4/domain/IPv6/UDP, flow addons, end-to-end echo over TCP/WS/REALITY |
| Vision | `internal/proxy/vless/vless_test.go` | framing/padding round-trip against a test server (flow=xtls-rprx-vision) |
| VMess | `internal/proxy/vmess/*_test.go` | KDF/auth-id vectors, AEAD header + chunk stream, e2e echo with a server implementation in the test |
| Trojan | `internal/proxy/trojan/*_test.go` | header golden bytes, UDP framing, e2e |
| Shadowsocks | `internal/proxy/ss/*_test.go` | legacy AEAD + SIP022 (BLAKE3 vectors from the spec), TCP/UDP echo |
| Hysteria2 | `internal/proxy/hysteria2/*_test.go` | local quic-go server: auth endpoint, stream echo, datagram echo, bad password fails |
| Inbounds | `internal/inbound/*_test.go` | SOCKS5 CONNECT/domain/UDP ASSOCIATE, HTTP CONNECT/absolute-form, error codes, race-free close |
| Rules | `internal/rules/compile_test.go` | every rule type, ordering, `evilexample.com` negative case, invalid patterns |
| DNS | `internal/dns/resolver_test.go` | UDP/DoH upstreams, cache hit (upstream query counted), single-flight with 20 concurrent lookups, raw `Exchange`, packet server |
| Netstack | `internal/netstack/netstack_test.go` | crafted IPv4/UDP and TCP SYN packets through the gVisor endpoint: DNS reply arrives, SYN-ACK is correct |
| Engine | `e2e/e2e_test.go` | SOCKS5 client → engine → VLESS/REALITY (official server) → echo; traffic counters; 6 sequential connections |
| Lifecycle | `internal/supervisor/supervisor_test.go` | phase machine, live uptime, idempotent stop/start, RPC shape, unknown-method error |
| **Stability** | `internal/supervisor/supervisor_test.go::TestSoakNoLeaks` | 1440 proxied connections from 24 workers: all echoed, registry drains to 0, goroutines return to baseline (the regression test for "dies after running for a while") |

## Not covered (honest list)

- No live carrier network / real subscription server: latency probes and
  subscription fetch are exercised only against local HTTP servers.
- The VPN extension (`vpnExtension`) cannot run on a desktop: `tun_up`,
  `protect` and the fd hand-off are validated by types + review, not by execution.
  The netstack is tested separately with crafted packets, and the whole svc
  graph is tested with the mixed inbound.
- Wi-Fi/cellular handover behaviour needs a device.
