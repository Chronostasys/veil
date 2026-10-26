# Veil design notes

## Goals, in order

1. **Never lie about state.** A proxy UI that shows "connected" while the
   tunnel is dead is worse than no UI. Every phase carries the reason it was
   entered, and every health number is measured.
2. **Survive the background.** No unbounded goroutines, no leaked file
   descriptors, no listener that dies silently, no config reload that kills the
   tun.
3. **Modern protocols, exactly.** REALITY, XTLS-Vision, VMess AEAD,
   Shadowsocks 2022, Hysteria2 — implemented against the reference wire format,
   not approximated.

## Process architecture on HarmonyOS

```
┌──────────────────────────────┐        ┌───────────────────────────────────┐
│ UI process                   │        │ VPN extension process             │
│  ArkUI pages                 │        │  VeilVpnAbility                   │
│  CoreClient (Unix socket) ───┼───────▶│   ├─ NAPI → libveil.so (shim)     │
└──────────────────────────────┘        │   │           └─ dlopen libveilcore │
                                        │   ├─ core: supervisor + engine    │
                                        │   ├─ VpnConnection (tun fd,       │
                                        │   │   protect(fd))               │
                                        │   └─ control socket (filesDir)    │
                                        └───────────────────────────────────┘
```

The extension is the only process that owns a tun descriptor, so it is the only
place the core can live. The UI is a thin client: it renders status and issues
RPCs. When the extension is not running the UI says so instead of pretending.

### Control protocol

Line-delimited JSON over `filesDir/veil.sock`:

```
UI    -> core  {"id":7,"method":"status","params":{}}
core  -> UI    {"id":7,"ok":true,"result":{...}}

ext   -> core  {"role":"host"}
core  -> ext   {"host":true,"id":1,"method":"protect","params":{"fd":42}}
ext   -> core  {"id":1,"ok":true}
core  -> ext   {"host":true,"id":2,"method":"tun_up","params":{"mtu":1400}}
ext   -> core  {"id":2,"ok":true,"result":{"fd":37}}
```

The host channel is the only way to reach `VpnConnection.protect`, and every
socket the engine opens must be protected before it connects (otherwise the
traffic loops into the tun). `transport.SetProtector` installs that hook into
`net.Dialer.Control`, so it applies uniformly to TCP, TLS, REALITY, WS and gRPC
without each protocol knowing about HarmonyOS.

## Lifecycle

```
stopped ──start──▶ starting ──ok──▶ running ──failure──▶ degraded ──▶ running
   ▲                  │                 │                                │
   └──────stop────────┴────failed◀──────┴──────────────stop──────────────┘
```

- `starting` fails only when no data path could be built at all.
- `degraded` means the mixed proxy works but the tun (or one listener) does
  not; the reason string is shown verbatim in the UI.
- The watchdog ticks every second. Every 2 s it checks: engine alive, mixed
  listener accepts a real TCP connection, heartbeat age < 10 s. Two consecutive
  failures restart the engine on the *same* tun fd (no VPN flap).
- Restart budget: 5 restarts per 10 minutes, then `failed` with the last error.
  This is deliberately visible instead of silently retrying forever.

## Data path

```
tun (gVisor netstack) ─┐
socks5/http (mixed)  ──┼─▶ engine.HandleTCP ─▶ route ─▶ group ─▶ outbound ─▶ wire
                       └─▶ engine.HandleUDP ─▶ route ─▶ udp association cache
```

Routing resolves a domain only when the rule set contains IP rules; the
outbound still receives the hostname so the exit node does the DNS lookup.

## Resource discipline

- Connections are registered in a capped registry (4096). Each gets a tracked
  byte counter and is closed when either side finishes.
- UDP associations are cached per (outbound, destination) and reaped after 60 s
  idle.
- Config reload swaps outbounds without touching the tun; retired clients are
  closed after a 2 minute grace period so live connections survive.
- The soak test (`core/internal/engine/soak_test.go`) opens thousands of
  connections and asserts that goroutines return to the baseline and that the
  registry is empty.
