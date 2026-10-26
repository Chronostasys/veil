# AGENTS.md — Veil

HarmonyOS NEXT (API 26 / HarmonyOS 7) proxy client. ArkTS UI + Go core loaded
through NAPI as a C shared library. Read `docs/DESIGN.md` and
`docs/PROTOCOLS.md` before changing anything.

## Layout

| Path | Rule |
| --- | --- |
| `core/internal/config` | frozen JSON schema; every other package depends on it |
| `core/internal/state`, `rpc` | frozen status/RPC shapes; the ArkTS `model/Types.ets` mirrors them |
| `core/internal/transport` | only place that creates sockets; always via `TCP`/`NewDialer` so fd protection applies |
| `core/internal/proxy/*` | one package per protocol; must implement `outbound.Outbound` (+ `PacketOutbound` when UDP works) |
| `core/internal/engine` | routing, groups, relay, stats, connection registry |
| `core/internal/supervisor` | lifecycle, watchdog, RPC dispatch — the only owner of the engine |
| `core/internal/netstack` | gVisor stack over the tun fd |
| `core/bridge` | c-shared entry points (`VeilStart`, `VeilCall`, `VeilShutdown`) |
| `entry/src/main/ets` | ArkUI; `core/LocalRpc.ets` is the socket protocol, `vpn/VeilVpnAbility.ets` is the RPC host |

## Invariants (do not break)

1. **No socket may bypass `transport.TCP`/`transport.NewDialer`.** On HarmonyOS
   every engine socket must be passed to `VpnConnection.protect(fd)` first, or
   traffic loops into the tun and the whole device loses connectivity.
2. **Status is measured.** `state.Phase` only changes in `supervisor` and always
   carries a reason. Never add a cached "connected" boolean the UI can read.
3. **Lifecycle ops are serialized** by `Supervisor.opMu`. The watchdog uses
   `TryLock` so it can never deadlock a user-initiated stop.
4. **Long-lived contexts are detached** from the RPC context
   (`context.WithoutCancel`); an RPC timeout must not kill the tunnel.
5. **Every connection is registered** in `engine.Registry` (capped), closed on
   either side, and counted. Soak test must stay green.
6. **Protocol wire formats are matched to the reference**, not approximated.
   `core/internal/proxy/vless/vision.go` and `transport/reality.go` carry the
   exact derivations; changes there need an interop test.
7. **Idle means zero wakeups.** No periodic ticker may run while the tunnel is
   idle: stats rates are computed lazily in `Snapshot`, the tun pump blocks in
   `poll(-1)`, UDP sessions are swept on creation, watchdog/heartbeat tick at
   5s, and the `alive` log line prints at most once a minute (or on change).
   Adding a `time.Ticker` to the steady-state path is a battery regression.
8. **io.Reader must never block to fill `p`.** Vision framing and TLS-in-TLS
   deadlock if a read waits for the next frame while the peer waits for our
   TLS Finished; `visionReader.Read` returns as soon as it has bytes. Same rule
   for the post-Direct raw switch: drain bufio → utls `input` → utls `rawInput`
   → raw TCP, in that order.

## Build & test

```bash
cd core && GOTOOLCHAIN=go1.27.3 go test ./... -count=1
cd core && GOTOOLCHAIN=go1.27.3 go vet ./...
scripts/build-core.sh         # entry/libs/arm64-v8a/libveilcore.so
hvigorw --mode module -p module=entry@default assembleHap --no-daemon
```

Required env for hvigorw: `DEVECO_SDK_HOME`, `JAVA_HOME` (DevEco jbr) and
`NODE_HOME` (DevEco node).

## Known traps

- `utls.HelloCustom` + `ApplyPreset` does **not** apply `utls.Config.ServerName`;
  patch `*utls.SNI` in the spec (see `transport/tls.go`).
- REALITY client: put the **zeroed** session id into `hello.Raw` before sealing;
  copy the ciphertext in afterwards (AAD = ClientHello with zeros).
- `reality.Server` (used only in tests) needs
  `reality.DetectPostHandshakeRecordsLens(cfg)` and a real TLS `Dest`.
- hvigor only packages prebuilt natives from `<module>/libs/<abi>/`.
- `entry/src/main/resources/base/element/color.json` and `theme/Theme.ets` hold
  the same palette for Canvas; keep them in sync.
- Packaging a HAP needs `DEVECO_SDK_HOME` **and** `JAVA_HOME` pointing at
  DevEco's bundled jbr; otherwise `PackageHap` fails with 00308018 ("Unable to
  locate a Java Runtime").
- When USB hdc drops, install over the wireless target:
  `hdc -t 127.0.0.1:5555 install -r entry/build/default/outputs/default/*signed.hap`.
  Always `aa force-stop org.bobli.veil` afterwards, or the old `.so` stays loaded.
- The desktop card (`ets/form/VeilCard*`) is a separate process
  (`org.bobli.veil:form`) that connects to `filesDir/veil.sock` on demand only.
  Never add timers/polling to it — the system refreshes it (min 30 min) and card
  taps raise `onFormEvent`.
- **Status() must stay truthful with no engine.** When `eng == nil` the
  supervisor used to leave `Mode` at its zero value, so the UI showed an empty
  mode (no chip highlighted) and every "switch mode" looked like a no-op. Always
  fall back to `s.cfg.Mode` / `s.Groups()` when the engine is down.
- **`Select` must persist implicit groups.** Configs that list only `nodes`
  have no explicit `groups`; the UI shows an implicit `proxy` group. Selecting a
  member used to be dropped silently while the tunnel was down. Create the group
  entry on first select so the choice survives to the next Start().
- **VPN tun state must be process-wide, not per-ability-instance.** The
  extension can be instantiated more than once per process (card-started vs
  app-started); `conn`/`tunFd` used to be instance fields, so `protect` landed on
  an instance without a connection and every outbound dial failed with
  "尚未建立 tun 连接，无法 protect fd". Keep them in module-level variables and
  lazily create the VpnConnection in `protect`.
- **Never reuse a tun fd after `Engine.Stop`/`DetachTun`** — they close it. A
  watchdog restart must `tun_down` the host and `tun_up` a fresh fd, otherwise
  the engine reports `tun=true` while the descriptor is dead and the host holds
  a stale VpnConnection.
