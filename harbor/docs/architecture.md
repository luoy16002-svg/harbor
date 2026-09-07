# Architecture and acceptance criteria

## Product direction

A quiet, native desktop utility: readable tables, useful detail panels, restrained color, explicit state. Simplified Chinese interface. No invented activity, decorative scores, or prefilled production metrics.

## Processes

1. `Harbor.exe`: WPF UI; single-instance gate; encrypted configuration; starts/stops engine and guardian.
2. `harbor-engine.exe`: owns loopback listeners, immutable routing generations, transport sessions, DNS, telemetry and optional Wintun session.
3. `Harbor.exe --guard`: independent process which waits for the UI and engine, restores an owned system-proxy lease after either exits, and records the outcome.

The engine's stdin/stdout is newline-delimited JSON with request IDs. Stdout contains protocol messages only. Stdin closure cancels the engine. No externally reachable administrative API.

## Reliability contracts

- Bind and verify listeners before enabling a system proxy.
- Write and flush a recovery journal before mutating Windows settings. Establish guardian readiness first.
- Restore settings before listener shutdown. Keep the journal until restoration is verified or a conflicting external change is explicitly recorded.
- Compare the complete applied proxy configuration before restoring. A competing application's edits must not be overwritten.
- Never change physical-interface DNS. TUN uses only its own temporary adapter. Default-route changes use ActiveStore and belong to that adapter.
- Bind upstream sockets to a physical interface by default to prevent loops through existing tunnels. System routing is an explicit option. Re-evaluate on network changes without reassigning established TCP streams.
- Bound handshake time, active connections, telemetry history, DNS cache, packet buffers and command sizes.
- Node health uses consecutive failures, recovery evidence and a hold-down period. Selection is sticky, not an instantaneous minimum-latency contest.

## Acceptance evidence

- Real loopback HTTP, CONNECT, SOCKS5 TCP and UDP flows, plus authenticated upstream protocol fixtures.
- Policy match explanations, atomic invalid-config rejection and preservation of established streams during updates.
- Hysteresis under alternating latency/failure sequences; no direct leakage on failed proxy policy.
- Cancellation, half-close, large payloads, parallel load, malformed handshakes and bounded shutdown.
- Recovery ownership, partially applied changes, normal shutdown, UI death, engine death and restart with an old journal.
- Wintun data path tested first using in-memory packets; live adapter testing must be identified separately from simulated-stack evidence.
- Build a self-contained Windows package and inspect the actual desktop at different sizes.

## Deliberate exclusions

TLS interception, arbitrary JavaScript execution, proprietary Snell compatibility and kernel-driver development are not prerequisites for this product. Unsupported protocol/configuration fields must produce a useful error instead of pretending to work.

## Isolation, privacy and change rehearsal

`--isolated DATA_DIRECTORY` uses a separate encrypted workspace and irreversibly disables system-proxy writes for that desktop process. Recovery skips journals in this mode. The child engine receives `--isolated` and rejects native TUN startup/validation before side effects. New workspaces default to system proxy mode, but opening the app does not connect. A read-only coexistence preflight guards normal-mode capture.

Each immutable runtime configuration carries a compiled domain filter. Network-affecting privacy changes require a stop; metadata visibility and retention can change live. DNS filtering checks questions before upstream traffic and reachable CNAME answers before caching/delivery. Retention and metadata hiding apply to telemetry, not the actual information needed in active forwarding sessions.

The rehearsal IPC validates two candidate configurations and compares target decisions using fresh selectors, without DNS, health probes or listeners. Its response explicitly reports `offline`, `networkRequests: 0` and `healthMeasured: false`. The UI's candidate editor exposes routing/privacy fields without exposing node credentials.

The UI uses custom WindowChrome, a consistent scroll theme, measured traffic timestamps and an offline adapter inventory. No process-aware routing or full-device firewall is implied by the network page.
