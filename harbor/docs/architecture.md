# Architecture and acceptance criteria

## Product direction

A quiet, native desktop utility: readable tables, useful detail panels, restrained color, explicit state. Simplified Chinese interface. No invented activity, decorative scores, or prefilled production metrics.

## Processes

1. `Harbor.exe`: WPF UI; single-instance gate; encrypted configuration; starts/stops engine and guardian.
2. `harbor-engine.exe`: owns loopback listeners, immutable routing generations, transport sessions, DNS, telemetry and optional Wintun session.
3. `Harbor.exe --guard`: independent process which waits for the UI and engine, restores an owned system-proxy lease after either exits, and records the outcome.

The engine's stdin/stdout is newline-delimited JSON with request IDs. Stdout contains protocol messages only. Stdin closure cancels the engine. No externally reachable administrative API.

The optional `routingMode` configuration field defaults to `rules` for existing workspaces. A local domain block is evaluated first, then enabled domain/process `directExceptions`. An exception requests `DIRECT`; otherwise the mode is evaluated. In rules mode, the first matching enabled rule or `finalPolicy` chooses a policy. In `global` mode, `finalPolicy` chooses it. In `direct` mode, the policy is `DIRECT`. Group selection and transport privacy rejection follow. Non-rule modes retain and validate the saved rules and references. The snapshot exposes the active mode.

Windows process exceptions use read-only endpoint ownership tables and limited image queries. TCP uses a full connection tuple; UDP uses the datagram binding, refusing conflicting owners. Source context comes from accepted sockets or packet endpoints, never from an asserted process name in proxy input. Four bounded blocking jobs serve new flows with a 250 ms caller deadline; timed-out work holds its permit until completion. There is no PID or executable cache. Missing ownership uses the existing mode. See [direct exceptions](direct-exceptions.md) for precise bounds, capture limitations and tests.

Mode changes use the existing immutable configuration generations. New TCP connections and new UDP destination sessions use the new generation; existing flows keep theirs. Desktop selections are synchronized with the saved profile, and a persistence failure rolls runtime routing back before returning an error. Direct-mode startup skips DNS preflight for the unused default proxy. Explicit proxy checks remain independent of routing mode, so mode selection does not invalidate their saved results.

Desktop start/stop transitions suspend status polling and advance a connection revision. Polls discard replies or errors from an earlier revision, including a delayed stopped reply arriving after a reconnect. An unexpected stopped state goes through the same UI action lock as an explicit disconnect.

HTTPS verification and startup preflight share two bounded job slots with explicit probes. `cancel_verification` accepts a `requestId` and cancels only that verification/preflight job. Stop cancels all verification jobs. Job registrations and slots are released on completion or abort; existing forwarded streams belong to the engine and are unaffected by verification cancellation.

The desktop captures the filtered proxy list and configuration at batch start and schedules at most two requests. It compares each proxy's configuration fingerprint before scheduling and before saving. A changed proxy or DNS/privacy context cannot inherit an older result. Cancellation waits for the engine's final replies before a new batch or startup preflight uses those slots. Sorting considers only recent successful HTTPS results and never changes the selected outbound automatically.

Subscription downloads have a separate cancellation token and leave connection controls available. After download, the desktop checks that the source subscription still matches, prepares a diff against the current profile, and holds the configuration lock through modal review and atomic apply. Empty feeds cannot erase proxies. Retained reference targets stay under subscription ownership. Failed persistence restores the previous runtime configuration.

Provider usage is optional metadata in the encrypted subscription record. Header parsing is bounded and rejects ambiguous or invalid counters; missing totals or expiry remain unknown. HTTP 304 responses preserve previously supplied usage when no new header is present, including its original observation time. Identical bodies can refresh usage and validators without configuring the engine.

Workspace writes record their predecessor in `workspace-history.dat`, a separate CurrentUser DPAPI file with a versioned envelope and at most ten snapshots. The complete history file is atomically replaced before the workspace. A history write failure aborts the workspace change; the desktop rolls back an already configured runtime. A workspace replacement failure can leave a duplicate of the current configuration in history, which is reused on retry. No cleanup operation after workspace commit can make a successful save appear to fail. Encrypted workspace and history files are bounded to 4 MiB and 64 MiB respectively.

History equality includes the profile and subscription identity, address, name, and owned proxies. It ignores fetch timestamps, validators, body digests, unsupported counts, and provider usage, so unchanged-feed refreshes still persist without adding snapshots. Desktop preferences, proxy-recovery journals, connection telemetry, and HTTPS check records are outside configuration history.

The history dialog captures the current and selected configuration for review. Restoring acquires the desktop action lock, requires a stopped engine, reloads the selected revision, and rejects a changed current or selected configuration. It cancels pending subscription and verification work, validates the candidate through the engine, then uses the normal workspace save path. The predecessor is retained for undo. Subscription ETag, Last-Modified, digest, and usage fields are cleared so historical proxies cannot inherit a stale conditional-fetch result. No feed is downloaded or connection started by restoration. Clearing history deletes only its single known file and works even if it cannot be decrypted.

## Reliability contracts

The TCP transport delegates to a shared dialer which polls A/AAAA resolution alongside caller-owned TCP attempts. It interleaves available families, reserves capacity for a late second family, and drops losing attempts before returning the connected socket. DNS work sharing also belongs to callers: cancelling an owner lets a surviving follower restart the query, and cancelling every caller leaves no detached network task. Configuration epochs isolate DNS caches and query groups. [Connection quality](connection-quality.md) documents scheduling, limits, counters, and the fault fixtures.

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

The UI uses custom WindowChrome, a consistent scroll theme, measured traffic timestamps and an offline adapter inventory. The network page is an inventory; process direct exceptions are configured separately in routing and do not implement a full-device firewall.
