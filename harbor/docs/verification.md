# Verification

These results apply to the 0.11.0 preview checked on 2026-09-08. They do not establish production readiness or carry over automatically to later builds.

| Check | Result | Scope |
| --- | --- | --- |
| Rust tests | 70 passed | Protocols, routing modes, Windows TCP/UDP ownership and direct exceptions, packets, privacy precedence, encrypted DNS sharing, cancellation, dual-stack scheduling, and adapter selection |
| Desktop checks | 68 passed | Imports, subscriptions, DPAPI, recovery, routing and direct exception parsing/presets, encrypted history, restoration, bounded batch scheduling, and cancellation |
| Independent interop | 49 passed | Xray v26.3.27, TCP/UDP paths, 2 MiB payloads, delayed replies, source-port reuse, and concurrent connections |
| Control interface | 13 passed | Isolation, preflight, stop, atomic configuration changes, targeted cancellation, and routing-mode changes over real TCP/UDP sessions |
| Connection quality | 5 passed | Delayed DNS family, long address lists, concurrent query sharing, path memory and privacy, and first-answer preflight; release-engine comparison with 0.8.0 |
| WPF workflows | 67 passed | Import, search, tray controls, HTTPS batches, subscription updates, mode selectors, direct exception presets/editor, configuration restoration, stale reviews, reconnect polling, and failed-save rollback |
| Layout | Passed | Ten pages, seven dialogs, path cards and a 620-pixel path editor, 1280/980-pixel main windows, a 620-pixel exception editor, a 640-pixel subscription preview, and a 660-pixel history preview |
| Build | Passed | Strict Clippy and desktop compilation without warnings |

Dependency advisory queries returned no findings for the locked dependencies at the time of the check. This is not a security audit.

UI traffic checks used four real SOCKS5 connections to a loopback echo server. Rendered charts show local test traffic, not internet speed.

TCP scheduling tests use virtual time to exercise slow resolution, stalled and failed addresses, delayed alternate families, attempt limits, and caller cancellation. Real local DNS and TCP tests check transaction IDs, query flags, owner handoff, cache generations, CNAME address selection, path memory, and metadata hiding. Separate 64-query UDP and verified DoT bursts each share one upstream question. Five [connection-quality scenarios](connection-quality.md) run against the packaged engine and record its hash; timings describe injected local faults and do not measure internet throughput.

Batch checks used two loopback HTTP CONNECT servers that held their replies until cancellation. Both sockets closed, the third queued proxy was untouched, previous results remained, and the active engine kept running. A separate privacy-blocked batch verified that changing the search field does not expand a batch already in progress. Historical times shown in the batch layout fixtures are synthetic data used to check sorting and retention.

Subscription checks used synthetic provider headers and in-memory HTTP responses. They exercised cancellation while waiting for headers and body bytes, old workspace loading, metadata updates on unchanged content, real preview buttons, empty-feed rejection, and late responses after a source change. A read-only workspace fixture forced persistence to fail after runtime configuration; the original disk bytes, desktop profile, and runtime proxy names were restored. Subscription screenshots contain fixture data, not the user's provider statistics.

Routing checks used isolated listeners and real loopback TCP and UDP echoes. Switching modes changed newly opened flows while established flows continued transferring data with their original generations. Invalid mode values left the running generation unchanged. Desktop checks exercised both mode selectors, direct startup without proxies, unused-proxy preflight, unchanged disk bytes after offline comparison, stale-result clearing after configuration/input changes, overlapping UI actions, and a forced save failure restoring disk, UI, and runtime mode. A delayed stopped reply was injected across an actual stop/start and could not stop or repaint the new session. Privacy blocks stayed effective in all three modes. Mode screenshots show a fixture proxy and offline path results.

Configuration-history checks used isolated DPAPI workspaces. They verified automatic predecessors, ten-version retention, metadata-only updates, write-size bounds, read-only history and workspace failures, corrupt envelopes, legacy storage, private-field previews, and clearing without changing preferences or recovery journals. Real WPF restore and cancel buttons exercised disconnected-only restoration, changed-current and changed-selected review rejection, invalid-policy validation, pending-download cancellation, and restoration of the pre-restore version. Restored feeds cleared validators and usage. Screenshots show synthetic local fixtures; no subscription service was contacted by these checks.

A limited external forwarding check completed HTTPS requests through the release engine's SOCKS5 and HTTP CONNECT listeners. This does not establish compatibility with every proxy, destination, or network.

A separate simultaneous check used the saved global routing configuration with direct exceptions and physical egress. A Bilibili HTTPS HEAD received a 302 response through `DIRECT`, while an example.com HTTPS HEAD received 200 through the selected proxy. Connection records confirmed both paths; the game-domain check was a route explanation only. The saved DoH configuration was used for this check. No Windows proxy, DNS or capture-route settings were changed.

Direct exception checks use real Windows IPv4/IPv6 TCP and UDP endpoint tables, a local direct server, a local SOCKS proxy, and actual SOCKS5, HTTP CONNECT and SOCKS UDP ingress. Matching process traffic goes direct; disabling the exceptions sends new connections through the proxy while old streams keep their generation. Unknown owners retain the global policy, closed UDP bindings are not cached, conflicting owners are refused, and domain/transport privacy restrictions retain precedence. The WPF editor checks idempotent presets, save/cancel, invalid input, encrypted history, disabling and failed-save rollback. See [direct exceptions](direct-exceptions.md) for bounds and capture scope.

Traffic-path checks cover ordered conflicts across all modes, legacy exception precedence, per-transport encrypted group selection, fixed-member rejection and separate sticky state. Real Windows process fixtures route CONNECT, SOCKS TCP and UDP through the new paths with legacy exceptions disabled. Desktop checks cover path-only subscription references, history, fingerprints, real card/editor actions, simulated process previews, node renaming and forced save rollback. See [traffic paths](traffic-paths.md).

An isolated copy of the saved configuration added a protected work-domain path using the selected proxy. The HTTPS request returned 200 and its connection record confirmed that the new path chose a proxy outbound. The original workspace bytes and Windows proxy, DNS and capture routes remained unchanged. This was one target on one connection, not an anonymity or reputation test.

## Not validated

- Live system-proxy writes and real recovery after process failure for this release.
- Native TUN capture, crash cleanup, sleep recovery, network switching, and sustained real-world traffic.
- Multi-VPN compatibility, games, and QUIC under system-wide capture.

TUN packet handling and recovery state machines have isolated tests. Those tests do not replace live network validation.

Harbor has no system-wide kill switch, installer, or automatic updater. Process direct exceptions are best effort for captured traffic; they do not establish live game compatibility. Harbor executables are unsigned; the bundled Wintun driver is signed.

## Run checks

On Windows x64, install Rust 1.95+, .NET SDK 9, and Python 3.11+, then run from `harbor/`:

```powershell
./scripts/build.ps1 -Visual
```

For independent protocol interop, install Python's `cryptography` package and place Xray v26.3.27 at `.cache/reference/xray.exe`. Then add `-Interop`. Xray is a test reference and is not part of Harbor.

The build downloads Wintun 0.14.1 from [the official distribution](https://www.wintun.net/), checks the pinned SHA-256, and verifies Authenticode before packaging.

These build checks use isolated workspaces, loopback listeners, or in-memory packets. Administrator-level TUN validation is a separate manual procedure in `scripts/validate-tun.ps1`.

Binary packages contain test summaries and build hashes in `docs/evidence/`. Raw local configuration, generated keys, and machine-specific network baselines are excluded from source control.

## Protocol caveats

VMess ends a session before its 16-bit payload nonce repeats. Very long sessions may need reconnecting. WebSocket does not provide native TCP half-close semantics.

After one side half-closes, an inactive stream expires after `halfCloseTimeoutSecs` (10 seconds by default). Traffic resets the timer. Applications that wait a long time for a response after sending FIN may need a higher value.
