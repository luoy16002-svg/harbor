# Verification

These results apply to the 0.7.0 preview checked on 2026-09-07. They do not establish production readiness or carry over automatically to later builds.

| Check | Result | Scope |
| --- | --- | --- |
| Rust tests | 36 passed | Protocols, routing modes, packets, privacy precedence, encrypted DNS, and adapter selection |
| Desktop checks | 47 passed | Imports, subscription headers and diffs, DPAPI, recovery state, mode defaults, saved history, bounded batch scheduling, and cancellation |
| Independent interop | 49 passed | Xray v26.3.27, TCP/UDP paths, 2 MiB payloads, delayed replies, source-port reuse, and concurrent connections |
| Control interface | 13 passed | Isolation, preflight, stop, atomic configuration changes, targeted cancellation, and routing-mode changes over real TCP/UDP sessions |
| WPF workflows | 43 passed | Import, search, tray controls, HTTPS batches, subscription updates, both mode selectors, stale-preview clearing, delayed status replies after reconnect, and failed-save rollback |
| Layout | Passed | Ten pages, four dialogs, 1280/980-pixel main windows, and a 640-pixel subscription preview |
| Build | Passed | Strict Clippy and desktop compilation without warnings |

Dependency advisory queries returned no findings for the locked dependencies at the time of the check. This is not a security audit.

UI traffic checks used four real SOCKS5 connections to a loopback echo server. Rendered charts show local test traffic, not internet speed.

Batch checks used two loopback HTTP CONNECT servers that held their replies until cancellation. Both sockets closed, the third queued proxy was untouched, previous results remained, and the active engine kept running. A separate privacy-blocked batch verified that changing the search field does not expand a batch already in progress. Historical times shown in the batch layout fixtures are synthetic data used to check sorting and retention.

Subscription checks used synthetic provider headers and in-memory HTTP responses. They exercised cancellation while waiting for headers and body bytes, old workspace loading, metadata updates on unchanged content, real preview buttons, empty-feed rejection, and late responses after a source change. A read-only workspace fixture forced persistence to fail after runtime configuration; the original disk bytes, desktop profile, and runtime proxy names were restored. Subscription screenshots contain fixture data, not the user's provider statistics.

Routing checks used isolated listeners and real loopback TCP and UDP echoes. Switching modes changed newly opened flows while established flows continued transferring data with their original generations. Invalid mode values left the running generation unchanged. Desktop checks exercised both mode selectors, direct startup without proxies, unused-proxy preflight, unchanged disk bytes after offline comparison, stale-result clearing after configuration/input changes, overlapping UI actions, and a forced save failure restoring disk, UI, and runtime mode. A delayed stopped reply was injected across an actual stop/start and could not stop or repaint the new session. Privacy blocks stayed effective in all three modes. Mode screenshots show a fixture proxy and offline path results.

A limited external forwarding check completed HTTPS requests through the release engine's SOCKS5 and HTTP CONNECT listeners. This does not establish compatibility with every proxy, destination, or network.

## Not validated

- Live system-proxy writes and real recovery after process failure for this release.
- Native TUN capture, crash cleanup, sleep recovery, network switching, and sustained real-world traffic.
- Multi-VPN compatibility, games, and QUIC under system-wide capture.

TUN packet handling and recovery state machines have isolated tests. Those tests do not replace live network validation.

Harbor has no system-wide kill switch, per-app routing, installer, or automatic updater. Harbor executables are unsigned; the bundled Wintun driver is signed.

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
