# Features

Implemented features and the checks completed for 0.13.0 are listed separately from unverified behavior.

| Feature | Implementation | Verification |
| --- | --- | --- |
| App icon and tray | Multi-size icon, connection state, connect/disconnect, navigation, and exit | Embedded resources and isolated tray workflows |
| Proxy search and saved checks | Name, protocol, and server search; encrypted results; expiry after configuration changes or 24 hours; numeric HTTPS sorting | Persistence, filtering, clearing, per-proxy invalidation, timestamps, and expired-result ordering |
| Imports and subscriptions | Cancellable HTTPS updates, a preview of added/changed/removed/retained proxies, ownership tracking, and atomic saves | Parser, body/header cancellation, real preview acceptance/cancellation, empty-feed rejection, stale-response rejection, and failed-save rollback |
| Subscription statistics | Optional provider upload/download/total/expiry data, timestamps, and an explicit unavailable state | Header bounds and parsing, old-workspace compatibility, DPAPI persistence, 304 replies, and identical-body metadata refresh |
| Configuration history | Ten encrypted predecessors, change previews, stopped-only restoration, undo through history, and explicit clearing | Atomic persistence failures, retention, corruption, stale reviews, real restore/cancel buttons, download cancellation, and HTTP validator reset |
| Proxy selection and rules | Live configuration updates, ordered groups, rule editing, and offline route comparisons; automatic members filtered by transport support and path/global protections | Policy tests, independent Xray TCP/UDP automatic-group payloads, invalid-update rollback, and established-stream preservation |
| Automatic proxy pools | Opt-in background HTTPS checks, stable/low-latency selection, up to three setup attempts within one deadline, cooldowns, member management and recovery history | Failure/TLS fixtures, cancellation, stale configuration, privacy retention, real SOCKS/HTTP/Xray and in-memory TUN recovery, WPF save/pause/rename/rollback |
| Routing modes | Rules, a single default outbound, or direct; saved selections and offline mode comparison | Legacy defaults, group selection, privacy precedence, real TCP/UDP transitions, and failed-save rollback in the desktop |
| Direct exceptions | Domain suffixes and read-only Windows socket process ownership before the global outbound or ordinary rules; game/video presets | Real IPv4/IPv6 ownership, SOCKS5/CONNECT/UDP forwarding, ambiguous-owner fallback, privacy precedence, preset editor and failed-save rollback; live game/TUN sessions unverified |
| Visual traffic paths | Ordered application / domain cards, direct/fixed/group/default exits, required encrypted proxies, overlap advice, configured member counts and TCP/UDP/process rehearsal | Per-transport group eligibility, privacy precedence, real Windows process forwarding, path-only subscription references, history, editor and card actions, preserved focus on unchanged refresh and failed-save rollback |
| Local proxy | HTTP and SOCKS5 listeners, TCP and persistent UDP sessions | Independent interop and loopback traffic |
| System proxy | WinINET settings, encrypted recovery journal, and an independent recovery process | Recovery state machine tested with simulated storage; live writes were not tested for this release |
| Upstream routing | Physical adapter selection or system routing; updates for new connections after network changes | Adapter selection checks and limited HTTPS forwarding with an existing TUN active |
| TUN | Wintun adapter, smoltcp TCP/IP stack, and route cleanup | In-memory packets and isolation checks; live capture and recovery remain unverified |
| HTTPS verification | One proxy or the current filtered list; two concurrent requests; progress and cancellation; proxy handshake, target certificate validation, and an HTTPS HEAD request | Success/failure fixtures, bounded scheduling, queued-work cancellation, configuration matching, and preserved forwarding during cancellation |
| DNS | DoH / DoT, verified TLS, pooling, cache, shared concurrent queries, and first-answer startup preflight | HTTP limits, certificate rejection, flag isolation, leader/follower cancellation, generation changes, and 64-way sharing over UDP and verified DoT |
| TCP setup | Streaming address resolution, bounded dual-stack attempts, current-answer path hints, and aggregate diagnostics | Virtual-time failure schedules, loser cleanup, hint invalidation, metadata hiding, and five local fault scenarios compared with the previous engine |
| Local domain filtering | Domain, hosts, and basic Adblock domain syntax; allow rules and CNAME checks | Domain boundaries, exceptions, and alias-chain tests |
| Connections and privacy | Real byte counts, filters, close-flow action, metadata hiding, retention, and summary export | Loopback transfers, blocked flows, retention, and field checks |
| Desktop layout | Eleven pages, import/edit dialogs, narrow layouts, and smooth scrolling | WPF rendering at 1280 and 980 pixels wide; guided workflows |

TCP health probes measure reachability and latency. They do not validate proxy credentials. HTTPS checks are shown separately. Automatic pools explicitly use those HTTPS outcomes for selection; ordinary groups retain TCP-only health behavior. See [automatic pools](automatic-pools.md).

See [protocols](protocols.md), [privacy](privacy.md), and [verification](verification.md) for limits.
