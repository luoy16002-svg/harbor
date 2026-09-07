# Features

Implemented features and the checks completed for 0.6.0 are listed separately from unverified behavior.

| Feature | Implementation | Verification |
| --- | --- | --- |
| App icon and tray | Multi-size icon, connection state, connect/disconnect, navigation, and exit | Embedded resources and isolated tray workflows |
| Proxy search and saved checks | Name, protocol, and server search; encrypted results; expiry after configuration changes or 24 hours; numeric HTTPS sorting | Persistence, filtering, clearing, per-proxy invalidation, timestamps, and expired-result ordering |
| Imports and subscriptions | Cancellable HTTPS updates, a preview of added/changed/removed/retained proxies, ownership tracking, and atomic saves | Parser, body/header cancellation, real preview acceptance/cancellation, empty-feed rejection, stale-response rejection, and failed-save rollback |
| Subscription statistics | Optional provider upload/download/total/expiry data, timestamps, and an explicit unavailable state | Header bounds and parsing, old-workspace compatibility, DPAPI persistence, 304 replies, and identical-body metadata refresh |
| Proxy selection and rules | Live configuration updates, ordered groups, rule editing, and offline route comparisons | Policy tests, invalid-update rollback, and established-stream preservation |
| Local proxy | HTTP and SOCKS5 listeners, TCP and persistent UDP sessions | Independent interop and loopback traffic |
| System proxy | WinINET settings, encrypted recovery journal, and an independent recovery process | Recovery state machine tested with simulated storage; live writes were not tested for this release |
| Upstream routing | Physical adapter selection or system routing; updates for new connections after network changes | Adapter selection checks and limited HTTPS forwarding with an existing TUN active |
| TUN | Wintun adapter, smoltcp TCP/IP stack, and route cleanup | In-memory packets and isolation checks; live capture and recovery remain unverified |
| HTTPS verification | One proxy or the current filtered list; two concurrent requests; progress and cancellation; proxy handshake, target certificate validation, and an HTTPS HEAD request | Success/failure fixtures, bounded scheduling, queued-work cancellation, configuration matching, and preserved forwarding during cancellation |
| DNS | DoH / DoT, verified TLS, pooling, cache, and startup preflight | HTTP limits, certificate rejection, DNS error handling, and partial address-family success |
| Local domain filtering | Domain, hosts, and basic Adblock domain syntax; allow rules and CNAME checks | Domain boundaries, exceptions, and alias-chain tests |
| Connections and privacy | Real byte counts, filters, close-flow action, metadata hiding, retention, and summary export | Loopback transfers, blocked flows, retention, and field checks |
| Desktop layout | Ten pages, import/edit dialogs, narrow layouts, and smooth scrolling | WPF rendering at 1280 and 980 pixels wide; guided workflows |

TCP health probes measure reachability and latency. They do not validate proxy credentials. HTTPS checks are shown separately.

See [protocols](protocols.md), [privacy](privacy.md), and [verification](verification.md) for limits.
