# Harbor

A Windows proxy client with a Rust forwarding engine and a WPF desktop. This is the **0.9.0 preview**.

## Use

Extract a Windows build and open `Harbor.exe`. The .NET runtime is included.

1. Add an HTTPS subscription, a share link, or a local configuration file.
2. Review the import and choose a proxy.
3. Run a connection check to test an HTTPS request through that proxy.
4. Connect. Disconnecting restores the system proxy settings owned by Harbor.

Opening Harbor does not start network capture. If another system proxy is active, Harbor asks before switching. Application proxy mode only serves apps configured to use the local listener, which defaults to `127.0.0.1:7897`.

Upstream connections use a physical network adapter by default to avoid routing back through an existing TUN. Choose system routing in settings to follow an existing VPN.

`Harbor-Local.cmd` opens an isolated workspace and disables system proxy, DNS, and route changes. Use it when trying the interface or developing the app.

## Features

- HTTP CONNECT, SOCKS5, Shadowsocks, Shadowsocks 2022, Trojan, VLESS, and VMess.
- Clash YAML, Base64 link collections, SIP008, and Harbor JSON imports.
- Routing rules, proxy groups, and offline comparisons of routing changes.
- Saved routing modes: rules, one default outbound, or direct; live switching preserves established connections.
- DoH / DoT, local domain lists, and connection privacy controls.
- Streaming dual-stack TCP setup, shared concurrent DNS queries, and bounded in-memory path hints.
- Live traffic, connection details, tray actions, and proxy search.
- Encrypted, saved HTTPS check results with timestamps and configuration-based expiry.
- Batch HTTPS checks for the filtered list, progress, cancellation, and numeric elapsed-time sorting.
- Subscription usage and expiry, cancellable downloads, and a preview of changed proxies before applying updates.
- Automatic encrypted configuration history with differences, reviewed restoration, and the ten most recent versions.

On the proxies page, search or filter the list and choose the batch check action. Harbor checks the list captured at that moment, with at most two requests in flight. Cancellation closes those verification connections while preserving completed results and active proxy traffic. Starting or stopping the proxy cancels an active batch first.

Sort by HTTPS elapsed time to put recent successful checks first, then select a proxy and use the existing set-as-outbound action. Harbor does not switch your outbound automatically. Each check sends one HTTPS HEAD request to `www.example.com` through the chosen proxy; measured time includes connection setup and the response, and does not measure download speed.

In subscription management, check for updates to review added, changed, removed, and retained proxies. Proxies still referenced by an outbound, rule, or group remain available. Cancelling a download or declining its preview keeps the existing workspace. Connection controls remain available while downloading; disconnecting cancels the pending download first.

Usage and expiry come from the provider's optional `Subscription-Userinfo` header and include the time received. They are separate from Harbor's local traffic counters. Missing or malformed statistics are shown as unavailable; a zero total does not imply an unlimited plan. Updates are user initiated.

Open settings and choose configuration history to review earlier versions. Before a configuration change, Harbor saves the previous workspace, including proxies, subscription addresses and ownership, routing, DNS, and privacy settings. It keeps at most ten encrypted versions under the current Windows user. Usage and download metadata updates do not consume history slots.

Disconnect before restoring. The preview lists changes without displaying passwords or subscription URL tokens. Harbor checks that the reviewed versions still match and validates the selected configuration before replacing the workspace. Restoration keeps the current configuration in history so it can be restored again. It leaves Harbor disconnected and preserves desktop system-proxy preferences. Restored subscriptions clear usage and HTTP cache markers; refresh them manually to fetch current content and provider statistics. Clearing history removes the saved versions while retaining the current workspace.

Choose a routing mode on the overview or routing page. Modes affect traffic entering Harbor and are separate from the system proxy, application proxy, and TUN connection methods.

| Mode | New connections |
| --- | --- |
| Rules (`rules`, the default) | Match enabled rules in order, then use the default outbound. |
| Single outbound (`global`) | Ignore routing rules and use the default outbound, including its selected group member. |
| Direct (`direct`) | Ignore routing rules and the default outbound and request a direct connection. No proxy import is required to connect. |

Local domain blocks and transport privacy restrictions apply in every mode. For example, direct mode rejects non-loopback traffic when blocking DIRECT is enabled. Rules and the selected default outbound stay saved when unused. Explicit proxy verification and background health probes still refer to the configured proxies.

Switching modes updates new TCP connections and new UDP destination sessions; existing sessions keep their original configuration. The routing page can compare a candidate mode and default outbound offline without applying either. Changing the active configuration or preview inputs clears older comparison results. Old profiles without `routingMode` continue to use rules.

New workspaces use AliDNS DoH first and Cloudflare DoH as a fallback. Certificates are verified; encrypted DNS does not silently fall back to plaintext. DNS settings can select a different provider or custom endpoint.

TCP setup starts from available DNS answers without waiting for a slow address family. Attempts alternate between IPv6 and IPv4, with at most eight attempts per dial; a recent successful address can be preferred if it is still in the current DNS response. Concurrent ordinary DNS questions share upstream work. Diagnostics show aggregate connection and query counters. See [connection quality](docs/connection-quality.md) for bounds, cancellation behavior, and reproducible local comparisons.

## Limits

TUN is experimental and requires administrator rights. Live system-wide capture, crash recovery, sleep recovery, and network switching have not been validated for this release. There is no system-wide kill switch or per-app routing.

REALITY, Vision, gRPC, XHTTP, AnyTLS, Hysteria2, and TUIC are unsupported. A successful HTTPS check is a past result for one target, not a speed test or a guarantee that every destination works.

## Build and test

Requires Windows x64, Rust 1.95+, .NET SDK 9, and Python 3.11+.

```powershell
./scripts/build.ps1
```

Add `-Visual` for isolated desktop checks or `-Interop` for local protocol interop. See [verification](docs/verification.md) for setup and test coverage.

[Features](docs/features.md) · [Privacy](docs/privacy.md) · [Protocols](docs/protocols.md) · [Licenses](THIRD-PARTY.md)
