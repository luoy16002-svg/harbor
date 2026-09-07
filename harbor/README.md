# Harbor

A Windows proxy client with a Rust forwarding engine and a WPF desktop. This is the **0.6.0 preview**.

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
- DoH / DoT, local domain lists, and connection privacy controls.
- Live traffic, connection details, tray actions, and proxy search.
- Encrypted, saved HTTPS check results with timestamps and configuration-based expiry.
- Batch HTTPS checks for the filtered list, progress, cancellation, and numeric elapsed-time sorting.
- Subscription usage and expiry, cancellable downloads, and a preview of changed proxies before applying updates.

On the proxies page, search or filter the list and choose the batch check action. Harbor checks the list captured at that moment, with at most two requests in flight. Cancellation closes those verification connections while preserving completed results and active proxy traffic. Starting or stopping the proxy cancels an active batch first.

Sort by HTTPS elapsed time to put recent successful checks first, then select a proxy and use the existing set-as-outbound action. Harbor does not switch your outbound automatically. Each check sends one HTTPS HEAD request to `www.example.com` through the chosen proxy; measured time includes connection setup and the response, and does not measure download speed.

In subscription management, check for updates to review added, changed, removed, and retained proxies. Proxies still referenced by an outbound, rule, or group remain available. Cancelling a download or declining its preview keeps the existing workspace. Connection controls remain available while downloading; disconnecting cancels the pending download first.

Usage and expiry come from the provider's optional `Subscription-Userinfo` header and include the time received. They are separate from Harbor's local traffic counters. Missing or malformed statistics are shown as unavailable; a zero total does not imply an unlimited plan. Updates are user initiated.

New workspaces use AliDNS DoH first and Cloudflare DoH as a fallback. Certificates are verified; encrypted DNS does not silently fall back to plaintext. DNS settings can select a different provider or custom endpoint.

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
