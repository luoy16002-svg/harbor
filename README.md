# Harbor

A Windows proxy client with its own Rust engine and a WPF desktop.

Harbor imports subscriptions, routes traffic through rules and proxy groups, and shows live connections. It includes encrypted DNS, local domain blocking, cancellable batch HTTPS checks, and tray controls.

The engine connects as DNS answers arrive, interleaves IPv6 and IPv4 attempts, shares duplicate DNS work, and remembers recent successful TCP paths. A [local fault benchmark](harbor/docs/connection-quality.md) compares connection setup against the preceding release.

Subscriptions show provider usage and expiry when available. Updates include a change preview and cancellable downloads.

Switch between rule routing, one default outbound, and direct routing. Preview path changes offline before selecting a mode; established connections keep their original route.

Keep a global proxy while sending selected games and video services directly. [Direct exceptions](harbor/docs/direct-exceptions.md) match domain suffixes and locally identified Windows TCP/UDP processes, with editable Genshin / miHoYo and Bilibili presets.

[Visual traffic paths](harbor/docs/traffic-paths.md) assign applications and websites to direct, a fixed proxy, a group, or the default outbound. Optional encryption requirements filter automatic groups separately for TCP and UDP and reject incompatible routes. The path checker evaluates simulated process matches offline. Capability notes explain DNS, TLS/WSS, and the limits of anonymity and IP reputation.

Configuration changes retain up to ten encrypted earlier versions. Review differences and restore a version from settings while disconnected; the configuration before restoration is kept for undo.

**Status:** 0.11.0 preview. The desktop UI is currently in Chinese. TUN support is experimental; live system-wide capture and recovery have not been validated for this release.

## Build

Requires Windows x64, Rust 1.95+, .NET SDK 9, and Python 3.11+.

```powershell
cd harbor
./scripts/build.ps1
```

The build downloads the pinned Wintun driver from its official source and verifies its hash and signature. Output goes to `harbor/dist/`.

For isolated UI checks, add `-Visual`. Protocol interop checks require a local Xray test server; see [verification](harbor/docs/verification.md).

## Project

- [Usage](harbor/README.md)
- [Supported features](harbor/docs/features.md) and [protocols](harbor/docs/protocols.md)
- [Privacy](harbor/docs/privacy.md) and [architecture](harbor/docs/architecture.md)
- [Third-party licenses](harbor/THIRD-PARTY.md)

MIT licensed. Third-party components retain their own licenses.
