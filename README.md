# Harbor

A Windows proxy client with its own Rust engine and a WPF desktop.

Harbor imports subscriptions, routes traffic through rules and proxy groups, and shows live connections. It includes encrypted DNS, local domain blocking, cancellable batch HTTPS checks, and tray controls.

Subscriptions show provider usage and expiry when available. Updates include a change preview and cancellable downloads.

**Status:** 0.6.0 preview. The desktop UI is currently in Chinese. TUN support is experimental; live system-wide capture and recovery have not been validated for this release.

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
