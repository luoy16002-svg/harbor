# Third-party components

Harbor's forwarding engine does not start Clash, sing-box or Xray. Protocol
implementations and flow lifecycle are in `engine/src/`.

- Wintun 0.14.1, WireGuard LLC: signed Windows layer-3 adapter. Its license is
  retained in `vendor/wintun/LICENSE.txt` and the binary package's `licenses/`.
- smoltcp 0.14.0: TCP/IP implementation, 0BSD. Vendored with its upstream license
  and one documented IPv6 AnyIP change in `vendor/smoltcp/HARBOR-PATCH.md`.
- Rust dependencies are pinned by `Cargo.lock`. They include Tokio, Hyper,
  rustls, RustCrypto, BLAKE3, Hickory Proto, tungstenite and their dependencies.
- YamlDotNet 18.1.0: MIT, https://github.com/aaubry/YamlDotNet/blob/master/LICENSE.txt.
- Microsoft .NET Windows Desktop Runtime 9.0.19: runtime files are included by
  the self-contained publish; tagged upstream notices are retained in `licenses/`.
  https://github.com/dotnet/runtime.
  .NET 9 reaches end of support on 2026-11-10; migrate this project to .NET 10 LTS
  before continuing distribution past that date.

The local interoperability test server uses Xray v26.3.27 (MPL-2.0), kept only
under `.cache/reference/`. Its executable is excluded from all release archives.
Generated test CA keys and test configuration are also excluded.

The `licenses/` directory in a binary package contains collected license texts
for Rust dependencies used by the build and the other redistributed components.
