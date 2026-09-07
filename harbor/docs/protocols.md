# Protocol implementation and verification

The forwarding engine is Harbor code. Tokio, Hyper, rustls, RustCrypto, tungstenite and smoltcp provide transport, cryptographic and TCP/IP building blocks. No external proxy core is launched by the product.

References:

- [Shadowsocks AEAD](https://shadowsocks.org/doc/aead.html) and [SIP008](https://shadowsocks.org/doc/sip008.html).
- [Trojan wire protocol](https://trojan-gfw.github.io/trojan/protocol).
- [VLESS reference framing](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/encoding.go).
- [VMess AEAD reference](https://github.com/XTLS/Xray-core/tree/main/proxy/vmess/aead) and [body framing](https://github.com/XTLS/Xray-core/blob/main/proxy/vmess/encoding/client.go).
- [Clash node schema](https://wiki.metacubex.one/en/config/proxies/), used only for subscription import.

TLS certificate chains and hostnames are verified. An optional CA is scoped to one node, never installed into the Windows trust store. VLESS without TLS and VMess without authenticated encryption are rejected.

VMess uses SHAKE-masked chunk lengths and padding. A session stops before its 16-bit payload nonce counter repeats. This avoids nonce reuse, but very long sessions may need reconnecting; it is a protocol compatibility limit, not evidence of unlimited session longevity.

Imported profiles do not automatically enable third-party TLS interception, scripts, plugins or global routing settings. Unsupported required options are retained as import issues and never silently discarded.

## Shadowsocks 2022

SIP022 AES-128-GCM and AES-256-GCM are implemented in `ss2022.rs`, using the BLAKE3 session-key derivation and fixed-size Base64 PSKs. TCP authenticates response type, timestamp and request-salt binding; UDP validates direction, timestamp, client session binding, packet authentication and the replay window before accepting a response. UDP sessions keep their socket/source port and can receive delayed multiple replies.

The TCP client sends the salt and two request-header records together. Response-header framing follows the independent implementation's single-read requirement. The receiver tracks up to eight recent UDP server-session IDs for at least sixty seconds, so server restarts do not silently disable replay protection; excess new sessions are rejected until room expires. EIH identity-key chains and the SS2022 ChaCha method are rejected explicitly.

References: [SIP022](https://shadowsocks.org/doc/sip022.html), [SIP023 / unsupported EIH](https://shadowsocks.org/doc/sip023.html), [pinned Xray reference](https://github.com/XTLS/Xray-core/tree/v26.3.27/proxy/shadowsocks_2022).
