# Visual traffic paths and protection requirements

The routing page in 0.11 shows an ordered list of application / website paths. A path has a name, domain suffixes, executable filenames, an outbound, and an optional encrypted-proxy requirement. Cards show the configured route and transport capabilities; the path checker evaluates a destination, TCP or UDP, and an optional simulated process name.

## Using paths

1. Choose the default outbound and routing mode at the top of the page.
2. Add a path, or open the editable Genshin / miHoYo or Bilibili preset.
3. Select direct, block, a fixed proxy, a proxy group, or follow the default outbound. Following the default means `finalPolicy`, including in direct mode.
4. Enable the encrypted-proxy requirement if this traffic must use an encrypted upstream. An incompatible fixed proxy is rejected. Automatic groups select only eligible members.
5. Check a destination and transport. Add a process filename to simulate a process rule. The checker does not contact the destination or inspect a running application.

Cards are checked from top to bottom. Move them with the arrow buttons, edit, disable, or remove them. Domain and process entries within one card are alternatives: either can match. A disabled card retains its settings. Saving affects new TCP connections and new UDP destination sessions; already established sessions retain their previous configuration. To apply a stricter requirement to an existing session, close that session or disconnect before changing the requirement.

The original direct-exception editor remains available below the cards, with its enabled state and counts. Existing workspaces start with no new cards; their routing is preserved. Paths participate in encrypted workspace history, reference renaming, subscription retention, validation, and failed-save rollback. Changing a path does not invalidate an explicit proxy HTTPS check because that check does not use routing rules.

## Evaluation order

1. Local privacy domain block.
2. First enabled matching traffic path.
3. Legacy domain / process direct exceptions.
4. Routing mode: rules and final policy, global final policy, or direct.
5. Group selection and the path's encrypted-proxy requirement.
6. Global transport and direct-connection restrictions.

No path can bypass a global domain block or transport restriction. Paths are explicit overrides of all three modes. The mode describes the behavior after the paths and direct exceptions have been considered.

For protected automatic groups, DIRECT, unencrypted members and members marked unavailable are excluded before selection. Unmeasured members can still be attempted; eligibility is not a successful health check. TCP and UDP eligibility are evaluated separately. A TLS-protected SOCKS5 TCP connection does not encrypt the standard SOCKS5 UDP relay. HTTP/HTTPS proxies have no UDP forwarding support. If no eligible encrypted member remains, the request is rejected. A manually selected group member is never silently replaced. Protected selections keep separate sticky state from ordinary selections, so an encrypted request does not move the same group's unprotected traffic to another member.

Group health is still based on bounded TCP reachability probes. It does not prove that proxy authentication, a particular destination, or UDP forwarding currently works. A failed application request is not replayed through another proxy. The proxy page provides separate, timestamped HTTPS verification. Fixed members avoid automatic exit changes; automatic groups retain the existing failure thresholds and switching hysteresis for new sessions.

## Configuration

```json
"trafficRoutes": [
  {
    "name": "Game direct",
    "enabled": true,
    "domains": ["mihoyo.com"],
    "processes": ["YuanShen.exe"],
    "policy": "DIRECT",
    "requireEncryptedProxy": false
  },
  {
    "name": "Work protection",
    "enabled": true,
    "domains": ["work.example"],
    "processes": ["Work.exe"],
    "policy": null,
    "requireEncryptedProxy": true
  }
]
```

The optional array defaults to empty. It supports 64 paths, 256 domain suffixes and 256 executable filenames per path, and 2,048 total matcher entries. Names are unique, trimmed, contain no control characters, and use at most 128 UTF-8 bytes. Matchers use the same ASCII validation and domain boundaries as [direct exceptions](direct-exceptions.md). Explicit policy references must exist, including on disabled paths. An explicitly DIRECT path cannot also require an encrypted proxy; following a default that later becomes DIRECT results in rejection.

The engine only queries Windows ownership when a process match could precede the first known domain match. Ownership remains bounded and best effort. A missing, inaccessible, ambiguous, or timed-out owner continues through domain and default routing. This is not an application identity guarantee or a system firewall. A helper or another local proxy may own the captured socket. Applications that bypass Harbor receive none of these routing controls; TUN capture remains experimental.

An offline `rehearse` target can include an optional `process` filename. It is simulated input to the offline evaluator, never asserted process identity on a forwarding connection. Real forwarding still derives ownership from local socket endpoints.

## What software can improve

The following distinctions informed the interface. Research was checked on 2026-09-08; implementation claims refer to the current source and packaged checks.

| Desired outcome | Practical capability and limit |
| --- | --- |
| Less exposed DNS | Harbor supports verified DoH / DoT without plaintext fallback. Its DNS queries go directly to the configured resolver using the configured egress. The resolver can still observe queries, and applications or proxy servers may resolve names independently. DoH protects the channel, not anonymity from its server. [RFC 8484, section 8](https://www.rfc-editor.org/rfc/rfc8484.html#section-8). |
| Encrypted transport | Existing TLS/WSS and authenticated proxy protocols protect their supported transports. The path requirement enforces eligibility and rejects a downgrade. Server-side protocol support is required. TLS does not hide packet timing and lengths or guarantee resistance to traffic analysis. [RFC 8446, appendix E.3](https://www.rfc-editor.org/rfc/rfc8446.html#appendix-E.3). |
| Anonymous browsing | A proxy changes network routing. Browser fingerprinting, cookies, account identity, DNS and WebRTC behavior need application-level controls. The Tor Project documents why merely directing another browser through a proxy does not reproduce Tor Browser's protections. [Tor browser guidance](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/). |
| A clean IP | IP reputation is affected by address history, network allocation and other users sharing an address. Changing a local setting cannot reset those facts. Cloudflare describes the collateral effects of sharing an IP across users. [Cloudflare's CGNAT analysis](https://blog.cloudflare.com/detecting-cgn-to-reduce-collateral-damage/). Harbor currently shows this information as unmeasured. |
| More stable routing | Fix an application to a chosen exit, or use an automatic group with eligible encrypted members and switching hysteresis. Existing connections retain their exit. Recent HTTPS checks help compare observed outcomes; they are not a guarantee for another destination or time. |
| Less tracking | Existing local domain filtering and reduced telemetry retention can reduce specific exposure. They do not remove application identifiers or the proxy operator's visibility. |

The interface therefore describes encryption, DNS, selection behavior, and observed checks instead of an anonymity percentage or a clean-IP score. No custom camouflage, browser-fingerprint spoofing, reputation reset, or third-party IP reputation lookup is implemented. Traffic shaping also has bandwidth and latency costs; the TLS specification discusses that tradeoff. Adding such a label alone would not improve a connection.

## Evidence

Policy checks cover ordered overlap, all modes, legacy exceptions, global blocks, per-transport protected groups, separate selection state, bounded configuration, and process rehearsal without network requests. Real Windows process fixtures exercise HTTP CONNECT, SOCKS TCP and SOCKS UDP forwarding with the new paths enabled and legacy exceptions disabled; old connections retain their generation after a path is disabled.

Desktop checks cover path-only subscription references, encrypted history restoration, capability descriptions and verification fingerprints. Isolated WPF checks use real editor and card buttons, invalid input, priority changes, enable/disable/remove, process previews, node renaming, and forced atomic-save failure. Screenshots contain local fixture names, not customer traffic or claimed internet performance. Live game capture, TUN recovery and reputation assessments remain unverified. See [verification](verification.md).
