# Privacy

## Local data

Workspaces, proxy credentials, subscription URLs, and recovery journals use Windows CurrentUser DPAPI. Saved HTTPS check results are also encrypted. Programs running as the same user, and administrators, may still access this data.

Connection records stay in memory. Completed records are kept for 300 seconds by default, configurable from 0 to 86,400 seconds. Hiding details clears stored destinations, sources, proxies, rule reasons, and error text. It does not remove records held by Windows, browsers, or other apps.

Request bodies are not logged. Diagnostic export contains summary fields. **Configuration export contains credentials.**

HTTPS checks send a HEAD request through the selected proxy to `www.example.com`. Saved results contain the proxy name, a configuration fingerprint, outcome, duration, and timestamp. They contain no response body and can be cleared from the proxy page. Results older than 24 hours are marked for retesting.

## Network

TLS verifies certificate chains and hostnames. A custom CA applies only to its configured proxy or DNS endpoint and is never installed in the Windows trust store.

Plain HTTP CONNECT and SOCKS5 provide no transport encryption. SOCKS5 over TLS protects TCP; its standard UDP path is still unencrypted. The encrypted-transport option checks the actual forwarding path.

The option to block non-loopback DIRECT traffic applies to Harbor's forwarded connections. It is not a firewall and does not control other applications, DNS upstream traffic, health probes, or subscription downloads.

DoH and DoT do not silently downgrade to plaintext. New workspaces try AliDNS DoH, then Cloudflare DoH. The selected resolver can see query names and source IPs. Users can choose one provider or configure a custom endpoint.

## Domain filtering

Local rules support domain lists, hosts entries, `||domain^`, and `@@||domain^`. Allow rules take precedence. CSS, scripts, URL paths, and Adblock modifiers are unsupported. No tracking list is downloaded by default.

A directly blocked question returns NXDOMAIN without an upstream query. CNAME answers are checked before delivery; at that point the resolver has already received the original question. Filtering cannot inspect names resolved outside Harbor or by a remote proxy.

Domain filtering does not prevent browser fingerprinting, account correlation, or tracking hosted on the same domain as wanted content.

## System integration

Opening Harbor does not capture traffic. System proxy mode asks before replacing another active proxy and records settings for recovery. Recovery only restores settings still owned by Harbor and preserves later changes from other programs.

Physical routing binds Harbor's own sockets to a hardware adapter without changing global routes. System routing can follow an existing VPN. Subscription downloads use a separate HTTP client.

`Harbor-Local.cmd` uses an isolated workspace and disables network-setting writes and native TUN startup.

Live TUN recovery and network switching remain unverified for this release. Harbor has no system-wide kill switch or WFP firewall.

There is no analytics or advertising SDK. Network requests come from forwarding, DNS, configured health probes, HTTPS checks, and subscription updates. Proxy operators and endpoint software remain separate trust boundaries.
