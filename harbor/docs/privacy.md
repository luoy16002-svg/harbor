# Privacy

## Local data

Workspaces, proxy credentials, subscription URLs, and recovery journals use Windows CurrentUser DPAPI. Saved HTTPS check results are also encrypted. Programs running as the same user, and administrators, may still access this data.

Configuration history retains up to ten earlier workspaces in a separate encrypted local file. These versions include earlier proxy credentials and subscription addresses until they age out or history is explicitly cleared from settings. The change preview shows field names instead of credential values and URL tokens. Clearing history does not delete the active configuration, saved HTTPS results, desktop preferences, or network-recovery journal. History is not a portable backup and is not synchronized or uploaded.

Provider-reported subscription usage and expiry are stored in the same encrypted workspace, with the time received. These statistics come from the subscription service and are independent of Harbor's own byte counts. The optional header convention is described in [Clash Party's response-header documentation](https://clashparty.org/docs/guide/urlscheme). Invalid or absent statistics do not become a zero-use or unlimited-plan claim.

Connection records stay in memory. Completed records are kept for 300 seconds by default, configurable from 0 to 86,400 seconds. Hiding details clears stored destinations, sources, proxies, rule reasons, and error text. It does not remove records held by Windows, browsers, or other apps.

The TCP dialer can retain up to 512 host-and-port hints in memory for five minutes after success. A hint contains the successful address, selected interface context, and TCP setup time. It is never written to disk or exported and is used only when that address appears in a current DNS response. Clearing DNS, changing DNS configuration, or detecting a physical-interface change invalidates hints. Hiding connection details clears and disables this memory for subsequent dials; numeric counters remain available. Active connection work still needs its destination to finish or cancel.

Request bodies are not logged. Diagnostic export contains summary fields. **Configuration export contains credentials.**

Enabled process paths and direct exceptions briefly read Windows endpoint ownership and executable image names for new flows. The engine retains no process or PID cache and adds no looked-up executable names or paths to connection records or diagnostic export. User-defined traffic path names can appear in a route reason until metadata is hidden; do not put sensitive identifiers in a path name if those reasons will be shared. Hiding metadata still permits the transient lookup needed to choose a route. The configured domain and process lists are saved with the encrypted workspace and configuration history and appear in explicit configuration exports. No game hooks, code injection or privilege adjustment are used.

HTTPS checks send a HEAD request through the selected proxy to `www.example.com`. Saved results contain the proxy name, a configuration fingerprint, outcome, duration, and timestamp. They contain no response body and can be cleared from the proxy page. Results older than 24 hours are marked for retesting.

Batch checks run only after a user action and cover the list captured when the action starts, with at most two requests at a time. Cancelling stops the remaining work and closes active verification connections. It keeps completed results and does not record unfinished checks as failures or stop normal proxy connections.

## Network

TLS verifies certificate chains and hostnames. A custom CA applies only to its configured proxy or DNS endpoint and is never installed in the Windows trust store.

Plain HTTP CONNECT and SOCKS5 provide no transport encryption. SOCKS5 over TLS protects TCP; its standard UDP path is still unencrypted. The encrypted-transport option checks the actual forwarding path. An individual traffic path can require an encrypted proxy even while global settings allow direct traffic elsewhere. All automatic groups filter transport support and global restrictions before selection, in addition to a path requirement when present; a fixed incompatible member or an exhausted protected group is rejected. This requirement applies to newly routed connections; existing sessions retain the old configuration. It does not change DNS provider trust, browser identity, or exit IP reputation. See [capabilities and research](traffic-paths.md).

The option to block non-loopback DIRECT traffic applies to Harbor's forwarded connections. It is not a firewall and does not control other applications, DNS upstream traffic, health probes, or subscription downloads.

Routing modes do not disable local domain blocking or transport restrictions. Direct mode requests a direct path and can still be rejected by the configured privacy settings. A mode change applies to new TCP connections and new UDP destination sessions; existing sessions keep their original route. The offline mode comparison sends no network requests and does not save its candidate configuration.

Enabled direct exceptions are evaluated before the selected mode and ordinary rules. They preserve domain blocking and transport restrictions. Unknown or ambiguous process ownership retains ordinary routing. These exceptions control only traffic entering Harbor; they do not implement a firewall or change DNS providers. See [direct exceptions](direct-exceptions.md).

DoH and DoT do not silently downgrade to plaintext. New workspaces try AliDNS DoH, then Cloudflare DoH. The selected resolver can see query names and source IPs. Users can choose one provider or configure a custom endpoint.

## Domain filtering

Local rules support domain lists, hosts entries, `||domain^`, and `@@||domain^`. Allow rules take precedence. CSS, scripts, URL paths, and Adblock modifiers are unsupported. No tracking list is downloaded by default.

A directly blocked question returns NXDOMAIN without an upstream query. CNAME answers are checked before delivery; at that point the resolver has already received the original question. Filtering cannot inspect names resolved outside Harbor or by a remote proxy.

Domain filtering does not prevent browser fingerprinting, account correlation, or tracking hosted on the same domain as wanted content.

## System integration

Opening Harbor does not capture traffic. System proxy mode asks before replacing another active proxy and records settings for recovery. Recovery only restores settings still owned by Harbor and preserves later changes from other programs.

Physical routing binds Harbor's own sockets to a hardware adapter without changing global routes. System routing can follow an existing VPN. Subscription downloads use a separate HTTP client.

Subscription updates run only after a user action. A changed feed is previewed before it replaces proxies; the preview names changed settings without displaying credentials. Cancellation closes the pending download, and empty or unsupported-only feeds preserve the existing workspace. No subscription URL or provider-suggested web page is opened automatically.

`Harbor-Local.cmd` uses an isolated workspace and disables network-setting writes and native TUN startup.

Live TUN recovery and network switching remain unverified for this release. Harbor has no system-wide kill switch or WFP firewall.

There is no analytics or advertising SDK. Network requests come from forwarding, DNS, configured health probes, HTTPS checks, and subscription updates. Proxy operators and endpoint software remain separate trust boundaries.

## Automatic pool monitoring

Automatic pools are opt-in and send bounded HTTPS HEAD requests through their selected members while the engine runs. Their URLs and trust settings are encrypted with the workspace; the check endpoint observes each request. Snapshots expose only categorized results, without check URLs or detailed errors. Member health samples and counters stay in memory. Setup-attempt names are hidden with other connection metadata, and recent outbound/recovery fields obey retention and history clearing. Pool exhaustion never adds a DIRECT fallback. See [automatic pools](automatic-pools.md).
