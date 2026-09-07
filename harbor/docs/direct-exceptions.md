# Direct exceptions with a global outbound

In the routing page, select the global outbound mode and open the direct exception editor. Add the Genshin / miHoYo and Bilibili presets, or enter your own domain suffixes and executable filenames. Enabling exceptions sends matching traffic through `DIRECT`; other traffic continues to use the selected default outbound. No country-wide or all-UDP bypass is added.

The optional configuration defaults to disabled for old and new workspaces:

```json
"directExceptions": {
  "enabled": true,
  "domains": ["bilibili.com", "mihoyo.com"],
  "processes": ["YuanShen.exe", "GenshinImpact.exe"]
}
```

Each list allows up to 256 entries. Domains are ASCII suffixes, with a label boundary: `bilibili.com` includes `api.bilibili.com` but excludes `notbilibili.com`. URLs, literal IPs and wildcards are rejected. Process entries are ASCII executable basenames, compared without ASCII case sensitivity; paths and wildcards are rejected. A basename match is a routing convenience, not an authenticated application identity.

Local domain blocking is evaluated first. Direct exceptions precede the routing mode and ordinary rules, and transport privacy restrictions apply afterward. A direct exception cannot override the option that blocks non-loopback direct connections. Disabling exceptions retains the lists. Saving uses normal validation, encrypted configuration history, and runtime rollback on persistence failure. Existing TCP connections and UDP destination sessions retain their original configuration generation.

## Windows socket ownership

Process matching uses the read-only Windows [TCP endpoint table](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable), [UDP endpoint table](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable), and [limited process image query](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew). It does not inject code, adjust privileges, hook a game, or install a firewall filter.

- TCP matches both local and remote addresses and ports. For HTTP/SOCKS clients these identify the connection to Harbor; for packet flows they identify the original connection.
- UDP matches its actual datagram source against a local or wildcard binding. It does not mistake the SOCKS TCP control port for the UDP source port. Multiple candidate owners produce no match.
- IPv4 and IPv6 tables are supported. Ownership is checked again while holding the queried process handle. Endpoint and PID results are never cached.
- Only enabled process lists trigger a lookup, and a matching domain needs no process lookup. At most four blocking lookup jobs run at once, with no waiting queue. The route caller waits at most 250 ms; an unfinished job retains its slot until the OS call returns. Each table buffer is limited to 8 MiB and three resize attempts; derived rows are temporary and bounded by that table.
- Missing, inaccessible, ambiguous, busy or timed-out ownership falls back to normal routing. It never grants direct routing by default. Windows endpoint tables are snapshots; process matching is best effort and cannot provide a kernel-enforced identity guarantee.

Process names and paths are transient lookup data. They are not added to connection records, diagnostics, or an executable cache. The configured exception lists are part of the encrypted workspace and its retained history; explicit configuration export includes them. Domain path checks and offline comparison do not look up or simulate a process. Explicit proxy verification still tests the chosen proxy independently of these exceptions.

## Capture and network scope

Exceptions affect traffic that enters Harbor. They do not make a game use a system HTTP proxy. Applications that ignore that proxy generally need TUN capture or their own SOCKS support. Harbor's TUN remains experimental: native game sessions, anti-cheat compatibility, system-wide capture and recovery have not been validated for this release. A process that cannot be queried may retain the proxy route. Restart an existing game connection to use a changed exception.

Use physical egress when `DIRECT` should leave through a hardware adapter while another VPN is active. System egress can follow that VPN. The DNS resolver remains the one configured in Harbor; a direct exception is not a switch to the operating system's DNS settings. Domain matching only works when Harbor knows the name, so process matching complements IP-only game connections. Traffic owned by a helper or a separate local proxy may be attributed to that process.

## Preset scope and checks

The game preset includes the Genshin executables, game browser and HoYoPlay helper names, plus eight relevant domain suffixes. Shared miHoYo domains and launcher processes also affect other miHoYo applications. The Bilibili preset contains eighteen site, API, image and video suffixes. It does not direct every browser process or a shared CDN parent domain. These are editable starting points, not a continuously updated or exhaustive service database.

Domain ownership lists were checked on 2026-09-08 against the project's [Bilibili](https://github.com/v2fly/domain-list-community/blob/master/data/bilibili), [Bilibili CDN](https://github.com/v2fly/domain-list-community/blob/master/data/bilibili-cdn), [miHoYo China](https://github.com/v2fly/domain-list-community/blob/master/data/mihoyo-cn), and [HoYoverse](https://github.com/v2fly/domain-list-community/blob/master/data/hoyoverse) entries. The presets contain a selected set of public domain names; no external list is downloaded at runtime.

Tests use real Windows IPv4/IPv6 TCP and UDP sockets, local direct and SOCKS proxy endpoints, and the actual SOCKS5, HTTP CONNECT and SOCKS UDP ingress paths. They verify process selection, unknown-owner fallback, closed-socket lookup, conflicting UDP owners, table bounds, domain boundaries, privacy precedence and unchanged established-flow generations. WPF checks exercise preset merging, save/cancel buttons, invalid input, encrypted history, disabling, and rollback after a forced write failure. No live game or native TUN session is claimed by these checks.
