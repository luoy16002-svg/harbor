# TCP connection quality

Since 0.9.0, Harbor uses a shared TCP setup path for direct forwarding, upstream proxy sockets, and TCP health probes. It addresses two specific delays: waiting for both DNS families before trying any address, and spending the entire attempt budget on IPv4 addresses before reaching a working IPv6 address. It also shares duplicate concurrent DNS questions. Proxy authentication, TLS, and application data start after a single TCP winner is selected.

## Release comparison on 2026-09-08

Both executables were optimized Windows x64 release builds, measured on the same machine with the local fixtures below. No external proxy or public DNS service was involved in these measurements.

| Fixture | 0.8.0 | 0.10.0 |
| --- | --- | --- |
| AAAA delayed 1,200 ms; 7 connections | Median 1,228.30 ms; p95 1,244.11 ms; 7/7 completed | Median 78.65 ms; p95 94.60 ms; 7/7 completed |
| Eight unusable A records and usable IPv6; 3 connections | 0/3 completed | 3/3 completed; median 16.06 ms |
| 32 simultaneous connections, 200 ms DNS delay | 64 upstream DNS queries; 32/32 completed | 2 upstream DNS queries; 62 shared joins; 32/32 completed |
| Same 32-connection burst, connection time | Median 225.67 ms; p95 228.64 ms | Median 219.84 ms; p95 222.59 ms |
| Preflight with delayed AAAA; one sample | 1,209.38 ms | 5.99 ms |

The burst reduces duplicate DNS work; its connection latency is similar because each caller still needs the first answer. Path-memory checks started two attempts on the first connection, one on the second, and two again after clearing DNS. Enabling metadata hiding left zero remembered paths. After each traffic scenario, the new engine reported zero active dials, active TCP attempts, and pending shared DNS questions.

The evidence records SHA-256 `9fab02f243337b51d50dccea2065b45cebcf1956bf851fafaf2c831af2ce1542` for the 0.8.0 engine and `b8d67413042362143851bcfd3bae0057f04f6e3fba6d561c4e072b96d4cfea7d` for 0.10.0. These controlled faults establish behavior in the tested scenarios, not general internet latency, throughput, or long-term network reliability.

## Scheduling and bounds

A and AAAA queries run concurrently with connection attempts. If IPv4 arrives first, the initial resolution window is at most 50 ms; an available recent IPv4 hint skips that window. IPv6 is preferred when both families are ready. Available addresses alternate by family and are deduplicated. No more than eight TCP attempts start for one dial. The final slot remains available for a second family whose DNS answer is still pending.

The default attempt spacing is 250 ms. A recent successful path supplies a smoothed TCP setup time; twice that time, bounded to 100-250 ms, sets the next dial's spacing. An explicit connection failure advances the next attempt after 10 ms. Caller connection timeouts still apply, and the dialer has its own 60-second upper bound. A winner or cancellation drops every remaining attempt and unfinished DNS future before returning control. There are no detached retry tasks.

Path hints retain at most 512 host-and-port entries for five minutes. They reorder addresses from the current lookup and cannot add an old address to a new DNS response. DNS clearing or reconfiguration and detected physical-interface changes invalidate hints. Results started before invalidation cannot populate the new epoch. Metadata hiding clears and disables per-host hints. These hints reflect TCP connection success; they do not establish that TLS, proxy credentials, or an application request succeeded.

The scheduler draws on the asynchronous resolution and staggered-connection approach in [RFC 8305](https://www.rfc-editor.org/rfc/rfc8305.html). It does not claim complete RFC 8305 or RFC 6724 conformance; there is no NAT64/DNS64 implementation or application-request replay. UDP destination resolution retains its existing behavior.

## Shared DNS work

Ordinary queries share work only when configuration generation, normalized name, record type, class, recursion-desired flag, and authenticated-data flag agree. EDNS, checking-disabled, and unusual query sections or flags bypass this cache and sharing path. Every caller receives its own transaction ID. Negative responses can be shared by concurrent callers but do not enter the positive cache.

At most 512 distinct ordinary questions can be pending in the shared registry. Each logical query has a 40-second budget, in addition to per-upstream timeouts. Cancelling a follower leaves the current owner alone. Cancelling the owner drops its network future and lets a surviving follower become the new owner; this can require another upstream query. Cancelling all callers releases the registry entry and network work. Old-generation replies cannot fill a new-generation cache.

The DNS snapshot exposes `coalesced` (joins to shared work), `upstreamQueries` (upstream attempts, including provider fallback), and `inFlight` (distinct shared questions still pending). Existing misses count logical cache misses, so they are not the upstream request count. The dialer reports started, successful, failed, cancelled, and active dials; attempt counts; multi-attempt successes; and hint hits. Exported counters contain no destination list. A TCP success does not imply an HTTPS check passed.

## Reproduce the comparison

The fixture uses local UDP DNS, a local SOCKS5 listener, and IPv4/IPv6 loopback echo servers. It sends no external requests and runs the engine with system-network writes disabled. Both loopback families must be available. It measures SOCKS CONNECT through receipt of an echoed payload, excluding the initial SOCKS greeting.

```powershell
python tests/connection_quality.py --engine dist/Harbor-0.10.0-preview-win-x64/harbor-engine.exe --baseline path/to/Harbor-0.8.0/harbor-engine.exe
```

The normal build runs all five scenarios against the packaged engine. Set `HARBOR_BASELINE_ENGINE` to an earlier executable before building to include a comparison. Each scenario uses a fresh engine. Slow-family and long-list samples use unique names and zero-TTL replies; the concurrent burst and hint scenario deliberately use caching. The report records both engine hashes in `.cache/connection-quality.json`, and matching evidence is included in the Windows package.

The five scenarios inject a 1,200 ms AAAA delay with usable IPv4, eight unusable IPv4 addresses plus usable IPv6, 32 synchronized connections with 200 ms DNS delay, repeated connections before/after hint invalidation and metadata hiding, and startup preflight with one slow DNS family. The first three report sample counts, failures, median, and p95. With seven or three samples, p95 is the slowest sample; these small fixtures expose specific faults and are not a population estimate or internet speed benchmark.
