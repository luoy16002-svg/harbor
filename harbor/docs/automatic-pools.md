# Automatic proxy pools

The **Pools** page combines background HTTPS health checks with bounded connection recovery. Add the proxies you want Harbor to use, arrange their initial priority, then select the pool as the default outbound or assign it to an application/website traffic path. Pools are opt-in: existing groups keep their previous behavior until explicitly configured with pool settings.

## Desktop workflow

1. Import proxies and open **Pools → Create pool**.
2. Select a few primary and backup proxies. Search, select the filtered list, or select recently successful saved HTTPS checks. Move members up or down to set the initial order.
3. Choose stable selection or low-latency selection. New pools enable background checks by default; choose an HTTPS check URL and interval if the defaults do not suit your network.
4. Save and use **Set as default outbound**, or select the pool in a traffic path. In direct routing mode, the ordinary default outbound remains unused; an explicit matching traffic path can still use it.
5. Start Harbor. The pool page shows actual HTTPS outcomes, recent samples, recovered connection counts, and the most recently connected outbound. Connection details list every setup attempt and the winning proxy.

**Pause monitoring** pauses background checks while preserving connection recovery within the configured pool. **Check now** schedules the selected pool; it coalesces checks already in progress and checks completed within the previous three seconds. Stopping the engine cancels all pool checks and clears runtime pool statistics.

## What is checked

Each check establishes a tunnel through one concrete proxy, verifies the destination TLS certificate and hostname, and sends one HTTPS `HEAD` request. HTTP 200–399 is success. Redirects are not followed, response headers are limited to 8 KiB, and response bodies are not downloaded. The default destination is `https://www.example.com/`; a private health endpoint and an optional PEM trust certificate can be configured. Certificates are always verified.

The interval starts when a check completes. At most two pool checks run concurrently across all pools. Large pools may queue beyond their requested interval. The dashboard shows the check time and distinguishes expired results; elapsed time includes proxy setup, destination TLS and HTTP, and is not download throughput.

A new member starts unverified and can be tried immediately. A failed first HTTPS check makes it unavailable. A previously successful member remains eligible after one failed check, then becomes unavailable after a second consecutive failure. A successful HTTPS check restores eligibility immediately. Checks blocked by local privacy rules are shown separately and do not establish a proxy fault. Results older than three check intervals become unverified; TCP reachability can then inform selection, but it is never displayed as HTTPS success.

Fresh HTTPS success takes precedence over an older failed port probe. Verified eligible members are preferred over unverified members. Stable selection keeps its current eligible member and does not switch back merely because an earlier member recovered. Low-latency selection uses smoothed HTTPS times: changing a still-eligible member requires a 60-second hold, at least three consecutive successful checks, a 30 ms improvement, and at least 20% improvement. New traffic through an unchanged member does not restart that hold.

HTTPS checks validate TCP paths only. TCP/UDP support and global/per-path encryption requirements are still applied separately on every selection. A pool cannot contain DIRECT, REJECT, or another group. Exhaustion rejects the connection; it does not add direct egress.

## Connection recovery

SOCKS5 TCP, HTTP CONNECT, ordinary HTTP proxy requests, and TUN TCP all use the same pool connection setup. Each flow holds its original configuration generation. If setup fails before any application payload is forwarded, Harbor may try other eligible members from that pool. Attempts are unique and limited to three, including the first. Per-attempt timeouts share the existing global connection timeout; retries do not multiply the total deadline. Closing a connecting flow cancels its current attempt and prevents queued attempts from starting.

Confirmed upstream dial, TLS, WebSocket, or authentication failures place that member in a 15-second connection cooldown. Destination-specific CONNECT failures do not mark the proxy itself unavailable. Success records the actual winning outbound; it does not claim a full HTTPS check succeeded.

Established streams, application requests already sent, and UDP datagrams are never replayed onto a backup. Some protocols report authentication failure only after their setup method returns; those later failures are not retried. Periodic HTTPS checks help identify such failures for subsequent connections. Recovery is therefore bounded setup recovery, not migration of active sessions or a guarantee that every interrupted request will succeed.

## Configuration and privacy

An automatic pool extends an ordinary `fallback` or `latency` group:

```json
{
  "name": "daily-pool",
  "kind": "fallback",
  "members": ["primary-proxy", "backup-proxy"],
  "pool": {
    "monitor": true,
    "checkUrl": "https://www.example.com/",
    "checkIntervalSecs": 120,
    "checkTimeoutMs": 8000,
    "connectAttempts": 3,
    "attemptTimeoutMs": 3000,
    "caPem": ""
  }
}
```

| Limit | Value |
| --- | --- |
| Automatic pools | 8 |
| Members in one pool | 128 |
| Total pool-member entries | 256 |
| Concurrent background HTTPS checks | 2 |
| Check interval | 30–3600 seconds |
| HTTPS check timeout | 1000–15000 ms |
| Connection attempts | 1–3, including the first |
| Timeout per connection attempt | 500–10000 ms, within the global deadline |
| Check history | Last 20 samples per member, memory only |

Pool settings use the existing encrypted workspace and configuration history. Renaming proxies or pools updates their references; failed persistence rolls back the active configuration. A subscription update retains proxies referenced by a pool.

Health records are tied to proxy credentials, the check destination, DNS/trust settings, physical-network epoch, and global routing protections. Reconfiguration cancels obsolete checks; their results cannot update a newer generation. A detected physical-interface change invalidates pool health and schedules new checks. Live network-switch behavior has not been validated under native TUN capture.

The check service receives a request through every monitored proxy. Do not put a secret into a public check URL. Runtime snapshots omit the URL, trust material, and detailed probe errors; the editor necessarily displays the configured URL. Health samples and aggregate counters stay in memory. Connection attempt names follow metadata hiding. Recent outbound/recovery fields follow the configured retention period and are removed when connection history is cleared. This feature does not establish anonymity, IP reputation, censorship resistance, UDP availability, or compatibility with every destination.

## Verification

Local fixtures exercise authentication failure, TLS trust, configured request paths, HTTP status handling, recovery, setup cancellation, shared deadlines, stale-generation rejection, latency hysteresis, and metadata retention. A real SOCKS client verifies the recovered payload and recorded winner. The in-memory TUN stack verifies recovery before forwarding buffered payload and preserves a 256 KiB half-closed stream. Desktop workflows exercise pool creation, default selection, monitoring, rename/reference updates, active-stream preservation, encrypted history, and failed-save rollback. Independent Xray interop additionally checks recovery for SOCKS, pipelined CONNECT, and ordinary HTTP through an encrypted backup.

See [verification](verification.md) for the release-specific evidence and remaining live-network limits.
