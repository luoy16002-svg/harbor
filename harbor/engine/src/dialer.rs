//! Streaming dual-stack connection scheduling with bounded, caller-owned attempts.
use crate::{dns::Resolver, net::Egress};
use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, stream::FuturesUnordered};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    net::SocketAddr,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpStream, time::Instant};

const MAX_ATTEMPTS: usize = 8;
const RESOLUTION_DELAY: Duration = Duration::from_millis(50);
const DEFAULT_DELAY: Duration = Duration::from_millis(250);
const MIN_DELAY: Duration = Duration::from_millis(100);
const HINT_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, PartialEq, Eq)]
struct Network {
    active: bool,
    ipv4: u32,
    ipv6: u32,
}
impl Network {
    fn read(egress: &Egress) -> Self {
        Self {
            active: egress.active.load(Ordering::Acquire),
            ipv4: egress.ipv4.load(Ordering::Relaxed),
            ipv6: egress.ipv6.load(Ordering::Relaxed),
        }
    }
}
#[derive(Clone)]
struct Hint {
    address: SocketAddr,
    network: Network,
    recorded: Instant,
    tcp_time: Duration,
}
#[derive(Default)]
struct Memory {
    epoch: u64,
    hints: HashMap<String, Hint>,
}

#[derive(Default)]
pub struct Dialer {
    memory: Mutex<Memory>,
    metadata_hidden: AtomicBool,
    started: AtomicU64,
    succeeded: AtomicU64,
    failed: AtomicU64,
    cancelled: AtomicU64,
    active: AtomicU64,
    attempts: AtomicU64,
    active_attempts: AtomicU64,
    cancelled_attempts: AtomicU64,
    fallbacks: AtomicU64,
    remembered: AtomicU64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DialStats {
    pub started: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub active: u64,
    pub attempts: u64,
    pub active_attempts: u64,
    pub cancelled_attempts: u64,
    pub fallbacks: u64,
    pub remembered: u64,
    pub remembered_paths: usize,
}

struct Work<'a> {
    active: &'a AtomicU64,
    cancelled: &'a AtomicU64,
    finished: bool,
}
impl<'a> Work<'a> {
    fn new(active: &'a AtomicU64, cancelled: &'a AtomicU64) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self {
            active,
            cancelled,
            finished: false,
        }
    }
}
impl Drop for Work<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        if !self.finished {
            self.cancelled.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Dialer {
    pub(crate) fn set_metadata_hidden(&self, hidden: bool) {
        if self.metadata_hidden.swap(hidden, Ordering::SeqCst) != hidden {
            self.clear();
        }
    }
    pub(crate) fn clear(&self) {
        let mut memory = self.memory.lock().unwrap();
        memory.epoch = memory.epoch.wrapping_add(1);
        memory.hints.clear();
    }
    pub fn stats(&self) -> DialStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        DialStats {
            started: load(&self.started),
            succeeded: load(&self.succeeded),
            failed: load(&self.failed),
            cancelled: load(&self.cancelled),
            active: load(&self.active),
            attempts: load(&self.attempts),
            active_attempts: load(&self.active_attempts),
            cancelled_attempts: load(&self.cancelled_attempts),
            fallbacks: load(&self.fallbacks),
            remembered: load(&self.remembered),
            remembered_paths: self
                .memory
                .lock()
                .unwrap()
                .hints
                .values()
                .filter(|hint| hint.recorded.elapsed() < HINT_TTL)
                .count(),
        }
    }
    pub(crate) async fn connect(
        &self,
        resolver: &Resolver,
        host: &str,
        port: u16,
    ) -> Result<TcpStream> {
        self.started.fetch_add(1, Ordering::Relaxed);
        let mut work = Work::new(&self.active, &self.cancelled);
        let key = format!("{}:{port}", host.trim_end_matches('.').to_lowercase());
        let network = Network::read(&resolver.egress);
        let (epoch, hint) = {
            let memory = self.memory.lock().unwrap();
            (
                memory.epoch,
                memory
                    .hints
                    .get(&key)
                    .filter(|hint| {
                        !self.metadata_hidden.load(Ordering::SeqCst)
                            && hint.recorded.elapsed() < HINT_TTL
                            && hint.network == network
                    })
                    .cloned(),
            )
        };
        let delay = hint.as_ref().map_or(DEFAULT_DELAY, |hint| {
            hint.tcp_time
                .saturating_mul(2)
                .clamp(MIN_DELAY, DEFAULT_DELAY)
        });
        let result = tokio::time::timeout(
            Duration::from_secs(60),
            race(
                resolver.lookup_family(host, port, false),
                resolver.lookup_family(host, port, true),
                hint.as_ref().map(|hint| hint.address),
                delay,
                |address| async move {
                    self.attempts.fetch_add(1, Ordering::Relaxed);
                    let mut attempt = Work::new(&self.active_attempts, &self.cancelled_attempts);
                    let started = Instant::now();
                    let result = resolver.egress.tcp(address).await;
                    attempt.finished = true;
                    result.map(|stream| (stream, started.elapsed()))
                },
            ),
        )
        .await
        .context("TCP connection budget expired")
        .and_then(|result| result);
        work.finished = true;
        match result {
            Ok((address, (stream, tcp_time), attempts, remembered)) => {
                self.succeeded.fetch_add(1, Ordering::Relaxed);
                if attempts > 1 {
                    self.fallbacks.fetch_add(1, Ordering::Relaxed);
                }
                if remembered {
                    self.remembered.fetch_add(1, Ordering::Relaxed);
                }
                let mut memory = self.memory.lock().unwrap();
                if !self.metadata_hidden.load(Ordering::SeqCst)
                    && memory.epoch == epoch
                    && Network::read(&resolver.egress) == network
                {
                    memory
                        .hints
                        .retain(|_, hint| hint.recorded.elapsed() < HINT_TTL);
                    if memory.hints.len() >= 512
                        && !memory.hints.contains_key(&key)
                        && let Some(old) = memory
                            .hints
                            .iter()
                            .min_by_key(|(_, hint)| hint.recorded)
                            .map(|(key, _)| key.clone())
                    {
                        memory.hints.remove(&old);
                    }
                    let tcp_time = hint
                        .as_ref()
                        .filter(|hint| hint.address == address)
                        .map_or(tcp_time, |hint| (hint.tcp_time * 3 + tcp_time) / 4);
                    memory.hints.insert(
                        key,
                        Hint {
                            address,
                            network,
                            recorded: Instant::now(),
                            tcp_time,
                        },
                    );
                }
                Ok(stream)
            }
            Err(error) => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                bail!("Connection setup failed for {host}:{port}: {error:#}")
            }
        }
    }
}

async fn race<V4, V6, Connect, Connected, Stream>(
    v4: V4,
    v6: V6,
    hint: Option<SocketAddr>,
    delay: Duration,
    mut connect: Connect,
) -> Result<(SocketAddr, Stream, usize, bool)>
where
    V4: Future<Output = Result<Vec<SocketAddr>>>,
    V6: Future<Output = Result<Vec<SocketAddr>>>,
    Connect: FnMut(SocketAddr) -> Connected,
    Connected: Future<Output = Result<Stream>>,
{
    tokio::pin!(v4, v6);
    let mut done = [false, false];
    let mut queues = [VecDeque::new(), VecDeque::new()];
    let mut seen = HashSet::new();
    let mut tried = [0usize, 0];
    let mut errors = Vec::new();
    let mut pending = FuturesUnordered::new();
    let mut started = 0;
    let mut last_family = None;
    let mut next = Instant::now();
    let mut resolution_until = None;
    let mut used_hint = false;
    loop {
        if pending.is_empty()
            && (started == MAX_ATTEMPTS
                || (done.iter().all(|value| *value) && queues.iter().all(VecDeque::is_empty)))
        {
            if started == 0 {
                bail!("DNS lookup failed: {}", errors.join("; "));
            }
            bail!("All destination addresses failed: {}", errors.join("; "));
        }
        let preferred = last_family.map_or_else(
            || hint.map_or(1, |address| usize::from(address.is_ipv6())),
            |family| 1 - family,
        );
        let family = if !queues[preferred].is_empty() {
            preferred
        } else {
            1 - preferred
        };
        // Keep one attempt available for a late second family; never spend the complete budget on one unresolved family.
        let reserved = started == MAX_ATTEMPTS - 1 && tried[1 - family] == 0 && !done[1 - family];
        let launch = started < MAX_ATTEMPTS && !queues[family].is_empty() && !reserved;
        let at = if started == 0
            && !done[1]
            && queues[1].is_empty()
            && hint.is_none_or(|address| address.is_ipv6())
        {
            resolution_until.unwrap_or(next).max(next)
        } else {
            next
        };
        tokio::select! {
            biased;
            result = &mut v6, if !done[1] => {
                done[1] = true;
                add_answers(result, true, hint, &mut queues, &mut seen, &mut errors);
            }
            result = &mut v4, if !done[0] => {
                done[0] = true; resolution_until = Some(Instant::now() + RESOLUTION_DELAY);
                add_answers(result, false, hint, &mut queues, &mut seen, &mut errors);
            }
            Some((address, result)) = pending.next(), if !pending.is_empty() => {
                match result {
                    Ok(stream) => return Ok((address, stream, started, used_hint && Some(address) == hint)),
                    Err(error) => { errors.push(format!("{error:#}")); next = Instant::now() + Duration::from_millis(10); }
                }
            }
            _ = tokio::time::sleep_until(at), if launch => {
                let address = queues[family].pop_front().unwrap();
                used_hint |= started == 0 && Some(address) == hint;
                started += 1; tried[family] += 1; last_family = Some(family);
                let attempt = connect(address); pending.push(async move { (address, attempt.await) });
                next = Instant::now() + delay;
            }
        }
    }
}

fn add_answers(
    result: Result<Vec<SocketAddr>>,
    ipv6: bool,
    hint: Option<SocketAddr>,
    queues: &mut [VecDeque<SocketAddr>; 2],
    seen: &mut HashSet<SocketAddr>,
    errors: &mut Vec<String>,
) {
    match result {
        Ok(mut addresses) => {
            addresses.retain(|address| address.is_ipv6() == ipv6 && seen.insert(*address));
            addresses.truncate(8);
            addresses.sort_by_key(|address| Some(*address) != hint);
            queues[usize::from(ipv6)].extend(addresses);
        }
        Err(error) => errors.push(format!("{}: {error:#}", if ipv6 { "AAAA" } else { "A" })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicUsize};

    fn v4(n: u8) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, n], 80))
    }
    fn v6(n: u16) -> SocketAddr {
        SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, n)),
            80,
        )
    }
    async fn resolved(wait: u64, addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>> {
        tokio::time::sleep(Duration::from_millis(wait)).await;
        Ok(addresses)
    }
    #[derive(Default)]
    struct Counters {
        active: AtomicUsize,
        peak: AtomicUsize,
        dropped: AtomicUsize,
        addresses: Mutex<Vec<SocketAddr>>,
    }
    struct Attempt {
        counters: Arc<Counters>,
    }
    impl Attempt {
        fn new(counters: &Arc<Counters>, address: SocketAddr) -> Self {
            counters.addresses.lock().unwrap().push(address);
            let active = counters.active.fetch_add(1, Ordering::SeqCst) + 1;
            counters.peak.fetch_max(active, Ordering::SeqCst);
            Self {
                counters: counters.clone(),
            }
        }
    }
    impl Drop for Attempt {
        fn drop(&mut self) {
            self.counters.active.fetch_sub(1, Ordering::SeqCst);
            self.counters.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_ready_address_does_not_wait_for_the_other_dns_family() {
        let started = Instant::now();
        let result = race(
            resolved(5, vec![v4(1)]),
            resolved(2000, vec![v6(1)]),
            None,
            DEFAULT_DELAY,
            |_| async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(result.0, v4(1));
        assert_eq!(result.2, 1);
        assert!(started.elapsed() < Duration::from_millis(100));
    }
    #[tokio::test(start_paused = true)]
    async fn ipv6_arriving_within_the_resolution_window_is_preferred() {
        let started = Instant::now();
        let result = race(
            resolved(5, vec![v4(1)]),
            resolved(25, vec![v6(1)]),
            None,
            DEFAULT_DELAY,
            |_| async { Ok(()) },
        )
        .await
        .unwrap();
        assert_eq!(result.0, v6(1));
        assert_eq!(result.2, 1);
        assert!(started.elapsed() < RESOLUTION_DELAY);
    }
    #[tokio::test(start_paused = true)]
    async fn a_stalled_family_loses_to_the_staggered_alternative_and_is_dropped() {
        let counters = Arc::new(Counters::default());
        let started = Instant::now();
        let result = race(
            resolved(0, vec![v4(1)]),
            resolved(0, vec![v6(1)]),
            None,
            DEFAULT_DELAY,
            |address| {
                let counters = counters.clone();
                async move {
                    let _attempt = Attempt::new(&counters, address);
                    tokio::time::sleep(if address.is_ipv6() {
                        Duration::from_secs(5)
                    } else {
                        Duration::from_millis(5)
                    })
                    .await;
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result.0, v4(1));
        assert_eq!(result.2, 2);
        assert!(
            started.elapsed() >= DEFAULT_DELAY && started.elapsed() < Duration::from_millis(300)
        );
        assert_eq!(counters.active.load(Ordering::SeqCst), 0);
        assert_eq!(counters.dropped.load(Ordering::SeqCst), 2);
    }
    #[tokio::test(start_paused = true)]
    async fn immediate_errors_advance_without_waiting_the_normal_stagger() {
        let started = Instant::now();
        let result = race(
            resolved(0, vec![v4(1)]),
            resolved(0, vec![v6(1)]),
            None,
            DEFAULT_DELAY,
            |address| async move {
                if address.is_ipv6() {
                    bail!("immediate fixture refusal");
                }
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(result.0, v4(1));
        assert!(started.elapsed() < Duration::from_millis(40));
    }
    #[tokio::test(start_paused = true)]
    async fn a_long_first_family_cannot_consume_the_late_second_familys_attempt() {
        let counters = Arc::new(Counters::default());
        let result = race(
            resolved(0, (1..=8).map(v4).collect()),
            resolved(2300, vec![v6(1)]),
            None,
            DEFAULT_DELAY,
            |address| {
                let counters = counters.clone();
                async move {
                    let _attempt = Attempt::new(&counters, address);
                    if address.is_ipv4() {
                        std::future::pending::<()>().await;
                    }
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result.0, v6(1));
        assert_eq!(result.2, MAX_ATTEMPTS);
        assert_eq!(counters.peak.load(Ordering::SeqCst), MAX_ATTEMPTS);
        assert_eq!(counters.active.load(Ordering::SeqCst), 0);
    }
    #[tokio::test(start_paused = true)]
    async fn cancelling_the_caller_drops_every_attempt_and_never_starts_queued_work() {
        let counters = Arc::new(Counters::default());
        let work = race(
            resolved(0, (1..=8).map(v4).collect()),
            resolved(0, (1..=8).map(v6).collect()),
            None,
            DEFAULT_DELAY,
            |address| {
                let counters = counters.clone();
                async move {
                    let _attempt = Attempt::new(&counters, address);
                    std::future::pending::<()>().await;
                    Ok(())
                }
            },
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(350), work)
                .await
                .is_err()
        );
        assert_eq!(counters.active.load(Ordering::SeqCst), 0);
        assert_eq!(counters.addresses.lock().unwrap().len(), 2);
        tokio::time::advance(Duration::from_secs(120)).await;
        assert_eq!(counters.addresses.lock().unwrap().len(), 2);
    }
    #[tokio::test(start_paused = true)]
    async fn exhausted_candidates_are_unique_interleaved_and_bounded() {
        let counters = Arc::new(Counters::default());
        let mut many = (1..=8).map(v4).collect::<Vec<_>>();
        many.extend(many.clone());
        let error = race(
            resolved(0, many),
            resolved(0, (1..=8).map(v6).collect()),
            None,
            DEFAULT_DELAY,
            |address| {
                let counters = counters.clone();
                async move {
                    let _attempt = Attempt::new(&counters, address);
                    bail!("fixture TCP failure");
                    #[allow(unreachable_code)]
                    Ok(())
                }
            },
        )
        .await
        .unwrap_err();
        let addresses = counters.addresses.lock().unwrap();
        assert_eq!(addresses.len(), MAX_ATTEMPTS);
        assert_eq!(addresses.iter().collect::<HashSet<_>>().len(), MAX_ATTEMPTS);
        assert!(
            addresses
                .windows(2)
                .all(|pair| pair[0].is_ipv6() != pair[1].is_ipv6())
        );
        assert!(
            error
                .to_string()
                .contains("All destination addresses failed")
        );
    }
    #[tokio::test(start_paused = true)]
    async fn remembered_paths_only_reorder_current_answers_and_do_not_wait_for_dns() {
        let remembered = v4(7);
        let result = race(
            resolved(0, vec![v4(1), remembered]),
            resolved(0, vec![v6(1)]),
            Some(remembered),
            MIN_DELAY,
            |_| async { Ok(()) },
        )
        .await
        .unwrap();
        assert_eq!(result.0, remembered);
        assert!(result.3);
        let result = race(
            resolved(500, vec![v4(1)]),
            resolved(0, vec![v6(1)]),
            Some(remembered),
            MIN_DELAY,
            |_| async { Ok(()) },
        )
        .await
        .unwrap();
        assert_eq!(result.0, v6(1));
        assert!(!result.3);
        let result = race(
            resolved(0, vec![v4(1)]),
            resolved(0, vec![v6(1)]),
            Some(remembered),
            MIN_DELAY,
            |_| async { Ok(()) },
        )
        .await
        .unwrap();
        assert_ne!(result.0, remembered);
        assert!(!result.3);
    }
    #[tokio::test(start_paused = true)]
    async fn failed_resolution_keeps_both_causes_and_starts_no_tcp_work() {
        let error = race(
            async { bail!("NXDomain") },
            async { bail!("fixture DNS timeout") },
            None,
            DEFAULT_DELAY,
            |_| async {
                panic!("TCP must not start without a DNS address");
                #[allow(unreachable_code)]
                Ok(())
            },
        )
        .await
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("A: NXDomain") && message.contains("AAAA: fixture DNS timeout"));
    }
}
