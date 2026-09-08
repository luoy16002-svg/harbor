//! Opt-in proxy pools: bounded HTTPS monitoring and pre-payload connection recovery.
use crate::{
    config::{Config, Group, GroupKind, Node},
    telemetry::now_ms,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct PoolSettings {
    pub monitor: bool,
    pub check_url: String,
    pub check_interval_secs: u64,
    pub check_timeout_ms: u64,
    pub connect_attempts: usize,
    pub attempt_timeout_ms: u64,
    pub ca_pem: String,
}
impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            monitor: true,
            check_url: "https://www.example.com/".into(),
            check_interval_secs: 120,
            check_timeout_ms: 8000,
            connect_attempts: 3,
            attempt_timeout_ms: 3000,
            ca_pem: String::new(),
        }
    }
}
impl PoolSettings {
    pub fn validate(&self) -> Result<()> {
        CheckTarget::parse(&self.check_url)?;
        ensure!(
            (30..=3600).contains(&self.check_interval_secs),
            "Pool check interval must be 30–3600 seconds"
        );
        ensure!(
            (1000..=15000).contains(&self.check_timeout_ms),
            "Pool check timeout must be 1000–15000 ms"
        );
        ensure!(
            (1..=3).contains(&self.connect_attempts),
            "Pool connection attempts must be 1–3"
        );
        ensure!(
            (500..=10000).contains(&self.attempt_timeout_ms),
            "Pool attempt timeout must be 500–10000 ms"
        );
        ensure!(self.ca_pem.len() <= 65536, "Pool CA exceeds 64 KiB");
        if !self.ca_pem.is_empty() {
            crate::transport::validate_ca(&self.ca_pem)?;
        }
        Ok(())
    }
}

pub fn validate(config: &Config) -> Result<()> {
    let pools: Vec<_> = config
        .groups
        .iter()
        .filter(|group| group.pool.is_some())
        .collect();
    ensure!(
        pools.len() <= 8,
        "At most eight automatic pools are supported"
    );
    ensure!(
        pools.iter().map(|group| group.members.len()).sum::<usize>() <= 256,
        "Automatic pools allow at most 256 total member entries"
    );
    for group in pools {
        group.pool.as_ref().unwrap().validate()?;
        ensure!(
            group.kind != GroupKind::Select,
            "An automatic pool cannot use manual selection"
        );
        ensure!(
            group.members.len() <= 128,
            "A pool allows at most 128 proxy members"
        );
        ensure!(
            group
                .members
                .iter()
                .all(|name| config.nodes.iter().any(|node| &node.name == name)),
            "Pool members must be concrete proxies; DIRECT and REJECT are not permitted"
        );
    }
    Ok(())
}

pub struct CheckTarget {
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub path: String,
}
impl CheckTarget {
    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            !value.is_empty()
                && value.len() <= 2048
                && value.trim() == value
                && !value.chars().any(char::is_control),
            "Invalid pool HTTPS URL"
        );
        let url = url::Url::parse(value)?;
        ensure!(
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "Pool checks require HTTPS without user information or fragments"
        );
        let host = url
            .host()
            .ok_or_else(|| anyhow::anyhow!("Missing pool check host"))?
            .to_string();
        // URL's IPv6 host rendering includes brackets; TLS and proxy destinations do not.
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        ensure!(port != 0, "Pool check port must be nonzero");
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let mut path = url.path().to_string();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        Ok(Self {
            host,
            port,
            authority,
            path,
        })
    }
}

pub fn fingerprint(config: &Config, group: &Group, node: &Node) -> [u8; 32] {
    let settings = group.pool.as_ref().expect("Pool settings required");
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(&(
            node,
            &settings.check_url,
            &settings.ca_pem,
            &config.dns_servers,
            &config.dns_tls,
            &config.egress_mode,
            config.privacy.block_direct,
            config.privacy.require_encrypted_proxy,
            &config.privacy.blocked_domains,
            &config.privacy.allowed_domains,
        ))
        .expect("Configuration has a JSON representation"),
    );
    Sha256::digest(bytes.as_slice()).into()
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolHealth {
    pub name: String,
    pub state: String,
    pub checking: bool,
    pub checked_at: Option<u64>,
    pub latency_ms: Option<f64>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub checks: u32,
    pub error_category: Option<String>,
    pub samples: Vec<Option<f64>>,
    #[serde(skip)]
    pub identity: [u8; 32],
    #[serde(skip)]
    pub updated: Option<Instant>,
    #[serde(skip)]
    pub due: Instant,
    #[serde(skip)]
    pub cooldown: Option<Instant>,
}
impl PoolHealth {
    pub fn new(name: &str, identity: [u8; 32], now: Instant) -> Self {
        Self {
            name: name.into(),
            state: "unknown".into(),
            checking: false,
            checked_at: None,
            latency_ms: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            checks: 0,
            error_category: None,
            samples: vec![],
            identity,
            updated: None,
            due: now,
            cooldown: None,
        }
    }
    pub fn fresh(&self, now: Instant, interval: u64) -> bool {
        self.updated.is_some_and(|updated| {
            now.saturating_duration_since(updated)
                <= Duration::from_secs(interval.saturating_mul(3))
        })
    }
    pub fn record(&mut self, result: Result<f64, &str>, now: Instant, interval: u64) {
        self.checking = false;
        self.updated = Some(now);
        self.checked_at = Some(now_ms());
        self.due = now + Duration::from_secs(interval);
        self.checks = self.checks.saturating_add(1);
        match result {
            Ok(ms) => {
                self.state = "healthy".into();
                self.consecutive_failures = 0;
                self.consecutive_successes = self.consecutive_successes.saturating_add(1);
                self.latency_ms = Some(
                    self.latency_ms
                        .map_or(ms, |previous| previous * 0.75 + ms * 0.25),
                );
                self.error_category = None;
                self.cooldown = None;
                self.samples.push(Some(ms));
            }
            Err("policy") => {
                self.state = "blocked".into();
                self.error_category = Some("policy".into());
                self.samples.push(None);
            }
            Err(category) => {
                self.consecutive_successes = 0;
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                self.state = if self.latency_ms.is_none() || self.consecutive_failures >= 2 {
                    "unavailable"
                } else {
                    "degraded"
                }
                .into();
                self.error_category = Some(category.into());
                self.samples.push(None);
            }
        }
        if self.samples.len() > 20 {
            self.samples.remove(0);
        }
    }
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolStats {
    pub connections: u64,
    pub attempts: u64,
    pub recovered: u64,
    pub failed: u64,
    pub last_outbound: Option<String>,
    pub last_recovery_at: Option<u64>,
    #[serde(skip)]
    pub last_outbound_at: Option<u64>,
}
impl PoolStats {
    pub fn prune(&mut self, privacy: &crate::privacy::Privacy) {
        let retain = privacy.history_secs.saturating_mul(1000);
        let now = now_ms();
        if privacy.hide_metadata
            || retain == 0
            || self
                .last_outbound_at
                .is_none_or(|at| now.saturating_sub(at) >= retain)
        {
            self.last_outbound = None;
            self.last_outbound_at = None;
        }
        if privacy.hide_metadata
            || retain == 0
            || self
                .last_recovery_at
                .is_some_and(|at| now.saturating_sub(at) >= retain)
        {
            self.last_recovery_at = None;
        }
    }
}

impl crate::policy::Selector {
    pub fn reconcile_pools(&mut self, config: &Config) {
        let now = Instant::now();
        self.pool_health.retain(|(group, node), _| {
            config
                .groups
                .iter()
                .any(|g| &g.name == group && g.pool.is_some() && g.members.contains(node))
        });
        self.pool_stats.retain(|name, _| {
            config
                .groups
                .iter()
                .any(|g| &g.name == name && g.pool.is_some())
        });
        for group in config.groups.iter().filter(|g| g.pool.is_some()) {
            let stats = self.pool_stats.entry(group.name.clone()).or_default();
            stats.prune(&config.privacy);
            if config.privacy.hide_metadata
                || stats
                    .last_outbound
                    .as_ref()
                    .is_some_and(|n| !group.members.contains(n))
            {
                stats.last_outbound = None;
                stats.last_outbound_at = None;
                stats.last_recovery_at = None;
            }
            for node in config
                .nodes
                .iter()
                .filter(|n| group.members.contains(&n.name))
            {
                let identity = fingerprint(config, group, node);
                let health = self
                    .pool_health
                    .entry((group.name.clone(), node.name.clone()))
                    .or_insert_with(|| PoolHealth::new(&node.name, identity, now));
                if health.identity != identity {
                    *health = PoolHealth::new(&node.name, identity, now);
                }
                health.checking = false;
                if let Some(updated) = health.updated {
                    health.due = updated
                        + Duration::from_secs(group.pool.as_ref().unwrap().check_interval_secs);
                }
            }
        }
    }
    pub fn pool_verified(&self, group: &Group, node: &str, now: Instant) -> bool {
        group.pool.as_ref().is_some_and(|p| {
            p.monitor
                && self
                    .pool_health
                    .get(&(group.name.clone(), node.into()))
                    .is_some_and(|h| {
                        h.fresh(now, p.check_interval_secs)
                            && matches!(h.state.as_str(), "healthy" | "degraded")
                    })
        })
    }
    pub fn pool_usable(&self, group: &Group, node: &str, now: Instant) -> bool {
        if let Some(settings) = &group.pool
            && let Some(h) = self.pool_health.get(&(group.name.clone(), node.into()))
        {
            if h.cooldown.is_some_and(|until| until > now) {
                return false;
            }
            if settings.monitor && h.fresh(now, settings.check_interval_secs) {
                if h.state == "unavailable" {
                    return false;
                }
                if matches!(h.state.as_str(), "healthy" | "degraded") {
                    return true;
                }
            }
        }
        node == "DIRECT"
            || self
                .health
                .get(node)
                .is_none_or(|h| h.state != "unavailable")
    }
    pub fn retry_candidates(
        &self,
        config: &Config,
        decision: &crate::policy::Decision,
    ) -> Vec<String> {
        let mut result = vec![decision.outbound.clone()];
        if decision.outbound == "REJECT" {
            return result;
        }
        if let Some(group) = config
            .groups
            .iter()
            .find(|g| g.name == decision.policy && g.pool.is_some())
        {
            let mut rest: Vec<_> = group
                .members
                .iter()
                .filter(|name| {
                    *name != &decision.outbound
                        && self.pool_usable(group, name, Instant::now())
                        && config.nodes.iter().any(|n| {
                            &n.name == *name
                                && (!decision.require_encrypted_proxy
                                    || crate::privacy::encrypted(n, "tcp"))
                        })
                })
                .collect();
            let now = Instant::now();
            rest.sort_by(|a, b| {
                let verified = self
                    .pool_verified(group, b, now)
                    .cmp(&self.pool_verified(group, a, now));
                if verified.is_eq() && group.kind == GroupKind::Latency {
                    let ms = |n: &str| {
                        if self.pool_verified(group, n, now) {
                            self.pool_health
                                .get(&(group.name.clone(), n.into()))
                                .and_then(|h| h.latency_ms)
                                .unwrap_or(f64::INFINITY)
                        } else {
                            f64::INFINITY
                        }
                    };
                    ms(a).total_cmp(&ms(b))
                } else {
                    verified
                }
            });
            result.extend(
                rest.into_iter()
                    .take(group.pool.as_ref().unwrap().connect_attempts - 1)
                    .cloned(),
            );
        }
        result
    }
    pub fn pools_snapshot(&self, config: &Config) -> serde_json::Value {
        serde_json::Value::Array(config.groups.iter().filter_map(|g| g.pool.as_ref().map(|settings| {
            let members: Vec<_> = g.members.iter().filter_map(|n| self.pool_health.get(&(g.name.clone(), n.clone()))).map(|h| {
                let mut value = serde_json::to_value(h).unwrap();
                value["fresh"] = serde_json::json!(settings.monitor && h.fresh(Instant::now(), settings.check_interval_secs));
                value["coolingDown"] = serde_json::json!(h.cooldown.is_some_and(|until| until > Instant::now())); value
            }).collect();
            serde_json::json!({"name":g.name,"monitor":settings.monitor,"members":members,"stats":self.pool_stats.get(&g.name)})
        })).collect())
    }
}

impl crate::engine::Engine {
    pub fn clear_pool_history(&self) {
        for stats in self.selector.lock().unwrap().pool_stats.values_mut() {
            stats.last_outbound = None;
            stats.last_outbound_at = None;
            stats.last_recovery_at = None;
        }
    }
    pub fn invalidate_pools(&self) {
        let mut selector = self.selector.lock().unwrap();
        for h in selector.pool_health.values_mut() {
            *h = PoolHealth::new(&h.name, h.identity, Instant::now());
        }
        self.pool_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn check_pool(&self, name: &str) -> Result<()> {
        ensure!(!self.cancel.is_cancelled(), "Engine is stopped");
        let current = self.current.load();
        let group = current
            .config
            .groups
            .iter()
            .find(|g| g.name == name && g.pool.is_some())
            .ok_or_else(|| anyhow::anyhow!("Unknown automatic pool"))?;
        ensure!(
            group.pool.as_ref().unwrap().monitor,
            "Resume pool monitoring before checking"
        );
        let now = Instant::now();
        for ((pool, _), health) in &mut self.selector.lock().unwrap().pool_health {
            if pool == name
                && !health.checking
                && health
                    .updated
                    .is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(3))
            {
                health.due = now;
            }
        }
        Ok(())
    }
}

/// There are never more than two live checks or 256 scheduled member records.
pub async fn monitor(engine: std::sync::Arc<crate::engine::Engine>) {
    use std::sync::atomic::Ordering;
    let mut tasks = tokio::task::JoinSet::new();
    let mut generation = 0;
    let mut epoch = 0;
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! { biased;
            _ = engine.cancel.cancelled() => break,
            _ = timer.tick() => {},
        }
        let snapshot = engine.current.load_full();
        let current_epoch = engine.pool_epoch.load(Ordering::SeqCst);
        if generation != snapshot.generation || epoch != current_epoch {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            for health in engine.selector.lock().unwrap().pool_health.values_mut() {
                health.checking = false;
            }
            generation = snapshot.generation;
            epoch = current_epoch;
        }
        while let Some(result) = tasks.try_join_next() {
            if let Ok((key, identity, result)) = result {
                let mut selector = engine.selector.lock().unwrap();
                if engine.current.load().generation == generation
                    && engine.pool_epoch.load(Ordering::SeqCst) == epoch
                    && let Some(h) = selector.pool_health.get_mut(&key)
                    && h.identity == identity
                    && let Some(settings) = snapshot
                        .config
                        .groups
                        .iter()
                        .find(|g| g.name == key.0)
                        .and_then(|g| g.pool.as_ref())
                {
                    h.record(result, Instant::now(), settings.check_interval_secs);
                }
            }
        }
        while tasks.len() < 2 {
            let job = {
                let mut selector = engine.selector.lock().unwrap();
                let key = selector
                    .pool_health
                    .iter()
                    .filter(|((group, _), h)| {
                        !h.checking
                            && h.due <= Instant::now()
                            && snapshot.config.groups.iter().any(|g| {
                                &g.name == group && g.pool.as_ref().is_some_and(|p| p.monitor)
                            })
                    })
                    .min_by_key(|(_, h)| h.due)
                    .map(|(key, _)| key.clone());
                key.map(|key| {
                    let h = selector.pool_health.get_mut(&key).unwrap();
                    h.checking = true;
                    (key, h.identity)
                })
            };
            let Some((key, identity)) = job else {
                break;
            };
            let snapshot = snapshot.clone();
            let resolver = engine.resolver.clone();
            tasks.spawn(async move {
                let settings = snapshot
                    .config
                    .groups
                    .iter()
                    .find(|g| g.name == key.0)
                    .unwrap()
                    .pool
                    .as_ref()
                    .unwrap();
                let target =
                    CheckTarget::parse(&settings.check_url).expect("Validated HTTPS target");
                let result = crate::verification::check_https(
                    &snapshot.config,
                    &resolver,
                    &key.1,
                    &target,
                    &settings.ca_pem,
                    settings.check_timeout_ms,
                )
                .await
                .map(|(_, ms)| ms)
                .map_err(|error| error.category);
                (key, identity, result)
            });
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    for health in engine.selector.lock().unwrap().pool_health.values_mut() {
        health.checking = false;
    }
}
