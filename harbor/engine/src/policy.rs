use crate::config::{Config, GroupKind, RoutingMode, RuleKind};
use anyhow::{Result, bail, ensure};
use ipnet::IpNet;
use serde::Serialize;
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub policy: String,
    pub outbound: String,
    pub reason: String,
    pub rule_index: Option<usize>,
    pub generation: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    pub name: String,
    pub state: String,
    pub latency_ms: Option<f64>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub samples: Vec<Option<f64>>,
    #[serde(skip)]
    pub updated: Option<Instant>,
}
impl Health {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            state: "unknown".into(),
            latency_ms: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            samples: vec![],
            updated: None,
        }
    }
    pub fn record(&mut self, latency: Option<Duration>, now: Instant) {
        self.updated = Some(now);
        let sample = latency.map(|d| d.as_secs_f64() * 1000.0);
        self.samples.push(sample);
        if self.samples.len() > 60 {
            self.samples.remove(0);
        }
        if let Some(ms) = sample {
            self.latency_ms = Some(self.latency_ms.map_or(ms, |old| old * 0.75 + ms * 0.25));
            self.consecutive_failures = 0;
            self.consecutive_successes = self.consecutive_successes.saturating_add(1);
            if self.state != "unavailable" || self.consecutive_successes >= 2 {
                self.state = "healthy".into();
            }
        } else {
            self.consecutive_successes = 0;
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            if self.consecutive_failures >= 3 {
                self.state = "unavailable".into();
            } else if self.state != "unavailable" {
                self.state = "degraded".into();
            }
        }
    }
    fn usable(&self) -> bool {
        self.state != "unavailable"
    }
}

#[derive(Default)]
pub struct Selector {
    pub health: HashMap<String, Health>,
    chosen: HashMap<(String, bool, bool), (String, Instant)>,
}
impl Selector {
    pub fn reconcile(&mut self, config: &Config) {
        self.health
            .retain(|name, _| config.nodes.iter().any(|n| &n.name == name));
        for node in &config.nodes {
            self.health
                .entry(node.name.clone())
                .or_insert_with(|| Health::new(&node.name));
        }
        self.chosen.retain(|(name, _, _), (node, _)| {
            config
                .groups
                .iter()
                .any(|g| &g.name == name && g.members.contains(node))
        });
    }
    pub fn record(&mut self, name: &str, latency: Option<Duration>, now: Instant) {
        self.health
            .entry(name.into())
            .or_insert_with(|| Health::new(name))
            .record(latency, now);
    }
    pub fn choose(&mut self, config: &Config, name: &str, now: Instant) -> Result<String> {
        self.choose_guarded(config, name, now, false, "tcp")
    }
    pub fn choose_guarded(
        &mut self,
        config: &Config,
        name: &str,
        now: Instant,
        encrypted: bool,
        protocol: &str,
    ) -> Result<String> {
        let Some(group) = config.groups.iter().find(|g| g.name == name) else {
            return Ok(name.into());
        };
        if group.kind == GroupKind::Select {
            return Ok(group.selected.as_ref().unwrap_or(&group.members[0]).clone());
        }
        let usable = |n: &String| {
            (n == "DIRECT" || self.health.get(n).is_none_or(Health::usable))
                && (!encrypted
                    || config
                        .nodes
                        .iter()
                        .find(|node| &node.name == n)
                        .is_some_and(|node| crate::privacy::encrypted(node, protocol)))
        };
        let candidates: Vec<_> = group.members.iter().filter(|n| usable(n)).collect();
        if candidates.is_empty() {
            bail!("No healthy eligible outbound in group {name}; direct fallback is disabled");
        }
        let latency = |n: &str| {
            if n == "DIRECT" {
                0.0
            } else {
                self.health
                    .get(n)
                    .and_then(|h| h.latency_ms)
                    .unwrap_or(f64::INFINITY)
            }
        };
        let preferred = if group.kind == GroupKind::Latency {
            *candidates
                .iter()
                .min_by(|a, b| latency(a).total_cmp(&latency(b)))
                .unwrap()
        } else {
            candidates[0]
        };
        let key = (name.to_owned(), encrypted, encrypted && protocol == "udp");
        if let Some((current, switched)) = self.chosen.get(&key)
            && candidates.contains(&current)
        {
            if group.kind == GroupKind::Fallback
                || now.duration_since(*switched) < Duration::from_secs(60)
            {
                return Ok(current.clone());
            }
            let old = latency(current);
            let new = latency(preferred);
            let enough_samples = preferred == "DIRECT"
                || self
                    .health
                    .get(preferred)
                    .is_some_and(|h| h.consecutive_successes >= 3);
            if preferred == current || !enough_samples || old - new < 30.0 || new > old * 0.8 {
                return Ok(current.clone());
            }
        }
        self.chosen.insert(key, (preferred.clone(), now));
        Ok(preferred.clone())
    }
}

pub fn decide(
    config: &Config,
    selector: &mut Selector,
    host: &str,
    port: u16,
    protocol: &str,
    generation: u64,
) -> Result<Decision> {
    decide_filtered(
        config,
        selector,
        &crate::privacy::DomainFilter::new(&config.privacy),
        (host, port, protocol),
        generation,
    )
}
pub fn decide_filtered(
    config: &Config,
    selector: &mut Selector,
    filter: &crate::privacy::DomainFilter,
    target: (&str, u16, &str),
    generation: u64,
) -> Result<Decision> {
    decide_with_process(config, selector, filter, target, None, generation)
}

pub fn decide_with_process(
    config: &Config,
    selector: &mut Selector,
    filter: &crate::privacy::DomainFilter,
    target: (&str, u16, &str),
    process: Option<&str>,
    generation: u64,
) -> Result<Decision> {
    let (host, port, protocol) = target;
    ensure!(
        matches!(protocol, "tcp" | "udp"),
        "Route protocol must be tcp or udp"
    );
    let host = host.trim_end_matches('.').to_lowercase();
    if filter.blocked(&host) {
        return Ok(Decision {
            policy: "REJECT".into(),
            outbound: "REJECT".into(),
            reason: "Privacy: local domain block rule".into(),
            rule_index: None,
            generation,
        });
    }
    let ip = host.parse::<IpAddr>().ok();
    let matched = if config.routing_mode == RoutingMode::Rules {
        config.rules.iter().enumerate().find(|(_, rule)| {
            if !rule.enabled {
                return false;
            }
            let value = rule.value.trim_end_matches('.').to_lowercase();
            match rule.kind {
                RuleKind::Domain => ip.is_none() && host == value,
                RuleKind::DomainSuffix => {
                    ip.is_none() && (host == value || host.ends_with(&format!(".{value}")))
                }
                RuleKind::DomainKeyword => ip.is_none() && host.contains(&value),
                RuleKind::IpCidr => {
                    ip.is_some_and(|ip| value.parse::<IpNet>().is_ok_and(|net| net.contains(&ip)))
                }
                RuleKind::Port => value.parse::<u16>() == Ok(port),
                RuleKind::Protocol => value == protocol,
            }
        })
    } else {
        None
    };
    let route = config
        .traffic_routes
        .iter()
        .find(|route| route.domain_matches(&host) || route.process_matches(process));
    let protected = route.is_some_and(|route| route.require_encrypted_proxy);
    let (policy, reason, rule_index) = if let Some(route) = route {
        (
            route
                .policy
                .as_ref()
                .unwrap_or(&config.final_policy)
                .clone(),
            format!("PATH · {}", route.name),
            None,
        )
    } else if config.direct_exceptions.domain_matches(&host) {
        ("DIRECT".into(), "EXCEPTION · Domain suffix".into(), None)
    } else if config.direct_exceptions.process_matches(process) {
        ("DIRECT".into(), "EXCEPTION · Local process".into(), None)
    } else if config.routing_mode == RoutingMode::Direct {
        ("DIRECT".into(), "MODE · Direct".into(), None)
    } else if config.routing_mode == RoutingMode::Global {
        (
            config.final_policy.clone(),
            "MODE · Global outbound".into(),
            None,
        )
    } else if let Some((index, rule)) = matched {
        (
            rule.policy.clone(),
            format!("{:?} · {}", rule.kind, rule.value),
            Some(index + 1),
        )
    } else {
        (config.final_policy.clone(), "FINAL".into(), None)
    };
    let mut reason = reason;
    let mut outbound =
        match selector.choose_guarded(config, &policy, Instant::now(), protected, protocol) {
            Ok(outbound) => outbound,
            Err(_) if protected => {
                reason += " · Protection: no healthy encrypted outbound for this transport";
                "REJECT".into()
            }
            Err(error) => return Err(error),
        };
    if protected
        && outbound != "REJECT"
        && config
            .nodes
            .iter()
            .find(|node| node.name == outbound)
            .is_none_or(|node| !crate::privacy::encrypted(node, protocol))
    {
        outbound = "REJECT".into();
        reason += " · Protection: an encrypted proxy is required for this transport";
    }
    if let Some(privacy_reason) = crate::privacy::rejection(config, &host, protocol, &outbound) {
        outbound = "REJECT".into();
        reason = privacy_reason.into();
    }
    Ok(Decision {
        policy,
        outbound,
        reason,
        rule_index,
        generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Group, Rule};
    #[test]
    fn routing_modes_preserve_legacy_rules_and_use_selected_groups() {
        let mut config = Config::default();
        config.nodes.push(
            serde_json::from_value(serde_json::json!({
                "name":"fixture", "kind":"socks5", "server":"127.0.0.1", "port":9
            }))
            .unwrap(),
        );
        config.groups.push(Group {
            name: "chosen".into(),
            kind: GroupKind::Select,
            members: vec!["fixture".into(), "DIRECT".into()],
            selected: Some("fixture".into()),
        });
        config.final_policy = "chosen".into();
        let mut legacy = serde_json::to_value(&config).unwrap();
        legacy.as_object_mut().unwrap().remove("routingMode");
        let legacy: Config = serde_json::from_value(legacy).unwrap();
        assert_eq!(legacy.routing_mode, RoutingMode::Rules);
        let mut selector = Selector::default();
        let rules = decide(&legacy, &mut selector, "localhost", 443, "tcp", 1).unwrap();
        assert_eq!(rules.outbound, "DIRECT");
        assert_eq!(rules.rule_index, Some(1));
        config.routing_mode = RoutingMode::Global;
        config.validate().unwrap();
        for protocol in ["tcp", "udp"] {
            let global = decide(&config, &mut selector, "localhost", 443, protocol, 2).unwrap();
            assert_eq!(global.policy, "chosen");
            assert_eq!(global.outbound, "fixture");
            assert_eq!(global.rule_index, None);
            assert_eq!(global.generation, 2);
        }
        config.routing_mode = RoutingMode::Direct;
        let direct = decide(&config, &mut selector, "example.invalid", 443, "tcp", 3).unwrap();
        assert_eq!(direct.policy, "DIRECT");
        assert_eq!(direct.outbound, "DIRECT");
        assert_eq!(direct.rule_index, None);
        config.routing_mode = RoutingMode::Rules;
        assert_eq!(
            decide(&config, &mut selector, "localhost", 443, "tcp", 4)
                .unwrap()
                .rule_index,
            Some(1)
        );
        assert_eq!(config.rules.len(), legacy.rules.len());
        let mut unknown = serde_json::to_value(config).unwrap();
        unknown["routingMode"] = serde_json::json!("unknown");
        assert!(serde_json::from_value::<Config>(unknown).is_err());
    }

    #[test]
    fn every_routing_mode_preserves_privacy_and_group_failure() {
        let mut config = Config::default();
        config.nodes.push(
            serde_json::from_value(serde_json::json!({
                "name":"fixture", "kind":"socks5", "server":"127.0.0.1", "port":9
            }))
            .unwrap(),
        );
        config.privacy.blocked_domains = vec!["blocked.invalid".into()];
        config.privacy.block_direct = true;
        config.privacy.require_encrypted_proxy = true;
        for mode in [RoutingMode::Rules, RoutingMode::Global, RoutingMode::Direct] {
            config.routing_mode = mode;
            for policy in ["DIRECT", "fixture"] {
                config.final_policy = policy.into();
                for protocol in ["tcp", "udp"] {
                    let mut selector = Selector::default();
                    let blocked =
                        decide(&config, &mut selector, "blocked.invalid", 443, protocol, 1)
                            .unwrap();
                    assert_eq!(blocked.outbound, "REJECT");
                    assert!(blocked.reason.contains("domain block"));
                    let restricted =
                        decide(&config, &mut selector, "other.invalid", 443, protocol, 1).unwrap();
                    assert_eq!(restricted.outbound, "REJECT");
                    assert!(restricted.reason.starts_with("Privacy:"));
                }
            }
        }
        config.privacy.require_encrypted_proxy = false;
        config.routing_mode = RoutingMode::Global;
        config.groups.push(Group {
            name: "auto".into(),
            kind: GroupKind::Fallback,
            members: vec!["fixture".into()],
            selected: None,
        });
        config.final_policy = "auto".into();
        config.validate().unwrap();
        let mut selector = Selector::default();
        for _ in 0..3 {
            selector.record("fixture", None, Instant::now());
        }
        assert!(decide(&config, &mut selector, "other.invalid", 443, "tcp", 1).is_err());
    }

    #[test]
    fn suffix_has_label_boundary_and_updates_are_validated() {
        let mut c = Config::default();
        c.rules.insert(
            0,
            Rule {
                kind: RuleKind::DomainSuffix,
                value: "example.com".into(),
                policy: "REJECT".into(),
                enabled: true,
            },
        );
        c.validate().unwrap();
        let mut s = Selector::default();
        for host in ["example.com", "api.EXAMPLE.com."] {
            assert_eq!(
                decide(&c, &mut s, host, 443, "tcp", 1).unwrap().outbound,
                "REJECT"
            );
        }
        assert_eq!(
            decide(&c, &mut s, "evilexample.com", 443, "tcp", 1)
                .unwrap()
                .outbound,
            "DIRECT"
        );
        c.final_policy = "missing".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn health_hysteresis_and_no_direct_failopen() {
        let t = Instant::now();
        let mut s = Selector::default();
        let mut c = Config::default();
        c.groups.push(Group {
            name: "auto".into(),
            kind: GroupKind::Latency,
            members: vec!["a".into(), "b".into()],
            selected: None,
        });
        s.record("a", Some(Duration::from_millis(100)), t);
        s.record("b", Some(Duration::from_millis(95)), t);
        assert_eq!(s.choose(&c, "auto", t).unwrap(), "b");
        for n in 0..50 {
            s.record(
                "a",
                Some(Duration::from_millis(if n % 2 == 0 { 80 } else { 120 })),
                t,
            );
            assert_eq!(
                s.choose(&c, "auto", t + Duration::from_secs(120)).unwrap(),
                "b"
            );
        }
        for _ in 0..2 {
            s.record("b", None, t);
            assert_eq!(s.choose(&c, "auto", t).unwrap(), "b");
        }
        s.record("b", None, t);
        assert_eq!(s.choose(&c, "auto", t).unwrap(), "a");
        for _ in 0..3 {
            s.record("a", None, t);
        }
        assert!(s.choose(&c, "auto", t).is_err());
        s.record("b", Some(Duration::from_millis(10)), t);
        assert!(s.choose(&c, "auto", t).is_err());
        s.record("b", Some(Duration::from_millis(10)), t);
        assert_eq!(s.choose(&c, "auto", t).unwrap(), "b");
    }
}
