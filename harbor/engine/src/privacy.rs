use crate::config::{Config, Node, NodeKind};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Privacy {
    pub block_direct: bool,
    pub require_encrypted_proxy: bool,
    pub hide_metadata: bool,
    pub history_secs: u64,
    pub blocked_domains: Vec<String>,
    pub allowed_domains: Vec<String>,
}
impl Default for Privacy {
    fn default() -> Self {
        Self {
            block_direct: false,
            require_encrypted_proxy: false,
            hide_metadata: false,
            history_secs: 300,
            blocked_domains: vec![],
            allowed_domains: vec![],
        }
    }
}
impl Privacy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.history_secs <= 86400,
            "Connection history must be 0–86400 seconds"
        );
        ensure!(
            self.blocked_domains.len() + self.allowed_domains.len() <= 20000,
            "At most 20000 privacy domains are supported"
        );
        ensure!(
            self.blocked_domains
                .iter()
                .chain(&self.allowed_domains)
                .map(String::len)
                .sum::<usize>()
                <= 512 * 1024,
            "Privacy domain text exceeds 512 KiB"
        );
        for domain in self.blocked_domains.iter().chain(&self.allowed_domains) {
            ensure!(
                valid_domain(domain),
                "Privacy rules must be ASCII domain names, without URLs or wildcards"
            );
        }
        Ok(())
    }
    pub fn routing_eq(&self, other: &Self) -> bool {
        self.block_direct == other.block_direct
            && self.require_encrypted_proxy == other.require_encrypted_proxy
            && self.blocked_domains == other.blocked_domains
            && self.allowed_domains == other.allowed_domains
    }
}
fn valid_domain(value: &str) -> bool {
    let value = value.trim_end_matches('.');
    !value.is_empty()
        && value.len() <= 253
        && value.parse::<IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
#[derive(Default, Debug)]
pub struct DomainFilter {
    blocked: HashSet<String>,
    allowed: HashSet<String>,
}
impl DomainFilter {
    pub fn new(settings: &Privacy) -> Self {
        let normalize = |values: &[String]| {
            values
                .iter()
                .map(|value| value.trim_end_matches('.').to_ascii_lowercase())
                .collect()
        };
        Self {
            blocked: normalize(&settings.blocked_domains),
            allowed: normalize(&settings.allowed_domains),
        }
    }
    pub fn blocked(&self, host: &str) -> bool {
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        if normalized.parse::<IpAddr>().is_ok() {
            return false;
        }
        let mut suffix = normalized.as_str();
        let mut blocked = false;
        loop {
            if self.allowed.contains(suffix) {
                return false;
            }
            blocked |= self.blocked.contains(suffix);
            match suffix.split_once('.') {
                Some((_, rest)) => suffix = rest,
                None => break,
            }
        }
        blocked
    }
    pub fn allowed(&self, host: &str) -> bool {
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        let mut suffix = normalized.as_str();
        loop {
            if self.allowed.contains(suffix) {
                return true;
            }
            match suffix.split_once('.') {
                Some((_, rest)) => suffix = rest,
                None => return false,
            }
        }
    }
}
pub fn encrypted(node: &Node, protocol: &str) -> bool {
    match node.kind {
        NodeKind::Shadowsocks | NodeKind::Trojan | NodeKind::Vless | NodeKind::Vmess => true,
        NodeKind::Https => protocol == "tcp",
        NodeKind::Socks5 | NodeKind::Http => node.tls && protocol == "tcp",
    }
}
pub fn rejection(
    config: &Config,
    host: &str,
    protocol: &str,
    outbound: &str,
) -> Option<&'static str> {
    if outbound == "REJECT" {
        return None;
    }
    let local = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if outbound == "DIRECT" {
        return (config.privacy.block_direct && !local)
            .then_some("Privacy: direct outbound disabled");
    }
    if config.privacy.require_encrypted_proxy
        && config
            .nodes
            .iter()
            .find(|node| node.name == outbound)
            .is_none_or(|node| !encrypted(node, protocol))
    {
        return Some("Privacy: this outbound does not encrypt the selected transport");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_exceptions_respect_label_boundaries() {
        let settings = Privacy {
            blocked_domains: vec!["track.example".into()],
            allowed_domains: vec!["allowed.track.example".into()],
            ..Default::default()
        };
        settings.validate().unwrap();
        let filter = DomainFilter::new(&settings);
        assert!(filter.blocked("API.TRACK.EXAMPLE."));
        for host in [
            "nottrack.example",
            "allowed.track.example",
            "api.allowed.track.example",
            "127.0.0.1",
        ] {
            assert!(!filter.blocked(host));
        }
        assert!(
            Privacy {
                blocked_domains: vec!["https://track.example/path".into()],
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}
