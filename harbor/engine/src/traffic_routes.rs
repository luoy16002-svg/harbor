//! Ordered application/domain routes, evaluated before mode-specific routing.
use crate::{config::Config, exceptions::DirectExceptions};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrafficRoute {
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub processes: Vec<String>,
    /// None follows final_policy, including when the ordinary mode is Direct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(default)]
    pub require_encrypted_proxy: bool,
}

impl TrafficRoute {
    fn matcher(&self) -> DirectExceptions {
        DirectExceptions {
            enabled: self.enabled,
            domains: self.domains.clone(),
            processes: self.processes.clone(),
        }
    }
    pub fn domain_matches(&self, host: &str) -> bool {
        self.enabled
            && self
                .domains
                .iter()
                .any(|domain| crate::exceptions::domain_matches(domain, host))
    }
    pub fn process_matches(&self, process: Option<&str>) -> bool {
        self.enabled
            && process
                .is_some_and(|name| self.processes.iter().any(|p| p.eq_ignore_ascii_case(name)))
    }
}

pub fn validate(config: &Config, policies: &HashSet<&str>) -> Result<()> {
    ensure!(
        config.traffic_routes.len() <= 64,
        "At most 64 traffic routes are supported"
    );
    let mut names = HashSet::new();
    let mut entries = 0;
    for route in &config.traffic_routes {
        ensure!(
            !route.name.is_empty()
                && route.name.len() <= 128
                && route.name.trim() == route.name
                && !route.name.chars().any(char::is_control)
                && names.insert(&route.name),
            "Invalid or duplicate traffic route name"
        );
        route.matcher().validate()?;
        entries += route.domains.len() + route.processes.len();
        ensure!(
            !route.domains.is_empty() || !route.processes.is_empty(),
            "Traffic route requires a domain or process"
        );
        if let Some(policy) = &route.policy {
            ensure!(
                policies.contains(policy.as_str()),
                "Traffic route refers to an unknown policy"
            );
            ensure!(
                !(route.require_encrypted_proxy && policy == "DIRECT"),
                "An encrypted traffic route cannot select DIRECT"
            );
        }
    }
    ensure!(
        entries <= 2048,
        "Traffic routes allow at most 2048 domain/process entries in total"
    );
    Ok(())
}

/// Only consult the OS when a process could change the first matching route.
pub fn needs_process(config: &Config, host: &str) -> bool {
    for route in config.traffic_routes.iter().filter(|route| route.enabled) {
        if route.domain_matches(host) {
            return false;
        }
        if !route.processes.is_empty() {
            return true;
        }
    }
    let exceptions = &config.direct_exceptions;
    exceptions.enabled && !exceptions.processes.is_empty() && !exceptions.domain_matches(host)
}
