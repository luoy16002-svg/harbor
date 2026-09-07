//! Explicit direct routing exceptions, independent of the ordinary rule mode.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectExceptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub processes: Vec<String>,
}

impl DirectExceptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.domains.len() <= 256 && self.processes.len() <= 256,
            "Direct exceptions allow at most 256 domains and 256 process names"
        );
        for domain in &self.domains {
            ensure!(
                valid_domain(domain),
                "Direct exception requires an ASCII domain suffix, without a URL, IP or wildcard"
            );
        }
        for process in &self.processes {
            ensure!(
                valid_process(process),
                "Direct exception requires an ASCII executable filename, without a path or wildcard"
            );
        }
        Ok(())
    }

    pub fn domain_matches(&self, host: &str) -> bool {
        if !self.enabled || host.parse::<IpAddr>().is_ok() {
            return false;
        }
        self.domains
            .iter()
            .any(|domain| domain_matches(domain, host))
    }

    pub fn process_matches(&self, process: Option<&str>) -> bool {
        self.enabled
            && process.is_some_and(|name| {
                self.processes
                    .iter()
                    .any(|entry| entry.eq_ignore_ascii_case(name))
            })
    }
}

pub fn domain_matches(domain: &str, host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    host == domain
        || host
            .strip_suffix(&domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

pub fn valid_domain(domain: &str) -> bool {
    let value = domain.strip_suffix('.').unwrap_or(domain);
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
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub fn valid_process(process: &str) -> bool {
    !process.is_empty()
        && process.len() <= 260
        && process.is_ascii()
        && process.trim() == process
        && process.to_ascii_lowercase().ends_with(".exe")
        && process.len() > 4
        && !process
            .bytes()
            .any(|b| b.is_ascii_control() || b"<>:\"/\\|?*".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_bounded_explicit_names_and_domain_boundaries() {
        let mut entries = DirectExceptions {
            enabled: true,
            domains: vec!["VIDEO.Example.".into()],
            processes: vec!["Game.exe".into()],
        };
        entries.validate().unwrap();
        for name in ["video.example", "CDN.video.example."] {
            assert!(entries.domain_matches(name));
        }
        for name in ["notvideo.example", "video.example.evil", "127.0.0.1", "::1"] {
            assert!(!entries.domain_matches(name));
        }
        assert!(entries.process_matches(Some("GAME.EXE")));
        assert!(!entries.process_matches(Some("OtherGame.exe")));
        assert!(!entries.process_matches(None));
        for bad in [
            "https://video.example",
            "*.example",
            "127.0.0.1",
            "::1",
            "-bad.example",
            "bad..example",
            "example..",
            "例子.cn",
        ] {
            assert!(!valid_domain(bad), "{bad}");
        }
        for bad in [
            "",
            "C:\\Game.exe",
            "../Game.exe",
            "*.exe",
            "game.exe\n",
            ".exe",
            "Game",
        ] {
            assert!(!valid_process(bad));
        }
        entries.enabled = false;
        assert!(!entries.domain_matches("video.example"));
        assert!(!entries.process_matches(Some("Game.exe")));
        entries.domains = vec!["example.com".into(); 257];
        assert!(entries.validate().is_err());
    }
}
