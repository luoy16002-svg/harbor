//! Pure configuration evaluation: no DNS lookup, listener, packet or network mutation.
use crate::{
    config::Config,
    policy::{self, Selector},
    privacy::DomainFilter,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

pub fn compare(before: &Config, after: &Config, targets: &[Target]) -> Result<Value> {
    before.validate()?;
    after.validate()?;
    ensure!(
        !targets.is_empty() && targets.len() <= 256,
        "Provide 1–256 route targets"
    );
    let before_filter = DomainFilter::new(&before.privacy);
    let after_filter = DomainFilter::new(&after.privacy);
    let mut previous = Selector::default();
    let mut candidate = Selector::default();
    previous.reconcile(before);
    candidate.reconcile(after);
    let mut rows = vec![];
    for target in targets {
        ensure!(
            !target.host.is_empty()
                && target.host.len() <= 253
                && target.port != 0
                && matches!(target.protocol.as_str(), "tcp" | "udp"),
            "Invalid route target"
        );
        ensure!(
            target
                .process
                .as_deref()
                .is_none_or(crate::exceptions::valid_process),
            "Invalid preview process name"
        );
        let a = policy::decide_with_process(
            before,
            &mut previous,
            &before_filter,
            (&target.host, target.port, &target.protocol),
            target.process.as_deref(),
            0,
        )?;
        let b = policy::decide_with_process(
            after,
            &mut candidate,
            &after_filter,
            (&target.host, target.port, &target.protocol),
            target.process.as_deref(),
            0,
        )?;
        rows.push(json!({"target":target,"before":a,"after":b,"changed":a.outbound != b.outbound || a.policy != b.policy || a.reason != b.reason}));
    }
    Ok(json!({"offline":true,"networkRequests":0,"healthMeasured":false,"rows":rows}))
}
