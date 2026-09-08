use crate::policy::Decision;
use serde::Serialize;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Flow {
    pub id: u64,
    pub destination: String,
    pub protocol: String,
    pub source: String,
    pub policy: String,
    pub outbound: String,
    pub reason: String,
    pub generation: u64,
    pub started_at: u64,
    pub duration_ms: u64,
    pub uploaded: u64,
    pub downloaded: u64,
    pub state: String,
    pub error: Option<String>,
    pub attempts: Vec<ConnectAttempt>,
    #[serde(skip)]
    ended_at: Option<u64>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectAttempt {
    pub outbound: String,
    pub state: String,
    pub elapsed_ms: u64,
    pub error_category: Option<String>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub time: u64,
    pub level: String,
    pub message: String,
}

#[derive(Default)]
pub struct Telemetry {
    next: AtomicU64,
    pub uploaded: AtomicU64,
    pub downloaded: AtomicU64,
    pub accepted: AtomicU64,
    pub failed: AtomicU64,
    pub flows: Mutex<VecDeque<Flow>>,
    pub events: Mutex<VecDeque<Event>>,
    private: AtomicBool,
    history_secs: AtomicU64,
}
impl Telemetry {
    pub fn configure(&self, settings: &crate::privacy::Privacy) {
        self.private.store(settings.hide_metadata, Ordering::SeqCst);
        self.history_secs
            .store(settings.history_secs, Ordering::Relaxed);
        if settings.hide_metadata {
            for flow in self.flows.lock().unwrap().iter_mut() {
                redact(flow);
            }
            self.events.lock().unwrap().clear();
        }
        self.prune();
    }
    pub fn prune(&self) {
        let keep = self
            .history_secs
            .load(Ordering::Relaxed)
            .saturating_mul(1000);
        let now = now_ms();
        self.flows.lock().unwrap().retain(|flow| {
            flow.ended_at
                .is_none_or(|end| keep > 0 && now.saturating_sub(end) < keep)
        });
    }
    pub fn clear_history(&self) {
        self.flows
            .lock()
            .unwrap()
            .retain(|flow| flow.ended_at.is_none());
        self.events.lock().unwrap().clear();
    }
    pub fn begin(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        protocol: &str,
        source: &str,
        decision: &Decision,
    ) -> FlowGuard {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.accepted.fetch_add(1, Ordering::Relaxed);
        let mut flows = self.flows.lock().unwrap();
        let mut flow = Flow {
            id,
            destination: format!("{host}:{port}"),
            protocol: protocol.into(),
            source: source.into(),
            policy: decision.policy.clone(),
            outbound: decision.outbound.clone(),
            reason: decision.reason.clone(),
            generation: decision.generation,
            started_at: now_ms(),
            duration_ms: 0,
            uploaded: 0,
            downloaded: 0,
            state: "connecting".into(),
            error: None,
            attempts: vec![],
            ended_at: None,
        };
        if self.private.load(Ordering::SeqCst) {
            redact(&mut flow);
        }
        flows.push_front(flow);
        if flows.len() > 4096
            && let Some(i) = flows
                .iter()
                .rposition(|f| f.state == "closed" || f.state == "failed")
        {
            flows.remove(i);
        }
        FlowGuard {
            id,
            telemetry: self.clone(),
            start: Instant::now(),
            finished: false,
        }
    }
    pub fn event(&self, level: &str, message: impl Into<String>) {
        let mut events = self.events.lock().unwrap();
        if self.private.load(Ordering::SeqCst) {
            return;
        }
        events.push_front(Event {
            time: now_ms(),
            level: level.into(),
            message: message.into(),
        });
        events.truncate(300);
    }
}
fn redact(flow: &mut Flow) {
    use zeroize::Zeroize;
    for value in [
        &mut flow.destination,
        &mut flow.source,
        &mut flow.policy,
        &mut flow.outbound,
        &mut flow.reason,
    ] {
        value.zeroize();
        *value = "已隐藏".into();
    }
    if let Some(error) = &mut flow.error {
        error.zeroize();
    }
    flow.error = None;
    for attempt in &mut flow.attempts {
        attempt.outbound.zeroize();
    }
    flow.attempts.clear();
}
pub struct FlowGuard {
    pub id: u64,
    telemetry: Arc<Telemetry>,
    start: Instant,
    finished: bool,
}
impl FlowGuard {
    pub fn attempt(&self, outbound: &str) {
        self.update(|f| {
            if f.attempts.len() < 3 {
                f.attempts.push(ConnectAttempt {
                    outbound: outbound.into(),
                    state: "connecting".into(),
                    elapsed_ms: 0,
                    error_category: None,
                });
            }
        });
    }
    pub fn attempt_finished(&self, elapsed_ms: u64, category: Option<&str>) {
        self.update(|f| {
            if let Some(a) = f.attempts.last_mut() {
                a.elapsed_ms = elapsed_ms;
                a.state = if category.is_some() {
                    "failed"
                } else {
                    "connected"
                }
                .into();
                a.error_category = category.map(str::to_owned);
            }
        });
    }
    pub fn routed(&self, decision: &Decision) {
        self.update(|f| {
            f.outbound = decision.outbound.clone();
            f.reason = decision.reason.clone();
        });
    }
    pub fn active(&self) {
        self.update(|f| f.state = "active".into());
    }
    pub fn add(&self, up: u64, down: u64) {
        self.telemetry.uploaded.fetch_add(up, Ordering::Relaxed);
        self.telemetry.downloaded.fetch_add(down, Ordering::Relaxed);
        self.update(|f| {
            f.uploaded += up;
            f.downloaded += down;
        });
    }
    pub fn finish(&mut self, error: Option<String>) {
        if self.finished {
            return;
        }
        self.finished = true;
        if error.is_some() {
            self.telemetry.failed.fetch_add(1, Ordering::Relaxed);
        }
        self.update(|f| {
            f.state = if error.is_some() { "failed" } else { "closed" }.into();
            f.error = error;
            f.ended_at = Some(now_ms());
        });
        self.telemetry.prune();
    }
    fn update(&self, update: impl FnOnce(&mut Flow)) {
        if let Some(f) = self
            .telemetry
            .flows
            .lock()
            .unwrap()
            .iter_mut()
            .find(|f| f.id == self.id)
        {
            f.duration_ms = self.start.elapsed().as_millis() as u64;
            update(f);
            if self.telemetry.private.load(Ordering::SeqCst) {
                redact(f);
            }
        }
    }
}
impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.finish(None);
    }
}
