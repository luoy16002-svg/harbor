use harbor_engine::{
    config::{Config, Group, GroupKind, RoutingMode},
    engine::Engine,
    policy::{self, Selector},
    pools::PoolSettings,
};
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

fn config(ports: &[u16], monitor: bool) -> Config {
    let mut config = Config {
        routing_mode: RoutingMode::Global,
        final_policy: "pool".into(),
        connect_timeout_ms: 1800,
        ..Config::default()
    };
    config.nodes = ports
        .iter()
        .enumerate()
        .map(|(i, p)| {
            serde_json::from_value(
                json!({"name":format!("n{i}"),"kind":"http","server":"127.0.0.1","port":p}),
            )
            .unwrap()
        })
        .collect();
    config.groups = vec![Group {
        name: "pool".into(),
        kind: GroupKind::Fallback,
        selected: None,
        members: config.nodes.iter().map(|n| n.name.clone()).collect(),
        pool: Some(PoolSettings {
            monitor,
            attempt_timeout_ms: 500,
            check_timeout_ms: 1000,
            ..Default::default()
        }),
    }];
    config
}
async fn start(mut config: Config) -> Arc<Engine> {
    for _ in 0..8 {
        let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dns = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let Ok(udp) = UdpSocket::bind(dns.local_addr().unwrap()).await else {
            continue;
        };
        config.listen = listen.local_addr().unwrap();
        config.dns_listen = dns.local_addr().unwrap();
        drop((listen, dns, udp));
        match Engine::start(config.clone()).await {
            Ok(engine) => return engine,
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::AddrInUse)
                }) => {}
            Err(error) => panic!("{error:#}"),
        }
    }
    panic!("Unable to reserve test ports");
}
struct Proxy {
    port: u16,
    requests: Arc<AtomicUsize>,
    status: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Proxy {
    async fn new(code: usize, tls: Option<Arc<rustls::ServerConfig>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let status = Arc::new(AtomicUsize::new(code));
        let reply = status.clone();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let (mut stream, _) = incoming.unwrap(); let count = count.clone(); let tls = tls.clone(); let reply = reply.clone();
                        tasks.spawn(async move {
                            let mut header = vec![];
                            loop {
                                let Ok(byte) = stream.read_u8().await else { return; }; header.push(byte);
                                if header.ends_with(b"\r\n\r\n") { break; }
                                assert!(header.len() <= 8192);
                            }
                            assert!(header.starts_with(b"CONNECT "));
                            count.fetch_add(1, Ordering::SeqCst);
                        let code = reply.load(Ordering::SeqCst);
                        if code == 0 { let _ = stream.read_u8().await; return; }
                        if code == 299 { let _ = stream.write_all(b"HTTP/1.1 200 Established\r\n\r\n").await; return; }
                            if stream.write_all(format!("HTTP/1.1 {code} fixture\r\n\r\n").as_bytes()).await.is_err() || code != 200 { return; }
                            if let Some(server) = tls {
                                let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(server).accept(stream).await else { return; };
                                let mut request = vec![];
                                loop { let Ok(byte) = stream.read_u8().await else { return; }; request.push(byte); if request.ends_with(b"\r\n\r\n") { break; } assert!(request.len() < 8192); }
                                assert!(request.starts_with(b"HEAD /health?fixture=private HTTP/1.1\r\nHost: localhost:9443\r\n"));
                                let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
                            } else {
                                let mut data = [0; 4096];
                                while let Ok(n) = stream.read(&mut data).await { if n == 0 || stream.write_all(&data[..n]).await.is_err() { break; } }
                            }
                        });
                    },
                    _ = tasks.join_next(), if !tasks.is_empty() => {},
                }
            }
        });
        Self {
            port,
            requests,
            status,
            task,
        }
    }
}
async fn until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(4), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Condition not reached");
}
fn cert() -> (String, Arc<rustls::ServerConfig>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    (cert.cert.pem(), Arc::new(server))
}

#[test]
fn validates_pool_limits_and_check_targets() {
    let valid = config(&[9, 10], true);
    valid.validate().unwrap();
    for url in [
        "http://localhost/",
        "https://user:secret@localhost/",
        "https://localhost/#secret",
        " https://localhost/",
        "https://localhost:0/",
    ] {
        let mut c = valid.clone();
        c.groups[0].pool.as_mut().unwrap().check_url = url.into();
        assert!(c.validate().is_err(), "{url}");
    }
    let mut c = valid.clone();
    c.groups[0].members.push("DIRECT".into());
    assert!(c.validate().is_err());
    let mut c = valid.clone();
    c.groups[0].pool.as_mut().unwrap().connect_attempts = 4;
    assert!(c.validate().is_err());
    let mut c = valid.clone();
    c.groups[0].pool.as_mut().unwrap().ca_pem = "not a certificate".into();
    assert!(c.validate().is_err());
    let mut c = valid.clone();
    c.groups[0].kind = GroupKind::Select;
    assert!(c.validate().is_err());
    let target = harbor_engine::pools::CheckTarget::parse("https://[::1]:9443/test?q=1").unwrap();
    assert_eq!(
        (
            &*target.host,
            target.port,
            &*target.authority,
            &*target.path
        ),
        ("::1", 9443, "[::1]:9443", "/test?q=1")
    );
}

#[test]
fn https_health_overrides_port_health_and_credentials_invalidate_it() {
    let mut c = config(&[9, 10], true);
    let mut s = Selector::default();
    s.reconcile(&c);
    let now = Instant::now();
    s.pool_health
        .get_mut(&("pool".into(), "n0".into()))
        .unwrap()
        .record(Err("proxy"), now, 120);
    s.pool_health
        .get_mut(&("pool".into(), "n1".into()))
        .unwrap()
        .record(Ok(50.0), now, 120);
    for _ in 0..3 {
        s.record("n1", None, now);
    }
    assert_eq!(s.choose(&c, "pool", now).unwrap(), "n1");
    c.nodes[1].password = "new credential".into();
    s.reconcile(&c);
    assert_eq!(
        s.pool_health[&("pool".into(), "n1".into())].state,
        "unknown"
    );
    assert!(s.choose(&c, "pool", now).is_err());
}

#[test]
fn protected_retry_candidates_exclude_plaintext_and_never_add_direct() {
    let mut c = config(&[9, 10, 11], false);
    c.nodes[0].kind = harbor_engine::config::NodeKind::Https;
    c.nodes[2].kind = harbor_engine::config::NodeKind::Https;
    c.privacy.require_encrypted_proxy = true;
    let mut s = Selector::default();
    s.reconcile(&c);
    let decision = policy::decide(&c, &mut s, "example.test", 443, "tcp", 1).unwrap();
    assert!(decision.require_encrypted_proxy);
    assert_eq!(s.retry_candidates(&c, &decision), ["n0", "n2"]);
    for h in s.pool_health.values_mut() {
        h.cooldown = Some(Instant::now() + Duration::from_secs(15));
    }
    assert_eq!(
        policy::decide(&c, &mut s, "example.test", 443, "tcp", 1)
            .unwrap()
            .outbound,
        "REJECT"
    );
}

#[test]
fn path_protection_survives_into_retry_candidates() {
    let mut c = config(&[9, 10, 11], false);
    c.nodes[0].kind = harbor_engine::config::NodeKind::Https;
    c.nodes[2].kind = harbor_engine::config::NodeKind::Https;
    c.traffic_routes.push(serde_json::from_value(json!({"name":"protected","enabled":true,"domains":["work.test"],"policy":"pool","requireEncryptedProxy":true})).unwrap());
    let mut selector = Selector::default();
    selector.reconcile(&c);
    let decision = policy::decide(&c, &mut selector, "work.test", 443, "tcp", 1).unwrap();
    assert!(!c.privacy.require_encrypted_proxy);
    assert!(decision.require_encrypted_proxy);
    assert_eq!(selector.retry_candidates(&c, &decision), ["n0", "n2"]);
}

#[tokio::test]
async fn pool_preflight_can_use_backup_when_primary_dns_is_blocked() {
    let mut c = config(&[9, 10], false);
    c.nodes[0].server = "blocked.invalid".into();
    c.privacy.blocked_domains.push("blocked.invalid".into());
    let ready = harbor_engine::verification::preflight(c).await.unwrap();
    assert_eq!(ready["outbound"], "n1");
}

#[tokio::test]
async fn established_stream_failure_never_replays_to_backup() {
    let first = Proxy::new(299, None).await;
    let backup = Proxy::new(200, None).await;
    let engine = start(config(&[first.port, backup.port], false)).await;
    let snapshot = engine.current.load_full();
    let mut decision = engine
        .decision(&snapshot, "payload.test", 443, "tcp")
        .unwrap();
    let flow = engine
        .telemetry
        .begin("payload.test", 443, "TCP", "fixture", &decision);
    let mut stream = engine
        .connect_flow(&snapshot, &mut decision, ("payload.test", 443), &flow)
        .await
        .unwrap();
    let _ = stream.write_all(b"must not be replayed").await;
    let _ = stream.read_u8().await;
    assert_eq!(backup.requests.load(Ordering::SeqCst), 0);
    assert_eq!(decision.outbound, "n0");
    drop(stream);
    engine.stop().await.unwrap();
}

#[tokio::test]
async fn old_connect_completion_cannot_update_new_pool_stats() {
    let first = Proxy::new(0, None).await;
    let backup = Proxy::new(200, None).await;
    let engine = start(config(&[first.port, backup.port], false)).await;
    let e = engine.clone();
    let task = tokio::spawn(async move {
        let snapshot = e.current.load_full();
        let mut decision = e
            .decision(&snapshot, "generation.test", 443, "tcp")
            .unwrap();
        let flow = e
            .telemetry
            .begin("generation.test", 443, "TCP", "fixture", &decision);
        e.connect_flow(&snapshot, &mut decision, ("generation.test", 443), &flow)
            .await
            .is_ok()
    });
    until(|| first.requests.load(Ordering::SeqCst) == 1).await;
    let mut changed = engine.current.load().config.clone();
    changed.nodes[0].password = "new generation".into();
    engine.configure(changed).unwrap();
    assert!(task.await.unwrap());
    assert_eq!(engine.snapshot()["pools"][0]["stats"]["attempts"], 0);
    assert!(
        engine.selector.lock().unwrap().pool_health[&("pool".into(), "n0".into())]
            .cooldown
            .is_none()
    );
    engine.stop().await.unwrap();
}

#[tokio::test]
async fn reconfiguration_cancels_stale_monitor_results() {
    let proxy = Proxy::new(0, None).await;
    let engine = start(config(&[proxy.port], true)).await;
    until(|| proxy.requests.load(Ordering::SeqCst) == 1).await;
    let mut changed = engine.current.load().config.clone();
    changed.groups[0].pool.as_mut().unwrap().monitor = false;
    changed.nodes[0].password = "replaced".into();
    engine.configure(changed).unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let snapshot = engine.snapshot();
    assert_eq!(snapshot["pools"][0]["members"][0]["checks"], 0);
    assert_eq!(snapshot["pools"][0]["members"][0]["checking"], false);
    assert_eq!(proxy.requests.load(Ordering::SeqCst), 1);
    engine.stop().await.unwrap();
}

#[test]
fn pool_outbound_history_obeys_metadata_and_retention_limits() {
    let now = harbor_engine::telemetry::now_ms();
    let mut stats = harbor_engine::pools::PoolStats {
        last_outbound: Some("private".into()),
        last_outbound_at: Some(now),
        last_recovery_at: Some(now),
        ..Default::default()
    };
    let mut privacy = harbor_engine::privacy::Privacy::default();
    stats.prune(&privacy);
    assert!(stats.last_outbound.is_some());
    privacy.history_secs = 0;
    stats.prune(&privacy);
    assert!(stats.last_outbound.is_none() && stats.last_recovery_at.is_none());
    stats.last_outbound = Some("private".into());
    stats.last_outbound_at = Some(now.saturating_sub(300001));
    stats.last_recovery_at = stats.last_outbound_at;
    privacy.history_secs = 300;
    stats.prune(&privacy);
    assert!(stats.last_outbound.is_none() && stats.last_recovery_at.is_none());
}

#[test]
fn latency_pool_requires_https_samples_and_traffic_does_not_restart_hold_down() {
    let mut c = config(&[9, 10, 11], true);
    c.groups[0].kind = GroupKind::Latency;
    let mut selector = Selector::default();
    selector.reconcile(&c);
    let now = Instant::now();
    let before = now - Duration::from_secs(70);
    selector
        .pool_health
        .get_mut(&("pool".into(), "n0".into()))
        .unwrap()
        .record(Ok(250.0), before, 120);
    assert_eq!(selector.choose(&c, "pool", before).unwrap(), "n0");
    for (node, ms) in [("n1", 80.0), ("n2", 40.0)] {
        selector
            .pool_health
            .get_mut(&("pool".into(), node.into()))
            .unwrap()
            .record(Ok(ms), now, 120);
        for _ in 0..3 {
            selector.record(node, Some(Duration::from_millis(1)), now);
        }
    }
    let decision = policy::decide(&c, &mut selector, "work.test", 443, "tcp", 1).unwrap();
    assert_eq!(decision.outbound, "n0");
    selector.remember_pool_outbound(&decision, "n0");
    for _ in 0..2 {
        selector
            .pool_health
            .get_mut(&("pool".into(), "n2".into()))
            .unwrap()
            .record(Ok(40.0), now, 120);
    }
    assert_eq!(selector.choose(&c, "pool", now).unwrap(), "n2");
    let decision = policy::decide(&c, &mut selector, "work.test", 443, "tcp", 1).unwrap();
    assert_eq!(selector.retry_candidates(&c, &decision), ["n2", "n1", "n0"]);
}

#[tokio::test]
async fn upstream_classification_preserves_authentication_and_dns_diagnostics() {
    let rejected = Proxy::new(407, None).await;
    for dns in [false, true] {
        let mut cfg = config(&[rejected.port], false);
        if dns {
            cfg.nodes[0].server = "blocked.invalid".into();
            cfg.privacy.blocked_domains.push("blocked.invalid".into());
        }
        let engine = start(cfg).await;
        let snapshot = engine.current.load_full();
        let result = harbor_engine::transport::connect(
            &snapshot.config,
            &engine.resolver,
            "n0",
            "example.test",
            443,
        )
        .await;
        let error = result.err().expect("Failure fixture connected");
        assert!(error.is::<harbor_engine::transport::UpstreamFailure>());
        assert!(
            error.to_string().contains(if dns { "DNS" } else { "407" }),
            "{error}"
        );
        engine
            .selector
            .lock()
            .unwrap()
            .pool_health
            .get_mut(&("pool".into(), "n0".into()))
            .unwrap()
            .cooldown = Some(Instant::now() + Duration::from_secs(15));
        let mut decision = engine
            .decision(&snapshot, "example.test", 443, "tcp")
            .unwrap();
        assert_eq!(decision.outbound, "REJECT");
        let flow = engine
            .telemetry
            .begin("example.test", 443, "TCP", "fixture", &decision);
        let error = engine
            .connect_flow(&snapshot, &mut decision, ("example.test", 443), &flow)
            .await
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "Blocked by routing policy");
        assert_eq!(engine.snapshot()["flows"][0]["attempts"], json!([]));
        engine.stop().await.unwrap();
    }
}

#[tokio::test]
async fn actual_socks_ingress_recovers_once_and_records_winner() {
    let bad = Proxy::new(407, None).await;
    let good = Proxy::new(200, None).await;
    let engine = start(config(&[bad.port, good.port], false)).await;
    let mut client = TcpStream::connect(engine.current.load().config.listen)
        .await
        .unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    client
        .write_all(&[5, 1, 0, 1, 203, 0, 113, 1, 1, 187])
        .await
        .unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    client.write_all(b"one payload").await.unwrap();
    let mut response = [0; 11];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"one payload");
    let value = engine.snapshot();
    let flow = &value["flows"][0];
    assert_eq!(flow["outbound"], "n1");
    assert_eq!(flow["attempts"][0]["errorCategory"], "proxy");
    assert_eq!(flow["attempts"][1]["state"], "connected");
    assert_eq!(value["pools"][0]["stats"]["recovered"], 1);
    assert_eq!(bad.requests.load(Ordering::SeqCst), 1);
    assert_eq!(good.requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        engine
            .decision(&engine.current.load(), "other.test", 443, "tcp")
            .unwrap()
            .outbound,
        "n1"
    );
    drop(client);
    engine.stop().await.unwrap();
    until(|| engine.flow_cancel.lock().unwrap().is_empty()).await;
}

#[tokio::test]
async fn destination_refusal_does_not_mark_proxy_bad() {
    let bad = Proxy::new(502, None).await;
    let good = Proxy::new(200, None).await;
    let engine = start(config(&[bad.port, good.port], false)).await;
    let snap = engine.current.load_full();
    let mut decision = engine
        .decision(&snap, "unavailable.test", 443, "tcp")
        .unwrap();
    let flow = engine
        .telemetry
        .begin("unavailable.test", 443, "TCP", "fixture", &decision);
    let stream = engine
        .connect_flow(&snap, &mut decision, ("unavailable.test", 443), &flow)
        .await
        .unwrap();
    assert!(
        engine.selector.lock().unwrap().pool_health[&("pool".into(), "n0".into())]
            .cooldown
            .is_none()
    );
    drop(stream);
    assert!(engine.flow_cancel.lock().unwrap().is_empty());
    engine.stop().await.unwrap();
}

#[tokio::test]
async fn targeted_cancel_stops_connecting_and_does_not_try_backup() {
    let hanging = Proxy::new(0, None).await;
    let good = Proxy::new(200, None).await;
    let engine = start(config(&[hanging.port, good.port], false)).await;
    let e = engine.clone();
    let (send, receive) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let snap = e.current.load_full();
        let mut decision = e.decision(&snap, "cancel.test", 443, "tcp").unwrap();
        let flow = e
            .telemetry
            .begin("cancel.test", 443, "TCP", "fixture", &decision);
        send.send(flow.id).unwrap();
        e.connect_flow(&snap, &mut decision, ("cancel.test", 443), &flow)
            .await
            .is_err()
    });
    let id = receive.await.unwrap();
    until(|| hanging.requests.load(Ordering::SeqCst) == 1).await;
    assert!(engine.close_flow(id));
    assert!(task.await.unwrap());
    assert_eq!(good.requests.load(Ordering::SeqCst), 0);
    assert!(engine.flow_cancel.lock().unwrap().is_empty());
    engine.stop().await.unwrap();
}

#[tokio::test]
async fn connection_budget_is_shared_and_bounded() {
    let a = Proxy::new(0, None).await;
    let b = Proxy::new(0, None).await;
    let c = Proxy::new(0, None).await;
    let mut cfg = config(&[a.port, b.port, c.port], false);
    cfg.connect_timeout_ms = 700;
    let engine = start(cfg).await;
    let snap = engine.current.load_full();
    let mut decision = engine.decision(&snap, "timeout.test", 443, "tcp").unwrap();
    let flow = engine
        .telemetry
        .begin("timeout.test", 443, "TCP", "fixture", &decision);
    let start = Instant::now();
    assert!(
        engine
            .connect_flow(&snap, &mut decision, ("timeout.test", 443), &flow)
            .await
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_millis(1250));
    assert_eq!(c.requests.load(Ordering::SeqCst), 0);
    assert!(engine.flow_cancel.lock().unwrap().is_empty());
    engine.stop().await.unwrap();
}

#[tokio::test]
async fn monitor_checks_tls_http_recovers_and_redacts_target() {
    let (pem, server) = cert();
    let bad = Proxy::new(407, Some(server.clone())).await;
    let good = Proxy::new(200, Some(server)).await;
    let mut cfg = config(&[bad.port, good.port], true);
    let p = cfg.groups[0].pool.as_mut().unwrap();
    p.check_url = "https://localhost:9443/health?fixture=private".into();
    p.ca_pem = pem;
    let engine = start(cfg).await;
    until(|| {
        engine
            .selector
            .lock()
            .unwrap()
            .pool_health
            .values()
            .all(|h| h.checks > 0)
    })
    .await;
    let snapshot = engine.snapshot();
    assert!(!snapshot.to_string().contains("fixture=private"));
    {
        let selector = engine.selector.lock().unwrap();
        assert_eq!(
            selector.pool_health[&("pool".into(), "n0".into())].state,
            "unavailable"
        );
        assert_eq!(
            selector.pool_health[&("pool".into(), "n1".into())].state,
            "healthy"
        );
    }
    assert_eq!(
        engine
            .decision(&engine.current.load(), "example.test", 443, "tcp")
            .unwrap()
            .outbound,
        "n1"
    );
    bad.status.store(200, Ordering::SeqCst);
    engine
        .selector
        .lock()
        .unwrap()
        .pool_health
        .get_mut(&("pool".into(), "n0".into()))
        .unwrap()
        .due = Instant::now();
    until(|| {
        engine.selector.lock().unwrap().pool_health[&("pool".into(), "n0".into())].state
            == "healthy"
    })
    .await;
    assert_eq!(
        engine
            .decision(&engine.current.load(), "other.test", 443, "tcp")
            .unwrap()
            .outbound,
        "n1"
    );
    engine.invalidate_pools();
    until(|| good.requests.load(Ordering::SeqCst) >= 2).await;
    let mut cfg = engine.current.load().config.clone();
    cfg.groups[0].pool.as_mut().unwrap().monitor = false;
    engine.configure(cfg).unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let count = good.requests.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(good.requests.load(Ordering::SeqCst), count);
    assert!(engine.check_pool("pool").is_err());
    engine.stop().await.unwrap();
}

#[tokio::test]
async fn monitor_rejects_untrusted_tls_and_never_reports_port_as_https() {
    let (_, server) = cert();
    let good = Proxy::new(200, Some(server)).await;
    let mut cfg = config(&[good.port], true);
    cfg.groups[0].pool.as_mut().unwrap().check_url =
        "https://localhost:9443/health?fixture=private".into();
    let engine = start(cfg).await;
    until(|| {
        engine
            .selector
            .lock()
            .unwrap()
            .pool_health
            .values()
            .all(|h| h.checks > 0)
    })
    .await;
    let value = engine.snapshot();
    assert_eq!(value["pools"][0]["members"][0]["errorCategory"], "tls");
    assert_eq!(
        engine
            .decision(&engine.current.load(), "example.test", 443, "tcp")
            .unwrap()
            .outbound,
        "REJECT"
    );
    engine.stop().await.unwrap();
}

#[tokio::test]
async fn monitor_is_bounded_and_stop_cancels_checks() {
    let proxy = Proxy::new(0, None).await;
    let engine = start(config(&[proxy.port; 6], true)).await;
    until(|| proxy.requests.load(Ordering::SeqCst) == 2).await;
    assert_eq!(
        engine
            .selector
            .lock()
            .unwrap()
            .pool_health
            .values()
            .filter(|h| h.checking)
            .count(),
        2
    );
    let started = Instant::now();
    engine.stop().await.unwrap();
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(proxy.requests.load(Ordering::SeqCst), 2);
    assert!(
        engine
            .selector
            .lock()
            .unwrap()
            .pool_health
            .values()
            .all(|h| !h.checking)
    );
}

#[tokio::test]
async fn metadata_hiding_clears_retry_names_even_on_late_success() {
    let bad = Proxy::new(407, None).await;
    let good = Proxy::new(200, None).await;
    let mut cfg = config(&[bad.port, good.port], false);
    cfg.privacy.hide_metadata = true;
    let engine = start(cfg).await;
    let snap = engine.current.load_full();
    let mut decision = engine.decision(&snap, "private.test", 443, "tcp").unwrap();
    let flow = engine
        .telemetry
        .begin("private.test", 443, "TCP", "fixture", &decision);
    let stream = engine
        .connect_flow(&snap, &mut decision, ("private.test", 443), &flow)
        .await
        .unwrap();
    let value = engine.snapshot();
    assert_eq!(value["flows"][0]["attempts"], json!([]));
    assert_eq!(value["flows"][0]["outbound"], "已隐藏");
    assert!(value["pools"][0]["stats"]["lastOutbound"].is_null());
    drop(stream);
    engine.stop().await.unwrap();
}
