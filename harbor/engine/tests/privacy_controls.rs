use harbor_engine::{
    config::Config,
    dns::Resolver,
    net::Egress,
    privacy::Privacy,
    rehearsal::{self, Target},
    telemetry::Telemetry,
};
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use std::{sync::Arc, time::Duration};
use tokio::net::UdpSocket;

#[tokio::test]
async fn cname_filter_follows_only_the_answer_chain_and_honors_explicit_exceptions() {
    use hickory_proto::{
        op::MessageType,
        rr::{
            RData, Record,
            rdata::{A, CNAME},
        },
    };
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = Resolver::new(
        vec![upstream.local_addr().unwrap()],
        Arc::new(Egress::default()),
    );
    resolver.set_privacy(&Privacy {
        blocked_domains: vec!["tracker.invalid".into()],
        allowed_domains: vec!["safe.fixture".into()],
        ..Default::default()
    });
    let server = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        for _ in 0..4 {
            let (length, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            let mut reply = Message::from_vec(&bytes[..length]).unwrap();
            reply.metadata.message_type = MessageType::Response;
            let name = reply.queries.as_slice()[0].name().clone();
            let alias = Name::from_ascii("collector.tracker.invalid.").unwrap();
            if name.to_ascii() == "unrelated.fixture." {
                reply.add_answer(Record::from_rdata(name, 60, RData::A(A::new(192, 0, 2, 1))));
                reply.add_answer(Record::from_rdata(
                    Name::from_ascii("unrelated.invalid.").unwrap(),
                    60,
                    RData::CNAME(CNAME(alias)),
                ));
            } else if name.to_ascii() == "loop.fixture." {
                reply.add_answer(Record::from_rdata(
                    name.clone(),
                    60,
                    RData::CNAME(CNAME(name)),
                ));
            } else {
                reply.add_answer(Record::from_rdata(
                    name,
                    60,
                    RData::CNAME(CNAME(alias.clone())),
                ));
                reply.add_answer(Record::from_rdata(
                    alias,
                    60,
                    RData::A(A::new(192, 0, 2, 2)),
                ));
            }
            upstream
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    for (name, blocked, error) in [
        ("blocked.fixture.", true, false),
        ("safe.fixture.", false, false),
        ("unrelated.fixture.", false, false),
        ("loop.fixture.", false, true),
    ] {
        let mut request = Message::query();
        request.metadata.id = 39;
        request.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        let response = resolver.query(&request).await;
        if error {
            assert!(response.is_err());
            continue;
        }
        let response = response.unwrap();
        assert_eq!(response.id, 39);
        assert_eq!(response.response_code == ResponseCode::NXDomain, blocked);
        assert_eq!(response.answers.as_slice().is_empty(), blocked);
    }
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resolver.stats().blocked, 1);
    assert_eq!(resolver.stats().errors, 1);
}

#[tokio::test]
async fn blocked_dns_never_reaches_the_upstream() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = Resolver::new(
        vec![upstream.local_addr().unwrap()],
        Arc::new(Egress::default()),
    );
    resolver.set_privacy(&Privacy {
        blocked_domains: vec!["tracker.invalid".into()],
        ..Default::default()
    });
    let mut request = Message::query();
    request.metadata.id = 37;
    request.add_query(Query::query(
        Name::from_ascii("metrics.tracker.invalid.").unwrap(),
        RecordType::A,
    ));
    let response = resolver.query(&request).await.unwrap();
    assert_eq!(response.id, 37);
    assert_eq!(response.response_code, ResponseCode::NXDomain);
    assert_eq!(resolver.stats().blocked, 1);
    assert_eq!(resolver.stats().misses, 0);
    let mut bytes = [0; 512];
    assert!(
        tokio::time::timeout(Duration::from_millis(80), upstream.recv(&mut bytes))
            .await
            .is_err()
    );
}

#[test]
fn rehearsal_enforces_transport_protection_without_mutating_configuration() {
    let mut before = Config::default();
    let node = serde_json::from_value(serde_json::json!({"name":"local-proxy","kind":"socks5","server":"127.0.0.1","port":1080,"tls":true})).unwrap();
    before.nodes.push(node);
    before.final_policy = "local-proxy".into();
    let original = serde_json::to_value(&before).unwrap();
    let mut after = before.clone();
    after.privacy.require_encrypted_proxy = true;
    let targets = vec![
        Target {
            host: "example.invalid".into(),
            port: 443,
            protocol: "tcp".into(),
            process: None,
        },
        Target {
            host: "example.invalid".into(),
            port: 443,
            protocol: "udp".into(),
            process: None,
        },
    ];
    let report = rehearsal::compare(&before, &after, &targets).unwrap();
    assert_eq!(report["rows"][0]["after"]["outbound"], "local-proxy");
    assert_eq!(report["rows"][1]["after"]["outbound"], "REJECT");
    assert_eq!(report["networkRequests"], 0);
    assert_eq!(serde_json::to_value(&before).unwrap(), original);
    after.final_policy = "DIRECT".into();
    after.privacy.block_direct = true;
    let report = rehearsal::compare(&before, &after, &targets).unwrap();
    assert!(
        report["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["after"]["outbound"] == "REJECT")
    );
    assert!(rehearsal::compare(&before, &after, &[]).is_err());
}

#[test]
fn metadata_hiding_clears_existing_details_and_zero_retention_removes_finished_flows() {
    let telemetry = Arc::new(Telemetry::default());
    telemetry.configure(&Privacy::default());
    let decision = harbor_engine::policy::Decision {
        require_encrypted_proxy: false,
        policy: "sensitive-policy".into(),
        outbound: "sensitive-node".into(),
        reason: "private-domain.invalid".into(),
        rule_index: None,
        generation: 1,
    };
    let mut flow = telemetry.begin(
        "private-domain.invalid",
        443,
        "TCP",
        "127.0.0.1:50000",
        &decision,
    );
    flow.active();
    telemetry.event("info", "private-domain.invalid");
    telemetry.configure(&Privacy {
        hide_metadata: true,
        history_secs: 0,
        ..Default::default()
    });
    let serialized = serde_json::to_string(&*telemetry.flows.lock().unwrap()).unwrap();
    assert!(
        !serialized.contains("private-domain")
            && !serialized.contains("sensitive-node")
            && !serialized.contains("50000")
    );
    assert!(telemetry.events.lock().unwrap().is_empty());
    telemetry.event("error", "private-domain.invalid");
    assert!(telemetry.events.lock().unwrap().is_empty());
    flow.finish(Some("private-domain.invalid failed".into()));
    assert!(telemetry.flows.lock().unwrap().is_empty());
    assert_eq!(
        telemetry.failed.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}
