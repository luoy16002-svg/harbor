use harbor_engine::{
    config::{Config, Group, GroupKind, RoutingMode},
    policy::{self, Selector},
    privacy::DomainFilter,
    rehearsal::{self, Target},
    traffic_routes::{self, TrafficRoute},
};
use std::time::Instant;

fn path(name: &str, policy: Option<&str>, encrypted: bool) -> TrafficRoute {
    TrafficRoute {
        name: name.into(),
        enabled: true,
        domains: vec!["work.example".into()],
        processes: vec![],
        policy: policy.map(Into::into),
        require_encrypted_proxy: encrypted,
    }
}
fn fixture() -> Config {
    let mut config = Config {
        final_policy: "plain".into(),
        ..Default::default()
    };
    for value in [
        serde_json::json!({"name":"plain","kind":"socks5","server":"127.0.0.1","port":9}),
        serde_json::json!({"name":"tls","kind":"https","server":"127.0.0.1","port":9}),
        serde_json::json!({"name":"aead","kind":"shadowsocks","server":"127.0.0.1","port":9,"password":"fixture"}),
    ] {
        config.nodes.push(serde_json::from_value(value).unwrap());
    }
    config
}
fn evaluate(
    config: &Config,
    selector: &mut Selector,
    host: &str,
    protocol: &str,
    process: Option<&str>,
) -> policy::Decision {
    policy::decide_with_process(
        config,
        selector,
        &DomainFilter::new(&config.privacy),
        (host, 443, protocol),
        process,
        7,
    )
    .unwrap()
}

#[test]
fn ordered_paths_override_modes_and_exceptions_without_weakening_global_blocks() {
    let mut config = fixture();
    let mut first = path("application", Some("aead"), true);
    first.domains.clear();
    first.processes = vec!["Work.exe".into()];
    config.traffic_routes = vec![first, path("website", Some("tls"), false)];
    config.direct_exceptions.enabled = true;
    config.direct_exceptions.domains = vec!["work.example".into()];
    config.validate().unwrap();
    let mut selector = Selector::default();
    for mode in [RoutingMode::Rules, RoutingMode::Global, RoutingMode::Direct] {
        config.routing_mode = mode;
        for protocol in ["tcp", "udp"] {
            let app = evaluate(
                &config,
                &mut selector,
                "SUB.WORK.EXAMPLE.",
                protocol,
                Some("WORK.EXE"),
            );
            assert_eq!(app.outbound, "aead");
            assert!(app.reason.contains("application"));
            assert_eq!(app.generation, 7);
            assert_eq!(
                evaluate(&config, &mut selector, "work.example", protocol, None).outbound,
                if protocol == "tcp" { "tls" } else { "REJECT" }
            );
            assert_eq!(
                evaluate(
                    &config,
                    &mut selector,
                    "203.0.113.1",
                    protocol,
                    Some("work.exe")
                )
                .outbound,
                "aead"
            );
        }
    }
    assert!(traffic_routes::needs_process(&config, "work.example"));
    config.traffic_routes.swap(0, 1);
    assert!(!traffic_routes::needs_process(&config, "work.example"));
    assert_eq!(
        evaluate(
            &config,
            &mut selector,
            "work.example",
            "tcp",
            Some("Work.exe")
        )
        .outbound,
        "tls"
    );
    config.routing_mode = RoutingMode::Global;
    for host in ["notwork.example", "work.example.evil", "203.0.113.1"] {
        assert_eq!(
            evaluate(&config, &mut selector, host, "udp", None).outbound,
            "plain"
        );
    }
    config.privacy.blocked_domains = vec!["work.example".into()];
    assert_eq!(
        evaluate(
            &config,
            &mut selector,
            "work.example",
            "tcp",
            Some("Work.exe")
        )
        .outbound,
        "REJECT"
    );
    config.traffic_routes[1].policy = Some("DIRECT".into());
    config.traffic_routes[1].require_encrypted_proxy = false;
    config.privacy.block_direct = true;
    assert_eq!(
        evaluate(
            &config,
            &mut selector,
            "203.0.113.1",
            "tcp",
            Some("Work.exe")
        )
        .outbound,
        "REJECT"
    );
}

#[test]
fn protected_groups_filter_per_transport_and_preserve_fixed_and_unprotected_choices() {
    let mut config = fixture();
    config.groups.push(Group {
        pool: None,
        name: "pool".into(),
        kind: GroupKind::Fallback,
        members: vec!["DIRECT".into(), "plain".into(), "tls".into(), "aead".into()],
        selected: None,
    });
    config.traffic_routes = vec![path("work", Some("pool"), true)];
    config.validate().unwrap();
    let mut selector = Selector::default();
    selector.reconcile(&config);
    assert_eq!(
        selector.choose(&config, "pool", Instant::now()).unwrap(),
        "DIRECT"
    );
    assert_eq!(
        evaluate(&config, &mut selector, "work.example", "tcp", None).outbound,
        "tls"
    );
    assert_eq!(
        evaluate(&config, &mut selector, "work.example", "udp", None).outbound,
        "aead"
    );
    assert_eq!(
        selector.choose(&config, "pool", Instant::now()).unwrap(),
        "DIRECT"
    );
    for _ in 0..3 {
        selector.record("aead", None, Instant::now());
    }
    assert_eq!(
        evaluate(&config, &mut selector, "work.example", "udp", None).outbound,
        "REJECT"
    );
    assert_eq!(
        evaluate(&config, &mut selector, "work.example", "tcp", None).outbound,
        "tls"
    );
    config.groups[0].kind = GroupKind::Select;
    config.groups[0].selected = Some("plain".into());
    assert_eq!(
        evaluate(&config, &mut selector, "work.example", "tcp", None).outbound,
        "REJECT"
    );
    config.traffic_routes[0].policy = None;
    config.final_policy = "DIRECT".into();
    assert_eq!(
        evaluate(&config, &mut selector, "work.example", "tcp", None).outbound,
        "REJECT"
    );
    config.final_policy = "tls".into();
    assert_eq!(
        evaluate(&config, &mut selector, "work.example", "tcp", None).outbound,
        "tls"
    );
    assert_eq!(
        evaluate(&config, &mut selector, "work.example", "udp", None).outbound,
        "REJECT"
    );
    assert!(policy::decide(&config, &mut selector, "work.example", 443, "other", 1).is_err());
}

#[test]
fn route_import_validates_references_budgets_and_legacy_defaults() {
    let mut config = fixture();
    config.traffic_routes = vec![path("work", None, true)];
    config.validate().unwrap();
    let mut json = serde_json::to_value(&config).unwrap();
    json.as_object_mut().unwrap().remove("trafficRoutes");
    assert!(
        serde_json::from_value::<Config>(json)
            .unwrap()
            .traffic_routes
            .is_empty()
    );
    for policy in ["missing", "DIRECT"] {
        config.traffic_routes[0].policy = Some(policy.into());
        assert!(config.validate().is_err());
    }
    config.traffic_routes[0].policy = None;
    for domain in [
        "https://work.example",
        "*.example",
        "127.0.0.1",
        "bad..example",
    ] {
        config.traffic_routes[0].domains = vec![domain.into()];
        assert!(config.validate().is_err());
    }
    config.traffic_routes = vec![path("same", None, false); 2];
    assert!(config.validate().is_err());
    config.traffic_routes = (0..9)
        .map(|i| {
            let mut route = path(&format!("path{i}"), None, false);
            route.domains = vec!["example.com".into(); 256];
            route
        })
        .collect();
    assert!(config.validate().is_err());
    config.traffic_routes.pop();
    config.validate().unwrap();
    config.traffic_routes = (0..65)
        .map(|i| path(&format!("path{i}"), None, false))
        .collect();
    assert!(config.validate().is_err());
}

#[test]
fn offline_process_preview_matches_the_live_decision_without_mutating_inputs() {
    let before = fixture();
    let mut after = before.clone();
    let mut route = path("protected app", Some("tls"), true);
    route.domains.clear();
    route.processes = vec!["Work.exe".into()];
    after.traffic_routes.push(route);
    let saved = serde_json::to_value(&after).unwrap();
    let targets: Vec<_> = ["tcp", "udp"]
        .into_iter()
        .map(|protocol| Target {
            host: "203.0.113.1".into(),
            port: 443,
            protocol: protocol.into(),
            process: Some("Work.exe".into()),
        })
        .collect();
    let report = rehearsal::compare(&before, &after, &targets).unwrap();
    assert_eq!(report["networkRequests"], 0);
    assert_eq!(report["healthMeasured"], false);
    assert_eq!(report["rows"][0]["after"]["outbound"], "tls");
    assert_eq!(report["rows"][1]["after"]["outbound"], "REJECT");
    assert_eq!(serde_json::to_value(&after).unwrap(), saved);
    let invalid = Target {
        process: Some("C:\\Work.exe".into()),
        ..targets.into_iter().next().unwrap()
    };
    assert!(rehearsal::compare(&before, &after, &[invalid]).is_err());
}
