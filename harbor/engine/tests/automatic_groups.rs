use harbor_engine::{
    config::{Config, Group, GroupKind, RoutingMode},
    policy::{self, Selector},
};
use std::time::{Duration, Instant};

fn fixture(kind: GroupKind, members: &[&str]) -> Config {
    let mut config = Config {
        routing_mode: RoutingMode::Global,
        final_policy: "pool".into(),
        ..Default::default()
    };
    for value in [
        serde_json::json!({"name":"plain","kind":"socks5","server":"127.0.0.1","port":9}),
        serde_json::json!({"name":"tls","kind":"https","server":"127.0.0.1","port":9}),
        serde_json::json!({"name":"aead","kind":"shadowsocks","server":"127.0.0.1","port":9,"password":"fixture"}),
    ] {
        config.nodes.push(serde_json::from_value(value).unwrap());
    }
    config.groups.push(Group {
        pool: None,
        name: "pool".into(),
        kind,
        members: members.iter().map(|v| (*v).into()).collect(),
        selected: None,
    });
    config.validate().unwrap();
    config
}
fn route(config: &Config, selector: &mut Selector, host: &str, protocol: &str) -> policy::Decision {
    policy::decide(config, selector, host, 443, protocol, 9).unwrap()
}

#[test]
fn automatic_groups_apply_global_guards_before_health_and_latency_selection() {
    for kind in [GroupKind::Fallback, GroupKind::Latency] {
        let mut config = fixture(kind, &["DIRECT", "plain", "tls", "aead"]);
        config.privacy.require_encrypted_proxy = true;
        let mut selector = Selector::default();
        // Global proxy encryption alone still permits an explicitly configured DIRECT member.
        assert_eq!(
            route(&config, &mut selector, "work.example", "tcp").outbound,
            "DIRECT"
        );
        config.privacy.block_direct = true;
        let now = Instant::now();
        for (name, ms) in [("plain", 1), ("tls", 2), ("aead", 50)] {
            selector.record(name, Some(Duration::from_millis(ms)), now);
        }
        assert_eq!(
            route(&config, &mut selector, "work.example", "tcp").outbound,
            "tls"
        );
        assert_eq!(
            route(&config, &mut selector, "work.example", "udp").outbound,
            "aead"
        );
        for _ in 0..3 {
            selector.record("aead", None, now);
        }
        let blocked = route(&config, &mut selector, "work.example", "udp");
        assert_eq!(blocked.outbound, "REJECT");
        assert!(blocked.reason.contains("global restrictions"));
        assert_eq!(blocked.generation, 9);
        assert_eq!(
            route(&config, &mut selector, "work.example", "tcp").outbound,
            "tls"
        );
        selector.record("aead", Some(Duration::from_millis(50)), now);
        assert_eq!(
            route(&config, &mut selector, "work.example", "udp").outbound,
            "REJECT"
        );
        selector.record("aead", Some(Duration::from_millis(50)), now);
        assert_eq!(
            route(&config, &mut selector, "work.example", "udp").outbound,
            "aead"
        );
    }
}

#[test]
fn unprotected_tcp_and_udp_keep_independent_sticky_outbounds() {
    let mut config = fixture(GroupKind::Fallback, &["tls", "aead", "plain"]);
    let mut selector = Selector::default();
    for _ in 0..4 {
        assert_eq!(
            route(&config, &mut selector, "work.example", "tcp").outbound,
            "tls"
        );
        assert_eq!(
            route(&config, &mut selector, "work.example", "udp").outbound,
            "aead"
        );
    }
    for _ in 0..3 {
        selector.record("aead", None, Instant::now());
    }
    assert_eq!(
        route(&config, &mut selector, "work.example", "udp").outbound,
        "plain"
    );
    assert_eq!(
        route(&config, &mut selector, "work.example", "tcp").outbound,
        "tls"
    );
    // A configuration edit invalidates an otherwise sticky member's protocol eligibility.
    config.nodes[0].kind = harbor_engine::config::NodeKind::Http;
    selector.reconcile(&config);
    let blocked = route(&config, &mut selector, "work.example", "udp");
    assert_eq!(blocked.outbound, "REJECT");
    assert!(blocked.reason.contains("supports UDP"));
}

#[test]
fn local_direct_exceptions_do_not_change_restricted_remote_group_selection() {
    let mut config = fixture(GroupKind::Fallback, &["DIRECT", "aead"]);
    config.privacy.block_direct = true;
    config.privacy.require_encrypted_proxy = true;
    let mut selector = Selector::default();
    for protocol in ["tcp", "udp"] {
        for local in ["LOCALHOST.", "127.0.0.1", "::1"] {
            assert_eq!(
                route(&config, &mut selector, local, protocol).outbound,
                "DIRECT"
            );
            assert_eq!(
                route(&config, &mut selector, "work.example", protocol).outbound,
                "aead"
            );
        }
    }
}

#[test]
fn fixed_nodes_and_selected_members_are_rejected_without_replacement() {
    let mut config = fixture(GroupKind::Select, &["plain", "tls", "aead"]);
    config.privacy.require_encrypted_proxy = true;
    config.groups[0].selected = Some("plain".into());
    let mut selector = Selector::default();
    let plain = route(&config, &mut selector, "work.example", "tcp");
    assert_eq!(plain.outbound, "REJECT");
    assert!(plain.reason.starts_with("Privacy:"));
    config.groups[0].selected = Some("tls".into());
    config.privacy.require_encrypted_proxy = false;
    for policy in ["pool", "tls"] {
        config.final_policy = policy.into();
        let udp = route(&config, &mut selector, "work.example", "udp");
        assert_eq!(udp.outbound, "REJECT");
        assert!(udp.reason.contains("does not support UDP"));
        assert_eq!(
            route(&config, &mut selector, "work.example", "tcp").outbound,
            "tls"
        );
    }
    config.final_policy = "pool".into();
    config.groups[0].kind = GroupKind::Fallback;
    config.groups[0].members = vec!["tls".into()];
    assert_eq!(
        route(&config, &mut selector, "work.example", "udp").outbound,
        "REJECT"
    );
}
