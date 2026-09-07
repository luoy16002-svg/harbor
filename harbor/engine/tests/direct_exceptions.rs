use harbor_engine::{
    config::{Config, EgressMode, RoutingMode},
    engine::Engine,
    exceptions::DirectExceptions,
    policy::{self, Selector},
    privacy::DomainFilter,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

fn fixture_config() -> Config {
    let mut config = Config {
        routing_mode: RoutingMode::Global,
        final_policy: "fixture".into(),
        ..Default::default()
    };
    config.nodes.push(
        serde_json::from_value(
            serde_json::json!({"name":"fixture", "kind":"socks5", "server":"127.0.0.1", "port":9}),
        )
        .unwrap(),
    );
    config.direct_exceptions = DirectExceptions {
        enabled: true,
        domains: vec!["video.example".into()],
        processes: vec!["Game.exe".into()],
    };
    config
}

#[test]
fn global_exceptions_keep_all_other_destinations_on_selected_outbound() {
    let mut config = fixture_config();
    let evaluate = |config: &Config, host: &str, protocol: &str, process: Option<&str>| {
        policy::decide_with_process(
            config,
            &mut Selector::default(),
            &DomainFilter::new(&config.privacy),
            (host, 443, protocol),
            process,
            7,
        )
        .unwrap()
    };
    config.validate().unwrap();
    for mode in [RoutingMode::Global, RoutingMode::Rules] {
        config.routing_mode = mode;
        for protocol in ["tcp", "udp"] {
            for host in ["video.example", "CDN.Video.Example."] {
                let decision = evaluate(&config, host, protocol, None);
                assert_eq!(decision.outbound, "DIRECT");
                assert_eq!(decision.generation, 7);
                assert_eq!(decision.rule_index, None);
            }
            for host in [
                "work.example",
                "notvideo.example",
                "video.example.evil",
                "203.0.113.1",
                "2001:db8::1",
            ] {
                assert_eq!(evaluate(&config, host, protocol, None).outbound, "fixture");
                assert_eq!(
                    evaluate(&config, host, protocol, Some("OtherGame.exe")).outbound,
                    "fixture"
                );
                assert_eq!(
                    evaluate(&config, host, protocol, Some("GAME.EXE")).outbound,
                    "DIRECT"
                );
            }
        }
    }
    config.direct_exceptions.enabled = false;
    assert_eq!(
        evaluate(&config, "video.example", "tcp", Some("Game.exe")).outbound,
        "fixture"
    );
    let mut json = serde_json::to_value(&config).unwrap();
    json.as_object_mut().unwrap().remove("directExceptions");
    let legacy: Config = serde_json::from_value(json).unwrap();
    assert!(!legacy.direct_exceptions.enabled);
}

#[test]
fn exceptions_cannot_override_domain_blocks_or_direct_transport_restrictions() {
    let mut config = fixture_config();
    config.privacy.block_direct = true;
    config.privacy.blocked_domains = vec!["video.example".into()];
    for mode in [RoutingMode::Global, RoutingMode::Rules, RoutingMode::Direct] {
        config.routing_mode = mode;
        for protocol in ["tcp", "udp"] {
            for host in ["video.example", "203.0.113.1"] {
                let decision = policy::decide_with_process(
                    &config,
                    &mut Selector::default(),
                    &DomainFilter::new(&config.privacy),
                    (host, 443, protocol),
                    Some("Game.exe"),
                    1,
                )
                .unwrap();
                assert_eq!(decision.outbound, "REJECT");
                assert!(decision.reason.starts_with("Privacy:"));
            }
        }
    }
}

async fn start(mut config: Config) -> Arc<Engine> {
    config.egress_mode = EgressMode::System;
    config.dns_tls.clear();
    config.dns_servers = vec!["127.0.0.1:9".parse().unwrap()];
    config.connect_timeout_ms = 1000;
    for _ in 0..8 {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dns = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let Ok(udp) = UdpSocket::bind(dns.local_addr().unwrap()).await else {
            continue;
        };
        config.listen = tcp.local_addr().unwrap();
        config.dns_listen = dns.local_addr().unwrap();
        drop((tcp, dns, udp));
        match Engine::start(config.clone()).await {
            Ok(engine) => return engine,
            Err(error)
                if error.chain().any(|e| {
                    e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::AddrInUse)
                }) => {}
            Err(error) => panic!("{error:#}"),
        }
    }
    panic!("No loopback fixture ports available")
}

async fn socks(engine: &Engine, target: SocketAddr, command: u8) -> TcpStream {
    let mut stream = TcpStream::connect(engine.current.load().config.listen)
        .await
        .unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut auth = [0; 2];
    stream.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, [5, 0]);
    let mut request = vec![5, command, 0];
    harbor_engine::transport::write_address(&mut request, &target.ip().to_string(), target.port())
        .unwrap();
    stream.write_all(&request).await.unwrap();
    stream
}

async fn marker(stream: &mut TcpStream, expected: &[u8; 5]) {
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    stream.write_all(b"hello").await.unwrap();
    let mut received = [0; 5];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, expected);
}

#[cfg(windows)]
#[tokio::test]
async fn actual_socks_and_connect_process_routes_preserve_old_flow_generation() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = direct.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            loop {
                let (mut stream, _) = direct.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut bytes = [0; 5];
                    while stream.read_exact(&mut bytes).await.is_ok() {
                        if stream.write_all(b"DRECT").await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let mock = tokio::spawn(async move {
            loop {
                let (mut stream, _) = proxy.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut auth = [0; 3];
                    if stream.read_exact(&mut auth).await.is_err() {
                        return;
                    }
                    assert_eq!(auth, [5, 1, 0]);
                    stream.write_all(&[5, 0]).await.unwrap();
                    let mut header = [0; 3];
                    stream.read_exact(&mut header).await.unwrap();
                    harbor_engine::transport::read_address(&mut stream)
                        .await
                        .unwrap();
                    stream
                        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    let mut bytes = [0; 5];
                    while stream.read_exact(&mut bytes).await.is_ok() {
                        if stream.write_all(b"PROXY").await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let mut config = fixture_config();
        config.nodes[0].port = proxy_port;
        config.direct_exceptions.processes = vec![
            std::env::current_exe()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string(),
        ];
        let engine = start(config).await;
        let mut old = socks(&engine, target, 1).await;
        marker(&mut old, b"DRECT").await;
        let mut http = TcpStream::connect(engine.current.load().config.listen)
            .await
            .unwrap();
        http.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut header = vec![];
        while !header.ends_with(b"\r\n\r\n") {
            header.push(http.read_u8().await.unwrap());
            assert!(header.len() < 4096);
        }
        assert!(String::from_utf8(header).unwrap().contains("200"));
        http.write_all(b"hello").await.unwrap();
        let mut bytes = [0; 5];
        http.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"DRECT");
        let mut updated = engine.current.load().config.clone();
        updated.direct_exceptions.enabled = false;
        assert_eq!(engine.configure(updated).unwrap(), 2);
        let mut new = socks(&engine, target, 1).await;
        marker(&mut new, b"PROXY").await;
        old.write_all(b"hello").await.unwrap();
        old.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"DRECT");
        let snapshot = engine.snapshot();
        let flows = snapshot["flows"].as_array().unwrap();
        assert!(
            flows
                .iter()
                .any(|f| f["outbound"] == "DIRECT" && f["generation"] == 1)
        );
        assert!(
            flows
                .iter()
                .any(|f| f["outbound"] == "fixture" && f["generation"] == 2)
        );
        assert!(
            !snapshot
                .to_string()
                .contains(&engine.current.load().config.direct_exceptions.processes[0])
        );
        engine.stop().await.unwrap();
        drop((old, new, http));
        echo.abort();
        mock.abort();
    })
    .await
    .unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn actual_socks_udp_uses_datagram_owner_and_unknown_sources_keep_global_policy() {
    tokio::time::timeout(Duration::from_secs(6), async {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 128];
            let (n, peer) = echo.recv_from(&mut bytes).await.unwrap();
            echo.send_to(&bytes[..n], peer).await.unwrap();
        });
        let mut config = fixture_config();
        config.final_policy = "REJECT".into();
        config.nodes.clear();
        config.direct_exceptions.processes = vec![
            std::env::current_exe()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string(),
        ];
        let engine = start(config).await;
        let mut control = socks(&engine, "0.0.0.0:0".parse().unwrap(), 3).await;
        let mut reply = [0; 3];
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0, 0]);
        let (host, port) = harbor_engine::transport::read_address(&mut control)
            .await
            .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_ne!(
            socket.local_addr().unwrap().port(),
            control.local_addr().unwrap().port()
        );
        let mut packet = vec![0, 0, 0];
        harbor_engine::transport::write_address(
            &mut packet,
            &target.ip().to_string(),
            target.port(),
        )
        .unwrap();
        packet.extend(b"game");
        socket
            .send_to(&packet, (host.as_str(), port))
            .await
            .unwrap();
        let mut buffer = [0; 128];
        let n = socket.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[n - 4..n], b"game");
        task.await.unwrap();
        let current = engine.current.load_full();
        let unknown = engine
            .decision_for_source(&current, ("203.0.113.1", 443, "udp"), None)
            .await
            .unwrap();
        assert_eq!(unknown.outbound, "REJECT");
        engine.stop().await.unwrap();
        drop(control);
    })
    .await
    .unwrap();
}
