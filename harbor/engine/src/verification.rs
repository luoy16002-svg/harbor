use crate::{config::Config, dns::Resolver, net::Egress, privacy, transport};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A user-initiated, single HTTPS request through one concrete proxy node.
/// This does not bind a listener, create an adapter, or mutate system settings.
pub async fn verify(config: Config, outbound: String, egress: Arc<Egress>) -> Result<Value> {
    verify_target(&config, &outbound, egress, "www.example.com", "").await
}

/// Check the default proxy server's address before the UI captures system traffic.
/// DIRECT/REJECT and literal IPs need no external DNS query.
pub async fn preflight(config: Config) -> Result<Value> {
    config.validate()?;
    let mut selector = crate::policy::Selector::default();
    selector.reconcile(&config);
    let outbound = selector.choose(&config, &config.final_policy, Instant::now())?;
    let Some(node) = config.nodes.iter().find(|node| node.name == outbound) else {
        return Ok(json!({"ready":true,"dnsRequired":false,"outbound":outbound}));
    };
    let resolver = Resolver::new(
        config.dns_servers.clone(),
        Arc::new(Egress::configured(config.egress_mode)?),
    );
    resolver.configure(config.dns_servers.clone(), config.dns_tls.clone());
    resolver.set_privacy(&config.privacy);
    let addresses = tokio::time::timeout(
        Duration::from_secs(15),
        resolver.lookup(&node.server, node.port),
    )
    .await
    .context("Proxy server DNS preflight timed out")??;
    Ok(
        json!({"ready":true,"dnsRequired":node.server.parse::<std::net::IpAddr>().is_err(),"outbound":outbound,"resolvedAddresses":addresses.len()}),
    )
}

async fn verify_target(
    config: &Config,
    outbound: &str,
    egress: Arc<Egress>,
    host: &str,
    ca: &str,
) -> Result<Value> {
    config.validate()?;
    ensure!(
        config.nodes.iter().any(|node| node.name == outbound),
        "Choose a concrete proxy node"
    );
    let filter = privacy::DomainFilter::new(&config.privacy);
    ensure!(
        !filter.blocked(host),
        "Verification target is blocked by domain rules"
    );
    if let Some(reason) = privacy::rejection(config, host, "tcp", outbound) {
        anyhow::bail!("Verification blocked by privacy settings: {reason}");
    }
    let resolver = Resolver::new(config.dns_servers.clone(), egress);
    resolver.configure(config.dns_servers.clone(), config.dns_tls.clone());
    resolver.set_privacy(&config.privacy);
    let started = Instant::now();
    let mut stage = "proxy connection and DNS";
    tokio::time::timeout(Duration::from_secs(20), async {
        let tunnel = transport::connect(config, &resolver, outbound, host, 443).await.context("Proxy connection failed")?;
        stage = "destination TLS handshake";
        let mut stream = transport::tls_named(tunnel, host, ca).await.context("Destination TLS verification failed")?;
        stage = "HTTPS response";
        stream.write_all(format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            ensure!(header.len() < 8192, "Verification response header exceeds 8 KiB");
            header.push(stream.read_u8().await.context("Incomplete HTTPS response")?);
        }
        let first = std::str::from_utf8(&header)?.lines().next().unwrap_or_default();
        let mut words = first.split_whitespace();
        ensure!(matches!(words.next(), Some("HTTP/1.1" | "HTTP/1.0")), "Invalid HTTPS response");
        let status: u16 = words.next().context("Missing HTTP status")?.parse()?;
        ensure!((200..400).contains(&status), "Verification destination returned HTTP {status}");
        Ok(json!({"outbound":outbound,"target":host,"protocol":"HTTPS","status":status,"elapsedMs":started.elapsed().as_millis(),"verified":"proxy-tunnel + destination TLS + HTTP response","udpVerified":false}))
    }).await.with_context(|| format!("Line verification timed out during {stage} (20 seconds)"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_rustls::{
        TlsAcceptor,
        rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer},
    };

    async fn fixture(proxy_status: &str, response: &str, trust: bool) -> Result<Value> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = cert.cert.pem();
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let proxy_status = proxy_status.to_owned();
        let response = response.to_owned();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
            }
            assert!(String::from_utf8_lossy(&header).starts_with("CONNECT localhost:443 HTTP/1.1"));
            stream
                .write_all(format!("HTTP/1.1 {proxy_status}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            if !proxy_status.starts_with("200") {
                return;
            }
            let Ok(mut stream) = TlsAcceptor::from(Arc::new(server)).accept(stream).await else {
                return;
            };
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n"));
            let _ = stream.write_all(response.as_bytes()).await;
        });
        let mut config = Config::default();
        config.nodes.push(
            serde_json::from_value(
                json!({"name":"fixture","kind":"http","server":"127.0.0.1","port":port}),
            )
            .unwrap(),
        );
        let result = verify_target(
            &config,
            "fixture",
            Arc::default(),
            "localhost",
            if trust { &pem } else { "" },
        )
        .await;
        task.await.unwrap();
        result
    }

    #[tokio::test]
    async fn verification_requires_proxy_and_tls_and_http() {
        let result = fixture(
            "200 Connection Established",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            true,
        )
        .await
        .unwrap();
        assert_eq!(result["status"], 200);
        assert_eq!(result["udpVerified"], false);
    }
    #[tokio::test]
    async fn open_port_is_not_a_working_proxy() {
        let error = fixture("407 Proxy Authentication Required", "", true)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("407"));
    }
    #[tokio::test]
    async fn destination_certificate_must_be_trusted() {
        assert!(
            fixture("200 Connection Established", "", false)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn failure_status_is_not_success() {
        assert!(
            fixture(
                "200 Connection Established",
                "HTTP/1.1 503 Unavailable\r\n\r\n",
                true
            )
            .await
            .is_err()
        );
    }
    #[tokio::test]
    async fn rejects_groups_and_direct_without_network() {
        assert!(
            verify(Config::default(), "DIRECT".into(), Arc::default())
                .await
                .is_err()
        );
    }
}
