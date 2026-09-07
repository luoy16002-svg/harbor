use crate::{
    config::{Config, Node, NodeKind},
    dns::Resolver,
    shadowsocks,
};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use sha2::{Digest, Sha224};
use std::{
    net::IpAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;

pub fn write_address(buffer: &mut Vec<u8>, host: &str, port: u16) -> Result<()> {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            buffer.push(1);
            buffer.extend(ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            buffer.push(4);
            buffer.extend(ip.octets());
        }
        Err(_) => {
            ensure!(
                !host.is_empty() && host.len() <= 253 && !host.chars().any(char::is_control),
                "Invalid destination hostname"
            );
            buffer.push(3);
            buffer.push(host.len() as u8);
            buffer.extend(host.as_bytes());
        }
    }
    buffer.extend(port.to_be_bytes());
    Ok(())
}
pub async fn read_address<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(String, u16)> {
    let kind = reader.read_u8().await?;
    read_address_kind(reader, kind).await
}
pub async fn read_address_kind<R: AsyncRead + Unpin>(
    reader: &mut R,
    kind: u8,
) -> Result<(String, u16)> {
    let host = match kind {
        1 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes).await?;
            IpAddr::from(bytes).to_string()
        }
        4 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes).await?;
            IpAddr::from(bytes).to_string()
        }
        3 => {
            let len = reader.read_u8().await? as usize;
            ensure!(len > 0, "Empty hostname");
            let mut bytes = vec![0; len];
            reader.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).context("Hostname is not UTF-8")?
        }
        _ => bail!("Unsupported address type"),
    };
    let port = reader.read_u16().await?;
    Ok((host, port))
}
pub fn parse_address(bytes: &[u8]) -> Result<(String, u16, usize)> {
    ensure!(!bytes.is_empty(), "Missing address");
    let (host, end) = match bytes[0] {
        1 => {
            ensure!(bytes.len() >= 7, "Truncated IPv4 address");
            (
                IpAddr::from(<[u8; 4]>::try_from(&bytes[1..5])?).to_string(),
                5,
            )
        }
        4 => {
            ensure!(bytes.len() >= 19, "Truncated IPv6 address");
            (
                IpAddr::from(<[u8; 16]>::try_from(&bytes[1..17])?).to_string(),
                17,
            )
        }
        3 => {
            ensure!(bytes.len() >= 2, "Truncated domain");
            let len = bytes[1] as usize;
            ensure!(len > 0 && bytes.len() >= len + 4, "Truncated domain");
            (
                std::str::from_utf8(&bytes[2..2 + len])?.to_string(),
                2 + len,
            )
        }
        _ => bail!("Unsupported address type"),
    };
    Ok((
        host,
        u16::from_be_bytes([bytes[end], bytes[end + 1]]),
        end + 2,
    ))
}

pub async fn tcp(resolver: &Resolver, host: &str, port: u16) -> Result<BoxStream> {
    let addresses = resolver.lookup(host, port).await?;
    // Race address families with a bounded stagger; a dead first address must not consume the entire connection timeout.
    let mut tasks = tokio::task::JoinSet::new();
    for (i, address) in addresses.into_iter().take(8).enumerate() {
        let egress = resolver.egress.clone();
        tasks.spawn(async move {
            tokio::time::sleep(Duration::from_millis(i as u64 * 200)).await;
            egress.tcp(address).await
        });
    }
    let mut error = String::new();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                tasks.abort_all();
                return Ok(Box::new(stream));
            }
            Ok(Err(e)) => error = e.to_string(),
            Err(e) => error = e.to_string(),
        }
    }
    bail!("All destination addresses failed: {error}")
}
fn tls_config() -> Result<Arc<ClientConfig>> {
    static TLS: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(config) = TLS.get() {
        return Ok(config.clone());
    }
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    ensure!(
        !roots.is_empty(),
        "Windows trusted certificate store is empty"
    );
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let _ = TLS.set(config.clone());
    Ok(config)
}
pub async fn tls(stream: BoxStream, node: &Node) -> Result<BoxStream> {
    let name = if node.tls_server_name.is_empty() {
        &node.server
    } else {
        &node.tls_server_name
    };
    tls_named(stream, name, &node.ca_pem).await
}
pub async fn tls_named(stream: BoxStream, name: &str, ca_pem: &str) -> Result<BoxStream> {
    let name = ServerName::try_from(name.to_string()).context("Invalid TLS server name")?;
    let config = if ca_pem.is_empty() {
        tls_config()?
    } else {
        let mut roots = RootCertStore::empty();
        use rustls::pki_types::pem::PemObject;
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            roots.add(cert?).context("Invalid custom CA certificate")?;
        }
        ensure!(!roots.is_empty(), "Custom CA contains no certificate");
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    };
    Ok(Box::new(
        TlsConnector::from(config)
            .connect(name, stream)
            .await
            .context("TLS certificate or handshake failed")?,
    ))
}

pub async fn socks_handshake(stream: &mut BoxStream, node: &Node) -> Result<()> {
    let auth = !node.username.is_empty() || !node.password.is_empty();
    stream
        .write_all(if auth { &[5, 1, 2] } else { &[5, 1, 0] })
        .await?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await?;
    ensure!(
        reply == [5, if auth { 2 } else { 0 }],
        "SOCKS5 authentication method rejected"
    );
    if auth {
        let mut credentials = vec![1, node.username.len() as u8];
        credentials.extend(node.username.as_bytes());
        credentials.push(node.password.len() as u8);
        credentials.extend(node.password.as_bytes());
        stream.write_all(&credentials).await?;
        stream.read_exact(&mut reply).await?;
        ensure!(reply == [1, 0], "SOCKS5 credentials rejected");
    }
    Ok(())
}
pub async fn socks_command(
    stream: &mut BoxStream,
    command: u8,
    host: &str,
    port: u16,
) -> Result<(String, u16)> {
    let mut request = vec![5, command, 0];
    write_address(&mut request, host, port)?;
    stream.write_all(&request).await?;
    let mut response = [0; 3];
    stream.read_exact(&mut response).await?;
    ensure!(
        response[0] == 5 && response[1] == 0 && response[2] == 0,
        "SOCKS5 request rejected (code {})",
        response[1]
    );
    read_address(stream).await
}

pub async fn wrapped(resolver: &Resolver, node: &Node) -> Result<BoxStream> {
    let mut stream = tcp(resolver, &node.server, node.port).await?;
    if node.tls || matches!(node.kind, NodeKind::Trojan | NodeKind::Https) {
        stream = tls(stream, node).await?;
    }
    if node.transport == "ws" {
        stream = crate::websocket::connect(stream, node).await?;
    }
    Ok(stream)
}

pub async fn connect(
    config: &Config,
    resolver: &Resolver,
    outbound: &str,
    host: &str,
    port: u16,
) -> Result<BoxStream> {
    ensure!(port != 0, "Destination port must be nonzero");
    if outbound == "REJECT" {
        bail!("Blocked by routing policy");
    }
    tokio::time::timeout(Duration::from_millis(config.connect_timeout_ms), async {
        if outbound == "DIRECT" {
            return tcp(resolver, host, port).await;
        }
        let node = config
            .nodes
            .iter()
            .find(|n| n.name == outbound)
            .context("Outbound no longer exists in this configuration")?;
        let mut stream = wrapped(resolver, node).await?;
        match node.kind {
            NodeKind::Http | NodeKind::Https => {
                let authority = if host.contains(':') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                };
                ensure!(
                    !authority
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace()),
                    "Invalid CONNECT authority"
                );
                let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
                if !node.username.is_empty() || !node.password.is_empty() {
                    request.push_str(&format!(
                        "Proxy-Authorization: Basic {}\r\n",
                        base64::engine::general_purpose::STANDARD
                            .encode(format!("{}:{}", node.username, node.password))
                    ));
                }
                request.push_str("\r\n");
                stream.write_all(request.as_bytes()).await?;
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    ensure!(
                        header.len() < 16384,
                        "Upstream HTTP response header too large"
                    );
                    header.push(stream.read_u8().await?);
                }
                let first = std::str::from_utf8(&header)?
                    .lines()
                    .next()
                    .unwrap_or_default();
                let code = first.split_whitespace().nth(1).unwrap_or_default();
                ensure!(
                    first.starts_with("HTTP/1.") && code == "200",
                    "HTTP proxy refused CONNECT ({code})"
                );
                Ok(stream)
            }
            NodeKind::Socks5 => {
                socks_handshake(&mut stream, node).await?;
                socks_command(&mut stream, 1, host, port).await?;
                Ok(stream)
            }
            NodeKind::Trojan => {
                let mut header =
                    format!("{:x}\r\n", Sha224::digest(node.password.as_bytes())).into_bytes();
                header.push(1);
                write_address(&mut header, host, port)?;
                header.extend(b"\r\n");
                stream.write_all(&header).await?;
                Ok(stream)
            }
            NodeKind::Shadowsocks => {
                shadowsocks::stream(stream, &node.cipher, &node.password, host, port).await
            }
            NodeKind::Vless => crate::vless::connect(stream, node, host, port).await,
            NodeKind::Vmess => crate::vmess::connect(stream, node, host, port).await,
        }
    })
    .await
    .context("Connection handshake timed out")?
}

pub async fn udp_exchange(
    config: &Config,
    resolver: &Resolver,
    outbound: &str,
    host: &str,
    port: u16,
    data: &[u8],
) -> Result<(String, u16, Vec<u8>)> {
    tokio::time::timeout(Duration::from_millis(config.connect_timeout_ms), async {
        if outbound == "REJECT" {
            bail!("Blocked by routing policy");
        }
        if outbound == "DIRECT" {
            let address = resolver
                .lookup(host, port)
                .await?
                .into_iter()
                .next()
                .context("No UDP address")?;
            let socket = resolver.egress.udp(address)?;
            socket.connect(address).await?;
            socket.send(data).await?;
            let mut buf = vec![0; 65535];
            let n = socket.recv(&mut buf).await?;
            buf.truncate(n);
            return Ok((address.ip().to_string(), address.port(), buf));
        }
        let node = config
            .nodes
            .iter()
            .find(|n| n.name == outbound)
            .context("Unknown outbound")?;
        match node.kind {
            NodeKind::Shadowsocks => {
                let address = resolver.lookup(&node.server, node.port).await?[0];
                let socket = resolver.egress.udp(address)?;
                socket.connect(address).await?;
                if crate::ss2022::supported(&node.cipher) {
                    let (mut sender, mut receiver) =
                        crate::ss2022::udp(&node.cipher, &node.password)?;
                    socket.send(&sender.seal(host, port, data)?).await?;
                    let mut bytes = vec![0; 65535];
                    loop {
                        let length = socket.recv(&mut bytes).await?;
                        let Ok(plain) = receiver.open(&bytes[..length]) else {
                            continue;
                        };
                        let (host, port, offset) = parse_address(&plain)?;
                        return Ok((host, port, plain[offset..].to_vec()));
                    }
                }
                let mut plain = vec![];
                write_address(&mut plain, host, port)?;
                plain.extend(data);
                socket
                    .send(&shadowsocks::seal_udp(
                        &node.cipher,
                        &node.password,
                        &plain,
                    )?)
                    .await?;
                let mut buf = vec![0; 65535];
                let n = socket.recv(&mut buf).await?;
                let plain = shadowsocks::open_udp(&node.cipher, &node.password, &buf[..n])?;
                let (host, port, offset) = parse_address(&plain)?;
                Ok((host, port, plain[offset..].to_vec()))
            }
            NodeKind::Socks5 => {
                let mut control = tcp(resolver, &node.server, node.port).await?;
                socks_handshake(&mut control, node).await?;
                let (relay_host, relay_port) = socks_command(&mut control, 3, "0.0.0.0", 0).await?;
                let relay_host = if relay_host == "0.0.0.0" || relay_host == "::" {
                    &node.server
                } else {
                    &relay_host
                };
                let address = resolver.lookup(relay_host, relay_port).await?[0];
                let socket = resolver.egress.udp(address)?;
                socket.connect(address).await?;
                let mut packet = vec![0, 0, 0];
                write_address(&mut packet, host, port)?;
                packet.extend(data);
                socket.send(&packet).await?;
                let mut buf = vec![0; 65535];
                let n = socket.recv(&mut buf).await?;
                ensure!(
                    n >= 3 && buf[..3] == [0, 0, 0],
                    "Invalid SOCKS5 UDP response"
                );
                let (host, port, offset) = parse_address(&buf[3..n])?;
                Ok((host, port, buf[3 + offset..n].to_vec()))
            }
            NodeKind::Trojan => {
                let mut stream = wrapped(resolver, node).await?;
                let mut request =
                    format!("{:x}\r\n", Sha224::digest(node.password.as_bytes())).into_bytes();
                request.push(3);
                write_address(&mut request, "0.0.0.0", 0)?;
                request.extend(b"\r\n");
                write_address(&mut request, host, port)?;
                ensure!(data.len() <= 65507, "Datagram too large");
                request.extend((data.len() as u16).to_be_bytes());
                request.extend(b"\r\n");
                request.extend(data);
                stream.write_all(&request).await?;
                let (host, port) = read_address(&mut stream).await?;
                let len = stream.read_u16().await? as usize;
                let mut crlf = [0; 2];
                stream.read_exact(&mut crlf).await?;
                ensure!(crlf == *b"\r\n", "Invalid Trojan UDP delimiter");
                let mut bytes = vec![0; len];
                stream.read_exact(&mut bytes).await?;
                Ok((host, port, bytes))
            }
            NodeKind::Vless => {
                let reply =
                    crate::vless::udp(wrapped(resolver, node).await?, node, host, port, data)
                        .await?;
                Ok((host.into(), port, reply))
            }
            NodeKind::Vmess => {
                let reply =
                    crate::vmess::udp(wrapped(resolver, node).await?, node, host, port, data)
                        .await?;
                Ok((host.into(), port, reply))
            }
            _ => bail!("This HTTP outbound does not support UDP"),
        }
    })
    .await
    .context("UDP exchange timed out")?
}
