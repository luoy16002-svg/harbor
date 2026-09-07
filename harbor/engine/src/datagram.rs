//! Persistent UDP associations. One physical source port / proxy session per routed flow.
use crate::{
    config::{Config, Node, NodeKind},
    dns::Resolver,
    shadowsocks,
    transport::{self, BoxStream},
    vless,
};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha224};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

#[derive(Debug)]
pub struct Packet {
    pub host: String,
    pub port: u16,
    pub data: Vec<u8>,
}

pub async fn run(
    config: &Config,
    resolver: &Resolver,
    outbound: &str,
    target: (&str, u16),
    mut input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Packet>,
    ready: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    let (host, port) = target;
    ensure!(port > 0, "UDP destination port is zero");
    if outbound == "REJECT" {
        bail!("Blocked by routing policy");
    }
    let node = config.nodes.iter().find(|n| n.name == outbound).cloned();
    if outbound != "DIRECT" && node.is_none() {
        bail!("Unknown outbound");
    }
    let Some(node) = node else {
        let address = resolver
            .lookup(host, port)
            .await?
            .into_iter()
            .next()
            .context("No UDP destination")?;
        let socket = resolver.egress.udp(address)?;
        socket.connect(address).await?;
        let _ = ready.send(());
        let send = async {
            while let Some(data) = input.recv().await {
                socket.send(&data).await?;
            }
            Ok::<(), anyhow::Error>(())
        };
        let receive = async {
            let mut data = vec![0; 65535];
            loop {
                let n = socket.recv(&mut data).await?;
                if output
                    .send(Packet {
                        host: address.ip().to_string(),
                        port: address.port(),
                        data: data[..n].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    return Ok::<(), anyhow::Error>(());
                }
            }
        };
        return tokio::select! {result=send=>result,result=receive=>result};
    };
    match node.kind {
        NodeKind::Http | NodeKind::Https => bail!("HTTP proxies do not support UDP"),
        NodeKind::Socks5 | NodeKind::Shadowsocks => {
            let mut control: Option<BoxStream> = None;
            let address = if node.kind == NodeKind::Socks5 {
                let mut stream = transport::wrapped(resolver, &node).await?;
                transport::socks_handshake(&mut stream, &node).await?;
                let (relay_host, relay_port) =
                    transport::socks_command(&mut stream, 3, "0.0.0.0", 0).await?;
                let relay_host = if relay_host == "0.0.0.0" || relay_host == "::" {
                    &node.server
                } else {
                    &relay_host
                };
                let address = resolver.lookup(relay_host, relay_port).await?[0];
                control = Some(stream);
                address
            } else {
                resolver.lookup(&node.server, node.port).await?[0]
            };
            let socket = resolver.egress.udp(address)?;
            socket.connect(address).await?;
            let _ = ready.send(());
            if node.kind == NodeKind::Shadowsocks && crate::ss2022::supported(&node.cipher) {
                let (mut sender, mut receiver) = crate::ss2022::udp(&node.cipher, &node.password)?;
                let send = async {
                    while let Some(data) = input.recv().await {
                        socket.send(&sender.seal(host, port, &data)?).await?;
                    }
                    Ok::<(), anyhow::Error>(())
                };
                let receive = async {
                    let mut bytes = vec![0; 65535];
                    loop {
                        let length = socket.recv(&mut bytes).await?;
                        let Ok(plain) = receiver.open(&bytes[..length]) else {
                            continue;
                        };
                        let (host, port, offset) = transport::parse_address(&plain)?;
                        if output
                            .send(Packet {
                                host,
                                port,
                                data: plain[offset..].to_vec(),
                            })
                            .await
                            .is_err()
                        {
                            return Ok::<(), anyhow::Error>(());
                        }
                    }
                };
                return tokio::select! {result=send=>result,result=receive=>result};
            }
            let send = async {
                while let Some(data) = input.recv().await {
                    let mut packet = vec![];
                    if node.kind == NodeKind::Socks5 {
                        packet.extend([0, 0, 0]);
                    }
                    transport::write_address(&mut packet, host, port)?;
                    packet.extend(data);
                    if node.kind == NodeKind::Shadowsocks {
                        packet = shadowsocks::seal_udp(&node.cipher, &node.password, &packet)?;
                    }
                    socket.send(&packet).await?;
                }
                Ok::<(), anyhow::Error>(())
            };
            let receive = async {
                let mut data = vec![0; 65535];
                loop {
                    let n = socket.recv(&mut data).await?;
                    let packet = if node.kind == NodeKind::Shadowsocks {
                        shadowsocks::open_udp(&node.cipher, &node.password, &data[..n])?
                    } else {
                        ensure!(n >= 3 && data[..3] == [0, 0, 0], "Invalid SOCKS UDP packet");
                        data[3..n].to_vec()
                    };
                    let (host, port, offset) = transport::parse_address(&packet)?;
                    if output
                        .send(Packet {
                            host,
                            port,
                            data: packet[offset..].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        return Ok::<(), anyhow::Error>(());
                    }
                }
            };
            let control_closed = async {
                if let Some(mut stream) = control {
                    let mut byte = [0; 1];
                    let _ = stream.read(&mut byte).await;
                    Err(anyhow::anyhow!("SOCKS UDP control connection closed"))
                } else {
                    std::future::pending::<Result<()>>().await
                }
            };
            tokio::select! {result=send=>result,result=receive=>result,result=control_closed=>result}
        }
        NodeKind::Trojan | NodeKind::Vless => {
            let stream = transport::wrapped(resolver, &node).await?;
            let _ = ready.send(());
            run_framed(stream, &node, host, port, input, output).await
        }
        NodeKind::Vmess => {
            let stream = transport::wrapped(resolver, &node).await?;
            let _ = ready.send(());
            crate::vmess::relay_udp(stream, &node, host, port, input, output).await
        }
    }
}
async fn run_framed(
    mut stream: BoxStream,
    node: &Node,
    host: &str,
    port: u16,
    mut input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Packet>,
) -> Result<()> {
    let trojan = node.kind == NodeKind::Trojan;
    let mut header = if trojan {
        let mut h = format!("{:x}\r\n", Sha224::digest(node.password.as_bytes())).into_bytes();
        h.push(3);
        transport::write_address(&mut h, "0.0.0.0", 0)?;
        h.extend(b"\r\n");
        h
    } else {
        let id = uuid::Uuid::parse_str(&node.uuid)?;
        let mut h = vec![0];
        h.extend(id.as_bytes());
        h.extend([0, 2]);
        vless::address(&mut h, host, port)?;
        h
    };
    stream.write_all(&header).await?;
    header.clear();
    let (mut read, mut write) = tokio::io::split(stream);
    let send = async {
        while let Some(data) = input.recv().await {
            ensure!(data.len() <= 65507, "UDP datagram too large");
            if trojan {
                let mut address = vec![];
                transport::write_address(&mut address, host, port)?;
                write.write_all(&address).await?;
            }
            write.write_u16(data.len() as u16).await?;
            if trojan {
                write.write_all(b"\r\n").await?;
            }
            write.write_all(&data).await?;
        }
        write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let receive = async {
        if !trojan {
            ensure!(
                read.read_u8().await? == 0,
                "VLESS response version mismatch"
            );
            let len = read.read_u8().await? as usize;
            let mut addons = vec![0; len];
            read.read_exact(&mut addons).await?;
        }
        loop {
            let (source, source_port) = if trojan {
                transport::read_address(&mut read).await?
            } else {
                (host.to_string(), port)
            };
            let len = read.read_u16().await? as usize;
            if trojan {
                let mut delimiter = [0; 2];
                read.read_exact(&mut delimiter).await?;
                ensure!(delimiter == *b"\r\n", "Invalid Trojan datagram delimiter");
            }
            let mut data = vec![0; len];
            read.read_exact(&mut data).await?;
            if output
                .send(Packet {
                    host: source,
                    port: source_port,
                    data,
                })
                .await
                .is_err()
            {
                return Ok::<(), anyhow::Error>(());
            }
        }
    };
    tokio::select! {result=send=>result,result=receive=>result}
}
