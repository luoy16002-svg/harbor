use crate::{bridge, config::Node, transport::BoxStream};
use anyhow::{Result, ensure};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn address(out: &mut Vec<u8>, host: &str, port: u16) -> Result<()> {
    out.extend(port.to_be_bytes());
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend(ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            out.push(3);
            out.extend(ip.octets());
        }
        Err(_) => {
            ensure!(!host.is_empty() && host.len() <= 253, "Invalid hostname");
            out.push(2);
            out.push(host.len() as u8);
            out.extend(host.as_bytes());
        }
    }
    Ok(())
}
pub async fn connect(
    mut stream: BoxStream,
    node: &Node,
    host: &str,
    port: u16,
) -> Result<BoxStream> {
    let id = uuid::Uuid::parse_str(&node.uuid)?;
    let mut header = vec![0];
    header.extend(id.as_bytes());
    header.extend([0, 1]);
    address(&mut header, host, port)?;
    stream.write_all(&header).await?;
    Ok(bridge::spawn(move |local| async move {
        let (mut remote_read, mut remote_write) = tokio::io::split(stream);
        let (mut local_read, mut local_write) = tokio::io::split(local);
        let upload = async {
            tokio::io::copy(&mut local_read, &mut remote_write).await?;
            remote_write.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        };
        let download = async {
            ensure!(
                remote_read.read_u8().await? == 0,
                "VLESS response version mismatch"
            );
            let len = remote_read.read_u8().await? as usize;
            let mut addons = vec![0; len];
            remote_read.read_exact(&mut addons).await?;
            tokio::io::copy(&mut remote_read, &mut local_write).await?;
            local_write.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        };
        tokio::try_join!(upload, download)?;
        Ok(())
    }))
}
pub async fn udp(
    mut stream: BoxStream,
    node: &Node,
    host: &str,
    port: u16,
    data: &[u8],
) -> Result<Vec<u8>> {
    let id = uuid::Uuid::parse_str(&node.uuid)?;
    let mut header = vec![0];
    header.extend(id.as_bytes());
    header.extend([0, 2]);
    address(&mut header, host, port)?;
    stream.write_all(&header).await?;
    ensure!(data.len() <= 65507, "UDP datagram too large");
    stream.write_u16(data.len() as u16).await?;
    stream.write_all(data).await?;
    ensure!(
        stream.read_u8().await? == 0,
        "VLESS response version mismatch"
    );
    let len = stream.read_u8().await? as usize;
    let mut addons = vec![0; len];
    stream.read_exact(&mut addons).await?;
    let len = stream.read_u16().await? as usize;
    let mut reply = vec![0; len];
    stream.read_exact(&mut reply).await?;
    Ok(reply)
}
