//! IP parsing helpers shared by the live adapter and deterministic packet tests.
use anyhow::{Result, bail, ensure};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoints {
    pub source: IpAddress,
    pub destination: IpAddress,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
}
type Payload<'a> = (IpAddress, IpAddress, IpProtocol, &'a [u8]);
fn ip_payload(bytes: &[u8]) -> Result<Option<Payload<'_>>> {
    ensure!(!bytes.is_empty(), "Empty packet");
    let (source, destination, protocol, payload) = match bytes[0] >> 4 {
        4 => {
            let packet = Ipv4Packet::new_checked(bytes)
                .map_err(|_| anyhow::anyhow!("Invalid IPv4 packet"))?;
            ensure!(packet.verify_checksum(), "Invalid IPv4 checksum");
            if packet.frag_offset() != 0 {
                return Ok(None);
            }
            (
                IpAddress::Ipv4(packet.src_addr()),
                IpAddress::Ipv4(packet.dst_addr()),
                packet.next_header(),
                &bytes[packet.header_len() as usize..packet.total_len() as usize],
            )
        }
        6 => {
            let packet = Ipv6Packet::new_checked(bytes)
                .map_err(|_| anyhow::anyhow!("Invalid IPv6 packet"))?;
            let mut next = packet.next_header();
            let mut offset = 40;
            let end = 40 + packet.payload_len() as usize;
            let mut extensions = 0;
            while !matches!(next, IpProtocol::Tcp | IpProtocol::Udp | IpProtocol::Icmpv6) {
                extensions += 1;
                ensure!(
                    extensions <= 8 && offset + 2 <= end,
                    "Invalid IPv6 extension chain"
                );
                let number = u8::from(next);
                if number == 44 {
                    ensure!(offset + 8 <= end, "Truncated IPv6 fragment");
                    if u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) & 0xfff8 != 0 {
                        return Ok(None);
                    }
                    next = bytes[offset].into();
                    offset += 8;
                } else if [0, 43, 60].contains(&number) {
                    let len = (bytes[offset + 1] as usize + 1) * 8;
                    ensure!(offset + len <= end, "Truncated IPv6 extension");
                    next = bytes[offset].into();
                    offset += len;
                } else {
                    return Ok(None);
                }
            }
            (
                IpAddress::Ipv6(packet.src_addr()),
                IpAddress::Ipv6(packet.dst_addr()),
                next,
                &bytes[offset..end],
            )
        }
        _ => bail!("Unsupported IP version"),
    };
    Ok(Some((source, destination, protocol, payload)))
}
pub fn endpoints(bytes: &[u8]) -> Result<Option<Endpoints>> {
    let Some((source, destination, protocol, payload)) = ip_payload(bytes)? else {
        return Ok(None);
    };
    if !matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp) {
        return Ok(None);
    }
    ensure!(
        payload.len() >= if protocol == IpProtocol::Tcp { 20 } else { 8 },
        "Truncated transport header"
    );
    Ok(Some(Endpoints {
        source,
        destination,
        source_port: u16::from_be_bytes([payload[0], payload[1]]),
        destination_port: u16::from_be_bytes([payload[2], payload[3]]),
        protocol: protocol.into(),
    }))
}
pub fn is_initial_syn(bytes: &[u8]) -> bool {
    let Ok(Some((source, destination, IpProtocol::Tcp, payload))) = ip_payload(bytes) else {
        return false;
    };
    let Ok(tcp) = smoltcp::wire::TcpPacket::new_checked(payload) else {
        return false;
    };
    tcp.syn() && !tcp.ack() && tcp.verify_checksum(&source, &destination)
}
pub fn is_external_icmp(bytes: &[u8]) -> bool {
    match ip_payload(bytes) {
        Ok(Some((_, destination, IpProtocol::Icmp, _))) => {
            destination != "198.18.0.2".parse::<IpAddress>().unwrap()
        }
        Ok(Some((_, destination, IpProtocol::Icmpv6, _))) => {
            destination != "fd00:6862::2".parse::<IpAddress>().unwrap()
        }
        _ => false,
    }
}
/// Extracts a conventional ClientHello SNI without decrypting or changing TLS traffic.
pub fn server_name(bytes: &[u8]) -> Option<String> {
    fn word(bytes: &[u8], offset: usize) -> Option<usize> {
        Some(u16::from_be_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?) as usize)
    }
    if bytes.first() != Some(&22) || bytes.get(5) != Some(&1) {
        return None;
    }
    let record_len = word(bytes, 3)?;
    if record_len + 5 > bytes.len() {
        return None;
    }
    let mut offset = 43;
    offset += 1 + *bytes.get(offset)? as usize;
    offset += 2 + word(bytes, offset)?;
    offset += 1 + *bytes.get(offset)? as usize;
    let end = offset + 2 + word(bytes, offset)?;
    offset += 2;
    if end > record_len + 5 {
        return None;
    }
    while offset + 4 <= end {
        let kind = word(bytes, offset)?;
        let len = word(bytes, offset + 2)?;
        offset += 4;
        if offset + len > end {
            return None;
        }
        if kind == 0 {
            let list_end = offset + 2 + word(bytes, offset)?;
            let mut cursor = offset + 2;
            if list_end > offset + len {
                return None;
            }
            while cursor + 3 <= list_end {
                let name_type = bytes[cursor];
                let name_len = word(bytes, cursor + 1)?;
                cursor += 3;
                if cursor + name_len > list_end {
                    return None;
                }
                if name_type == 0 {
                    let name = std::str::from_utf8(&bytes[cursor..cursor + name_len]).ok()?;
                    if name.len() <= 253
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                    {
                        return Some(name.to_ascii_lowercase());
                    }
                    return None;
                }
                cursor += name_len;
            }
        }
        offset += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_packets_are_rejected_without_panics() {
        for length in 0..160 {
            let bytes = vec![0xff; length];
            assert!(endpoints(&bytes).is_err());
            assert!(server_name(&bytes).is_none());
        }
        for first in [0x45, 0x60] {
            for length in 0..60 {
                let mut bytes = vec![0; length];
                if length > 0 {
                    bytes[0] = first;
                }
                let _ = endpoints(&bytes);
            }
        }
    }
}
