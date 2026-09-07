use anyhow::{Context, Result, bail};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

#[derive(Default)]
pub struct Egress {
    pub ipv4: AtomicU32,
    pub ipv6: AtomicU32,
    pub active: AtomicBool,
}
impl Egress {
    pub fn configured(mode: crate::config::EgressMode) -> Result<Self> {
        let egress = Self::default();
        #[cfg(windows)]
        if mode == crate::config::EgressMode::Physical {
            let (ipv4, ipv6) = crate::native_tun::physical_routes(0)?;
            egress.ipv4.store(ipv4, Ordering::Relaxed);
            egress.ipv6.store(ipv6, Ordering::Relaxed);
            egress.active.store(true, Ordering::Release);
        }
        #[cfg(not(windows))]
        let _ = mode;
        Ok(egress)
    }

    fn socket(&self, address: SocketAddr, udp: bool) -> Result<Socket> {
        let s = Socket::new(
            Domain::for_address(address),
            if udp { Type::DGRAM } else { Type::STREAM },
            Some(if udp { Protocol::UDP } else { Protocol::TCP }),
        )?;
        s.set_nonblocking(true)?;
        let index = if address.is_ipv4() {
            self.ipv4.load(Ordering::Relaxed)
        } else {
            self.ipv6.load(Ordering::Relaxed)
        };
        if self.active.load(Ordering::Acquire) && index == 0 && !address.ip().is_loopback() {
            bail!("No physical egress interface for this address family");
        }
        if index != 0 && !address.ip().is_loopback() {
            #[cfg(windows)]
            unsafe {
                use std::os::windows::io::AsRawSocket;
                use windows_sys::Win32::Networking::WinSock::*;
                let (level, option, value) = if address.is_ipv4() {
                    (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
                } else {
                    (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
                };
                if setsockopt(
                    s.as_raw_socket() as usize,
                    level,
                    option,
                    (&value as *const u32).cast(),
                    4,
                ) != 0
                {
                    bail!("Cannot bind egress interface: {}", WSAGetLastError());
                }
            }
        }
        if udp {
            s.bind(
                &SocketAddr::new(
                    if address.is_ipv4() {
                        IpAddr::from([0, 0, 0, 0])
                    } else {
                        IpAddr::from([0u16; 8])
                    },
                    0,
                )
                .into(),
            )?;
        }
        Ok(s)
    }
    pub async fn tcp(&self, address: SocketAddr) -> Result<TcpStream> {
        let s: std::net::TcpStream = self.socket(address, false)?.into();
        let stream = TcpSocket::from_std_stream(s)
            .connect(address)
            .await
            .with_context(|| format!("TCP connection to {address} failed"))?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
    pub fn udp(&self, address: SocketAddr) -> Result<UdpSocket> {
        let socket: std::net::UdpSocket = self.socket(address, true)?.into();
        Ok(UdpSocket::from_std(socket)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_physical_route_never_falls_back_to_the_system_tunnel() {
        let egress = Egress::default();
        egress.active.store(true, Ordering::Release);
        for address in ["192.0.2.1:443", "[2001:db8::1]:443"] {
            assert!(egress.socket(address.parse().unwrap(), false).is_err());
        }
        assert!(
            egress
                .socket("127.0.0.1:443".parse().unwrap(), false)
                .is_ok()
        );
    }
}
