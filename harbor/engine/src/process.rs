//! Best-effort local socket ownership. Never a source of client-supplied identity.
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug)]
pub enum Source {
    Tcp {
        local: SocketAddr,
        remote: SocketAddr,
    },
    Udp {
        local: SocketAddr,
    },
}

pub struct Resolver {
    slots: Arc<Semaphore>,
}
impl Default for Resolver {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(4)),
        }
    }
}
impl Resolver {
    pub async fn name(&self, source: Source) -> Option<String> {
        // A timed-out blocking call keeps its permit until it actually exits.
        // No waiting queue and no persistent PID, executable or endpoint cache.
        let permit = self.slots.clone().try_acquire_owned().ok()?;
        let work = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            lookup(source)
        });
        tokio::time::timeout(Duration::from_millis(250), work)
            .await
            .ok()?
            .ok()?
    }
}

#[cfg(not(windows))]
fn lookup(_: Source) -> Option<String> {
    None
}

#[cfg(windows)]
fn lookup(source: Source) -> Option<String> {
    windows::lookup(source)
}

#[cfg(windows)]
mod windows {
    use super::Source;
    use std::{
        mem::{offset_of, size_of},
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE},
        NetworkManagement::IpHelper::*,
        Networking::WinSock::{AF_INET, AF_INET6},
        System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        },
    };

    #[derive(Clone, Copy)]
    struct Row {
        local: SocketAddr,
        remote: Option<SocketAddr>,
        pid: u32,
    }

    fn canonical(address: SocketAddr) -> SocketAddr {
        match address {
            SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => {
                SocketAddr::new(v6.ip().to_ipv4_mapped().unwrap().into(), v6.port())
            }
            value => value,
        }
    }

    fn owner(rows: impl IntoIterator<Item = Row>, source: Source) -> Option<u32> {
        let (local, remote) = match source {
            Source::Tcp { local, remote } => (canonical(local), Some(canonical(remote))),
            Source::Udp { local } => (canonical(local), None),
        };
        let mut found = None;
        for row in rows {
            let row_local = canonical(row.local);
            let matched = if let Some(remote) = remote {
                row_local == local && row.remote.map(canonical) == Some(remote)
            } else {
                row.remote.is_none()
                    && row_local.port() == local.port()
                    && row_local.is_ipv4() == local.is_ipv4()
                    && (row_local == local || row_local.ip().is_unspecified())
            };
            if matched {
                // Shared UDP bindings, missing owners and conflicting snapshots
                // are ambiguous. Never choose the first entry from an OS table.
                if row.pid == 0 || found.is_some_and(|pid| pid != row.pid) {
                    return None;
                }
                found = Some(row.pid);
            }
        }
        found
    }

    fn table(tcp: bool, ipv6: bool) -> Option<(Vec<u32>, usize)> {
        let family = if ipv6 { AF_INET6 } else { AF_INET } as u32;
        let mut bytes = 0u32;
        let call = |buffer, bytes: &mut u32| unsafe {
            // The API is synchronous; backing memory remains live and aligned.
            if tcp {
                GetExtendedTcpTable(buffer, bytes, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
            } else {
                GetExtendedUdpTable(buffer, bytes, 0, family, UDP_TABLE_OWNER_PID, 0)
            }
        };
        if call(std::ptr::null_mut(), &mut bytes) != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        for _ in 0..3 {
            if !(4..=8 * 1024 * 1024).contains(&bytes) {
                return None;
            }
            let mut buffer = vec![0u32; (bytes as usize).div_ceil(4)];
            let capacity = bytes;
            let result = call(buffer.as_mut_ptr().cast(), &mut bytes);
            if result == 0 && bytes <= capacity {
                return Some((buffer, bytes as usize));
            }
            if result != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }
        }
        None
    }

    // Only called with SDK POD row types for the corresponding table class.
    fn rows<T: Copy>(buffer: &[u32], length: usize, offset: usize) -> Option<Vec<T>> {
        let count = *buffer.first()? as usize;
        let end = offset.checked_add(count.checked_mul(size_of::<T>())?)?;
        if end > length || length > std::mem::size_of_val(buffer) {
            return None;
        }
        let base = buffer.as_ptr().cast::<u8>();
        Some(
            (0..count)
                .map(|index| unsafe {
                    // Bounds were checked above. SDK rows contain no pointers or invalid
                    // bit patterns; unaligned reads also tolerate table padding.
                    base.add(offset + index * size_of::<T>())
                        .cast::<T>()
                        .read_unaligned()
                })
                .collect(),
        )
    }

    fn v4(ip: u32, port: u32) -> SocketAddr {
        SocketAddr::new(
            Ipv4Addr::from(ip.to_ne_bytes()).into(),
            u16::from_be(port as u16),
        )
    }
    fn v6(ip: [u8; 16], port: u32, scope: u32) -> SocketAddr {
        SocketAddrV6::new(Ipv6Addr::from(ip), u16::from_be(port as u16), 0, scope).into()
    }
    fn query(source: Source) -> Option<u32> {
        let (local, tcp) = match source {
            Source::Tcp { local, .. } => (local, true),
            Source::Udp { local } => (local, false),
        };
        let ipv6 = canonical(local).is_ipv6();
        let (buffer, length) = table(tcp, ipv6)?;
        let entries: Vec<Row> = match (tcp, ipv6) {
            (true, false) => rows::<MIB_TCPROW_OWNER_PID>(
                &buffer,
                length,
                offset_of!(MIB_TCPTABLE_OWNER_PID, table),
            )?
            .into_iter()
            .map(|r| Row {
                local: v4(r.dwLocalAddr, r.dwLocalPort),
                remote: Some(v4(r.dwRemoteAddr, r.dwRemotePort)),
                pid: r.dwOwningPid,
            })
            .collect(),
            (true, true) => rows::<MIB_TCP6ROW_OWNER_PID>(
                &buffer,
                length,
                offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
            )?
            .into_iter()
            .map(|r| Row {
                local: v6(r.ucLocalAddr, r.dwLocalPort, r.dwLocalScopeId),
                remote: Some(v6(r.ucRemoteAddr, r.dwRemotePort, r.dwRemoteScopeId)),
                pid: r.dwOwningPid,
            })
            .collect(),
            (false, false) => rows::<MIB_UDPROW_OWNER_PID>(
                &buffer,
                length,
                offset_of!(MIB_UDPTABLE_OWNER_PID, table),
            )?
            .into_iter()
            .map(|r| Row {
                local: v4(r.dwLocalAddr, r.dwLocalPort),
                remote: None,
                pid: r.dwOwningPid,
            })
            .collect(),
            (false, true) => rows::<MIB_UDP6ROW_OWNER_PID>(
                &buffer,
                length,
                offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
            )?
            .into_iter()
            .map(|r| Row {
                local: v6(r.ucLocalAddr, r.dwLocalPort, r.dwLocalScopeId),
                remote: None,
                pid: r.dwOwningPid,
            })
            .collect(),
        };
        owner(entries, source)
    }

    struct ProcessHandle(HANDLE);
    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub(super) fn lookup(source: Source) -> Option<String> {
        let pid = query(source)?;
        // Read-only limited query access. No privilege adjustment or injection.
        let handle =
            ProcessHandle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        if handle.0.is_null() {
            return None;
        }
        let mut path = vec![0u16; 32768];
        let mut length = path.len() as u32;
        if unsafe { QueryFullProcessImageNameW(handle.0, 0, path.as_mut_ptr(), &mut length) } == 0 {
            return None;
        }
        let path = String::from_utf16(path.get(..length as usize)?).ok()?;
        let name = path.rsplit(['\\', '/']).next()?.to_string();
        // Confirm ownership while holding the process handle. Nothing is cached.
        if query(source) != Some(pid) {
            return None;
        }
        Some(name)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn exact_tcp_tuple_and_conservative_udp_binding_match() {
            let local = "127.0.0.1:33001".parse().unwrap();
            let remote = "127.0.0.1:33002".parse().unwrap();
            let tcp = Source::Tcp { local, remote };
            let row = Row {
                local,
                remote: Some(remote),
                pid: 7,
            };
            assert_eq!(owner([row], tcp), Some(7));
            assert_eq!(
                owner(
                    [Row {
                        remote: Some("127.0.0.1:33003".parse().unwrap()),
                        ..row
                    }],
                    tcp
                ),
                None
            );
            let udp = Source::Udp { local };
            let row = Row {
                local: "0.0.0.0:33001".parse().unwrap(),
                remote: None,
                pid: 7,
            };
            assert_eq!(owner([row], udp), Some(7));
            assert_eq!(
                owner(
                    [
                        row,
                        Row {
                            local,
                            pid: 8,
                            ..row
                        }
                    ],
                    udp
                ),
                None
            );
            assert_eq!(
                owner(
                    [Row {
                        local: "[::]:33001".parse().unwrap(),
                        ..row
                    }],
                    udp
                ),
                None
            );
            assert_eq!(owner([Row { pid: 0, ..row }], udp), None);
        }
        #[test]
        fn truncated_tables_cannot_be_read() {
            assert!(rows::<MIB_TCPROW_OWNER_PID>(&[u32::MAX, 0], 8, 4).is_none());
            assert!(rows::<MIB_TCPROW_OWNER_PID>(&[1, 0], 8, 4).is_none());
            assert!(rows::<MIB_TCPROW_OWNER_PID>(&[], 0, 4).is_none());
        }
        #[test]
        fn windows_resolves_live_ipv4_ipv6_tcp_udp_and_drops_closed_udp() {
            use std::net::{TcpListener, TcpStream, UdpSocket};
            let expected = std::env::current_exe()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            for host in ["127.0.0.1:0", "[::1]:0"] {
                let listener = TcpListener::bind(host).unwrap();
                let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                let (_accepted, _) = listener.accept().unwrap();
                let source = Source::Tcp {
                    local: stream.local_addr().unwrap(),
                    remote: stream.peer_addr().unwrap(),
                };
                assert_eq!(lookup(source), Some(expected.clone()));
                let socket = UdpSocket::bind(host).unwrap();
                let source = Source::Udp {
                    local: socket.local_addr().unwrap(),
                };
                assert_eq!(lookup(source), Some(expected.clone()));
                drop(socket);
                assert_eq!(lookup(source), None);
            }
        }
    }
}
