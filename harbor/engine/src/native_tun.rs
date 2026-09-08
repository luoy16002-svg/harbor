//! All Windows adapter mutation is isolated here. Addresses and routes are transient.
use crate::{engine::Engine, net::Egress};
use anyhow::{Context, Result, ensure};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use windows_sys::{
    Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::*},
    core::GUID,
};

fn error(code: u32, operation: &str) -> Result<()> {
    if code != 0 {
        Err(anyhow::anyhow!(
            "{operation}: {}",
            std::io::Error::from_raw_os_error(code as i32)
        ))
    } else {
        Ok(())
    }
}
fn address(ip: IpAddr) -> SOCKADDR_INET {
    let mut value = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(ip) => {
            value.Ipv4.sin_family = AF_INET;
            value.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        }
        IpAddr::V6(ip) => {
            value.Ipv6.sin6_family = AF_INET6;
            value.Ipv6.sin6_addr.u.Byte = ip.octets();
        }
    }
    value
}
pub fn physical_routes(exclude: u32) -> Result<(u32, u32)> {
    // The OS owns this variable-length table. Copy only validated rows before freeing it.
    unsafe {
        let mut table = std::ptr::null_mut();
        error(
            GetIpForwardTable2(AF_UNSPEC, &mut table),
            "Read default routes",
        )?;
        struct Table(*mut MIB_IPFORWARD_TABLE2);
        impl Drop for Table {
            fn drop(&mut self) {
                unsafe {
                    FreeMibTable(self.0.cast());
                }
            }
        }
        let table = Table(table);
        ensure!(
            !table.0.is_null() && (*table.0).NumEntries < 1_000_000,
            "Invalid route table"
        );
        let rows =
            std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize);
        let mut v4 = (u32::MAX, 0);
        let mut v6 = (u32::MAX, 0);
        for row in rows {
            if row.DestinationPrefix.PrefixLength != 0
                || row.InterfaceIndex == exclude
                || row.Loopback
            {
                continue;
            }
            let family = row.DestinationPrefix.Prefix.si_family;
            let mut interface = MIB_IPINTERFACE_ROW::default();
            InitializeIpInterfaceEntry(&mut interface);
            interface.Family = family;
            interface.InterfaceIndex = row.InterfaceIndex;
            if GetIpInterfaceEntry(&mut interface) != 0 || !interface.Connected {
                continue;
            }
            let mut adapter = MIB_IF_ROW2 {
                InterfaceIndex: row.InterfaceIndex,
                ..Default::default()
            };
            // HardwareInterface is bit 0. Virtual default routes must not capture
            // Harbor's own upstream sockets, even when they have a lower metric.
            if GetIfEntry2(&mut adapter) != 0
                || adapter.InterfaceAndOperStatusFlags._bitfield & 1 == 0
            {
                continue;
            }
            let score = row.Metric.saturating_add(interface.Metric);
            let best = if family == AF_INET {
                &mut v4
            } else if family == AF_INET6 {
                &mut v6
            } else {
                continue;
            };
            if score < best.0 {
                *best = (score, row.InterfaceIndex);
            }
        }
        Ok((v4.1, v6.1))
    }
}
struct NetworkLease {
    index: u32,
    routes: Vec<MIB_IPFORWARD_ROW2>,
    addresses: Vec<MIB_UNICASTIPADDRESS_ROW>,
}
impl NetworkLease {
    fn new(index: u32) -> Self {
        Self {
            index,
            routes: vec![],
            addresses: vec![],
        }
    }
    fn configure(&mut self, adapter: &wintun::Adapter, capture: bool) -> Result<()> {
        for (ip, prefix) in [
            (IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)), 30),
            (IpAddr::V6("fd00:6862::1".parse::<Ipv6Addr>().unwrap()), 126),
        ] {
            let mut row = MIB_UNICASTIPADDRESS_ROW::default();
            unsafe {
                InitializeUnicastIpAddressEntry(&mut row);
            }
            row.InterfaceIndex = self.index;
            row.Address = address(ip);
            row.OnLinkPrefixLength = prefix;
            row.DadState = IpDadStatePreferred;
            row.ValidLifetime = u32::MAX;
            row.PreferredLifetime = u32::MAX;
            error(
                unsafe { CreateUnicastIpAddressEntry(&row) },
                "Assign temporary TUN address",
            )?;
            self.addresses.push(row);
            let mut interface = MIB_IPINTERFACE_ROW::default();
            unsafe {
                InitializeIpInterfaceEntry(&mut interface);
            }
            interface.InterfaceIndex = self.index;
            interface.Family = if ip.is_ipv4() { AF_INET } else { AF_INET6 };
            error(
                unsafe { GetIpInterfaceEntry(&mut interface) },
                "Read TUN interface",
            )?;
            interface.UseAutomaticMetric = false;
            interface.Metric = 1;
            interface.NlMtu = 1500;
            interface.DadTransmits = 0;
            interface.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
            error(
                unsafe { SetIpInterfaceEntry(&mut interface) },
                "Configure TUN interface",
            )?;
        }
        if capture {
            let mut dns: Vec<u16> = "198.18.0.2"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let settings = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                Flags: DNS_SETTING_NAMESERVER as u64,
                NameServer: dns.as_mut_ptr(),
                ..Default::default()
            };
            error(
                unsafe { SetInterfaceDnsSettings(GUID::from_u128(adapter.get_guid()), &settings) },
                "Set DNS on temporary TUN adapter",
            )?;
            for prefix in ["0.0.0.0", "128.0.0.0", "::", "8000::"] {
                let ip: IpAddr = prefix.parse().unwrap();
                let mut row = MIB_IPFORWARD_ROW2::default();
                unsafe {
                    InitializeIpForwardEntry(&mut row);
                }
                row.InterfaceIndex = self.index;
                row.DestinationPrefix.Prefix = address(ip);
                row.DestinationPrefix.PrefixLength = 1;
                row.NextHop = address(if ip.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                });
                row.Metric = 1;
                row.Protocol = RouteProtocolNetMgmt;
                error(
                    unsafe { CreateIpForwardEntry2(&row) },
                    "Add temporary TUN route",
                )?;
                self.routes.push(row);
            }
        }
        Ok(())
    }
    fn restore(&mut self) -> Result<()> {
        let mut failure = None;
        self.routes.retain(|row| {
            let code = unsafe { DeleteIpForwardEntry2(row) };
            if code == 0 || code == 1168 {
                false
            } else {
                failure = Some(code);
                true
            }
        });
        if let Some(code) = failure {
            return error(code, "Remove temporary TUN route");
        }
        Ok(())
    }
}
impl Drop for NetworkLease {
    fn drop(&mut self) {
        let _ = self.restore();
        for row in &self.addresses {
            unsafe {
                DeleteUnicastIpAddressEntry(row);
            }
        }
    }
}

pub struct TunHandle {
    lease: NetworkLease,
    session: Option<Arc<wintun::Session>>,
    cancel: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    reader: Option<std::thread::JoinHandle<()>>,
    egress: Arc<Egress>,
    pub received: Arc<AtomicU64>,
    pub sent: Arc<AtomicU64>,
    pub dropped: Arc<AtomicU64>,
    pub index: u32,
}
impl TunHandle {
    pub fn start(engine: Arc<Engine>, capture: bool) -> Result<Self> {
        let (v4, v6) = physical_routes(0)?;
        ensure!(
            !capture || v4 != 0 || v6 != 0,
            "No usable physical default route"
        );
        let dll = std::env::current_exe()?
            .parent()
            .context("No executable directory")?
            .join("wintun.dll");
        #[cfg(debug_assertions)]
        let dll = if !dll.exists() {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("vendor/wintun/bin/amd64/wintun.dll")
        } else {
            dll
        };
        ensure!(
            dll.is_absolute() && dll.exists(),
            "Signed wintun.dll is missing beside harbor-engine.exe"
        );
        // Only a fully qualified, application-owned DLL path is passed to the loader.
        let library =
            unsafe { wintun::load_from_path(&dll) }.context("Load signed Wintun driver")?;
        let adapter = wintun::Adapter::create(
            &library,
            &format!("Harbor-{}", std::process::id()),
            "Harbor",
            None,
        )
        .context("Create TUN adapter. Start Harbor as administrator.")?;
        let index = adapter.get_adapter_index()?;
        let session = Arc::new(adapter.start_session(4 * 1024 * 1024)?);
        let cancel = engine.cancel.child_token();
        let (packet_tx, packet_rx) = mpsc::channel(2048);
        let (output, mut outgoing) = mpsc::channel::<Vec<u8>>(2048);
        let received = Arc::new(AtomicU64::new(0));
        let sent = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let read_session = session.clone();
        let count = received.clone();
        let token = cancel.clone();
        let reader = std::thread::Builder::new()
            .name("harbor-wintun-reader".into())
            .spawn(move || {
                while !token.is_cancelled() {
                    match read_session.receive_blocking() {
                        Ok(packet) => {
                            let bytes = packet.bytes().to_vec();
                            drop(packet);
                            count.fetch_add(1, Ordering::Relaxed);
                            if packet_tx.blocking_send(bytes).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            })?;
        let e = engine.clone();
        let token = cancel.clone();
        let stack = tokio::spawn(async move {
            if let Err(error) = crate::stack::run(e.clone(), packet_rx, output, token).await {
                e.telemetry
                    .event("error", format!("TUN packet bridge stopped: {error}"));
                e.cancel.cancel();
            }
        });
        let write_session = session.clone();
        let count = sent.clone();
        let lost = dropped.clone();
        let token = cancel.clone();
        let writer = tokio::spawn(async move {
            loop {
                tokio::select! {_=token.cancelled()=>break,packet=outgoing.recv()=>{let Some(bytes)=packet else{break;};match write_session.allocate_send_packet(bytes.len() as u16){Ok(mut packet)=>{packet.bytes_mut().copy_from_slice(&bytes);write_session.send_packet(packet);count.fetch_add(1,Ordering::Relaxed);},Err(_)=>{lost.fetch_add(1,Ordering::Relaxed);}}}}
            }
        });
        engine.egress.ipv4.store(v4, Ordering::Relaxed);
        engine.egress.ipv6.store(v6, Ordering::Relaxed);
        engine.egress.active.store(capture, Ordering::Release);
        let mut handle = Self {
            lease: NetworkLease::new(index),
            session: Some(session),
            cancel,
            tasks: vec![stack, writer],
            reader: Some(reader),
            egress: engine.egress.clone(),
            received,
            sent,
            dropped,
            index,
        };
        handle.lease.configure(&adapter, capture)?;
        let e = engine.clone();
        let token = handle.cancel.clone();
        let monitor = tokio::spawn(async move {
            loop {
                tokio::select! {_=token.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(3))=>{
                    if let Ok((v4,v6))=physical_routes(index){let old4=e.egress.ipv4.swap(v4,Ordering::Relaxed);let old6=e.egress.ipv6.swap(v6,Ordering::Relaxed);if old4!=v4||old6!=v6{e.resolver.clear();e.invalidate_pools();e.telemetry.event("info","Physical network changed. New connections use the updated interface; existing streams retain their route.");}}
                }}
            }
        });
        handle.tasks.push(monitor);
        engine.telemetry.event(
            "info",
            format!("Wintun adapter {index} ready. Physical interfaces: IPv4 {v4}, IPv6 {v6}."),
        );
        Ok(handle)
    }
    pub async fn stop(mut self) -> Result<()> {
        self.lease.restore()?;
        self.cancel.cancel();
        if let Some(session) = &self.session {
            session.shutdown()?;
        }
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        if let Some(reader) = self.reader.take() {
            let _ = tokio::task::spawn_blocking(move || reader.join()).await;
        }
        self.session.take();
        self.egress.active.store(false, Ordering::Release);
        Ok(())
    }
}
impl Drop for TunHandle {
    fn drop(&mut self) {
        let _ = self.lease.restore();
        self.cancel.cancel();
        if let Some(session) = &self.session {
            let _ = session.shutdown();
        }
        for task in &self.tasks {
            task.abort();
        }
        self.egress.active.store(false, Ordering::Release);
    }
}

/// Administrator-only adapter validation without default-route or system-proxy capture.
/// It sends one DNS datagram through the actual Wintun ring to a loopback-only fixture.
pub async fn validate_isolated() -> Result<serde_json::Value> {
    use hickory_proto::{
        op::{Message, MessageType, Query},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let listen = probe.local_addr()?;
    drop(probe);
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let dns_listen = probe.local_addr()?;
    drop(probe);
    let fixture = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let fixture_address = fixture.local_addr()?;
    let config = crate::config::Config {
        listen,
        dns_listen,
        dns_servers: vec![fixture_address],
        dns_tls: vec![],
        ..Default::default()
    };
    let engine = Engine::start(config).await?;
    let handle = match TunHandle::start(engine.clone(), false) {
        Ok(handle) => handle,
        Err(error) => {
            engine.stop().await?;
            return Err(error);
        }
    };
    let index = handle.index;
    let answer = tokio::spawn(async move {
        let mut bytes = vec![0; 4096];
        let (n, peer) = fixture.recv_from(&mut bytes).await?;
        let mut response = Message::from_vec(&bytes[..n])?;
        let name = response.queries.as_slice()[0].name().clone();
        response.metadata.message_type = MessageType::Response;
        response.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(A::new(203, 0, 113, 12)),
        ));
        fixture.send_to(&response.to_vec()?, peer).await?;
        Ok::<(), anyhow::Error>(())
    });
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        let socket = tokio::net::UdpSocket::bind("198.18.0.1:0").await?;
        socket.connect("198.18.0.2:53").await?;
        let mut request = Message::query();
        request.metadata.id = 2468;
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("harbor-adapter.invalid.")?,
            RecordType::A,
        ));
        socket.send(&request.to_vec()?).await?;
        let mut bytes = vec![0; 4096];
        let n = socket.recv(&mut bytes).await?;
        let response = Message::from_vec(&bytes[..n])?;
        ensure!(
            response.id == 2468
                && response.answers.as_slice().first().map(|a| &a.data)
                    == Some(&RData::A(A::new(203, 0, 113, 12))),
            "Live adapter DNS mismatch"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Live adapter validation timed out")
    .and_then(|result| result);
    let received = handle.received.load(Ordering::Relaxed);
    let sent = handle.sent.load(Ordering::Relaxed);
    let cleanup = handle.stop().await;
    engine.stop().await?;
    answer.abort();
    let _ = answer.await;
    cleanup?;
    result?;
    let mut removed = false;
    for _ in 0..40 {
        let mut interface = MIB_IPINTERFACE_ROW::default();
        unsafe {
            InitializeIpInterfaceEntry(&mut interface);
        }
        interface.InterfaceIndex = index;
        interface.Family = AF_INET;
        if unsafe { GetIpInterfaceEntry(&mut interface) } == 1168 {
            removed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ensure!(removed, "Temporary adapter is still present after close");
    Ok(
        serde_json::json!({"passed":true,"test":"isolated live Wintun adapter","receivedPackets":received,"sentPackets":sent,"adapterRemoved":removed,"defaultRoutesModified":false,"systemProxyModified":false,"globalCaptureTested":false}),
    )
}
