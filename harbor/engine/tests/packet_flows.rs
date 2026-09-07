//! Exercises the actual packet dispatcher with a second independent TCP/IP endpoint.
//! No adapter, administrator rights or system route changes are needed.
use harbor_engine::{
    config::Config,
    engine::Engine,
    stack::{self, QueueDevice},
};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketSet},
    socket::{tcp, udp},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpCidr},
};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

struct Harness {
    engine: Arc<Engine>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    device: QueueDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    input: mpsc::Sender<Vec<u8>>,
    output: mpsc::Receiver<Vec<u8>>,
    started: Instant,
}
impl Harness {
    async fn new() -> Self {
        let engine = Self::start_engine().await;
        let cancel = engine.cancel.child_token();
        let (input, receive) = mpsc::channel(2048);
        let (send, output) = mpsc::channel(2048);
        let task = tokio::spawn(stack::run(engine.clone(), receive, send, cancel.clone()));
        let mut device = QueueDevice::default();
        let mut config = InterfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = 42;
        let mut interface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
        interface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new("198.18.0.1".parse().unwrap(), 30))
                .unwrap();
            ips.push(IpCidr::new("fd00:6862::1".parse().unwrap(), 126))
                .unwrap();
        });
        interface
            .routes_mut()
            .add_default_ipv4_route("198.18.0.2".parse().unwrap())
            .unwrap();
        interface
            .routes_mut()
            .add_default_ipv6_route("fd00:6862::2".parse().unwrap())
            .unwrap();
        Self {
            engine,
            cancel,
            task,
            device,
            interface,
            sockets: SocketSet::new(vec![]),
            input,
            output,
            started: Instant::now(),
        }
    }
    async fn start_engine() -> Arc<Engine> {
        // Reserve all three sockets together. UDP-only discovery did not prove
        // the DNS TCP port was free, and parallel fixtures could reclaim a port
        // between discovery and Engine::start. Only address collisions retry.
        for _ in 0..8 {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dns_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dns = dns_tcp.local_addr().unwrap();
            let dns_udp = match UdpSocket::bind(dns).await {
                Ok(socket) => socket,
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(error) => panic!("DNS fixture reservation failed: {error}"),
            };
            let config = Config {
                listen: tcp.local_addr().unwrap(),
                dns_listen: dns,
                connect_timeout_ms: 1000,
                ..Config::default()
            };
            drop((tcp, dns_tcp, dns_udp));
            match Engine::start(config).await {
                Ok(engine) => return engine,
                Err(error)
                    if error.chain().any(|cause| {
                        cause
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse)
                    }) => {}
                Err(error) => panic!("Packet fixture engine failed: {error:#}"),
            }
        }
        panic!("Could not reserve loopback ports for the packet fixture after 8 attempts");
    }
    async fn step(&mut self) {
        assert!(
            self.started.elapsed() < Duration::from_secs(10),
            "Packet exchange timed out"
        );
        while let Ok(bytes) = self.output.try_recv() {
            self.device.incoming.push_back(bytes);
        }
        self.interface.poll(
            SmolInstant::from_millis(self.started.elapsed().as_millis() as i64),
            &mut self.device,
            &mut self.sockets,
        );
        while let Some(bytes) = self.device.outgoing.pop_front() {
            self.input.send(bytes).await.unwrap();
        }
        tokio::select! {bytes=self.output.recv()=>{self.device.incoming.push_back(bytes.expect("Packet dispatcher stopped"));},_=tokio::time::sleep(Duration::from_millis(1))=>{}}
    }
    async fn finish(self) {
        self.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        self.engine.stop().await.unwrap();
        for _ in 0..20 {
            if self.engine.flow_cancel.lock().unwrap().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            self.engine.flow_cancel.lock().unwrap().is_empty(),
            "Cancelled flow handles leaked"
        );
    }
}
async fn tcp_roundtrip(bind: &str) {
    let listener = TcpListener::bind(bind).await.unwrap();
    let target = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = vec![];
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes.len(), 256 * 1024);
        stream.write_all(&bytes).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut h = Harness::new().await;
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 32768]),
        tcp::SocketBuffer::new(vec![0; 32768]),
    );
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None);
    let local: std::net::IpAddr = if target.is_ipv4() {
        "198.18.0.1".parse().unwrap()
    } else {
        "fd00:6862::1".parse().unwrap()
    };
    socket
        .connect(
            h.interface.context(),
            (target.ip(), target.port()),
            (local, 40001),
        )
        .unwrap();
    let handle = h.sockets.add(socket);
    let payload: Vec<_> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
    let mut sent = 0;
    let mut received = vec![];
    let mut closed = false;
    loop {
        h.step().await;
        let socket = h.sockets.get_mut::<tcp::Socket>(handle);
        if socket.can_send() && sent < payload.len() {
            sent += socket.send_slice(&payload[sent..]).unwrap();
        }
        if sent == payload.len() && !closed {
            socket.close();
            closed = true;
        }
        if socket.can_recv() {
            socket
                .recv(|bytes| {
                    received.extend_from_slice(bytes);
                    (bytes.len(), ())
                })
                .unwrap();
        }
        if closed && received.len() == payload.len() && !socket.may_recv() {
            break;
        }
    }
    assert_eq!(payload, received);
    server.await.unwrap();
    h.finish().await;
}
#[tokio::test]
async fn ipv4_tcp_large_stream_and_half_close() {
    tcp_roundtrip("127.0.0.1:0").await;
}
#[tokio::test]
async fn ipv6_tcp_large_stream_and_half_close() {
    tcp_roundtrip("[::1]:0").await;
}

#[tokio::test]
async fn udp_persists_and_receives_delayed_multiple_replies() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut peer: Option<SocketAddr> = None;
        let mut buffer = vec![0; 4096];
        for _ in 0..8 {
            let (n, source) = server.recv_from(&mut buffer).await.unwrap();
            if let Some(previous) = peer {
                assert_eq!(source, previous);
            }
            peer = Some(source);
            server.send_to(&buffer[..n], source).await.unwrap();
            tokio::time::sleep(Duration::from_millis(3)).await;
            server.send_to(&buffer[..n], source).await.unwrap();
        }
    });
    let mut h = Harness::new().await;
    let mut socket = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 65536]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 65536]),
    );
    socket.bind(40002).unwrap();
    let handle = h.sockets.add(socket);
    for sequence in 0..8 {
        let payload = vec![sequence; if sequence % 2 == 0 { 1200 } else { 3500 }];
        h.sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(&payload, target)
            .unwrap();
        let mut replies = 0;
        while replies < 2 {
            h.step().await;
            let socket = h.sockets.get_mut::<udp::Socket>(handle);
            while let Ok((bytes, meta)) = socket.recv() {
                assert_eq!(bytes, payload);
                assert_eq!(meta.endpoint.port, target.port());
                replies += 1;
            }
        }
    }
    echo.await.unwrap();
    h.finish().await;
}

#[tokio::test]
async fn any_ip_ipv6_handshake_for_unassigned_destination() {
    // Both peers live entirely in memory; 2001:db8::/32 never reaches a network socket.
    let mut server = stack::Stack::new();
    let mut h = Harness::new().await;
    let mut listener = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 4096]),
        tcp::SocketBuffer::new(vec![0; 4096]),
    );
    let target: std::net::IpAddr = "2001:db8::123".parse().unwrap();
    let local: std::net::IpAddr = "fd00:6862::1".parse().unwrap();
    listener.listen((target, 443)).unwrap();
    server.sockets.add(listener);
    let mut client = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 4096]),
        tcp::SocketBuffer::new(vec![0; 4096]),
    );
    client
        .connect(h.interface.context(), (target, 443), (local, 40003))
        .unwrap();
    let handle = h.sockets.add(client);
    for i in 0..20 {
        let now = SmolInstant::from_millis(i);
        h.interface.poll(now, &mut h.device, &mut h.sockets);
        server.device.incoming.extend(h.device.outgoing.drain(..));
        server
            .interface
            .poll(now, &mut server.device, &mut server.sockets);
        h.device.incoming.extend(server.device.outgoing.drain(..));
        if h.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Established {
            h.finish().await;
            return;
        }
    }
    panic!("Unassigned IPv6 destination failed to establish");
}

#[tokio::test]
async fn tun_dns_interception_returns_real_addresses_and_caches() {
    use hickory_proto::{
        op::{Message, MessageType, Query},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };
    let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = dns.local_addr().unwrap();
    let mut h = Harness::new().await;
    h.engine.resolver.configure(vec![upstream], vec![]);
    let server = tokio::spawn(async move {
        let mut bytes = vec![0; 4096];
        let (n, peer) = dns.recv_from(&mut bytes).await.unwrap();
        let mut response = Message::from_vec(&bytes[..n]).unwrap();
        let name = response.queries.as_slice()[0].name().clone();
        response.metadata.message_type = MessageType::Response;
        response.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(A::new(203, 0, 113, 9)),
        ));
        dns.send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let mut socket = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 8192]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 8192]),
    );
    socket.bind(40004).unwrap();
    let handle = h.sockets.add(socket);
    let destination: SocketAddr = "198.18.0.2:53".parse().unwrap();
    for id in [10, 11] {
        let mut request = Message::query();
        request.metadata.id = id;
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("fixture.invalid.").unwrap(),
            RecordType::A,
        ));
        h.sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(&request.to_vec().unwrap(), destination)
            .unwrap();
        loop {
            h.step().await;
            if let Ok((bytes, _)) = h.sockets.get_mut::<udp::Socket>(handle).recv() {
                let response = Message::from_vec(bytes).unwrap();
                assert_eq!(response.id, id);
                assert_eq!(
                    &response.answers.as_slice()[0].data,
                    &RData::A(A::new(203, 0, 113, 9))
                );
                break;
            }
        }
    }
    assert_eq!(h.engine.resolver.stats().hits, 1);
    server.await.unwrap();
    h.finish().await;
}
