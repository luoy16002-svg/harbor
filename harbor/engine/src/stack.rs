//! Harbor's packet-to-flow dispatch. smoltcp owns TCP sequencing and retransmission.
use crate::{
    engine::{Engine, relay},
    packet::{self, Endpoints},
    transport,
};
use anyhow::{Context, Result};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Wake, Waker},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::{Notify, mpsc},
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct QueueDevice {
    pub incoming: VecDeque<Vec<u8>>,
    pub outgoing: VecDeque<Vec<u8>>,
}
pub struct Receive(Vec<u8>);
pub struct Transmit<'a>(&'a mut VecDeque<Vec<u8>>);
impl RxToken for Receive {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let value = f(&mut bytes);
        if self.0.len() < 2048 {
            self.0.push_back(bytes);
        }
        value
    }
}
impl Device for QueueDevice {
    type RxToken<'a> = Receive;
    type TxToken<'a> = Transmit<'a>;
    fn receive(&mut self, _: SmolInstant) -> Option<(Receive, Transmit<'_>)> {
        self.incoming
            .pop_front()
            .map(|bytes| (Receive(bytes), Transmit(&mut self.outgoing)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Transmit<'_>> {
        if self.outgoing.len() < 2048 {
            Some(Transmit(&mut self.outgoing))
        } else {
            None
        }
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}
struct Waking(Arc<Notify>);
impl Wake for Waking {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}
struct TcpFlow {
    socket: SocketHandle,
    stream: DuplexStream,
    ended: bool,
    write_closed: bool,
    last: Instant,
    task: tokio::task::JoinHandle<()>,
}
struct UdpListener {
    socket: SocketHandle,
    last: Instant,
}

pub struct Stack {
    pub device: QueueDevice,
    pub interface: Interface,
    pub sockets: SocketSet<'static>,
    tcp: HashMap<Endpoints, TcpFlow>,
    udp: HashMap<(IpAddress, u16), UdpListener>,
}
impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

impl Stack {
    pub fn new() -> Self {
        let mut device = QueueDevice::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut interface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
        interface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new("198.18.0.2".parse().unwrap(), 30))
                .unwrap();
            ips.push(IpCidr::new("fd00:6862::2".parse().unwrap(), 126))
                .unwrap();
        });
        interface.set_any_ip(true);
        interface
            .routes_mut()
            .add_default_ipv4_route("198.18.0.2".parse().unwrap())
            .unwrap();
        interface
            .routes_mut()
            .add_default_ipv6_route("fd00:6862::2".parse().unwrap())
            .unwrap();
        Self {
            device,
            interface,
            sockets: SocketSet::new(vec![]),
            tcp: HashMap::new(),
            udp: HashMap::new(),
        }
    }
    fn ingest(&mut self, bytes: Vec<u8>, engine: &Arc<Engine>, cancel: &CancellationToken) {
        if packet::is_external_icmp(&bytes) {
            return;
        }
        if let Ok(Some(endpoints)) = packet::endpoints(&bytes) {
            if endpoints.destination_port == 0 || endpoints.source_port == 0 {
                return;
            }
            if endpoints.protocol == 6 && !self.tcp.contains_key(&endpoints) {
                if !packet::is_initial_syn(&bytes) {
                    return;
                }
                if self.tcp.len() >= engine.current.load().config.max_connections.min(2048) {
                    return;
                }
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; 32768]),
                    tcp::SocketBuffer::new(vec![0; 32768]),
                );
                socket.set_nagle_enabled(false);
                socket.set_ack_delay(None);
                socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
                    engine.current.load().config.idle_timeout_secs,
                )));
                if socket
                    .listen(IpEndpoint::new(
                        endpoints.destination,
                        endpoints.destination_port,
                    ))
                    .is_err()
                {
                    return;
                }
                let handle = self.sockets.add(socket);
                let (bridge, local) = tokio::io::duplex(65536);
                let e = engine.clone();
                let token = cancel.clone();
                let task = tokio::spawn(async move {
                    tokio::select! {_=token.cancelled()=>{},result=forward(e.clone(),local,endpoints)=>{if let Err(error)=result{e.telemetry.event("debug",format!("TUN stream: {error}"));}}}
                });
                self.tcp.insert(
                    endpoints,
                    TcpFlow {
                        socket: handle,
                        stream: bridge,
                        ended: false,
                        write_closed: false,
                        last: Instant::now(),
                        task,
                    },
                );
            }
            if endpoints.protocol == 17
                && !self
                    .udp
                    .contains_key(&(endpoints.destination, endpoints.destination_port))
            {
                if self.udp.len() >= 512 {
                    return;
                }
                let mut socket = udp::Socket::new(
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 65536]),
                    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 65536]),
                );
                if socket
                    .bind(IpEndpoint::new(
                        endpoints.destination,
                        endpoints.destination_port,
                    ))
                    .is_err()
                {
                    return;
                }
                let handle = self.sockets.add(socket);
                self.udp.insert(
                    (endpoints.destination, endpoints.destination_port),
                    UdpListener {
                        socket: handle,
                        last: Instant::now(),
                    },
                );
            }
        }
        if self.device.incoming.len() < 2048 {
            self.device.incoming.push_back(bytes);
        }
    }
}
async fn forward(engine: Arc<Engine>, mut local: DuplexStream, endpoints: Endpoints) -> Result<()> {
    let _permit = engine
        .capacity
        .clone()
        .try_acquire_owned()
        .context("Active flow limit reached")?;
    if endpoints.destination_port == 53 {
        return engine.resolver.serve_stream(&mut local).await;
    }
    let current = engine.current.load_full();
    let destination = endpoints.destination.to_string();
    let mut prefix = Vec::with_capacity(4096);
    let mut name = None;
    if endpoints.destination_port == 443 || endpoints.destination_port == 80 {
        // The cap covers the entire sniff, including fragmented ClientHello records.
        // Bytes already read are always forwarded, including on timeout.
        let read_prefix = async {
            let mut chunk = [0; 4096];
            while prefix.len() < 16384 {
                let capacity = chunk.len().min(16384 - prefix.len());
                let n = local.read(&mut chunk[..capacity]).await?;
                if n == 0 {
                    break;
                }
                prefix.extend_from_slice(&chunk[..n]);
                if endpoints.destination_port == 443 {
                    if prefix[0] != 22 {
                        break;
                    }
                    if prefix.len() >= 5
                        && prefix.len() >= 5 + u16::from_be_bytes([prefix[3], prefix[4]]) as usize
                    {
                        break;
                    }
                } else if prefix.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Ok::<(), std::io::Error>(())
        };
        let _ = tokio::time::timeout(Duration::from_millis(150), read_prefix).await;
        name = packet::server_name(&prefix);
        if name.is_none()
            && endpoints.destination_port == 80
            && let Ok(text) = std::str::from_utf8(&prefix)
        {
            name = text.lines().find_map(|line| {
                line.split_once(':')
                    .filter(|(key, _)| key.eq_ignore_ascii_case("host"))
                    .map(|(_, value)| value.trim().split(':').next().unwrap_or("").to_string())
            });
        }
    }
    let decision = engine
        .decision_for_source(
            &current,
            (
                name.as_deref().unwrap_or(&destination),
                endpoints.destination_port,
                "tcp",
            ),
            Some(crate::process::Source::Tcp {
                local: std::net::SocketAddr::new(endpoints.source.into(), endpoints.source_port),
                remote: std::net::SocketAddr::new(
                    endpoints.destination.into(),
                    endpoints.destination_port,
                ),
            }),
        )
        .await?;
    let mut flow = engine.telemetry.begin(
        name.as_deref().unwrap_or(&destination),
        endpoints.destination_port,
        "TUN/TCP",
        &format!("{}:{}", endpoints.source, endpoints.source_port),
        &decision,
    );
    match transport::connect(
        &current.config,
        &engine.resolver,
        &decision.outbound,
        &destination,
        endpoints.destination_port,
    )
    .await
    {
        Ok(mut upstream) => {
            if !prefix.is_empty() {
                upstream.write_all(&prefix).await?;
                flow.add(prefix.len() as u64, 0);
            }
            relay(
                engine,
                local,
                upstream,
                flow,
                current.config.idle_timeout_secs,
            )
            .await
        }
        Err(error) => {
            flow.finish(Some(error.to_string()));
            Err(error)
        }
    }
}

pub async fn run(
    engine: Arc<Engine>,
    mut input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut stack = Stack::new();
    let start = Instant::now();
    let notify = Arc::new(Notify::new());
    let waker = Waker::from(Arc::new(Waking(notify.clone())));
    let mut udp_sessions = HashMap::<Endpoints, mpsc::Sender<Vec<u8>>>::new();
    let mut tasks = tokio::task::JoinSet::new();
    let (udp_reply, mut udp_replies) = mpsc::channel::<(Endpoints, Vec<u8>)>(256);
    loop {
        let now = SmolInstant::from_millis(start.elapsed().as_millis() as i64);
        stack
            .interface
            .poll(now, &mut stack.device, &mut stack.sockets);
        let mut remove = vec![];
        for (key, flow) in &mut stack.tcp {
            let socket = stack.sockets.get_mut::<tcp::Socket>(flow.socket);
            let mut context = TaskContext::from_waker(&waker);
            if socket.can_recv() {
                let result = socket.recv(|bytes| {
                    match Pin::new(&mut flow.stream).poll_write(&mut context, bytes) {
                        std::task::Poll::Ready(Ok(n)) => (n, n),
                        std::task::Poll::Ready(Err(_)) => {
                            flow.ended = true;
                            (0, 0)
                        }
                        std::task::Poll::Pending => (0, 0),
                    }
                });
                if result.unwrap_or(0) > 0 {
                    flow.last = Instant::now();
                }
            }
            if !socket.may_recv()
                && !flow.write_closed
                && matches!(
                    socket.state(),
                    tcp::State::CloseWait
                        | tcp::State::LastAck
                        | tcp::State::Closing
                        | tcp::State::TimeWait
                        | tcp::State::Closed
                )
                && Pin::new(&mut flow.stream)
                    .poll_shutdown(&mut context)
                    .is_ready()
            {
                flow.write_closed = true;
            }
            if socket.can_send() && !flow.ended {
                let result = socket.send(|bytes| {
                    let mut buf = ReadBuf::new(bytes);
                    match Pin::new(&mut flow.stream).poll_read(&mut context, &mut buf) {
                        std::task::Poll::Ready(Ok(())) => {
                            let n = buf.filled().len();
                            if n == 0 {
                                flow.ended = true;
                            }
                            (n, n)
                        }
                        std::task::Poll::Ready(Err(_)) => {
                            flow.ended = true;
                            (0, 0)
                        }
                        std::task::Poll::Pending => (0, 0),
                    }
                });
                if result.unwrap_or(0) > 0 {
                    flow.last = Instant::now();
                }
            }
            if flow.ended {
                socket.close();
            }
            if !socket.is_open()
                || flow.last.elapsed()
                    > Duration::from_secs(engine.current.load().config.idle_timeout_secs)
            {
                remove.push(*key);
            }
        }
        for key in remove {
            if let Some(flow) = stack.tcp.remove(&key) {
                flow.task.abort();
                stack.sockets.remove(flow.socket);
            }
        }
        for ((destination, port), listener) in &mut stack.udp {
            let socket = stack.sockets.get_mut::<udp::Socket>(listener.socket);
            while let Ok((bytes, meta)) = socket.recv() {
                listener.last = Instant::now();
                let key = Endpoints {
                    source: meta.endpoint.addr,
                    destination: *destination,
                    source_port: meta.endpoint.port,
                    destination_port: *port,
                    protocol: 17,
                };
                if *port == 53 {
                    let bytes = bytes.to_vec();
                    let e = engine.clone();
                    let output = udp_reply.clone();
                    if tasks.len() < 256 {
                        tasks.spawn(async move {
                            if let Ok(request) = hickory_proto::op::Message::from_vec(&bytes) {
                                let response = e.resolver.answer(&request).await;
                                if let Ok(bytes) = crate::dns::udp_wire(&request, response) {
                                    let _ = output.send((key, bytes)).await;
                                }
                            }
                        });
                    }
                    continue;
                }
                if udp_sessions
                    .get(&key)
                    .is_some_and(|sender| sender.is_closed())
                {
                    udp_sessions.remove(&key);
                }
                if !udp_sessions.contains_key(&key) {
                    if udp_sessions.len() >= 512 {
                        continue;
                    }
                    let (send, receive) = mpsc::channel(8);
                    udp_sessions.insert(key, send);
                    let (reply, mut replies) = mpsc::channel::<crate::datagram::Packet>(8);
                    let e = engine.clone();
                    let output = udp_reply.clone();
                    let token = cancel.clone();
                    tasks.spawn(async move{let receiver=async{while let Some(packet)=replies.recv().await{if output.send((key,packet.data)).await.is_err(){break;}}};tokio::select!{_=receiver=>{},_=e.udp_session(key.destination.to_string(),key.destination_port,std::net::SocketAddr::new(key.source.into(),key.source_port).to_string(),receive,reply,token)=>{}}});
                }
                if let Some(sender) = udp_sessions.get(&key) {
                    let _ = sender.try_send(bytes.to_vec());
                }
            }
        }
        while let Ok((key, bytes)) = udp_replies.try_recv() {
            if let Some(listener) = stack.udp.get(&(key.destination, key.destination_port)) {
                let socket = stack.sockets.get_mut::<udp::Socket>(listener.socket);
                let _ = socket.send_slice(&bytes, IpEndpoint::new(key.source, key.source_port));
            }
        }
        let now = SmolInstant::from_millis(start.elapsed().as_millis() as i64);
        stack
            .interface
            .poll(now, &mut stack.device, &mut stack.sockets);
        while let Some(packet) = stack.device.outgoing.pop_front() {
            tokio::select! {_=cancel.cancelled()=>break,result=output.send(packet)=>{if result.is_err(){return Ok(());}}}
        }
        while tasks.try_join_next().is_some() {}
        udp_sessions.retain(|_, send| !send.is_closed());
        let stale: Vec<_> = stack
            .udp
            .iter()
            .filter(|(destination, listener)| {
                listener.last.elapsed() > Duration::from_secs(60)
                    && !udp_sessions
                        .keys()
                        .any(|key| (key.destination, key.destination_port) == **destination)
            })
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            if let Some(listener) = stack.udp.remove(&key) {
                stack.sockets.remove(listener.socket);
            }
        }
        let delay = stack
            .interface
            .poll_delay(now, &stack.sockets)
            .map(|d| Duration::from_millis(d.total_millis()))
            .unwrap_or(Duration::from_millis(50))
            .min(Duration::from_millis(50));
        tokio::select! {
            _=cancel.cancelled()=>break,_=notify.notified()=>{},_=tokio::time::sleep(delay)=>{},
            reply=udp_replies.recv()=>{if let Some((key,bytes))=reply&& let Some(listener)=stack.udp.get(&(key.destination,key.destination_port)){let socket=stack.sockets.get_mut::<udp::Socket>(listener.socket);let _=socket.send_slice(&bytes,IpEndpoint::new(key.source,key.source_port));}},
            bytes=input.recv()=>{let Some(bytes)=bytes else{break;};stack.ingest(bytes,&engine,&cancel);for _ in 0..127{let Ok(bytes)=input.try_recv()else{break;};stack.ingest(bytes,&engine,&cancel);}}
        }
    }
    for flow in stack.tcp.values() {
        flow.task.abort();
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
