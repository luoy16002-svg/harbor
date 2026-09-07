use crate::net::Egress;
use crate::{
    config::DnsTlsServer,
    transport::{self, BoxStream},
};
use anyhow::{Context, Result, bail, ensure};
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};
use tokio_util::sync::CancellationToken;

struct EncryptedServer {
    settings: DnsTlsServer,
    connections: [tokio::sync::Mutex<Option<EncryptedConnection>>; 4],
    next: AtomicU64,
}
enum EncryptedConnection {
    Tls(BoxStream),
    Https(crate::dns_https::HttpsConnection),
}
impl EncryptedServer {
    fn new(settings: DnsTlsServer) -> Self {
        Self {
            settings,
            connections: std::array::from_fn(|_| tokio::sync::Mutex::new(None)),
            next: AtomicU64::new(0),
        }
    }
    async fn exchange(&self, egress: &Egress, request: &Message) -> Result<Message> {
        let index = self.next.fetch_add(1, Ordering::Relaxed) as usize % self.connections.len();
        let mut slot = self.connections[index].lock().await;
        // Remove the stream before any await: cancellation must discard an unfinished response.
        let connect = || async {
            let stream = transport::tls_named(
                Box::new(egress.tcp(self.settings.address).await?),
                &self.settings.server_name,
                &self.settings.ca_pem,
            )
            .await?;
            Ok::<_, anyhow::Error>(if self.settings.https_path.is_some() {
                EncryptedConnection::Https(
                    crate::dns_https::HttpsConnection::connect(stream).await?,
                )
            } else {
                EncryptedConnection::Tls(stream)
            })
        };
        let reused = slot.is_some();
        let mut stream = match slot.take() {
            Some(stream) => stream,
            None => connect().await?,
        };
        let mut result = self.exchange_connection(&mut stream, request).await;
        if reused && result.is_err() {
            drop(stream);
            stream = connect().await?;
            result = self.exchange_connection(&mut stream, request).await;
        }
        let response = result?;
        *slot = Some(stream);
        Ok(response)
    }
    async fn exchange_connection(
        &self,
        connection: &mut EncryptedConnection,
        request: &Message,
    ) -> Result<Message> {
        match connection {
            EncryptedConnection::Tls(stream) => Self::exchange_stream(stream, request).await,
            EncryptedConnection::Https(connection) => {
                connection.exchange(&self.settings, request).await
            }
        }
    }
    async fn exchange_stream(stream: &mut BoxStream, request: &Message) -> Result<Message> {
        let mut query = request.clone();
        query.metadata.id = rand::random();
        let wire = query.to_vec()?;
        stream
            .write_u16(wire.len().try_into().context("DNS request too large")?)
            .await?;
        stream.write_all(&wire).await?;
        let len = stream.read_u16().await? as usize;
        ensure!(len >= 12, "Truncated encrypted DNS response");
        let mut wire = vec![0; len];
        stream.read_exact(&mut wire).await?;
        let mut response = Message::from_vec(&wire)?;
        validate_response(&query, &response)?;
        response.metadata.id = request.id;
        Ok(response)
    }
}

struct Entry {
    message: Message,
    expires: Instant,
    stored: Instant,
}
pub struct Resolver {
    pub egress: Arc<Egress>,
    servers: RwLock<Vec<SocketAddr>>,
    cache: Mutex<HashMap<String, Entry>>,
    hits: AtomicU64,
    misses: AtomicU64,
    errors: AtomicU64,
    encrypted: RwLock<Vec<Arc<EncryptedServer>>>,
    generation: AtomicU64,
    filter: RwLock<crate::privacy::DomainFilter>,
    blocked: AtomicU64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsStats {
    pub hits: u64,
    pub misses: u64,
    pub errors: u64,
    pub entries: usize,
    pub servers: Vec<SocketAddr>,
    pub encrypted: bool,
    pub blocked: u64,
}
impl Resolver {
    pub fn new(servers: Vec<SocketAddr>, egress: Arc<Egress>) -> Self {
        Self {
            servers: RwLock::new(servers),
            egress,
            cache: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            encrypted: RwLock::new(vec![]),
            generation: AtomicU64::new(0),
            filter: RwLock::new(Default::default()),
            blocked: AtomicU64::new(0),
        }
    }
    pub fn configure(&self, servers: Vec<SocketAddr>, tls: Vec<DnsTlsServer>) {
        *self.servers.write().unwrap() = servers;
        *self.encrypted.write().unwrap() = tls
            .into_iter()
            .map(|s| Arc::new(EncryptedServer::new(s)))
            .collect();
        self.clear();
    }
    pub fn clear(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.cache.lock().unwrap().clear();
    }
    pub fn set_privacy(&self, settings: &crate::privacy::Privacy) {
        *self.filter.write().unwrap() = crate::privacy::DomainFilter::new(settings);
        self.clear();
    }
    pub fn stats(&self) -> DnsStats {
        DnsStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            entries: self.cache.lock().unwrap().len(),
            servers: self.servers.read().unwrap().clone(),
            encrypted: !self.encrypted.read().unwrap().is_empty(),
            blocked: self.blocked.load(Ordering::Relaxed),
        }
    }
    fn blocked_answer(&self, request: &Message) -> Message {
        self.blocked.fetch_add(1, Ordering::Relaxed);
        let mut response = Message::query();
        response.metadata.id = request.id;
        response.metadata.message_type = MessageType::Response;
        response.metadata.recursion_desired = request.recursion_desired;
        response.metadata.recursion_available = true;
        response.metadata.response_code = ResponseCode::NXDomain;
        response.add_queries(request.queries.as_slice().iter().cloned());
        response
    }
    fn blocked_alias(&self, request: &Message, response: &Message) -> Result<bool> {
        let filter = self.filter.read().unwrap();
        let question = &request.queries.as_slice()[0];
        let mut name = question.name().clone();
        name.set_fqdn(true);
        // An explicit exception for the original question also permits its alias chain.
        let original_allowed = filter.allowed(&name.to_ascii());
        let mut visited = HashSet::new();
        for _ in 0..32 {
            ensure!(visited.insert(name.clone()), "DNS alias cycle");
            let mut aliases = response.answers.iter().filter_map(|record| {
                if record.name == name
                    && record.dns_class == question.query_class()
                    && let RData::CNAME(target) = &record.data
                {
                    Some(target.0.clone())
                } else {
                    None
                }
            });
            let Some(target) = aliases.next() else {
                return Ok(false);
            };
            ensure!(
                aliases.all(|alias| alias == target),
                "Conflicting DNS aliases"
            );
            if !original_allowed && filter.blocked(&target.to_ascii()) {
                return Ok(true);
            }
            name = target;
        }
        bail!("DNS alias chain exceeds 32 names")
    }
    pub async fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        if host.eq_ignore_ascii_case("localhost") {
            return Ok(vec![
                SocketAddr::from(([127, 0, 0, 1], port)),
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port),
            ]);
        }
        ensure!(
            !self.filter.read().unwrap().blocked(host),
            "DNS lookup blocked by local domain rule: {host}"
        );
        let name = Name::from_ascii(host).context("Invalid DNS name")?;
        let mut a = Message::query();
        a.metadata.id = rand::random();
        a.metadata.recursion_desired = true;
        a.add_query(Query::query(name.clone(), RecordType::A));
        let mut aaaa = Message::query();
        aaaa.metadata.id = rand::random();
        aaaa.metadata.recursion_desired = true;
        aaaa.add_query(Query::query(name, RecordType::AAAA));
        let (v4, v6) = tokio::join!(self.query(&a), self.query(&aaaa));
        let mut addresses = Vec::new();
        let mut failures = Vec::new();
        for (kind, result) in [("A", v4), ("AAAA", v6)] {
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    failures.push(format!("{kind}: {error:#}"));
                    continue;
                }
            };
            let previous_count = addresses.len();
            for record in response.answers.as_slice() {
                let ip = match &record.data {
                    RData::A(a) => Some(IpAddr::V4(a.0)),
                    RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                    _ => None,
                };
                if let Some(ip) = ip {
                    addresses.push(SocketAddr::new(ip, port));
                }
            }
            if addresses.len() == previous_count {
                failures.push(if response.response_code == ResponseCode::NoError {
                    format!("{kind}: NODATA (no address record)")
                } else {
                    format!("{kind}: {:?}", response.response_code)
                });
            }
        }
        ensure!(
            !addresses.is_empty(),
            "DNS lookup failed for {host}: {}",
            failures.join("; ")
        );
        Ok(addresses)
    }
    pub async fn query(&self, request: &Message) -> Result<Message> {
        ensure!(
            request.message_type == MessageType::Query
                && request.op_code == hickory_proto::op::OpCode::Query
                && request.queries.as_slice().len() == 1,
            "Expected one DNS question"
        );
        let q = &request.queries.as_slice()[0];
        if self.filter.read().unwrap().blocked(&q.name().to_ascii()) {
            return Ok(self.blocked_answer(request));
        }
        let cacheable = request.additionals.as_slice().is_empty()
            && request.edns.is_none()
            && !request.checking_disabled;
        let generation = self.generation.load(Ordering::SeqCst);
        let key = format!(
            "{generation}:{}:{:?}:{:?}",
            q.name().to_ascii().trim_end_matches('.').to_lowercase(),
            q.query_type(),
            q.query_class()
        );
        if cacheable {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(&key)
                && entry.expires > Instant::now()
            {
                self.hits.fetch_add(1, Ordering::Relaxed);
                let mut message = entry.message.clone();
                message.metadata.id = request.id;
                let age = entry.stored.elapsed().as_secs() as u32;
                for record in message.answers.iter_mut() {
                    record.ttl = record.ttl.saturating_sub(age);
                }
                for record in message.authorities.iter_mut() {
                    record.ttl = record.ttl.saturating_sub(age);
                }
                for record in message.additionals.iter_mut() {
                    record.ttl = record.ttl.saturating_sub(age);
                }
                return Ok(message);
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        let encrypted = self.encrypted.read().unwrap().clone();
        let servers = self.servers.read().unwrap().clone();
        let mut last = String::new();
        let count = if encrypted.is_empty() {
            servers.len()
        } else {
            encrypted.len()
        };
        for index in 0..count {
            let exchange = async {
                if encrypted.is_empty() {
                    self.exchange(servers[index], request).await
                } else {
                    encrypted[index].exchange(&self.egress, request).await
                }
            };
            // HTTPS includes a certificate handshake and HTTP response before DNS data arrives.
            // Keep it bounded, but allow more than the former 3-second DoT-only budget.
            let timeout = if encrypted
                .get(index)
                .is_some_and(|server| server.settings.https_path.is_some())
            {
                5
            } else {
                3
            };
            match tokio::time::timeout(Duration::from_secs(timeout), exchange).await {
                Ok(Ok(message)) => {
                    if self.blocked_alias(request, &message).inspect_err(|_| {
                        self.errors.fetch_add(1, Ordering::Relaxed);
                    })? {
                        return Ok(self.blocked_answer(request));
                    }
                    if cacheable
                        && generation == self.generation.load(Ordering::SeqCst)
                        && message.response_code == ResponseCode::NoError
                        && !message.truncation
                        && !message.answers.as_slice().is_empty()
                    {
                        let ttl = message
                            .answers
                            .as_slice()
                            .iter()
                            .chain(message.authorities.as_slice())
                            .chain(message.additionals.as_slice())
                            .map(|r| r.ttl)
                            .min()
                            .unwrap_or(0)
                            .min(3600);
                        if ttl > 0 {
                            let mut cache = self.cache.lock().unwrap();
                            if cache.len() >= 2048 {
                                cache.retain(|_, e| e.expires > Instant::now());
                                if cache.len() >= 2048
                                    && let Some(key) = cache.keys().next().cloned()
                                {
                                    cache.remove(&key);
                                }
                            }
                            cache.insert(
                                key,
                                Entry {
                                    message: message.clone(),
                                    expires: Instant::now() + Duration::from_secs(ttl as u64),
                                    stored: Instant::now(),
                                },
                            );
                        }
                    }
                    return Ok(message);
                }
                Ok(Err(e)) => last = format!("{e:#}"),
                Err(_) => last = "DNS upstream timeout".into(),
            }
        }
        self.errors.fetch_add(1, Ordering::Relaxed);
        bail!("DNS failed: {last}")
    }
    async fn exchange(&self, server: SocketAddr, request: &Message) -> Result<Message> {
        let mut wire_request = request.clone();
        wire_request.metadata.id = rand::random();
        let wire = wire_request.to_vec()?;
        let udp = self.egress.udp(server)?;
        udp.connect(server).await?;
        udp.send(&wire).await?;
        let mut bytes = vec![0u8; 65535];
        let n = udp.recv(&mut bytes).await?;
        let mut response = Message::from_vec(&bytes[..n])?;
        validate_response(&wire_request, &response)?;
        if response.truncation {
            let mut tcp = self.egress.tcp(server).await?;
            tcp.write_u16(wire.len() as u16).await?;
            tcp.write_all(&wire).await?;
            let len = tcp.read_u16().await? as usize;
            ensure!(len <= 65535, "DNS response too large");
            let mut body = vec![0; len];
            tcp.read_exact(&mut body).await?;
            response = Message::from_vec(&body)?;
            validate_response(&wire_request, &response)?;
        }
        response.metadata.id = request.id;
        Ok(response)
    }
    pub async fn answer(&self, request: &Message) -> Message {
        match self.query(request).await {
            Ok(response) => response,
            Err(_) => {
                let mut response = Message::query();
                response.metadata.id = request.id;
                response.metadata.message_type = MessageType::Response;
                response.metadata.response_code = ResponseCode::ServFail;
                response.metadata.recursion_desired = request.recursion_desired;
                response.add_queries(request.queries.as_slice().iter().cloned());
                response
            }
        }
    }
    pub async fn serve_stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<()> {
        loop {
            let len = match tokio::time::timeout(Duration::from_secs(10), stream.read_u16()).await?
            {
                Ok(len) => len,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            ensure!(len >= 12, "Truncated DNS-over-TCP request");
            let mut bytes = vec![0; len as usize];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut bytes)).await??;
            let request = Message::from_vec(&bytes)?;
            let response = self.answer(&request).await.to_vec()?;
            tokio::time::timeout(Duration::from_secs(10), async {
                stream.write_u16(response.len() as u16).await?;
                stream.write_all(&response).await
            })
            .await??;
        }
    }
    pub async fn serve_tcp(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
        cancel: CancellationToken,
    ) {
        let permits = Arc::new(tokio::sync::Semaphore::new(128));
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {_=cancel.cancelled()=>break,Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},connection=listener.accept()=>{let Ok((mut stream,_))=connection else{break};let Ok(permit)=permits.clone().try_acquire_owned()else{continue};let resolver=self.clone();tasks.spawn(async move{let _permit=permit;let _=resolver.serve_stream(&mut stream).await;});}}
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    pub async fn serve(self: Arc<Self>, socket: UdpSocket, cancel: CancellationToken) {
        let socket = Arc::new(socket);
        let permits = Arc::new(tokio::sync::Semaphore::new(128));
        let mut tasks = tokio::task::JoinSet::new();
        let mut buf = vec![0u8; 4096];
        loop {
            tokio::select! {_ = cancel.cancelled()=>break,Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},received=socket.recv_from(&mut buf)=>{
                let Ok((n,peer))=received else{break};let Ok(permit)=permits.clone().try_acquire_owned() else{continue};let Ok(request)=Message::from_vec(&buf[..n])else{continue};let resolver=self.clone();let socket=socket.clone();
                tasks.spawn(async move {let _permit=permit;let response=resolver.answer(&request).await;if let Ok(bytes)=udp_wire(&request,response){let _=socket.send_to(&bytes,peer).await;}});
            }}
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}
pub(crate) fn validate_response(request: &Message, response: &Message) -> Result<()> {
    let mut expected = request.queries.as_slice().to_vec();
    for question in &mut expected {
        question.name.set_fqdn(true);
    }
    ensure!(
        response.id == request.id
            && response.message_type == MessageType::Response
            && response.op_code == request.op_code
            && response.queries.as_slice() == expected,
        "DNS response does not match request"
    );
    Ok(())
}

pub fn udp_wire(request: &Message, mut response: Message) -> Result<Vec<u8>> {
    let bytes = response.to_vec()?;
    let limit = request.max_payload().clamp(512, 1232) as usize;
    if bytes.len() <= limit {
        return Ok(bytes);
    }
    response.metadata.truncation = true;
    response.answers.clear();
    response.authorities.clear();
    response.additionals.clear();
    Ok(response.to_vec()?)
}
