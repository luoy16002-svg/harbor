use crate::{
    config::Config,
    dns::Resolver,
    net::Egress,
    policy::{self, Decision, Selector},
    telemetry::{FlowGuard, Telemetry},
    transport,
};
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tokio_util::sync::CancellationToken;

pub(crate) struct FlowRegistration {
    engine: std::sync::Weak<Engine>,
    id: u64,
}
impl Drop for FlowRegistration {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.upgrade() {
            engine.flow_cancel.lock().unwrap().remove(&self.id);
        }
    }
}

struct RegisteredStream {
    inner: transport::BoxStream,
    _registration: FlowRegistration,
}
impl AsyncRead for RegisteredStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for RegisteredStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct RuntimeConfig {
    pub config: Config,
    pub generation: u64,
    pub filter: crate::privacy::DomainFilter,
}
pub struct Engine {
    pub current: ArcSwap<RuntimeConfig>,
    probe_lock: tokio::sync::Mutex<()>,
    pub pool_epoch: AtomicU64,
    pool_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub selector: Mutex<Selector>,
    pub telemetry: Arc<Telemetry>,
    pub resolver: Arc<Resolver>,
    pub egress: Arc<Egress>,
    pub cancel: CancellationToken,
    pub flow_cancel: Mutex<HashMap<u64, CancellationToken>>,
    pub started: Instant,
    pub capacity: Arc<tokio::sync::Semaphore>,
    process_resolver: crate::process::Resolver,
    #[cfg(windows)]
    pub tun: Mutex<Option<crate::native_tun::TunHandle>>,
}
impl Engine {
    /// Tries only pool members and only before application payload is forwarded.
    pub async fn connect_flow(
        self: &Arc<Self>,
        snapshot: &RuntimeConfig,
        decision: &mut Decision,
        target: (&str, u16),
        flow: &FlowGuard,
    ) -> Result<transport::BoxStream> {
        ensure!(decision.outbound != "REJECT", "Blocked by routing policy");
        let config = &snapshot.config;
        let settings = config
            .groups
            .iter()
            .find(|g| g.name == decision.policy)
            .and_then(|g| g.pool.as_ref());
        let candidates = self
            .selector
            .lock()
            .unwrap()
            .retry_candidates(config, decision);
        let token = self.cancel.child_token();
        self.flow_cancel
            .lock()
            .unwrap()
            .insert(flow.id, token.clone());
        let registration = FlowRegistration {
            engine: Arc::downgrade(self),
            id: flow.id,
        };
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(config.connect_timeout_ms);
        let mut last = anyhow::anyhow!("Pool connection budget exhausted");
        for (index, candidate) in candidates.into_iter().enumerate() {
            if token.is_cancelled() {
                anyhow::bail!("Connection cancelled");
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let budget = settings.map_or(remaining, |s| {
                remaining.min(Duration::from_millis(s.attempt_timeout_ms))
            });
            flow.attempt(&candidate);
            let started = Instant::now();
            let attempt = tokio::time::timeout(
                budget,
                transport::connect(config, &self.resolver, &candidate, target.0, target.1),
            );
            let result = tokio::select! { biased;
                _ = token.cancelled() => { flow.attempt_finished(started.elapsed().as_millis() as u64, Some("cancelled")); anyhow::bail!("Connection cancelled"); },
                result = attempt => result.unwrap_or_else(|_| Err(anyhow::anyhow!("Connection attempt timed out"))),
            };
            let hard_failure = result
                .as_ref()
                .is_err_and(|error| error.is::<transport::UpstreamFailure>());
            flow.attempt_finished(
                started.elapsed().as_millis() as u64,
                result
                    .as_ref()
                    .err()
                    .map(|_| if hard_failure { "proxy" } else { "connect" }),
            );
            if settings.is_some() {
                let mut selector = self.selector.lock().unwrap();
                if self.current.load().generation == snapshot.generation {
                    if let Some(h) = selector
                        .pool_health
                        .get_mut(&(decision.policy.clone(), candidate.clone()))
                    {
                        if hard_failure {
                            h.cooldown = Some(Instant::now() + Duration::from_secs(15));
                        } else if result.is_ok() {
                            h.cooldown = None;
                        }
                    }
                    if let Some(stats) = selector.pool_stats.get_mut(&decision.policy) {
                        if index == 0 {
                            stats.connections += 1;
                        }
                        stats.attempts += 1;
                        if result.is_ok() {
                            if index > 0 {
                                stats.recovered += 1;
                                if !config.privacy.hide_metadata && config.privacy.history_secs > 0
                                {
                                    stats.last_recovery_at = Some(crate::telemetry::now_ms());
                                }
                            }
                            if !config.privacy.hide_metadata && config.privacy.history_secs > 0 {
                                stats.last_outbound = Some(candidate.clone());
                                stats.last_outbound_at = Some(crate::telemetry::now_ms());
                            }
                        }
                    }
                    if result.is_ok() {
                        selector.remember_pool_outbound(decision, &candidate);
                    }
                }
            }
            match result {
                Ok(inner) => {
                    decision.outbound = candidate;
                    if index > 0 {
                        decision.reason += &format!(
                            " · Pool: recovered on attempt {} before forwarding",
                            index + 1
                        );
                    }
                    flow.routed(decision);
                    return Ok(Box::new(RegisteredStream {
                        inner,
                        _registration: registration,
                    }));
                }
                Err(error) => last = error,
            }
        }
        if settings.is_some() {
            let mut selector = self.selector.lock().unwrap();
            if self.current.load().generation == snapshot.generation
                && let Some(stats) = selector.pool_stats.get_mut(&decision.policy)
            {
                stats.failed += 1;
            }
        }
        Err(last)
    }
    pub async fn start(config: Config) -> Result<Arc<Self>> {
        config.validate()?;
        let listener = TcpListener::bind(config.listen)
            .await
            .context("The proxy port is unavailable")?;
        let dns = UdpSocket::bind(config.dns_listen)
            .await
            .context("The DNS port is unavailable")?;
        let dns_tcp = TcpListener::bind(config.dns_listen)
            .await
            .context("The TCP DNS port is unavailable")?;
        let egress = Arc::new(Egress::configured(config.egress_mode)?);
        let resolver = Arc::new(Resolver::new(config.dns_servers.clone(), egress.clone()));
        resolver.configure(config.dns_servers.clone(), config.dns_tls.clone());
        resolver.set_privacy(&config.privacy);
        let mut selector = Selector::default();
        selector.reconcile(&config);
        let capacity = Arc::new(tokio::sync::Semaphore::new(config.max_connections));
        let engine = Arc::new(Self {
            probe_lock: tokio::sync::Mutex::new(()),
            pool_epoch: AtomicU64::new(0),
            pool_task: Mutex::new(None),
            current: ArcSwap::from_pointee(RuntimeConfig {
                filter: crate::privacy::DomainFilter::new(&config.privacy),
                config,
                generation: 1,
            }),
            selector: Mutex::new(selector),
            telemetry: Arc::new(Telemetry::default()),
            resolver,
            egress,
            cancel: CancellationToken::new(),
            flow_cancel: Mutex::new(HashMap::new()),
            started: Instant::now(),
            capacity,
            process_resolver: Default::default(),
            #[cfg(windows)]
            tun: Mutex::new(None),
        });
        engine
            .telemetry
            .configure(&engine.current.load().config.privacy);
        if engine.current.load().config.tun {
            #[cfg(windows)]
            {
                let handle = crate::native_tun::TunHandle::start(engine.clone(), true)?;
                *engine.tun.lock().unwrap() = Some(handle);
            }
            #[cfg(not(windows))]
            anyhow::bail!("TUN requires Windows");
        }
        #[cfg(windows)]
        if !engine.current.load().config.tun
            && engine.current.load().config.egress_mode == crate::config::EgressMode::Physical
        {
            let e = engine.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3));
                loop {
                    tokio::select! {
                        _ = e.cancel.cancelled() => break,
                        _ = interval.tick() => {
                            // Losing a physical route leaves that family unavailable;
                            // it must not silently fall back through another VPN.
                            let (v4, v6) = crate::native_tun::physical_routes(0).unwrap_or_default();
                            let previous4 = e.egress.ipv4.swap(v4, Ordering::Relaxed);
                            let previous6 = e.egress.ipv6.swap(v6, Ordering::Relaxed);
                            if previous4 != v4 || previous6 != v6 {
                                e.resolver.clear();
                                e.invalidate_pools();
                                e.telemetry.event("info", "Physical network changed. New connections use the updated interface.");
                            }
                        }
                    }
                }
            });
        }
        engine
            .telemetry
            .event("info", "Engine ready. Listeners are bound to loopback.");
        let e = engine.clone();
        tokio::spawn(async move {
            crate::inbound::serve(e, listener).await;
        });
        let e = engine.clone();
        tokio::spawn(async move {
            e.resolver.clone().serve(dns, e.cancel.clone()).await;
        });
        let e = engine.clone();
        tokio::spawn(async move {
            e.resolver
                .clone()
                .serve_tcp(dns_tcp, e.cancel.clone())
                .await;
        });
        let e = engine.clone();
        tokio::spawn(async move {
            e.probe_loop().await;
        });
        let e = engine.clone();
        *engine.pool_task.lock().unwrap() = Some(tokio::spawn(async move {
            crate::pools::monitor(e).await;
        }));
        Ok(engine)
    }
    pub fn configure(&self, config: Config) -> Result<u64> {
        config.validate()?;
        let mut selector = self.selector.lock().unwrap();
        let old = self.current.load_full();
        ensure!(
            config.privacy.routing_eq(&old.config.privacy),
            "Privacy routing changes require stopping Harbor first so existing flows cannot retain weaker settings"
        );
        ensure!(
            config.listen == old.config.listen
                && config.dns_listen == old.config.dns_listen
                && config.tun == old.config.tun
                && config.egress_mode == old.config.egress_mode
                && config.max_connections == old.config.max_connections,
            "Listener, egress, TUN and connection-limit changes require stopping the engine first"
        );
        selector.reconcile(&config);
        if config.dns_servers != old.config.dns_servers || config.dns_tls != old.config.dns_tls {
            self.resolver
                .configure(config.dns_servers.clone(), config.dns_tls.clone());
        }
        let generation = old.generation + 1;
        self.telemetry.configure(&config.privacy);
        self.resolver
            .dialer
            .set_metadata_hidden(config.privacy.hide_metadata);
        self.current.store(Arc::new(RuntimeConfig {
            filter: crate::privacy::DomainFilter::new(&config.privacy),
            config,
            generation,
        }));
        self.pool_epoch.fetch_add(1, Ordering::SeqCst);
        drop(selector);
        self.telemetry.event(
            "info",
            format!(
                "Profile generation {generation} applied. Existing streams retain their route."
            ),
        );
        Ok(generation)
    }
    pub fn decision(
        &self,
        snapshot: &RuntimeConfig,
        host: &str,
        port: u16,
        protocol: &str,
    ) -> Result<Decision> {
        policy::decide_filtered(
            &snapshot.config,
            &mut self.selector.lock().unwrap(),
            &snapshot.filter,
            (host, port, protocol),
            snapshot.generation,
        )
    }
    pub async fn decision_for_source(
        &self,
        snapshot: &RuntimeConfig,
        target: (&str, u16, &str),
        source: Option<crate::process::Source>,
    ) -> Result<Decision> {
        let process = if crate::traffic_routes::needs_process(&snapshot.config, target.0)
            && !snapshot.filter.blocked(target.0)
            && let Some(source) = source
        {
            self.process_resolver.name(source).await
        } else {
            None
        };
        policy::decide_with_process(
            &snapshot.config,
            &mut self.selector.lock().unwrap(),
            &snapshot.filter,
            target,
            process.as_deref(),
            snapshot.generation,
        )
    }
    pub fn close_flow(&self, id: u64) -> bool {
        if let Some(token) = self.flow_cancel.lock().unwrap().get(&id) {
            token.cancel();
            true
        } else {
            false
        }
    }
    pub async fn stop(&self) -> Result<()> {
        self.telemetry.event("info", "Engine stopping.");
        #[cfg(windows)]
        {
            let tun = self.tun.lock().unwrap().take();
            if let Some(tun) = tun {
                tun.stop().await?;
            }
        }
        self.cancel.cancel();
        let pool_task = self.pool_task.lock().unwrap().take();
        if let Some(task) = pool_task {
            let _ = task.await;
        }
        Ok(())
    }
    pub fn snapshot(&self) -> Value {
        self.telemetry.prune();
        let current = self.current.load();
        let mut selector = self.selector.lock().unwrap();
        for stats in selector.pool_stats.values_mut() {
            stats.prune(&current.config.privacy);
        }
        let flows = self.telemetry.flows.lock().unwrap();
        let active = flows
            .iter()
            .filter(|f| f.state == "active" || f.state == "connecting")
            .count();
        json!({"running":!self.cancel.is_cancelled(),"version":env!("CARGO_PKG_VERSION"),"generation":current.generation,"routingMode":current.config.routing_mode,"uptimeSecs":self.started.elapsed().as_secs(),"listen":current.config.listen,"dnsListen":current.config.dns_listen,"tun":current.config.tun,"activeConnections":active,"accepted":self.telemetry.accepted.load(Ordering::Relaxed),"failed":self.telemetry.failed.load(Ordering::Relaxed),"uploaded":self.telemetry.uploaded.load(Ordering::Relaxed),"downloaded":self.telemetry.downloaded.load(Ordering::Relaxed),"flows":flows.iter().take(500).collect::<Vec<_>>(),"events":self.telemetry.events.lock().unwrap().iter().take(100).collect::<Vec<_>>(),"nodes":selector.health.values().collect::<Vec<_>>(),"pools":selector.pools_snapshot(&current.config),"dns":self.resolver.stats(),"dialing":self.resolver.dial_stats()})
    }
    pub async fn probe(&self) -> Value {
        let _probe = self.probe_lock.lock().await;
        let current = self.current.load_full();
        let mut tasks = tokio::task::JoinSet::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(8));
        for node in &current.config.nodes {
            let node = node.clone();
            let resolver = self.resolver.clone();
            let semaphore = semaphore.clone();
            let timeout = current.config.connect_timeout_ms;
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await.ok();
                let start = Instant::now();
                let latency = match tokio::time::timeout(
                    Duration::from_millis(timeout),
                    transport::tcp(&resolver, &node.server, node.port),
                )
                .await
                {
                    Ok(Ok(_)) => Some(start.elapsed()),
                    _ => None,
                };
                (node.name.clone(), latency)
            });
        }
        while let Some(Ok((name, latency))) = tasks.join_next().await {
            if self.current.load().generation == current.generation {
                self.selector
                    .lock()
                    .unwrap()
                    .record(&name, latency, Instant::now());
            }
        }
        json!(
            self.selector
                .lock()
                .unwrap()
                .health
                .values()
                .collect::<Vec<_>>()
        )
    }
    async fn probe_loop(self: Arc<Self>) {
        loop {
            let interval = self.current.load().config.probe_interval_secs;
            tokio::select! {_ = self.cancel.cancelled()=>break,_ = tokio::time::sleep(Duration::from_secs(interval))=>{tokio::select!{_ = self.cancel.cancelled()=>break,_ = self.probe()=>{}}}}
        }
    }

    pub async fn udp_session(
        self: Arc<Self>,
        host: String,
        port: u16,
        source: String,
        mut input: tokio::sync::mpsc::Receiver<Vec<u8>>,
        output: tokio::sync::mpsc::Sender<crate::datagram::Packet>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let _permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .context("Active flow limit reached")?;
        let current = self.current.load_full();
        let decision = self
            .decision_for_source(
                &current,
                (&host, port, "udp"),
                source
                    .parse()
                    .ok()
                    .map(|local| crate::process::Source::Udp { local }),
            )
            .await?;
        let mut flow = self.telemetry.begin(&host, port, "UDP", &source, &decision);
        flow.active();
        let token = self.cancel.child_token();
        self.flow_cancel
            .lock()
            .unwrap()
            .insert(flow.id, token.clone());
        let _registration = FlowRegistration {
            engine: Arc::downgrade(&self),
            id: flow.id,
        };
        let (send, receive) = tokio::sync::mpsc::channel(32);
        let (reply, replies) = tokio::sync::mpsc::channel(32);
        let (ready, handshake) = tokio::sync::oneshot::channel();
        let setup = async {
            if tokio::time::timeout(
                Duration::from_millis(current.config.connect_timeout_ms),
                handshake,
            )
            .await
            .is_ok_and(|r| r.is_ok())
            {
                std::future::pending::<Result<()>>().await
            } else {
                Err(anyhow::anyhow!("UDP setup timed out or failed"))
            }
        };
        let mut replies = replies;
        let start = Instant::now();
        let activity = AtomicU64::new(0);
        let upload = async {
            while let Some(bytes) = input.recv().await {
                let len = bytes.len();
                if send.send(bytes).await.is_err() {
                    break;
                }
                flow.add(len as u64, 0);
                activity.store(start.elapsed().as_secs(), Ordering::Relaxed);
            }
            Ok::<(), anyhow::Error>(())
        };
        let download = async {
            while let Some(packet) = replies.recv().await {
                let packet: crate::datagram::Packet = packet;
                flow.add(0, packet.data.len() as u64);
                activity.store(start.elapsed().as_secs(), Ordering::Relaxed);
                if output.send(packet).await.is_err() {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        let idle = async {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if start.elapsed().as_secs() - activity.load(Ordering::Relaxed)
                    > current.config.idle_timeout_secs
                {
                    break;
                }
            }
        };
        let result = tokio::select! {
            result=setup=>result,_=token.cancelled()=>Ok(()),_=cancel.cancelled()=>Ok(()),_=idle=>Ok(()),result=upload=>result,result=download=>result,
            result=crate::datagram::run(&current.config,&self.resolver,&decision.outbound,(&host,port),receive,reply,ready)=>result,
        };
        self.flow_cancel.lock().unwrap().remove(&flow.id);
        flow.finish(result.as_ref().err().map(ToString::to_string));
        result
    }
    pub async fn udp(
        &self,
        host: &str,
        port: u16,
        data: &[u8],
        source: &str,
    ) -> Result<(String, u16, Vec<u8>)> {
        let current = self.current.load_full();
        let decision = self
            .decision_for_source(
                &current,
                (host, port, "udp"),
                source
                    .parse()
                    .ok()
                    .map(|local| crate::process::Source::Udp { local }),
            )
            .await?;
        let mut flow = self.telemetry.begin(host, port, "UDP", source, &decision);
        flow.active();
        flow.add(data.len() as u64, 0);
        let result = transport::udp_exchange(
            &current.config,
            &self.resolver,
            &decision.outbound,
            host,
            port,
            data,
        )
        .await;
        match &result {
            Ok((_, _, bytes)) => {
                flow.add(0, bytes.len() as u64);
                flow.finish(None);
            }
            Err(error) => flow.finish(Some(error.to_string())),
        }
        result
    }
}

pub async fn relay<A, B>(
    engine: Arc<Engine>,
    mut a: A,
    mut b: B,
    mut flow: FlowGuard,
    idle_secs: u64,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    flow.active();
    let token = engine
        .flow_cancel
        .lock()
        .unwrap()
        .entry(flow.id)
        .or_insert_with(|| engine.cancel.child_token())
        .clone();
    let _registration = FlowRegistration {
        engine: Arc::downgrade(&engine),
        id: flow.id,
    };
    let started = Instant::now();
    let last = AtomicU64::new(0);
    let half_closed = std::sync::atomic::AtomicBool::new(false);
    let half_close_secs = engine.current.load().config.half_close_timeout_secs;
    let (mut ar, mut aw) = tokio::io::split(&mut a);
    let (mut br, mut bw) = tokio::io::split(&mut b);
    let upload = async {
        let mut buffer = vec![0u8; 32768];
        loop {
            let n = ar.read(&mut buffer).await?;
            if n == 0 {
                bw.shutdown().await?;
                half_closed.store(true, Ordering::Release);
                last.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                return Ok::<(), anyhow::Error>(());
            }
            bw.write_all(&buffer[..n]).await?;
            flow.add(n as u64, 0);
            last.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
    };
    let download = async {
        let mut buffer = vec![0u8; 32768];
        loop {
            let n = br.read(&mut buffer).await?;
            if n == 0 {
                aw.shutdown().await?;
                half_closed.store(true, Ordering::Release);
                last.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                return Ok::<(), anyhow::Error>(());
            }
            aw.write_all(&buffer[..n]).await?;
            flow.add(0, n as u64);
            last.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
    };
    let idle = async {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if started.elapsed().as_millis() as u64 - last.load(Ordering::Relaxed)
                > if half_closed.load(Ordering::Acquire) {
                    half_close_secs.min(idle_secs) * 1000
                } else {
                    idle_secs * 1000
                }
            {
                break;
            }
        }
    };
    let result = tokio::select! {_ = token.cancelled()=>Err(anyhow::anyhow!("Connection cancelled")),_ = idle=>Err(anyhow::anyhow!("Connection idle timeout")),result=async{tokio::try_join!(upload,download)?;Ok::<(),anyhow::Error>(())}=>result};
    engine.flow_cancel.lock().unwrap().remove(&flow.id);
    flow.finish(result.as_ref().err().map(ToString::to_string));
    result
}
