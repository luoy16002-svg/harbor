use crate::{
    engine::{Engine, relay},
    telemetry::FlowGuard,
    transport::{self, BoxStream},
};
use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{HeaderMap, HeaderName, HeaderValue},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, BoxError>;
fn response(status: StatusCode, text: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(
            Full::new(Bytes::from(text.to_string()))
                .map_err(|e: Infallible| match e {})
                .boxed_unsync(),
        )
        .unwrap()
}

pub async fn serve(engine: Arc<Engine>, listener: TcpListener) {
    let limit = Arc::new(tokio::sync::Semaphore::new(
        engine.current.load().config.max_connections,
    ));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {_ = engine.cancel.cancelled()=>break,Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},accepted=listener.accept()=>{
            let Ok((stream,peer))=accepted else{break};let Ok(permit)=limit.clone().try_acquire_owned()else{drop(stream);continue};let e=engine.clone();tasks.spawn(async move{let _permit=permit;let result=tokio::select!{_ = e.cancel.cancelled()=>Ok(()),result=handle(e.clone(),stream,peer)=>result};if let Err(error)=result {e.telemetry.event("debug",format!("Local client {peer}: {error}"));}});
        }}
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
async fn handle(engine: Arc<Engine>, stream: TcpStream, peer: SocketAddr) -> Result<()> {
    stream.set_nodelay(true)?;
    let local = stream.local_addr()?;
    let mut first = [0; 1];
    ensure!(
        tokio::time::timeout(Duration::from_secs(5), stream.peek(&mut first)).await?? > 0,
        "Empty handshake"
    );
    if first[0] == 5 {
        return socks(engine, stream, peer).await;
    }
    let service = service_fn(move |request| {
        let engine = engine.clone();
        async move {
            Ok::<_, Infallible>(match http(engine, request, peer, local).await {
                Ok(response) => response,
                Err(error) => response(StatusCode::BAD_GATEWAY, &format!("Harbor: {error}")),
            })
        }
    });
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_headers(100)
        .max_buf_size(32768)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await?;
    Ok(())
}
async fn socks(engine: Arc<Engine>, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
    let setup = async {
        ensure!(stream.read_u8().await? == 5, "SOCKS version mismatch");
        let count = stream.read_u8().await? as usize;
        ensure!(count > 0, "No SOCKS authentication methods");
        let mut methods = vec![0; count];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            stream.write_all(&[5, 255]).await?;
            bail!("No supported authentication method");
        }
        stream.write_all(&[5, 0]).await?;
        let mut header = [0; 3];
        stream.read_exact(&mut header).await?;
        ensure!(header[0] == 5 && header[2] == 0, "Invalid SOCKS request");
        let (host, port) = transport::read_address(&mut stream).await?;
        Ok::<_, anyhow::Error>((header[1], host, port))
    };
    let (command, host, port) = tokio::time::timeout(Duration::from_secs(10), setup).await??;
    if command == 3 {
        return udp_associate(engine, stream, peer).await;
    }
    if command != 1 {
        stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("SOCKS command unsupported");
    }
    let _permit = engine
        .capacity
        .clone()
        .try_acquire_owned()
        .context("Active flow limit reached")?;
    let config = engine.current.load_full();
    let decision = engine
        .decision_for_source(
            &config,
            (&host, port, "tcp"),
            Some(crate::process::Source::Tcp {
                local: peer,
                remote: stream.local_addr()?,
            }),
        )
        .await?;
    let mut flow = engine
        .telemetry
        .begin(&host, port, "SOCKS5", &peer.to_string(), &decision);
    match transport::connect(
        &config.config,
        &engine.resolver,
        &decision.outbound,
        &host,
        port,
    )
    .await
    {
        Ok(upstream) => {
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            relay(
                engine,
                stream,
                upstream,
                flow,
                config.config.idle_timeout_secs,
            )
            .await
        }
        Err(error) => {
            flow.finish(Some(error.to_string()));
            let _ = stream
                .write_all(&[
                    5,
                    if decision.outbound == "REJECT" { 2 } else { 5 },
                    0,
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])
                .await;
            Err(error)
        }
    }
}
async fn udp_associate(
    engine: Arc<Engine>,
    mut control: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(SocketAddr::new(control.local_addr()?.ip(), 0)).await?);
    let address = socket.local_addr()?;
    let mut reply = vec![5, 0, 0];
    transport::write_address(&mut reply, &address.ip().to_string(), address.port())?;
    control.write_all(&reply).await?;
    let mut buffer = vec![0; 65535];
    let mut control_byte = [0; 1];
    let mut pinned: Option<SocketAddr> = None;
    let mut tasks = tokio::task::JoinSet::new();
    let mut sessions =
        std::collections::HashMap::<(String, u16), tokio::sync::mpsc::Sender<Vec<u8>>>::new();
    let cancel = engine.cancel.child_token();
    let (output, mut replies) = tokio::sync::mpsc::channel::<crate::datagram::Packet>(128);
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,_=control.read(&mut control_byte)=>break,
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{sessions.retain(|_,sender|!sender.is_closed());},
            Some(packet)=replies.recv()=>{if let Some(source)=pinned{let mut bytes=vec![0,0,0];if transport::write_address(&mut bytes,&packet.host,packet.port).is_ok(){bytes.extend(packet.data);let _=socket.send_to(&bytes,source).await;}}},
            received=socket.recv_from(&mut buffer)=>{
                let (n,source)=received?;if source.ip()!=peer.ip()||pinned.is_some_and(|p|p!=source)||n<7||buffer[..3]!=[0,0,0]{continue;}
                let Ok((host,port,offset))=transport::parse_address(&buffer[3..n])else{continue};pinned=Some(source);let key=(host.clone(),port);
                if sessions.get(&key).is_some_and(|sender|sender.is_closed()){sessions.remove(&key);}
                if !sessions.contains_key(&key){
                    if sessions.len()>=128{continue;}let (send,receive)=tokio::sync::mpsc::channel(32);sessions.insert(key.clone(),send);let e=engine.clone();let output=output.clone();let cancel=cancel.clone();
                    tasks.spawn(async move{let _=e.udp_session(host,port,source.to_string(),receive,output,cancel).await;});
                }
                if let Some(sender)=sessions.get(&key){let _=sender.try_send(buffer[3+offset..n].to_vec());}
            }
        }
    }
    cancel.cancel();
    sessions.clear();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

fn strip_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|v| HeaderName::from_bytes(v.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}
async fn http(
    engine: Arc<Engine>,
    mut request: Request<Incoming>,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<Response<Body>> {
    let connect = request.method() == Method::CONNECT;
    if !connect && request.headers().contains_key("upgrade") {
        return Ok(response(
            StatusCode::NOT_IMPLEMENTED,
            "Use an HTTPS CONNECT tunnel for WebSocket traffic.",
        ));
    }
    let (host, port) = if connect {
        let authority = request
            .uri()
            .authority()
            .context("CONNECT requires host:port")?;
        (
            authority.host().trim_matches(['[', ']']).to_string(),
            authority.port_u16().context("CONNECT requires a port")?,
        )
    } else {
        ensure!(
            request.uri().scheme_str() == Some("http"),
            "HTTP proxy requires an absolute http:// URL"
        );
        (
            request
                .uri()
                .host()
                .context("URL has no host")?
                .trim_matches(['[', ']'])
                .to_string(),
            request.uri().port_u16().unwrap_or(80),
        )
    };
    let _permit = engine
        .capacity
        .clone()
        .try_acquire_owned()
        .context("Active flow limit reached")?;
    let config = engine.current.load_full();
    let decision = engine
        .decision_for_source(
            &config,
            (&host, port, "tcp"),
            Some(crate::process::Source::Tcp {
                local: peer,
                remote: local,
            }),
        )
        .await?;
    let mut flow = engine.telemetry.begin(
        &host,
        port,
        if connect { "CONNECT" } else { "HTTP" },
        &peer.to_string(),
        &decision,
    );
    if decision.outbound == "REJECT" {
        flow.finish(Some("Blocked by routing policy".into()));
        return Ok(response(
            StatusCode::FORBIDDEN,
            "Blocked by Harbor routing policy.",
        ));
    }
    let upstream = match transport::connect(
        &config.config,
        &engine.resolver,
        &decision.outbound,
        &host,
        port,
    )
    .await
    {
        Ok(s) => s,
        Err(error) => {
            flow.finish(Some(error.to_string()));
            return Err(error);
        }
    };
    if connect {
        let upgrade = hyper::upgrade::on(&mut request);
        tokio::spawn(async move {
            let _permit = _permit;
            match tokio::time::timeout(Duration::from_secs(10), upgrade).await {
                Ok(Ok(stream)) => {
                    let _ = relay(
                        engine,
                        TokioIo::new(stream),
                        upstream,
                        flow,
                        config.config.idle_timeout_secs,
                    )
                    .await;
                }
                _ => {
                    flow.finish(Some("Client did not complete CONNECT upgrade".into()));
                }
            }
        });
        return Ok(response(StatusCode::OK, ""));
    }
    flow.active();
    let id = flow.id;
    let measured = Measured {
        stream: upstream,
        flow,
        _permit,
    };
    let token = engine.cancel.child_token();
    engine.flow_cancel.lock().unwrap().insert(id, token.clone());
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(measured)).await?;
    let e = engine.clone();
    tokio::spawn(async move {
        tokio::select! {_ = token.cancelled()=>{},_ = connection=>{}}
        e.flow_cancel.lock().unwrap().remove(&id);
    });
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    *request.uri_mut() = path.parse()?;
    strip_hop(request.headers_mut());
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    request
        .headers_mut()
        .insert("host", HeaderValue::from_str(&authority)?);
    request
        .headers_mut()
        .insert("connection", HeaderValue::from_static("close"));
    let mut result = tokio::time::timeout(
        Duration::from_secs(config.config.idle_timeout_secs),
        sender.send_request(request),
    )
    .await
    .context("HTTP response timeout")??;
    strip_hop(result.headers_mut());
    Ok(result.map(|body| body.map_err(|e| Box::new(e) as BoxError).boxed_unsync()))
}
struct Measured {
    stream: BoxStream,
    flow: FlowGuard,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl AsyncRead for Measured {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            self.flow.add(0, (buf.filled().len() - before) as u64);
        }
        if let Poll::Ready(Err(e)) = &result {
            self.flow.finish(Some(e.to_string()));
        }
        result
    }
}
impl AsyncWrite for Measured {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            self.flow.add(n as u64, 0);
        }
        if let Poll::Ready(Err(e)) = &result {
            self.flow.finish(Some(e.to_string()));
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
