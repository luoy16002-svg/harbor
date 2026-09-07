use bytes::Bytes;
use harbor_engine::{
    config::{Config, DnsTlsServer},
    dns::Resolver,
    net::Egress,
};
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use http_body_util::{BodyExt, Full};
use hyper::{Response, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Clone, Copy)]
enum Mode {
    Normal,
    NxDomain,
    ServFail,
    WrongType,
    Oversize,
    Redirect,
}

async fn fixture(mode: Mode) -> (DnsTlsServer, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["dns.harbor.test".into()]).unwrap();
    let ca_pem = cert.cert.pem();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let count = accepts.clone();
    let task = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                connection = listener.accept() => {
                    let (stream, _) = connection.unwrap(); let acceptor = acceptor.clone(); count.fetch_add(1, Ordering::SeqCst);
                    tasks.spawn(async move {
                        let Ok(stream) = acceptor.accept(stream).await else { return; };
                        let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| async move {
                            assert_eq!(request.method(), "POST"); assert_eq!(request.uri(), "/dns-query");
                            assert_eq!(request.headers()["content-type"], "application/dns-message");
                            let data = request.into_body().collect().await.unwrap().to_bytes();
                            let mut answer = Message::from_vec(&data).unwrap(); assert_eq!(answer.id, 0);
                            answer.metadata.message_type = MessageType::Response; answer.metadata.recursion_available = true;
                            match mode {
                                Mode::NxDomain => answer.metadata.response_code = ResponseCode::NXDomain,
                                Mode::ServFail => answer.metadata.response_code = ResponseCode::ServFail,
                                _ if answer.queries.as_slice()[0].query_type() == RecordType::A => {
                                    let name = answer.queries.as_slice()[0].name().clone(); answer.add_answer(Record::from_rdata(name, 60, RData::A(A::new(203, 0, 113, 7))));
                                },
                                _ => {},
                            }
                            let body = if matches!(mode, Mode::Oversize) { vec![0; 70000] } else { answer.to_vec().unwrap() };
                            Ok::<_, Infallible>(Response::builder().status(if matches!(mode, Mode::Redirect) { 302 } else { 200 })
                                .header("Content-Type", if matches!(mode, Mode::WrongType) { "text/html" } else { "application/dns-message" })
                                .header("Location", "https://redirect.invalid/dns-query").body(Full::new(Bytes::from(body))).unwrap())
                        });
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
                    });
                },
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            }
        }
    });
    (
        DnsTlsServer {
            address,
            server_name: "dns.harbor.test".into(),
            ca_pem,
            https_path: Some("/dns-query".into()),
        },
        accepts,
        task,
    )
}
fn query(host: &str) -> Message {
    let mut query = Message::query();
    query.metadata.id = 1234;
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(host).unwrap(), RecordType::A));
    query
}
fn resolver(server: DnsTlsServer) -> Resolver {
    let resolver = Resolver::new(
        vec!["127.0.0.1:9".parse().unwrap()],
        Arc::new(Egress::default()),
    );
    resolver.configure(vec!["127.0.0.1:9".parse().unwrap()], vec![server]);
    resolver
}

#[tokio::test]
async fn doh_verifies_tls_reuses_connections_and_preserves_dns_ids() {
    let (server, accepts, task) = fixture(Mode::Normal).await;
    let resolver = resolver(server);
    for i in 0..12 {
        let response = resolver
            .query(&query(&format!("fixture{i}.invalid")))
            .await
            .unwrap();
        assert_eq!(response.id, 1234);
        assert_eq!(response.answers.as_slice().len(), 1);
    }
    resolver.query(&query("fixture0.invalid")).await.unwrap();
    assert_eq!(resolver.stats().hits, 1);
    assert_eq!(accepts.load(Ordering::SeqCst), 4);
    task.abort();
}
#[tokio::test]
async fn a_answer_succeeds_when_aaaa_has_no_records() {
    let (server, _, task) = fixture(Mode::Normal).await;
    let resolver = resolver(server);
    assert_eq!(
        resolver.lookup("node.invalid", 10012).await.unwrap(),
        vec!["203.0.113.7:10012".parse::<std::net::SocketAddr>().unwrap()]
    );
    task.abort();
}
#[tokio::test]
async fn tls_failures_are_not_misreported_as_missing_dns_records_or_sent_over_udp() {
    let (mut server, _, task) = fixture(Mode::Normal).await;
    server.server_name = "wrong.harbor.test".into();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = Resolver::new(vec![udp.local_addr().unwrap()], Arc::default());
    resolver.configure(vec![udp.local_addr().unwrap()], vec![server]);
    let error = resolver
        .lookup("private.invalid", 443)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("TLS certificate or handshake failed") && !error.contains("NODATA"),
        "{error}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), udp.recv(&mut [0; 512]))
            .await
            .is_err()
    );
    task.abort();
}
#[tokio::test]
async fn negative_dns_responses_keep_their_actual_response_code() {
    for (mode, reason) in [(Mode::NxDomain, "NXDomain"), (Mode::ServFail, "ServFail")] {
        let (server, _, task) = fixture(mode).await;
        let error = resolver(server)
            .lookup("node.invalid", 443)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(reason), "{error}");
        task.abort();
    }
}
#[tokio::test]
async fn doh_rejects_redirects_wrong_content_types_and_oversized_bodies() {
    for (mode, reason) in [
        (Mode::Redirect, "HTTP 302"),
        (Mode::WrongType, "Content-Type"),
        (Mode::Oversize, "65535"),
    ] {
        let (server, _, task) = fixture(mode).await;
        let error = resolver(server)
            .query(&query("node.invalid"))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(reason), "{error}");
        task.abort();
    }
}
#[test]
fn doh_paths_cannot_change_the_configured_authority_or_inject_headers() {
    for path in [
        "https://other.invalid/dns-query",
        "//other.invalid/dns-query",
        "/dns-query\r\nHost: other.invalid",
        "/dns-query#fragment",
        "",
    ] {
        let mut config = Config::default();
        config.dns_tls[0].https_path = Some(path.into());
        assert!(config.validate().is_err());
    }
    Config::default().validate().unwrap();
}
