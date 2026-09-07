use harbor_engine::{config::DnsTlsServer, dns::Resolver, net::Egress};
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

async fn fixture() -> (DnsTlsServer, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
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
            tokio::select! {connection=listener.accept()=>{let(stream,_)=connection.unwrap();let acceptor=acceptor.clone();count.fetch_add(1,Ordering::SeqCst);tasks.spawn(async move{let Ok(mut stream)=acceptor.accept(stream).await else{return};while let Ok(len)=stream.read_u16().await{let mut bytes=vec![0;len as usize];if stream.read_exact(&mut bytes).await.is_err(){break;}let mut response=Message::from_vec(&bytes).unwrap();let name=response.queries.as_slice()[0].name().clone();response.metadata.message_type=MessageType::Response;response.metadata.recursion_available=true;response.add_answer(Record::from_rdata(name,60,RData::A(A::new(203,0,113,7))));let bytes=response.to_vec().unwrap();if stream.write_u16(bytes.len() as u16).await.is_err()||stream.write_all(&bytes).await.is_err(){break;}}});},Some(_)=tasks.join_next(),if !tasks.is_empty()=>{}}
        }
    });
    (
        DnsTlsServer {
            address,
            server_name: "dns.harbor.test".into(),
            ca_pem,
            https_path: None,
        },
        accepts,
        task,
    )
}
fn query(name: &str) -> Message {
    let mut request = Message::query();
    request.metadata.id = 1234;
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    request
}

#[tokio::test]
async fn verified_dns_reuses_connections_and_caches_answers() {
    let (settings, accepts, task) = fixture().await;
    let resolver = Resolver::new(
        vec!["127.0.0.1:9".parse().unwrap()],
        Arc::new(Egress::default()),
    );
    resolver.configure(vec!["127.0.0.1:9".parse().unwrap()], vec![settings]);
    for i in 0..12 {
        let response = resolver
            .query(&query(&format!("host{i}.invalid")))
            .await
            .unwrap();
        assert_eq!(response.id, 1234);
        assert_eq!(response.answers.as_slice().len(), 1);
    }
    resolver.query(&query("host0.invalid")).await.unwrap();
    assert_eq!(resolver.stats().hits, 1);
    assert!(resolver.stats().encrypted);
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        4,
        "TLS connection pool was not reused"
    );
    task.abort();
}
#[tokio::test]
async fn wrong_tls_name_is_rejected_without_plaintext_fallback() {
    let (mut settings, _, task) = fixture().await;
    settings.server_name = "wrong.harbor.test".into();
    let plain = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = plain.local_addr().unwrap();
    let resolver = Resolver::new(vec![address], Arc::new(Egress::default()));
    resolver.configure(vec![address], vec![settings]);
    assert!(resolver.query(&query("private.invalid")).await.is_err());
    let mut bytes = [0; 512];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), plain.recv(&mut bytes))
            .await
            .is_err(),
        "Failed TLS query leaked to UDP"
    );
    task.abort();
}
#[tokio::test]
async fn untrusted_dns_certificate_is_rejected() {
    let (mut settings, _, task) = fixture().await;
    settings.ca_pem = rcgen::generate_simple_self_signed(vec!["different.harbor.test".into()])
        .unwrap()
        .cert
        .pem();
    let resolver = Resolver::new(vec![], Arc::new(Egress::default()));
    resolver.configure(vec![], vec![settings]);
    assert!(resolver.query(&query("private.invalid")).await.is_err());
    task.abort();
}

#[tokio::test]
async fn tcp_dns_supports_pipelining_and_udp_truncation_preserves_the_answer() {
    let (settings, _, upstream) = fixture().await;
    let resolver = Arc::new(Resolver::new(vec![], Arc::new(Egress::default())));
    resolver.configure(vec![], vec![settings]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let server = tokio::spawn(resolver.clone().serve_tcp(listener, cancel.clone()));
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    for id in [41, 42] {
        let mut request = query(&format!("tcp{id}.invalid"));
        request.metadata.id = id;
        let bytes = request.to_vec().unwrap();
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    }
    for id in [41, 42] {
        let length = tokio::time::timeout(Duration::from_secs(3), stream.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = vec![0; length as usize];
        stream.read_exact(&mut bytes).await.unwrap();
        let response = Message::from_vec(&bytes).unwrap();
        assert_eq!(response.id, id);
        assert_eq!(response.answers.as_slice().len(), 1);
        assert_eq!(
            response.queries.as_slice()[0].name().to_ascii(),
            format!("tcp{id}.invalid.")
        );
    }
    let request = query("large.invalid");
    let mut response = request.clone();
    response.metadata.message_type = MessageType::Response;
    for last in 1..80 {
        response.add_answer(Record::from_rdata(
            Name::from_ascii("large.invalid.").unwrap(),
            60,
            RData::A(A::new(203, 0, 113, last)),
        ));
    }
    assert!(response.to_vec().unwrap().len() > 512);
    let bytes = harbor_engine::dns::udp_wire(&request, response.clone()).unwrap();
    assert!(bytes.len() <= 512);
    let truncated = Message::from_vec(&bytes).unwrap();
    assert!(truncated.truncation);
    assert!(truncated.answers.as_slice().is_empty());
    assert_eq!(response.answers.as_slice().len(), 79);
    stream.write_u16(11).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    cancel.cancel();
    server.await.unwrap();
    upstream.abort();
}
