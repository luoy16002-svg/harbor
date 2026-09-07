//! Local fixtures for shared DNS work, cancellation, epoch isolation and dialing memory.
use harbor_engine::{dns::Resolver, net::Egress, transport};
use hickory_proto::{
    op::{Edns, Message, MessageType, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME},
    },
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    time::Instant,
};

struct Fixture {
    address: std::net::SocketAddr,
    count: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn wait_for(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.count.load(Ordering::SeqCst) < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
async fn fixture<F>(response: F) -> Fixture
where
    F: Fn(&Message) -> (Duration, Message) + Send + Sync + 'static,
{
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        let mut bytes = vec![0; 65535];
        loop {
            tokio::select! {
                packet = socket.recv_from(&mut bytes) => {
                    let (length, peer) = packet.unwrap(); let request = Message::from_vec(&bytes[..length]).unwrap();
                    observed.fetch_add(1, Ordering::SeqCst); let (delay, reply) = response(&request); let socket = socket.clone();
                    tasks.spawn(async move { tokio::time::sleep(delay).await; let _ = socket.send_to(&reply.to_vec().unwrap(), peer).await; });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    Fixture {
        address,
        count,
        task,
    }
}
fn query(name: &str, id: u16) -> Message {
    let mut query = Message::query();
    query.metadata.id = id;
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query
}
fn reply(request: &Message, suffix: u8) -> Message {
    let mut answer = request.clone();
    answer.metadata.message_type = MessageType::Response;
    answer.metadata.recursion_available = true;
    let question = &request.queries.as_slice()[0];
    let data = if question.query_type() == RecordType::AAAA {
        RData::AAAA(AAAA(std::net::Ipv6Addr::LOCALHOST))
    } else {
        RData::A(A::new(127, 0, 0, suffix))
    };
    answer.add_answer(Record::from_rdata(question.name().clone(), 60, data));
    answer
}
fn resolver(server: &Fixture) -> Arc<Resolver> {
    Arc::new(Resolver::new(
        vec![server.address],
        Arc::new(Egress::default()),
    ))
}

#[tokio::test]
async fn a_burst_shares_one_upstream_exchange_and_preserves_every_request_id() {
    let server = fixture(|request| (Duration::from_millis(120), reply(request, 1))).await;
    let resolver = resolver(&server);
    let replies = futures_util::future::join_all((0..64).map(|id| {
        let resolver = resolver.clone();
        async move {
            resolver
                .query(&query("shared.fixture.invalid", id))
                .await
                .unwrap()
        }
    }))
    .await;
    for (id, response) in replies.iter().enumerate() {
        assert_eq!(response.id, id as u16);
    }
    assert_eq!(server.count.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.stats().coalesced, 63);
    assert_eq!(resolver.stats().upstream_queries, 1);
    assert_eq!(resolver.stats().in_flight, 0);
    resolver
        .query(&query("shared.fixture.invalid", 777))
        .await
        .unwrap();
    assert_eq!(resolver.stats().hits, 1);
}

#[tokio::test]
async fn cancelling_the_original_caller_transfers_work_to_a_waiting_caller() {
    let server = fixture(|request| (Duration::from_millis(250), reply(request, 1))).await;
    let resolver = resolver(&server);
    let owner = {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolver.query(&query("handoff.fixture.invalid", 1)).await })
    };
    server.wait_for(1).await;
    let follower = {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolver.query(&query("handoff.fixture.invalid", 2)).await })
    };
    while resolver.stats().coalesced == 0 {
        tokio::task::yield_now().await;
    }
    owner.abort();
    let _ = owner.await;
    let response = tokio::time::timeout(Duration::from_secs(2), follower)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.id, 2);
    assert_eq!(server.count.load(Ordering::SeqCst), 2);
    assert_eq!(resolver.stats().in_flight, 0);
}

#[tokio::test]
async fn cancelling_followers_preserves_the_owner_and_cancelling_all_releases_work() {
    let server = fixture(|request| (Duration::from_millis(180), reply(request, 1))).await;
    let resolver = resolver(&server);
    let owner = {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolver.query(&query("owner.fixture.invalid", 1)).await })
    };
    server.wait_for(1).await;
    let follower = {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolver.query(&query("owner.fixture.invalid", 2)).await })
    };
    while resolver.stats().coalesced == 0 {
        tokio::task::yield_now().await;
    }
    follower.abort();
    let _ = follower.await;
    assert_eq!(owner.await.unwrap().unwrap().id, 1);
    assert_eq!(server.count.load(Ordering::SeqCst), 1);
    let cancelled = {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolver.query(&query("cancelled.fixture.invalid", 3)).await })
    };
    server.wait_for(2).await;
    cancelled.abort();
    let _ = cancelled.await;
    assert_eq!(resolver.stats().in_flight, 0);
    resolver
        .query(&query("cancelled.fixture.invalid", 4))
        .await
        .unwrap();
    assert_eq!(server.count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn query_options_and_address_families_do_not_share_incompatible_work() {
    let server = fixture(|request| (Duration::from_millis(100), reply(request, 1))).await;
    let resolver = resolver(&server);
    let replies = futures_util::future::join_all((0..48).map(|id| {
        let resolver = resolver.clone();
        async move {
            let mut request = query("options.fixture.invalid", id);
            match id / 8 {
                1 => request.metadata.recursion_desired = false,
                2 => request.metadata.checking_disabled = true,
                3 => {
                    request.set_edns(Edns::new());
                }
                4 => request.queries.as_mut_slice()[0].query_type = RecordType::AAAA,
                5 => request.metadata.authentic_data = true,
                _ => {}
            }
            resolver.query(&request).await.unwrap()
        }
    }))
    .await;
    assert_eq!(replies.len(), 48);
    assert_eq!(server.count.load(Ordering::SeqCst), 20);
    assert_eq!(resolver.stats().coalesced, 28);
    assert_eq!(resolver.stats().in_flight, 0);
}

#[tokio::test]
async fn an_old_dns_epoch_cannot_join_or_populate_the_new_epoch() {
    let old = fixture(|request| (Duration::from_millis(180), reply(request, 2))).await;
    let new = fixture(|request| (Duration::from_millis(1), reply(request, 3))).await;
    let resolver = resolver(&old);
    let pending = {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolver.query(&query("epoch.fixture.invalid", 1)).await })
    };
    old.wait_for(1).await;
    resolver.configure(vec![new.address], vec![]);
    let current = resolver
        .query(&query("epoch.fixture.invalid", 2))
        .await
        .unwrap();
    assert!(
        matches!(current.answers.as_slice()[0].data, RData::A(A(address)) if address.octets()[3] == 3)
    );
    assert!(
        matches!(pending.await.unwrap().unwrap().answers.as_slice()[0].data, RData::A(A(address)) if address.octets()[3] == 2)
    );
    let cached = resolver
        .query(&query("epoch.fixture.invalid", 3))
        .await
        .unwrap();
    assert!(
        matches!(cached.answers.as_slice()[0].data, RData::A(A(address)) if address.octets()[3] == 3)
    );
    assert_eq!(new.count.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.stats().entries, 1);
}

#[tokio::test]
async fn shared_negative_results_are_not_kept_as_successful_cache_entries() {
    let server = fixture(|request| {
        let mut response = reply(request, 1);
        response.answers.clear();
        response.metadata.response_code = ResponseCode::NXDomain;
        (Duration::from_millis(80), response)
    })
    .await;
    let resolver = resolver(&server);
    let replies = futures_util::future::join_all((0..12).map(|id| {
        let resolver = resolver.clone();
        async move {
            resolver
                .query(&query("negative.fixture.invalid", id))
                .await
                .unwrap()
        }
    }))
    .await;
    assert!(
        replies
            .iter()
            .all(|reply| reply.response_code == ResponseCode::NXDomain)
    );
    assert_eq!(server.count.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.stats().entries, 0);
    resolver
        .query(&query("negative.fixture.invalid", 99))
        .await
        .unwrap();
    assert_eq!(server.count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn first_address_preflight_finishes_with_either_ready_family() {
    for slow_ipv6 in [false, true] {
        let server = fixture(move |request| {
            let ipv6 = request.queries.as_slice()[0].query_type() == RecordType::AAAA;
            (
                Duration::from_millis(if ipv6 == slow_ipv6 { 700 } else { 1 }),
                reply(request, 1),
            )
        })
        .await;
        let resolver = resolver(&server);
        let started = Instant::now();
        let addresses = resolver
            .lookup_first("preflight.fixture.invalid", 443)
            .await
            .unwrap();
        assert!(!addresses.is_empty());
        assert!(started.elapsed() < Duration::from_millis(350));
        assert_eq!(resolver.stats().in_flight, 0);
    }
}

#[tokio::test]
async fn tcp_memory_reuses_current_addresses_and_dns_clear_invalidates_it() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = fixture(|request| {
        let mut response = reply(request, 1);
        if request.queries.as_slice()[0].query_type() == RecordType::AAAA {
            response.answers.clear();
        }
        (Duration::from_millis(1), response)
    })
    .await;
    let resolver = resolver(&server);
    for expected in [0, 1] {
        let stream = transport::tcp(&resolver, "memory.fixture.invalid", port)
            .await
            .unwrap();
        let accepted = listener.accept().await.unwrap();
        assert_eq!(resolver.dial_stats().remembered, expected);
        drop(stream);
        drop(accepted);
    }
    assert_eq!(resolver.dial_stats().remembered_paths, 1);
    resolver.clear();
    assert_eq!(resolver.dial_stats().remembered_paths, 0);
    let stream = transport::tcp(&resolver, "memory.fixture.invalid", port)
        .await
        .unwrap();
    let accepted = listener.accept().await.unwrap();
    assert_eq!(resolver.dial_stats().remembered, 1);
    assert_eq!(resolver.dial_stats().active_attempts, 0);
    drop(stream);
    drop(accepted);
    resolver.egress.ipv4.store(123, Ordering::Relaxed);
    let stream = transport::tcp(&resolver, "memory.fixture.invalid", port)
        .await
        .unwrap();
    let accepted = listener.accept().await.unwrap();
    assert_eq!(resolver.dial_stats().remembered, 1);
    drop(stream);
    drop(accepted);
    resolver.set_privacy(&harbor_engine::privacy::Privacy {
        hide_metadata: true,
        ..Default::default()
    });
    for _ in 0..2 {
        let stream = transport::tcp(&resolver, "memory.fixture.invalid", port)
            .await
            .unwrap();
        let accepted = listener.accept().await.unwrap();
        drop(stream);
        drop(accepted);
        assert_eq!(resolver.dial_stats().remembered_paths, 0);
        assert_eq!(resolver.dial_stats().remembered, 1);
    }
}

#[tokio::test]
async fn tcp_address_selection_uses_only_the_requested_family_and_reachable_names() {
    let server = fixture(|request| {
        let mut response = request.clone();
        response.metadata.message_type = MessageType::Response;
        let original = request.queries.as_slice()[0].name().clone();
        let target = Name::from_ascii("alias.fixture.invalid.").unwrap();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("unrelated.fixture.invalid.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 99)),
        ));
        response.add_answer(Record::from_rdata(
            original,
            60,
            RData::CNAME(CNAME(target.clone())),
        ));
        if request.queries.as_slice()[0].query_type() == RecordType::A {
            response.add_answer(Record::from_rdata(
                target,
                60,
                RData::A(A::new(127, 0, 0, 1)),
            ));
        }
        (Duration::ZERO, response)
    })
    .await;
    let addresses = resolver(&server)
        .lookup_first("origin.fixture.invalid", 80)
        .await
        .unwrap();
    assert_eq!(addresses, vec!["127.0.0.1:80".parse().unwrap()]);
}
