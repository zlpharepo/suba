use super::wire::{AgentFrame, ManagerFrame, Ready};
use super::*;
use crate::{
    config::KeyPair,
    state::peers::{IdentitySigner, Purpose},
};
use futures_util::{SinkExt, StreamExt};

fn signer() -> IdentitySigner {
    IdentitySigner::new(Uuid::now_v7(), &KeyPair::generate().unwrap()).unwrap()
}

fn call() -> EdgeCall {
    EdgeCall::Challenge(ChallengeRequest {
        actor: signer().identity,
        invitation: None,
    })
}

fn challenge(agent: &IdentitySigner, manager: &IdentitySigner) -> Challenge {
    Challenge {
        nonce: "example-session-nonce".into(),
        actor: agent.identity.clone(),
        target: manager.identity.clone(),
        purpose: Purpose::EdgeSession,
        expires_at: chrono::Utc::now().timestamp_millis() + 60_000,
    }
}

#[test]
fn websocket_addresses_preserve_prefix_and_allow_only_tls_or_literal_loopback() {
    let id = Uuid::now_v7();
    assert_eq!(
        wire::address("https://manager.example.com/prefix/", id)
            .unwrap()
            .as_str(),
        format!("wss://manager.example.com/prefix/api/peers/edge/connect?host={id}")
    );
    assert_eq!(
        wire::address("http://127.0.0.1:4321", id).unwrap().scheme(),
        "ws"
    );
    assert_eq!(
        wire::address("http://[::1]:4321", id).unwrap().scheme(),
        "ws"
    );
    for endpoint in [
        "http://localhost",
        "http://manager.example.com",
        "ws://127.0.0.1",
        "https://manager.example.com?token=example",
        "https://user:example@manager.example.com",
    ] {
        assert!(wire::address(endpoint, id).is_err());
    }
}

#[test]
fn session_handshake_binds_signer_direction_purpose_nonce_and_instances() {
    let agent = signer();
    let manager = signer();
    let other = signer();
    let original = challenge(&agent, &manager);
    let proof = manager.sign("challenge", original.clone()).unwrap();
    wire::verify_challenge(&proof, &agent.identity, &manager.identity).unwrap();
    assert!(wire::verify_challenge(&proof, &agent.identity, &other.identity).is_err());
    for field in 0..3 {
        let mut changed = original.clone();
        match field {
            0 => changed.actor = other.identity.clone(),
            1 => changed.target = other.identity.clone(),
            _ => changed.purpose = Purpose::Request,
        }
        assert!(wire::verify_challenge(
            &manager.sign("challenge", changed).unwrap(),
            &agent.identity,
            &manager.identity
        )
        .is_err());
    }
    for field in 0..6 {
        let mut ready = Ready {
            nonce: original.nonce.clone(),
            session: Uuid::now_v7(),
            agent: agent.identity.id,
            manager: manager.identity.id,
        };
        match field {
            1 => ready.nonce = "different-session-nonce".into(),
            2 => ready.agent = other.identity.id,
            3 => ready.manager = other.identity.id,
            4 => ready.session = Uuid::nil(),
            _ => {}
        }
        let proof = manager
            .sign(if field == 5 { "response" } else { "edge-ready" }, ready)
            .unwrap();
        assert_eq!(
            wire::verify_ready(&proof, &original, &manager.identity).is_ok(),
            field == 0
        );
    }
}

#[test]
fn wire_directions_and_frame_limits_are_enforced() {
    let command = ManagerFrame::Call {
        session: Uuid::now_v7(),
        id: 1,
        call: Box::new(call()),
    };
    let bytes = serde_json::to_vec(&command).unwrap();
    assert!(serde_json::from_slice::<AgentFrame>(&bytes).is_err());
    let answer = AgentFrame::Pong {
        session: Uuid::now_v7(),
        id: 1,
    };
    assert!(serde_json::from_slice::<ManagerFrame>(&serde_json::to_vec(&answer).unwrap()).is_err());
    assert!(wire::decode::<ManagerFrame>(
        reqwest_websocket::Message::Binary(bytes.clone().into()),
        bytes.len() - 1
    )
    .is_err());
    assert!(wire::decode::<ManagerFrame>(
        reqwest_websocket::Message::Binary(bytes.clone().into()),
        bytes.len()
    )
    .is_ok());
}

#[tokio::test]
async fn session_replacement_fences_old_replies_and_closes_pending_calls() {
    let hub = EdgeHub::new();
    let host = Uuid::now_v7();
    let (old, _old_commands) = Session::new(Uuid::now_v7());
    hub.attach(host, old.clone()).unwrap();
    let (id, pending) = old.enqueue(call()).unwrap();
    let (new, _new_commands) = Session::new(Uuid::now_v7());
    hub.attach(host, new.clone()).unwrap();
    assert!(pending.await.is_err());
    assert!(old
        .answer(old.id, id, Err(wire::Failure::Unavailable))
        .is_err());
    hub.detach(host, &old);
    assert_eq!(hub.host_status(host).state, EdgeState::Online);
    let (id, pending) = new.enqueue(call()).unwrap();
    assert!(new
        .answer(old.id, id, Err(wire::Failure::Unavailable))
        .is_err());
    new.answer(new.id, id, Err(wire::Failure::NotFound))
        .unwrap();
    assert!(matches!(
        pending.await.unwrap(),
        Err(wire::Failure::NotFound)
    ));
    hub.disconnect(host);
    assert_eq!(hub.host_status(host).state, EdgeState::Offline);
}

/// Detaching a session closes it: it stops accepting calls and reports no
/// connection, whether or not it was the host's current one.
#[tokio::test]
async fn detaching_a_session_closes_it() {
    let hub = EdgeHub::new();
    let host = Uuid::now_v7();
    let (session, _commands) = Session::new(Uuid::now_v7());
    hub.attach(host, session.clone()).unwrap();
    hub.detach(host, &session);
    assert_eq!(hub.host_status(host).state, EdgeState::Offline);
    assert!(
        session.enqueue(call()).is_err(),
        "a detached session takes no calls"
    );
    assert!(
        hub.exchange(host, call()).await.is_err(),
        "a detached session is not reachable through the hub"
    );
    session.close();
    let (current, _commands) = Session::new(Uuid::now_v7());
    hub.attach(host, current.clone()).unwrap();
    hub.detach(host, &session);
    assert_eq!(
        hub.host_status(host).state,
        EdgeState::Online,
        "detaching a replaced session must not disturb the current one"
    );
    assert!(current.enqueue(call()).is_ok());
}

#[tokio::test]
async fn pending_calls_are_bounded_correlated_and_removed_on_cancellation() {
    let (session, mut commands) = Session::new(Uuid::now_v7());
    let mut pending = Vec::new();
    for _ in 0..CALL_LIMIT {
        let (id, answer) = session.enqueue(call()).unwrap();
        pending.push((id, answer));
        commands.recv().await.unwrap();
    }
    assert!(session.enqueue(call()).is_err());
    let (first, receiver) = pending.remove(0);
    drop(PendingCall {
        session: session.clone(),
        id: first,
    });
    assert!(receiver.await.is_err());
    assert!(!session.wants(first));
    session
        .answer(session.id, first, Err(wire::Failure::Unavailable))
        .unwrap();
    assert!(session
        .answer(
            session.id,
            CALL_LIMIT as u64 + 1,
            Err(wire::Failure::Unavailable)
        )
        .is_err());
    let (id, receiver) = pending.pop().unwrap();
    session
        .answer(session.id, id, Err(wire::Failure::NotFound))
        .unwrap();
    assert!(matches!(
        receiver.await.unwrap(),
        Err(wire::Failure::NotFound)
    ));
    session.close();
    for (_, receiver) in pending {
        assert!(receiver.await.is_err());
    }
    assert!(session.enqueue(call()).is_err());
}

#[tokio::test]
async fn disconnected_mutation_is_uncertain_but_is_never_requeued() {
    let hub = EdgeHub::new();
    let host = Uuid::now_v7();
    let (session, mut commands) = Session::new(Uuid::now_v7());
    hub.attach(host, session.clone()).unwrap();
    let agent = signer();
    let manager = signer();
    let proof = manager
        .sign(
            "request",
            ResourceRequest {
                challenge: challenge(&agent, &manager),
                method: "PUT".into(),
                path: "/collections/example".into(),
                if_match: None,
                body: Some("{}".into()),
            },
        )
        .unwrap();
    let request = hub.exchange(host, EdgeCall::Resource(proof));
    let close = async {
        commands.recv().await.unwrap();
        hub.disconnect(host);
    };
    let (result, ()) = tokio::join!(request, close);
    assert!(matches!(result, Err(Error::PeerUncertain)));
    assert!(commands.try_recv().is_err());
    assert!(matches!(
        hub.exchange(host, call()).await,
        Err(Error::PeerUnavailable)
    ));
    assert_eq!(hub.local_status().state, EdgeState::Disabled);
    let mut control = hub.control.subscribe();
    hub.reconnect();
    assert!(control.has_changed().unwrap());
    control.borrow_and_update();
    hub.shutdown();
    assert!(control.borrow().stopped);
    let (replacement, _commands) = Session::new(Uuid::now_v7());
    assert!(hub.attach(host, replacement).is_err());
}

struct TlsServer {
    handle: axum_server::Handle<std::net::SocketAddr>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    port: u16,
    pem: String,
    tls: axum_server::tls_rustls::RustlsConfig,
}

impl TlsServer {
    async fn start() -> Self {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = certificate.cert.pem();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            pem.as_bytes().to_vec(),
            certificate.signing_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let router = axum::Router::new().route(
            "/prefix/api/peers/edge/connect",
            axum::routing::get(|ws: axum::extract::WebSocketUpgrade| async {
                ws.on_upgrade(|mut socket| async move {
                    if let Some(Ok(message)) = socket.recv().await {
                        let _ = socket.send(message).await;
                    }
                })
            }),
        );
        let handle = axum_server::Handle::new();
        let server = axum_server::from_tcp_rustls(listener, tls.clone())
            .unwrap()
            .handle(handle.clone());
        let task = tokio::spawn(server.serve(router.into_make_service()));
        assert!(handle.listening().await.is_some());
        Self {
            handle,
            task,
            port,
            pem,
            tls,
        }
    }

    fn client(&self, proxy: Option<&str>) -> reqwest::Client {
        crate::state::peers::outbound_builder(proxy)
            .unwrap()
            .http1_only()
            .add_root_certificate(reqwest::Certificate::from_pem(self.pem.as_bytes()).unwrap())
            .build()
            .unwrap()
    }

    fn url(&self) -> url::Url {
        wire::address(
            &format!("https://localhost:{}/prefix", self.port),
            Uuid::now_v7(),
        )
        .unwrap()
    }
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        self.handle.shutdown();
        self.task.abort();
    }
}

struct Proxy {
    port: u16,
    task: tokio::task::JoinHandle<()>,
    requests: mpsc::Receiver<String>,
}

impl Proxy {
    async fn start(target: u16, tls: Option<axum_server::tls_rustls::RustlsConfig>) -> Self {
        use axum_server::accept::Accept;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (request, requests) = mpsc::channel(8);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let tls = tls.clone();
                        let request = request.clone();
                        connections.spawn(async move {
                            if let Some(tls) = tls {
                                if let Ok((stream, ())) = axum_server::tls_rustls::RustlsAcceptor::new(tls).accept(stream, ()).await {
                                    tunnel(stream, target, request).await;
                                }
                            } else { tunnel(stream, target, request).await; }
                        });
                    },
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        });
        Self {
            port,
            task,
            requests,
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn tunnel<S>(mut stream: S, target: u16, request: mpsc::Sender<String>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut headers = Vec::new();
    while headers.len() < 8192 && !headers.ends_with(b"\r\n\r\n") {
        let Ok(byte) = stream.read_u8().await else {
            return;
        };
        headers.push(byte);
    }
    let headers = String::from_utf8(headers).unwrap();
    if !headers.starts_with(&format!("CONNECT localhost:{target} HTTP/1.1\r\n")) {
        return;
    }
    request.send(headers).await.unwrap();
    let Ok(mut remote) =
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, target)).await
    else {
        return;
    };
    if stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
}

#[tokio::test]
async fn actual_wss_verifies_certificates_hostnames_and_explicit_http_and_https_connect() {
    let server = TlsServer::start().await;
    let untrusted = crate::state::peers::outbound_builder(None)
        .unwrap()
        .http1_only()
        .build()
        .unwrap();
    assert!(wire::dial(&untrusted, server.url()).await.is_err());
    let client = server.client(None);
    let mut mismatch = server.url();
    mismatch.set_host(Some("127.0.0.1")).unwrap();
    assert!(wire::dial(&client, mismatch).await.is_err());
    let mut socket = wire::dial(&client, server.url()).await.unwrap();
    socket
        .send(reqwest_websocket::Message::Text("example-direct".into()))
        .await
        .unwrap();
    assert!(
        matches!(socket.next().await.unwrap().unwrap(), reqwest_websocket::Message::Text(text) if text == "example-direct")
    );
    for secure in [false, true] {
        let mut proxy = Proxy::start(server.port, secure.then(|| server.tls.clone())).await;
        let endpoint = format!(
            "{}://example:example-password@localhost:{}",
            if secure { "https" } else { "http" },
            proxy.port
        );
        let client = server.client(Some(&endpoint));
        let mut socket =
            tokio::time::timeout(Duration::from_secs(5), wire::dial(&client, server.url()))
                .await
                .unwrap()
                .unwrap();
        socket
            .send(reqwest_websocket::Message::Text("example-proxied".into()))
            .await
            .unwrap();
        assert!(
            matches!(socket.next().await.unwrap().unwrap(), reqwest_websocket::Message::Text(text) if text == "example-proxied")
        );
        let headers = proxy.requests.recv().await.unwrap().to_ascii_lowercase();
        assert!(headers.contains("proxy-authorization: basic "));
        if secure {
            let untrusted = crate::state::peers::outbound_builder(Some(&endpoint))
                .unwrap()
                .http1_only()
                .build()
                .unwrap();
            assert!(wire::dial(&untrusted, server.url()).await.is_err());
            let mismatch = endpoint.replace("localhost", "127.0.0.1");
            assert!(wire::dial(&server.client(Some(&mismatch)), server.url())
                .await
                .is_err());
        }
    }
}
