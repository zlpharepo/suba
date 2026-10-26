use super::*;
use crate::config::KeyPair;

struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("suba-peers-{}", Uuid::now_v7())))
    }
    fn store(&self) -> Peers {
        Peers::load(&self.0).unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn signer() -> IdentitySigner {
    IdentitySigner::new(Uuid::now_v7(), &KeyPair::generate().unwrap()).unwrap()
}

async fn pair_proof(
    store: &Peers,
    receiver: &IdentitySigner,
    caller: &IdentitySigner,
    invitation: &Invitation,
) -> Signed<PairClaim> {
    let challenge = store
        .challenge(
            receiver,
            ChallengeRequest {
                actor: caller.identity.clone(),
                invitation: Some(invitation.id),
            },
        )
        .await
        .unwrap();
    challenge.verify("challenge", &receiver.identity).unwrap();
    caller
        .sign(
            "pair",
            PairClaim {
                invitation_proof: invitation_proof(&invitation.secret, &challenge.payload).unwrap(),
                challenge: challenge.payload,
            },
        )
        .unwrap()
}

async fn paired() -> (Scratch, Peers, IdentitySigner, IdentitySigner) {
    let scratch = Scratch::new();
    let store = scratch.store();
    let receiver = signer();
    let caller = signer();
    let invitation = store
        .invite(
            &receiver,
            "Example operator".into(),
            "https://server.example.com/base/".into(),
        )
        .await
        .unwrap();
    let proof = pair_proof(&store, &receiver, &caller, &invitation).await;
    store.accept(&receiver, proof).await.unwrap();
    (scratch, store, receiver, caller)
}

async fn request_proof(
    store: &Peers,
    receiver: &IdentitySigner,
    caller: &IdentitySigner,
) -> Signed<ResourceRequest> {
    let challenge = store
        .challenge(
            receiver,
            ChallengeRequest {
                actor: caller.identity.clone(),
                invitation: None,
            },
        )
        .await
        .unwrap()
        .payload;
    caller
        .sign(
            "request",
            ResourceRequest {
                challenge,
                method: "PUT".into(),
                path: "/collections/example".into(),
                if_match: Some("\"example-etag\"".into()),
                body: Some("{}".into()),
            },
        )
        .unwrap()
}

#[test]
fn identity_requires_matching_keys_and_signatures_are_bound_to_their_purpose() {
    let mut pair = KeyPair::generate().unwrap();
    pair.public_key = KeyPair::generate().unwrap().public_key;
    assert!(matches!(
        IdentitySigner::new(Uuid::now_v7(), &pair),
        Err(Error::PeerIdentity)
    ));
    let canonical_pair = KeyPair::generate().unwrap();
    let id = Uuid::now_v7();
    let canonical = IdentitySigner::new(id, &canonical_pair).unwrap();
    let mut reformatted = canonical_pair;
    reformatted.public_key = reformatted.public_key.replace('\n', "\r\n");
    assert_eq!(
        canonical.identity,
        IdentitySigner::new(id, &reformatted).unwrap().identity
    );
    let source = signer();
    let other = signer();
    let proof = source.sign("challenge", "example").unwrap();
    assert!(proof.verify("challenge", &source.identity).is_ok());
    assert!(proof.verify("pair", &source.identity).is_err());
    assert!(proof.verify("challenge", &other.identity).is_err());
    let mut changed = proof.clone();
    changed.payload = "changed";
    assert!(changed.verify("challenge", &source.identity).is_err());
    let mut identity = source.identity.clone();
    identity.fingerprint = other.identity.fingerprint;
    assert!(proof.verify("challenge", &identity).is_err());
}

#[test]
fn endpoints_require_tls_and_resource_scope_excludes_auth_trust_and_recursion() {
    assert_eq!(
        endpoint("https://server.example.com/base/").unwrap(),
        "https://server.example.com/base"
    );
    assert!(endpoint("http://127.0.0.1:4321").is_ok());
    assert!(endpoint("http://[::1]:4321").is_ok());
    for url in [
        "http://server.example.com",
        "http://localhost",
        "http://192.0.2.1",
        "ftp://server.example.com",
        "https://user:secret@server.example.com",
        "https://server.example.com?token=example",
        "https://server.example.com#fragment",
    ] {
        assert!(endpoint(url).is_err());
    }
    for path in [
        "/system/metrics",
        "/providers/example",
        "/collections/example/content?format=links",
        "/cores/sing-box/configs/example",
    ] {
        assert!(resource_allowed("GET", path));
    }
    for path in [
        "/auth/password",
        "/peers",
        "/hosts",
        "/hosts/example/system/metrics",
        "/s/example",
        "https://server.example.com/providers",
        "//server.example.com/providers",
        "/providers-other",
    ] {
        assert!(!resource_allowed("GET", path));
    }
    assert!(!resource_allowed("DELETE", "/system/metrics"));
    assert!(!resource_allowed("CONNECT", "/providers"));
}

#[tokio::test]
async fn invitations_bind_both_identities_and_are_consumed_once_without_persisting_secrets() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let receiver = signer();
    let caller = signer();
    let invitation = store
        .invite(
            &receiver,
            "Example operator".into(),
            "https://server.example.com".into(),
        )
        .await
        .unwrap();
    let proof = pair_proof(&store, &receiver, &caller, &invitation).await;
    let receipt = store.accept(&receiver, proof.clone()).await.unwrap();
    receipt.verify("paired", &receiver.identity).unwrap();
    assert_eq!(receipt.payload.actor, caller.identity.id);
    assert!(store.accept(&receiver, proof).await.is_err());
    assert!(store
        .challenge(
            &receiver,
            ChallengeRequest {
                actor: caller.identity.clone(),
                invitation: Some(invitation.id)
            }
        )
        .await
        .is_err());
    let trusted = scratch.store().trusted().await;
    assert_eq!(trusted.len(), 1);
    assert_eq!(trusted[0].id, caller.identity.id);
    let saved =
        std::fs::read_to_string(scratch.0.join(crate::config::config_name("peers"))).unwrap();
    assert!(!saved.contains(&invitation.secret));
    assert!(!saved.contains("PRIVATE KEY"));
}

#[tokio::test]
async fn an_invitation_mac_cannot_be_transplanted_to_another_identity_or_challenge() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let receiver = signer();
    let caller = signer();
    let other = signer();
    let invitation = store
        .invite(
            &receiver,
            "Example".into(),
            "https://server.example.com".into(),
        )
        .await
        .unwrap();
    let proof = pair_proof(&store, &receiver, &caller, &invitation).await;
    let challenge = store
        .challenge(
            &receiver,
            ChallengeRequest {
                actor: other.identity.clone(),
                invitation: Some(invitation.id),
            },
        )
        .await
        .unwrap()
        .payload;
    let substituted = other
        .sign(
            "pair",
            PairClaim {
                challenge,
                invitation_proof: proof.payload.invitation_proof,
            },
        )
        .unwrap();
    assert!(store.accept(&receiver, substituted).await.is_err());
    assert!(store.trusted().await.is_empty());
}

#[tokio::test]
async fn expired_and_revoked_invitations_cannot_create_trust() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let receiver = signer();
    let caller = signer();
    let invitation = store
        .invite(
            &receiver,
            "Example".into(),
            "https://server.example.com".into(),
        )
        .await
        .unwrap();
    let proof = pair_proof(&store, &receiver, &caller, &invitation).await;
    store.revoke_invitation(invitation.id).await;
    assert!(store.accept(&receiver, proof).await.is_err());
    let invitation = store
        .invite(
            &receiver,
            "Example".into(),
            "https://server.example.com".into(),
        )
        .await
        .unwrap();
    store
        .pending
        .lock()
        .await
        .invitations
        .get_mut(&invitation.id)
        .unwrap()
        .until = Instant::now() - Duration::from_secs(1);
    assert!(store
        .challenge(
            &receiver,
            ChallengeRequest {
                actor: caller.identity,
                invitation: Some(invitation.id)
            }
        )
        .await
        .is_err());
}

#[tokio::test]
async fn resource_proofs_bind_body_method_path_etag_and_cannot_be_replayed() {
    let (_scratch, store, receiver, caller) = paired().await;
    for change in 0..4 {
        let mut proof = request_proof(&store, &receiver, &caller).await;
        match change {
            0 => proof.payload.body = Some("{\"changed\":true}".into()),
            1 => proof.payload.method = "DELETE".into(),
            2 => proof.payload.path = "/collections/other".into(),
            _ => proof.payload.if_match = None,
        }
        assert!(store.authorize(&receiver, &proof).await.is_err());
    }
    let proof = request_proof(&store, &receiver, &caller).await;
    let grant = store.authorize(&receiver, &proof).await.unwrap();
    assert!(store.allows(&grant).await.is_ok());
    assert!(store.authorize(&receiver, &proof).await.is_err());
}

#[tokio::test]
async fn revocation_invalidates_outstanding_challenges_and_internal_grants() {
    let (_scratch, store, receiver, caller) = paired().await;
    let used = request_proof(&store, &receiver, &caller).await;
    let grant = store.authorize(&receiver, &used).await.unwrap();
    let pending = request_proof(&store, &receiver, &caller).await;
    store.revoke(caller.identity.id).await.unwrap();
    assert!(store.allows(&grant).await.is_err());
    assert!(store.authorize(&receiver, &pending).await.is_err());
    assert!(store
        .challenge(
            &receiver,
            ChallengeRequest {
                actor: caller.identity,
                invitation: None
            }
        )
        .await
        .is_err());
}

#[tokio::test]
async fn direct_https_checks_certificate_hostnames_and_the_pinned_instance() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let remote_dir = Scratch::new();
    let local_dir = Scratch::new();
    let state = crate::AppState::build(&crate::config::ServerConfig {
        listen: "127.0.0.1".parse().unwrap(),
        port: 0,
        config_dir: remote_dir.0.join("config"),
        data_dir: remote_dir.0.join("data"),
        privileged: Default::default(),
    })
    .await
    .unwrap();
    let remote = state.settings().peer_signer().await.unwrap();
    let caller = signer();
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
    let endpoint = format!("https://localhost:{port}");
    let invitation = state
        .peers()
        .invite(&remote, "Example operator".into(), endpoint.clone())
        .await
        .unwrap();
    let tampering = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
    let mode = tampering.clone();
    let router = crate::routers::AppRouter::route(state.web_dir())
        .with_state(state.clone())
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let mode = mode.clone();
                async move {
                    use axum::response::IntoResponse as _;
                    let mode = mode.load(std::sync::atomic::Ordering::SeqCst);
                    let corrupt = (mode == 1 && request.uri().path() == "/api/peers/challenges")
                        || (mode == 2 && request.uri().path() == "/api/peers/requests");
                    let response = next.run(request).await;
                    if !corrupt {
                        return response;
                    }
                    let bytes = axum::body::to_bytes(response.into_body(), REPLY_LIMIT)
                        .await
                        .unwrap();
                    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    value["signature"] = serde_json::json!("00".repeat(64));
                    axum::Json(value).into_response()
                }
            },
        ));
    let handle = axum_server::Handle::new();
    let server = axum_server::from_tcp_rustls(listener, tls)
        .unwrap()
        .handle(handle.clone());
    let task = tokio::spawn(server.serve(router.into_make_service()));
    assert!(handle.listening().await.is_some());
    let mut local = local_dir.store();
    assert!(
        local
            .pair(&caller, "Example remote".into(), invitation.clone())
            .await
            .is_err(),
        "an untrusted TLS issuer must fail before pairing"
    );
    assert!(state.peers().trusted().await.is_empty());
    local.http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let host = local
        .pair(&caller, "Example remote".into(), invitation)
        .await
        .unwrap();
    let reply = local
        .forward(
            &caller,
            &host,
            "GET".into(),
            "/system/info".into(),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(reply.status, 200);
    let payload: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(reply.body).unwrap()).unwrap();
    assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
    for mode in [1, 2] {
        tampering.store(mode, std::sync::atomic::Ordering::SeqCst);
        assert!(
            local
                .forward(
                    &caller,
                    &host,
                    "GET".into(),
                    "/system/info".into(),
                    None,
                    None
                )
                .await
                .is_err(),
            "a forged challenge or reply must not be accepted even over trusted TLS"
        );
    }
    tampering.store(0, std::sync::atomic::Ordering::SeqCst);
    let mut mismatch = host.clone();
    mismatch.endpoint = format!("https://127.0.0.1:{port}");
    assert!(
        local
            .forward(
                &caller,
                &mismatch,
                "GET".into(),
                "/system/info".into(),
                None,
                None
            )
            .await
            .is_err(),
        "trusting the issuer must not disable hostname validation"
    );
    mismatch = host;
    mismatch.identity = signer().identity;
    assert!(
        local
            .forward(
                &caller,
                &mismatch,
                "GET".into(),
                "/system/info".into(),
                None,
                None
            )
            .await
            .is_err(),
        "TLS success must not override the pinned instance key"
    );
    handle.shutdown();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn expired_challenges_and_a_restarted_process_reject_old_proofs() {
    let (scratch, store, receiver, caller) = paired().await;
    let proof = request_proof(&store, &receiver, &caller).await;
    store
        .pending
        .lock()
        .await
        .challenges
        .get_mut(&proof.payload.challenge.nonce)
        .unwrap()
        .until = Instant::now() - Duration::from_secs(1);
    assert!(store.authorize(&receiver, &proof).await.is_err());
    let proof = request_proof(&store, &receiver, &caller).await;
    assert!(scratch.store().authorize(&receiver, &proof).await.is_err());
}
