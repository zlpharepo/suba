use super::*;
use crate::state::peers::{Challenge, ChallengeRequest, IdentitySigner, ResourceRequest, Signed};
use reqwest::Method;

async fn post(server: &Server, path: &str, value: Value) -> reqwest::Response {
    server
        .authed(Method::POST, path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(value.to_string())
        .send()
        .await
        .unwrap()
}

async fn get(server: &Server, path: &str) -> Value {
    let response = server.authed(Method::GET, path).send().await.unwrap();
    assert_eq!(response.status(), 200);
    body(response).await
}

async fn pair(local: &Server, remote: &Server) -> String {
    let invitation = post(
        remote,
        "/api/peers/invitations",
        json!({"name":"Example desktop", "endpoint":remote.base}),
    )
    .await;
    assert_eq!(invitation.status(), 201);
    assert_eq!(invitation.headers()[header::CACHE_CONTROL], "no-store");
    let added = post(
        local,
        "/api/hosts",
        json!({"name":"Example server", "invitation":body(invitation).await}),
    )
    .await;
    assert_eq!(added.status(), 201);
    body(added).await["id"].as_str().unwrap().to_string()
}

fn signer(server: &Server) -> IdentitySigner {
    let config: crate::config::AppConfig = crate::config::read_config(
        server.root.join("config").to_str().unwrap(),
        crate::config::APP_CONFIG_BASENAME,
    )
    .unwrap();
    IdentitySigner::new(config.instance_id.unwrap(), &config.key_pair.unwrap()).unwrap()
}

async fn proof(local: &Server, remote: &Server, path: &str) -> Signed<ResourceRequest> {
    let signer = signer(local);
    let response = remote
        .client
        .post(format!("{}/api/peers/challenges", remote.base))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_vec(&ChallengeRequest {
                actor: signer.identity.clone(),
                invitation: None,
            })
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let challenge: Signed<Challenge> = serde_json::from_value(body(response).await).unwrap();
    signer
        .sign(
            "request",
            ResourceRequest {
                challenge: challenge.payload,
                method: "GET".into(),
                path: path.into(),
                if_match: None,
                body: None,
            },
        )
        .unwrap()
}

async fn execute(remote: &Server, proof: &Signed<ResourceRequest>) -> reqwest::Response {
    remote
        .client
        .post(format!("{}/api/peers/requests", remote.base))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(proof).unwrap())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn machine_handshakes_do_not_initialize_an_unpaired_instance() {
    let server = Server::start().await;
    let read = || {
        crate::config::read_config::<crate::config::AppConfig>(
            server.root.join("config").to_str().unwrap(),
            crate::config::APP_CONFIG_BASENAME,
        )
        .unwrap()
    };
    assert!(read().instance_id.is_none());
    let caller = IdentitySigner::new(
        uuid::Uuid::now_v7(),
        &crate::config::KeyPair::generate().unwrap(),
    )
    .unwrap();
    let response = server
        .client
        .post(format!("{}/api/peers/challenges", server.base))
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_vec(&ChallengeRequest {
                actor: caller.identity,
                invitation: None,
            })
            .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert!(read().instance_id.is_none());
}

#[tokio::test]
async fn direct_management_preserves_remote_ownership_and_local_authentication() {
    let local = Server::start().await;
    let remote = Server::start().await;
    for path in ["/api/hosts", "/api/peers", "/api/peers/identity"] {
        assert_eq!(local.get(path).send().await.unwrap().status(), 401);
    }
    let host = pair(&local, &remote).await;
    let base = format!("/api/hosts/{host}");
    assert_eq!(
        get(&local, &(base.clone() + "/system/info")).await["version"],
        env!("CARGO_PKG_VERSION")
    );
    let write = local.put_json(&(base.clone()+"/providers/remote-only"),json!({"type":"inline","payload":"trojan://example-password@proxy.example.com:443#example"})).await;
    assert_eq!(write.status(), 201);
    assert!(get(&local, "/api/providers")
        .await
        .as_object()
        .unwrap()
        .is_empty());
    assert!(get(&remote, "/api/providers")
        .await
        .get("remote-only")
        .is_some());
    assert_eq!(
        local
            .put_json(
                &(base.clone() + "/collections/example"),
                json!({"providers":["remote-only"]})
            )
            .await
            .status(),
        201
    );
    let token = local
        .authed(
            Method::PUT,
            &(base.clone() + "/collections/example/tokens/phone"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(token.status(), 201);
    let token = body(token).await;
    let path = token["path"].as_str().unwrap();
    assert_eq!(remote.get(path).send().await.unwrap().status(), 200);
    assert_eq!(local.get(path).send().await.unwrap().status(), 404);
    let preview = local
        .authed(
            Method::GET,
            &(base.clone() + "/collections/example/content?format=links"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(preview.status(), 200);
    assert_eq!(preview.headers()["x-suba-nodes"], "1");
    assert_eq!(preview.headers()[header::CACHE_CONTROL], "no-store");
    assert!(preview.text().await.unwrap().starts_with("trojan://"));
    let identity = get(&local, "/api/peers/identity").await;
    let peers = get(&remote, "/api/peers").await;
    assert_eq!(peers[0]["id"], identity["id"]);
    assert!(!peers.to_string().contains("PRIVATE KEY"));
    assert_eq!(
        remote
            .authed(
                Method::DELETE,
                &format!("/api/peers/{}", identity["id"].as_str().unwrap())
            )
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        local
            .authed(Method::GET, &(base + "/system/info"))
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
    assert_eq!(
        local
            .authed(Method::GET, "/api/system/info")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    drop(local);
    assert_eq!(
        remote.get(path).send().await.unwrap().status(),
        200,
        "distribution does not depend on the operator"
    );
}

#[tokio::test]
async fn peer_requests_are_single_use_and_cannot_delegate_or_become_admin_sessions() {
    let local = Server::start().await;
    let remote = Server::start().await;
    let host = pair(&local, &remote).await;
    let allowed = proof(&local, &remote, "/system/info").await;
    assert_eq!(execute(&remote, &allowed).await.status(), 200);
    assert_eq!(execute(&remote, &allowed).await.status(), 401);
    for path in [
        "/auth/password",
        "/peers",
        "/hosts",
        "/hosts/example/system/info",
        "/s/example",
    ] {
        assert_eq!(
            execute(&remote, &proof(&local, &remote, path).await)
                .await
                .status(),
            404
        );
        assert_eq!(
            local
                .authed(Method::GET, &format!("/api/hosts/{host}{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
    }
    let fake = serde_json::to_string(&allowed).unwrap();
    assert_eq!(
        remote
            .client
            .get(format!("{}/api/system/info", remote.base))
            .bearer_auth(fake)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        remote
            .client
            .get(format!("{}/api/system/info", remote.base))
            .header("x-suba-peer-id", signer(&local).identity.id.to_string())
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let removed = local
        .authed(Method::DELETE, &format!("/api/hosts/{host}"))
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 204);
    assert_eq!(
        get(&remote, "/api/peers").await.as_array().unwrap().len(),
        1,
        "removing a local connection is not remote revocation"
    );
}

#[tokio::test]
async fn changed_endpoints_cannot_change_the_pinned_remote_identity() {
    let local = Server::start().await;
    let remote = Server::start().await;
    let other = Server::start().await;
    let host = pair(&local, &remote).await;
    pair(&local, &other).await;
    assert_eq!(
        local
            .put_json(
                &format!("/api/hosts/{host}"),
                json!({"name":"Example", "endpoint":other.base})
            )
            .await
            .status(),
        200
    );
    assert_eq!(
        local
            .put_json(
                &format!("/api/hosts/{host}/collections/wrong-target"),
                json!({"providers":[]})
            )
            .await
            .status(),
        502
    );
    assert!(get(&other, "/api/collections")
        .await
        .as_object()
        .unwrap()
        .is_empty());
    assert_eq!(
        local
            .put_json(
                &format!("/api/hosts/{host}"),
                json!({"name":"Example", "endpoint":remote.base})
            )
            .await
            .status(),
        200
    );
    assert_eq!(
        local
            .authed(Method::GET, &format!("/api/hosts/{host}/system/info"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

#[cfg(feature = "singbox-core")]
#[tokio::test]
async fn remote_config_writes_preserve_etags_and_do_not_touch_local_documents() {
    let local = Server::start().await;
    let remote = Server::start().await;
    let version = remote.root.join("data/sing-box/versions/1.14.3");
    std::fs::create_dir_all(version.join("bin")).unwrap();
    let schema = br#"{"type":"object","properties":{"log":{"type":"object"}},"$defs":{"Inbound":{"oneOf":[{"type":"object","properties":{"type":{"const":"socks"}}}]},"Outbound":{"oneOf":[{"type":"object","properties":{"type":{"const":"direct"}}}]}}}"#;
    std::fs::write(version.join("schema.json"), schema).unwrap();
    std::fs::write(version.join("bin/sing-box"), []).unwrap();
    let metadata = suba_singbox::core::Metadata {
        version: suba_singbox::core::Version::from_tag("1.14.3"),
        tag: "v1.14.3".into(),
        asset: "example.tar.gz".into(),
        platform: "linux-amd64".into(),
        asset_sha256: "0".repeat(64),
        binary_sha256: suba_core::checksum::sha256_hex(&[]),
        schema_sha256: suba_core::checksum::sha256_hex(schema),
        installed_at: 1_700_000_000,
    };
    std::fs::write(
        version.join("metadata.json"),
        serde_json::to_vec(&metadata).unwrap(),
    )
    .unwrap();
    assert_eq!(remote.put_json("/api/cores/sing-box",json!({"version":"1.14.3","config":"default","privilege":"operator","collections":[]})).await.status(),200);
    let host = pair(&local, &remote).await;
    let path = format!("/api/hosts/{host}/cores/sing-box/configs/default");
    let response = local.authed(Method::GET, &path).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let etag = response.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_string();
    let write = || {
        local
            .authed(Method::PUT, &path)
            .header(header::IF_MATCH, &etag)
            .header(header::CONTENT_TYPE, "application/json")
            .body("{\"log\":{\"level\":\"warn\"}}")
    };
    let saved = write().send().await.unwrap();
    assert_eq!(saved.status(), 200);
    assert_ne!(saved.headers()[header::ETAG], etag);
    assert_eq!(write().send().await.unwrap().status(), 412);
    assert_eq!(
        get(&remote, "/api/cores/sing-box/configs/default").await["log"]["level"],
        "warn"
    );
    assert!(get(&local, "/api/cores/sing-box/configs/default")
        .await
        .get("log")
        .is_none());
    assert_ne!(
        uuid::Uuid::parse_str(&host).unwrap(),
        signer(&local).identity.id
    );
}
