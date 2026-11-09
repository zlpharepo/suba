use std::{os::unix::fs::PermissionsExt, time::Duration};

use reqwest::Method;
use serde_json::{json, Value};
use suba_singbox::core::{Dirs, Metadata, Version};

use super::{body, Server};
use crate::{AgentOptions, AppState, ServerConfig, SubaServer};

struct RunningAgent {
    state: AppState,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), crate::Error>>>,
}

impl RunningAgent {
    fn start(server: SubaServer) -> Self {
        let state = server.state.clone();
        let (stop, signal) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve_until(
            async {
                let _ = signal.await;
            },
            Duration::from_secs(2),
        ));
        Self {
            state,
            stop: Some(stop),
            task: Some(task),
        }
    }

    async fn stop(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

impl Drop for RunningAgent {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            self.state
                .singbox()
                .shutdown(Duration::from_millis(100))
                .unwrap();
        }
    }
}

fn install(root: &std::path::Path) {
    let dirs = Dirs::new(root.join("data"));
    let version = Version::from_tag("1.14.3");
    let schema = serde_json::to_vec(
        &json!({"type": "object", "properties": {}, "additionalProperties": true,
            "$defs": {
                "Inbound": {"oneOf": [{"type": "object", "properties": {"type": {"const": "vless"}}}]},
                "Outbound": {"oneOf": [{"type": "object", "properties": {"type": {"const": "direct"}}}]}
            }
        }),
    )
    .unwrap();
    let metadata = Metadata {
        version: version.clone(),
        tag: version.tag(),
        asset: "fixture.tar.gz".into(),
        platform: "fixture".into(),
        asset_sha256: "fixture".into(),
        binary_sha256: "fixture".into(),
        schema_sha256: suba_singbox::core::sha256_hex(&schema),
        installed_at: 1_700_000_000,
    };
    std::fs::create_dir_all(dirs.binary(&version).parent().unwrap()).unwrap();
    std::fs::write(
        dirs.metadata(&version),
        serde_json::to_vec(&metadata).unwrap(),
    )
    .unwrap();
    std::fs::write(dirs.schema(&version), schema).unwrap();
    std::fs::write(
        dirs.binary(&version),
        "#!/bin/sh\nif [ \"$5\" = check ]; then exit 0; fi\nif [ \"$1\" = generate ]; then echo fixture-generated; exit 0; fi\nif [ \"$5\" = run ]; then exec sleep 600; fi\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(
        dirs.binary(&version),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}

async fn get(server: &Server, path: &str) -> Value {
    let response = server.authed(Method::GET, path).send().await.unwrap();
    assert_eq!(response.status(), 200, "{path}");
    body(response).await
}

async fn put(server: &Server, path: &str, value: Value) -> Value {
    let response = server.put_json(path, value).await;
    assert!(
        response.status().is_success(),
        "{path}: {}",
        response.text().await.unwrap()
    );
    let bytes = response.bytes().await.unwrap();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}

async fn write(server: &Server, path: &str, value: Value) {
    let previous = server.authed(Method::GET, path).send().await.unwrap();
    assert_eq!(previous.status(), 200);
    let etag = previous.headers()[http::header::ETAG].clone();
    let response = server
        .authed(Method::PUT, path)
        .header(http::header::IF_MATCH, etag)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(value.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
}

fn config(port: u16) -> Value {
    json!({"inbounds": [{"type": "vless", "tag": "shared", "listen": "127.0.0.1", "listen_port": port}]})
}

#[tokio::test]
async fn manager_saves_and_publishes_native_agent_snapshots_and_offline_boot_uses_the_last_success()
{
    let manager = Server::start().await;
    let root = manager.root.join("agent");
    install(&root);
    let server_config = || ServerConfig {
        listen: "127.0.0.1".parse().unwrap(),
        port: 0,
        config_dir: root.join("config"),
        data_dir: root.join("data"),
        privileged: Default::default(),
    };
    let invitation = manager
        .authed(Method::POST, "/api/peers/invitations")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(
            json!({"name": "Example Agent", "endpoint": manager.base, "mode": "edge"}).to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(invitation.status(), 201);
    let invitation = body(invitation).await;
    let token = format!(
        "{}.{}",
        invitation["id"].as_str().unwrap(),
        invitation["secret"].as_str().unwrap()
    );
    let node = SubaServer::edge_agent(
        server_config(),
        AgentOptions {
            manager_api_url: format!("{}/api", manager.base),
            token: Some(token.clone()),
        },
    )
    .await
    .unwrap();
    let id = node
        .state
        .settings()
        .existing_peer_signer()
        .await
        .unwrap()
        .identity
        .id;
    use tower::ServiceExt;
    let manager_identity = node.state.peers().edge_upstream().await.unwrap().manager;
    use crate::state::peers::{ChallengeRequest, IdentitySigner, ResourceRequest};
    let manager_config: crate::config::AppConfig =
        crate::config::read_config(manager.root.join("config").to_str().unwrap(), "config")
            .unwrap();
    let manager_signer = IdentitySigner::new(
        manager_config.instance_id.unwrap(),
        &manager_config.key_pair.unwrap(),
    )
    .unwrap();
    let node_signer = node.state.settings().existing_peer_signer().await.unwrap();
    let challenge = node
        .state
        .peers()
        .challenge(
            &node_signer,
            ChallengeRequest {
                actor: manager_identity,
                invitation: None,
            },
        )
        .await
        .unwrap();
    let proof = manager_signer
        .sign(
            "request",
            ResourceRequest {
                challenge: challenge.payload,
                method: "GET".into(),
                path: "/system/info".into(),
                if_match: None,
                body: None,
            },
        )
        .unwrap();
    let grant = node
        .state
        .peers()
        .authorize(&node_signer, &proof)
        .await
        .unwrap();
    for path in [
        "/providers",
        "/collections",
        "/inbounds/users",
        "/inbounds/endpoints",
        "/cores/sing-box/configs",
        "/environments",
        "/auth/password",
    ] {
        let mut request = http::Request::builder()
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        request.extensions_mut().insert(grant.clone());
        let response = crate::routers::AppRouter::agent_resources()
            .with_state(node.state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), 404, "{path}");
    }
    let agent = RunningAgent::start(node);
    let prefix = format!("/api/environments/{id}");
    tokio::time::timeout(Duration::from_secs(5), async {
        while manager
            .authed(Method::GET, &format!("{prefix}/system/info"))
            .send()
            .await
            .unwrap()
            .status()
            != 200
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();

    let module = format!("{prefix}/cores/sing-box");
    put(&manager, &module, json!({"version": "1.14.3", "config": "default", "privilege": "operator", "autostart": true})).await;
    let document = format!("{module}/configs/default");
    let generated = manager
        .authed(Method::POST, &format!("{module}/generate"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(json!({"command": "uuid"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(generated.status(), 200);
    assert_eq!(body(generated).await["output"], "fixture-generated");
    write(&manager, &document, config(19099)).await;
    assert!(
        agent.state.singbox().settings().unwrap().version.is_none(),
        "Save keeps runtime ownership separate"
    );
    assert!(!agent.state.singbox().assembled());

    put(
        &manager,
        &format!("{prefix}/inbounds/endpoints/default/shared"),
        json!({"address": "proxy.example.invalid"}),
    )
    .await;
    let endpoints = get(&manager, "/api/inbounds/endpoints").await;
    assert_eq!(endpoints["entries"][0]["host"], id.to_string());
    assert_eq!(endpoints["entries"][0]["host_name"], "Example Agent");
    let grant = json!({"host": id, "config": "default", "inbound": "shared"});
    put(
        &manager,
        "/api/inbounds/users/example",
        json!({"inbounds": [grant]}),
    )
    .await;
    let users = get(&manager, "/api/inbounds/users").await;
    assert_eq!(users[0]["grants"][0]["state"], "stopped");
    assert_eq!(users[0]["grants"][0]["host"], id.to_string());

    let status = format!("{module}/status");
    assert_eq!(
        put(&manager, &status, json!({"action": "start"})).await["running"],
        true
    );
    let product = agent.state.singbox().product().unwrap();
    let credential = product["inbounds"][0]["users"][0]["uuid"].as_str().unwrap();
    let users = get(&manager, "/api/inbounds/users").await;
    assert_eq!(users[0]["grants"][0]["state"], "applied");
    assert!(users[0]["grants"][0]["link"]
        .as_str()
        .unwrap()
        .contains(credential));
    let exported = manager
        .authed(
            Method::GET,
            "/api/inbounds/users/example/content?format=links",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(exported.headers()["x-suba-nodes"], "1");
    assert!(exported.text().await.unwrap().contains(credential));
    let authored = std::fs::read_to_string(
        manager
            .root
            .join(format!("config/hosts/{id}/sing-box/default.json")),
    )
    .unwrap();
    assert!(!authored.contains(credential));
    let access: crate::state::access::UsersConfig =
        crate::config::read_config(manager.root.join("config").to_str().unwrap(), "users").unwrap();
    let snapshot = std::fs::read_to_string(root.join("data/agent/deployment.json")).unwrap();
    assert!(!snapshot.contains(&access.users["example"].secret));
    assert!(!snapshot.contains(&token));
    assert!(!root
        .join("config")
        .join(crate::config::config_name("users"))
        .exists());

    write(&manager, &document, config(19100)).await;
    assert_eq!(agent.state.singbox().product().unwrap(), product);
    assert_eq!(
        get(&manager, "/api/inbounds/users").await[0]["grants"][0]["state"],
        "pending"
    );
    assert_eq!(
        put(&manager, &status, json!({"action": "restart"})).await["running"],
        true
    );
    assert_eq!(
        agent.state.singbox().product().unwrap()["inbounds"][0]["listen_port"],
        19100
    );

    let dirs = Dirs::new(root.join("data"));
    let binary = dirs.binary(&Version::from_tag("1.14.3"));
    std::fs::write(&binary, "#!/bin/sh\nexit 1\n").unwrap();
    let before = agent.state.singbox().status().pid;
    let successful = std::fs::read(root.join("data/agent/deployment.json")).unwrap();
    write(&manager, &document, config(19101)).await;
    assert!(!manager
        .put_json(&status, json!({"action": "restart"}))
        .await
        .status()
        .is_success());
    assert_eq!(
        agent.state.singbox().status().pid,
        before,
        "failed preflight keeps the serving core"
    );
    assert_eq!(
        std::fs::read(root.join("data/agent/deployment.json")).unwrap(),
        successful
    );
    install(&root);
    put(
        &manager,
        "/api/inbounds/users/example",
        json!({"inbounds": []}),
    )
    .await;
    assert_eq!(
        agent.state.singbox().product().unwrap()["inbounds"][0]["users"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    put(&manager, &status, json!({"action": "restart"})).await;
    assert!(
        agent.state.singbox().product().unwrap()["inbounds"][0]["users"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    let last_success = agent.state.singbox().product().unwrap();
    put(
        &manager,
        &module,
        json!({"version": null, "config": "default", "privilege": "operator"}),
    )
    .await;
    assert_eq!(get(&manager, &module).await["version"], Value::Null);
    agent.stop().await;
    put(
        &manager,
        "/api/inbounds/users/example",
        json!({"inbounds": [{"host": id, "config": "default", "inbound": "shared"}]}),
    )
    .await;
    assert_eq!(
        get(&manager, "/api/inbounds/users").await[0]["grants"][0]["state"],
        "unknown"
    );
    manager.task.abort();

    let node = SubaServer::edge_agent(
        server_config(),
        AgentOptions {
            manager_api_url: format!("{}/api", manager.base),
            token: None,
        },
    )
    .await
    .unwrap();
    let restarted = RunningAgent::start(node);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !restarted.state.singbox().status().running {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(restarted.state.singbox().product().unwrap(), last_success);
    restarted.stop().await;
}
