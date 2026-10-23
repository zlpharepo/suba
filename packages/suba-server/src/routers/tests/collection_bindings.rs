use std::os::unix::fs::PermissionsExt;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use reqwest::Method;
use serde_json::{json, Value};
use suba_singbox::core::{Dirs, Metadata, Version};

use super::{body, Server};

const MODULE: &str = "/api/cores/sing-box";
const CONFIG: &str = "/api/cores/sing-box/configs/bound";
const SECTION: &str = "/api/cores/sing-box/configs/bound/sections/outbounds";
const ENTRY: &str = "/api/cores/sing-box/configs/bound/sections/outbounds/group";
const REFERENCES: &str = "/api/cores/sing-box/configs/bound/references";
const STATUS: &str = "/api/cores/sing-box/status";

fn install(server: &Server) {
    let dirs = Dirs::new(server.root.join("data"));
    let version = Version::from_tag("1.14.2");
    let schema = json!({
        "type": "object",
        "properties": {"outbounds": {"type": "array", "items": {
            "type": "object", "additionalProperties": false,
            "properties": {
                "type": {"type": "string"}, "tag": {"type": "string"},
                "outbounds": {"type": "array", "items": {"type": "string"}},
                "default": {"type": "string"}, "server": {"type": "string"},
                "server_port": {"type": "integer"}, "password": {"type": "string"},
                "tls": {"type": "object"}
            }
        }}}, "additionalProperties": false,
        "$defs": {
            "Inbound": {"oneOf": [{"type": "object", "properties": {"type": {"const": "mixed"}}}]},
            "Outbound": {"oneOf": [{"type": "object", "properties": {"type": {"const": "direct"}}}]}
        }
    });
    let metadata = Metadata {
        version: version.clone(),
        tag: version.tag(),
        asset: "fixture.tar.gz".to_owned(),
        platform: "fixture".to_owned(),
        asset_sha256: "fixture".to_owned(),
        binary_sha256: "fixture".to_owned(),
        schema_sha256: suba_singbox::core::sha256_hex(&serde_json::to_vec(&schema).unwrap()),
        installed_at: 1_700_000_000,
    };
    std::fs::create_dir_all(dirs.binary(&version).parent().unwrap()).unwrap();
    std::fs::write(
        dirs.metadata(&version),
        serde_json::to_vec(&metadata).unwrap(),
    )
    .unwrap();
    std::fs::write(dirs.schema(&version), serde_json::to_vec(&schema).unwrap()).unwrap();
    std::fs::write(
        dirs.binary(&version),
        "#!/bin/sh\nif [ \"$5\" = check ]; then exit 0; fi\necho started\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n",
    )
    .unwrap();
    std::fs::set_permissions(
        dirs.binary(&version),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}

async fn choose(server: &Server, names: &[&str]) {
    let response = server.put_json(MODULE, json!({
        "version": "1.14.2", "config": "bound", "privilege": "operator", "collections": names
    })).await;
    assert_eq!(response.status(), 200);
}

async fn get(server: &Server, path: &str) -> Value {
    let response = server.authed(Method::GET, path).send().await.unwrap();
    assert_eq!(response.status(), 200);
    body(response).await
}

fn product(server: &Server) -> Value {
    serde_json::from_slice(
        &std::fs::read(server.root.join("data/sing-box/config/config.json")).unwrap(),
    )
    .unwrap()
}

async fn action(server: &Server, action: &str) -> reqwest::Response {
    server.put_json(STATUS, json!({"action": action})).await
}

struct CoreGuard(Option<rustix::process::Pid>);

impl Drop for CoreGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        }
    }
}

#[tokio::test]
async fn collection_conversion_skips_remain_visible_without_blocking_usable_members() {
    let server = Server::start().await;
    install(&server);
    assert_eq!(server.put_json("/api/providers/source", json!({
        "type": "inline",
        "payload": "trojan://fixture-password@example.com:443#working\ntrojan://private-password@example.com:444?type=grpc&mode=multi#private-node\n"
    })).await.status(), 201);
    assert_eq!(
        server
            .put_json("/api/collections/first", json!({"providers": ["source"]}))
            .await
            .status(),
        201
    );
    choose(&server, &["first"]).await;
    let authored = json!({"outbounds": [{"type": "selector", "tag": "group", "x-suba-collections": ["first"]}]});
    assert_eq!(
        server.put_json(CONFIG, authored.clone()).await.status(),
        200
    );
    let references = get(&server, REFERENCES).await;
    assert_eq!(
        references["skipped"],
        json!([{
            "path": "nodes[1].transport.grpc.multi_mode",
            "reason": "multi mode cannot be represented by sing-box"
        }])
    );
    let started = action(&server, "start").await;
    assert_eq!(started.status(), 200);
    let pid = body(started).await["pid"].as_i64().unwrap() as i32;
    let mut guard = CoreGuard(rustix::process::Pid::from_raw(pid));
    let assembled = product(&server);
    assert_eq!(assembled["outbounds"][0]["outbounds"], json!(["working"]));
    assert_eq!(assembled["outbounds"].as_array().unwrap().len(), 2);
    assert!(assembled.get("skipped").is_none());
    assert_eq!(get(&server, CONFIG).await, authored);
    assert_eq!(action(&server, "stop").await.status(), 200);
    guard.0 = None;
}

#[tokio::test]
async fn collection_bindings_http_writes_preserve_drafts_and_static_failures() {
    let server = Server::start().await;
    install(&server);
    choose(&server, &["private-missing"]).await;
    let group = json!({"type": "selector", "tag": "group", "outbounds": [], "x-suba-collections": ["private-missing"]});
    let authored = json!({"outbounds": [group.clone()]});
    let saved = server.put_json(CONFIG, authored.clone()).await;
    assert_eq!(saved.status(), 200);
    let etag = saved.headers()[http::header::ETAG].clone();
    assert_eq!(
        body(saved).await["warnings"],
        json!(["outbounds.x-suba-collections: a selected collection is unavailable"])
    );
    assert_eq!(get(&server, CONFIG).await, authored);
    assert_eq!(get(&server, ENTRY).await, group);
    let unavailable = server.authed(Method::GET, REFERENCES).send().await.unwrap();
    assert_eq!(unavailable.status(), 422);
    assert_eq!(
        body(unavailable).await["message"],
        "outbounds.x-suba-collections: a selected collection is unavailable"
    );

    let saved = server.put_json(SECTION, json!([group])).await;
    assert_eq!(saved.status(), 200);
    assert_eq!(saved.headers()[http::header::ETAG], etag);
    let mut changed = group.clone();
    changed["type"] = json!("urltest");
    let saved = server.put_json(ENTRY, changed.clone()).await;
    assert_eq!(saved.status(), 200);
    assert_ne!(saved.headers()[http::header::ETAG], etag);
    let stale = server
        .authed(Method::PUT, CONFIG)
        .header(http::header::IF_MATCH, etag)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(authored.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), 412);
    assert_eq!(get(&server, CONFIG).await, json!({"outbounds": [changed]}));

    for (path, value) in [
        (CONFIG, json!({"x-suba-collections": ["private-missing"]})),
        (
            SECTION,
            json!([{"type": "direct", "x-suba-collections": []}]),
        ),
        (
            ENTRY,
            json!({"type": "selector", "tag": "group", "x-suba-collections": "private-missing"}),
        ),
        (
            ENTRY,
            json!({"type": "selector", "tag": "group", "x-suba-collections": [false]}),
        ),
        (
            ENTRY,
            json!({"type": "selector", "tag": "group", "nested": {"x-suba-collections": []}}),
        ),
    ] {
        let refused = server.put_json(path, value).await;
        assert_eq!(refused.status(), 422);
        let error = body(refused).await.to_string();
        assert!(error.contains("x-suba-collections"));
        assert!(!error.contains("private-missing"));
        assert_eq!(get(&server, ENTRY).await, changed);
    }
    for command in ["start", "restart"] {
        let refused = action(&server, command).await;
        assert_eq!(refused.status(), 422);
        assert!(!body(refused).await.to_string().contains("private-missing"));
    }
    assert!(!server
        .root
        .join("data/sing-box/config/config.json")
        .exists());
    let copied = server
        .authed(Method::POST, "/api/cores/sing-box/configs")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(json!({"name": "copy", "copy": "bound"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(copied.status(), 201);
    assert_eq!(
        get(&server, "/api/cores/sing-box/configs/copy").await,
        json!({"outbounds": [changed]})
    );
    assert_eq!(
        server
            .authed(Method::DELETE, "/api/cores/sing-box/configs/copy")
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        server
            .authed(Method::DELETE, ENTRY)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(get(&server, SECTION).await, json!([]));
    assert_eq!(
        server
            .authed(Method::DELETE, SECTION)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(get(&server, CONFIG).await, json!({}));
}

#[tokio::test]
async fn collection_bindings_http_refresh_changes_only_the_next_expansion() {
    let revision = Arc::new(AtomicUsize::new(0));
    let fetched = Arc::new(AtomicUsize::new(0));
    let current = Arc::clone(&revision);
    let count = Arc::clone(&fetched);
    let upstream = axum::Router::new().route(
        "/",
        axum::routing::get(move || {
            count.fetch_add(1, Ordering::SeqCst);
            let revision = current.load(Ordering::SeqCst);
            async move {
                if revision == 0 {
                    "trojan://example-password@old.example.com:443#old\n"
                } else {
                    "trojan://example-password@new.example.com:443#new\n"
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let server = Server::start().await;
    install(&server);
    assert_eq!(
        server
            .put_json(
                "/api/providers/remote",
                json!({"type": "remote", "url": format!("http://{address}/"), "interval": 0})
            )
            .await
            .status(),
        201
    );
    for name in ["first", "second"] {
        assert_eq!(
            server
                .put_json(
                    &format!("/api/collections/{name}"),
                    json!({"providers": ["remote"]})
                )
                .await
                .status(),
            201
        );
    }
    choose(&server, &["first", "second"]).await;
    let group = json!({"type": "urltest", "tag": "group", "outbounds": ["manual"], "x-suba-collections": ["second", "first"]});
    let authored = json!({"outbounds": [{"type": "direct", "tag": "manual"}, group.clone()]});
    let saved = server.put_json(CONFIG, authored.clone()).await;
    assert_eq!(saved.status(), 200);
    assert_eq!(body(saved).await["warnings"], json!([]));
    let catalog = get(&server, REFERENCES).await;
    assert_eq!(
        catalog["tags"][0]["collections"],
        json!(["first", "second"])
    );
    assert_eq!(catalog["tags"][0]["tag"], "old");
    assert_eq!(catalog["tags"][2]["value"], group);
    let started = action(&server, "start").await;
    assert_eq!(started.status(), 200);
    let pid = body(started).await["pid"].clone();
    let mut core = CoreGuard(rustix::process::Pid::from_raw(pid.as_i64().unwrap() as i32));
    let initial = product(&server);
    assert_eq!(
        initial["outbounds"][1]["outbounds"],
        json!(["manual", "old"])
    );
    assert!(initial["outbounds"][1].get("x-suba-collections").is_none());
    assert_eq!(fetched.load(Ordering::SeqCst), 1);
    revision.store(1, Ordering::SeqCst);
    let refreshed = server
        .authed(Method::POST, "/api/providers/remote/refresh")
        .send()
        .await
        .unwrap();
    assert_eq!(refreshed.status(), 200);
    assert_eq!(fetched.load(Ordering::SeqCst), 2);
    assert_eq!(get(&server, STATUS).await["pid"], pid);
    assert_eq!(product(&server), initial);
    let catalog = get(&server, REFERENCES).await;
    assert_eq!(catalog["tags"][0]["tag"], "new");
    assert_eq!(
        catalog["tags"][0]["collections"],
        json!(["first", "second"])
    );
    assert_eq!(catalog["tags"][2]["value"], group);
    let restarted = action(&server, "restart").await;
    assert_eq!(restarted.status(), 200);
    let pid = body(restarted).await["pid"].clone();
    core.0 = rustix::process::Pid::from_raw(pid.as_i64().unwrap() as i32);
    let current = product(&server);
    assert_eq!(current["outbounds"].as_array().unwrap().len(), 3);
    assert_eq!(current["outbounds"][2], catalog["tags"][0]["value"]);
    assert_eq!(
        current["outbounds"][1]["outbounds"],
        json!(["manual", "new"])
    );
    assert_eq!(get(&server, CONFIG).await, authored);
    assert_eq!(
        fetched.load(Ordering::SeqCst),
        2,
        "neither preview nor start refreshes providers"
    );

    choose(&server, &[]).await;
    assert_eq!(get(&server, STATUS).await["pid"], pid);
    let refused = action(&server, "restart").await;
    assert_eq!(refused.status(), 422);
    assert_eq!(get(&server, STATUS).await["pid"], pid);
    assert_eq!(product(&server), current);
    choose(&server, &["first", "second"]).await;
    assert_eq!(
        server
            .authed(Method::DELETE, "/api/collections/first")
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    let refused = action(&server, "restart").await;
    assert_eq!(refused.status(), 422);
    assert_eq!(get(&server, STATUS).await["pid"], pid);
    assert_eq!(product(&server), current);
    assert_eq!(action(&server, "stop").await.status(), 200);
    core.0 = None;
    upstream.abort();
}
