use std::{collections::BTreeMap, path::Path};

use reqwest::Method;
use serde_json::{json, Value};

use super::{body, Server};

const REFERENCES: &str = "/api/cores/sing-box/configs/edited/references";

fn files(root: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, found: &mut BTreeMap<std::path::PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, found);
            } else {
                found.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(path).unwrap(),
                );
            }
        }
    }

    let mut found = BTreeMap::new();
    visit(root, root, &mut found);
    found
}

fn write_config(server: &Server, name: &str, document: Value) {
    let directory = server.root.join("config/sing-box");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join(format!("{name}.json")),
        serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();
}

async fn choose(server: &Server, collections: &[&str]) {
    assert_eq!(
        server
            .put_json(
                "/api/cores/sing-box",
                json!({
                    "version": null,
                    "config": "active",
                    "privilege": "operator",
                    "collections": collections
                }),
            )
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn reference_catalog_reads_the_named_config_without_writing() {
    let server = Server::start().await;
    write_config(
        &server,
        "active",
        json!({"outbounds": [{"type": "direct", "tag": "active-only"}]}),
    );
    let outbound = json!({"type": "selector", "tag": "edited-only", "outbounds": ["pending"]});
    write_config(&server, "edited", json!({"outbounds": [outbound.clone()]}));
    choose(&server, &[]).await;
    let before = files(&server.root);

    for _ in 0..2 {
        let response = server.authed(Method::GET, REFERENCES).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            body(response).await,
            json!({
                "tags": [{
                    "tag": "edited-only",
                    "space": "outbound",
                    "kind": "selector",
                    "path": "outbounds[0].tag",
                    "source": "config",
                    "value": outbound
                }],
                "unchecked": suba_singbox::assemble::UNCHECKED
            })
        );
    }

    let absent = server
        .authed(
            Method::GET,
            "/api/cores/sing-box/configs/unwritten/references",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(absent.status(), 200);
    assert_eq!(body(absent).await["tags"], json!([]));
    assert_eq!(files(&server.root), before);
}

#[tokio::test]
async fn reference_catalog_is_authenticated_and_read_only() {
    let server = Server::start().await;
    let anonymous = server.get(REFERENCES).send().await.unwrap();
    assert_eq!(anonymous.status(), 401);

    let response = server.authed(Method::GET, REFERENCES).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(body(response).await["tags"], json!([]));

    for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
        assert_eq!(
            server
                .authed(method, REFERENCES)
                .send()
                .await
                .unwrap()
                .status(),
            405
        );
    }
    assert_eq!(
        server
            .authed(Method::GET, "/api/cores/sing-box/references")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        server
            .authed(
                Method::GET,
                "/api/cores/sing-box/configs/..%2Fescape/references"
            )
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
}

#[cfg(feature = "singbox")]
#[tokio::test]
async fn reference_catalog_uses_selected_collections_without_refreshing() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let fetched = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&fetched);
    let provider = axum::Router::new().route(
        "/",
        axum::routing::get(move || {
            let count = Arc::clone(&count);
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                "trojan://example-password@alpha.example.com:443#shared\n"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move { axum::serve(listener, provider).await.unwrap() });
    let server = Server::start().await;
    assert_eq!(
        server
            .put_json(
                "/api/providers/remote",
                json!({
                    "type": "remote", "url": format!("http://{address}/"), "interval": 0
                })
            )
            .await
            .status(),
        201
    );
    assert_eq!(fetched.load(Ordering::SeqCst), 1);
    assert_eq!(
        server.put_json("/api/providers/other", json!({
            "type": "inline", "payload": "trojan://example-password@beta.example.com:443#unselected\n"
        })).await.status(),
        201
    );
    for (name, providers) in [
        ("first", vec!["remote"]),
        ("repeated", vec!["remote"]),
        ("unused", vec!["other"]),
    ] {
        assert_eq!(
            server
                .put_json(
                    &format!("/api/collections/{name}"),
                    json!({"providers": providers})
                )
                .await
                .status(),
            201
        );
    }
    choose(&server, &["first", "repeated"]).await;
    let authored = json!({"type": "direct", "tag": "shared"});
    write_config(&server, "edited", json!({"outbounds": [authored.clone()]}));
    write_config(
        &server,
        "active",
        json!({"outbounds": [{"type": "direct", "tag": "active-only"}]}),
    );
    let before = files(&server.root);

    let mut previous = None;
    for _ in 0..2 {
        let response = server.authed(Method::GET, REFERENCES).send().await.unwrap();
        assert_eq!(response.status(), 200);
        let catalog = body(response).await;
        let entries = catalog["tags"].as_array().unwrap();
        assert_eq!(
            entries.len(),
            2,
            "node identities deduplicate, tag collisions do not"
        );
        let generated = entries
            .iter()
            .find(|entry| entry["source"] == "collection")
            .unwrap();
        let config = entries
            .iter()
            .find(|entry| entry["source"] == "config")
            .unwrap();
        assert_eq!(generated["tag"], "shared");
        assert_eq!(generated["space"], "outbound");
        assert_eq!(generated["kind"], "trojan");
        assert_eq!(generated["path"], "outbounds[0].tag");
        assert_eq!(generated["value"]["tag"], "shared");
        assert_eq!(generated["value"]["type"], "trojan");
        assert_eq!(generated["value"]["server"], "alpha.example.com");
        assert_eq!(generated["value"]["server_port"], 443);
        assert_eq!(generated["value"]["password"], "example-password");
        assert_eq!(config["value"], authored);
        assert_eq!(config["path"], "outbounds[0].tag");
        if let Some(previous) = previous {
            assert_eq!(catalog, previous);
        }
        previous = Some(catalog);
    }
    assert_eq!(
        fetched.load(Ordering::SeqCst),
        1,
        "preview never refreshes providers"
    );
    assert_eq!(files(&server.root), before);
    upstream.abort();
}

#[cfg(not(feature = "singbox"))]
#[tokio::test]
async fn reference_catalog_without_rendering_keeps_only_authored_definitions() {
    let server = Server::start().await;
    choose(&server, &["unavailable"]).await;
    let outbound = json!({"type": "direct", "tag": "authored"});
    write_config(&server, "edited", json!({"outbounds": [outbound.clone()]}));
    let response = server.authed(Method::GET, REFERENCES).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        body(response).await["tags"],
        json!([{
            "tag": "authored", "space": "outbound", "kind": "direct",
            "path": "outbounds[0].tag", "source": "config", "value": outbound
        }])
    );
}
