use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::response::IntoResponse;
use http::StatusCode;
use reqwest::Method;
use serde_json::{json, Value};

use super::{body, Server};

const FIRST: &str = "trojan://example-password@first.example.com:443#First\n\
                     trojan://example-password@second.example.com:443#Second\n";
const NEXT: &str = "trojan://example-password@second.example.com:443#Second\n\
                    trojan://example-password@third.example.com:443#Third\n";

async fn nodes(server: &Server) -> Value {
    let response = server
        .authed(Method::GET, "/api/providers/remote/nodes")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    body(response).await
}

fn names(nodes: &Value) -> Vec<&str> {
    nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| node["name"].as_str().unwrap())
        .collect()
}

fn age_snapshot(server: &Server) {
    let path = server.root.join("data/providers/remote.json");
    let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["updated_at"] = json!(1);
    value["fetched_at"] = json!(1);
    value["checked_at"] = json!(1);
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

#[tokio::test]
async fn provider_snapshots_expose_only_latest_nodes_and_successful_update_time() {
    let mode = Arc::new(AtomicUsize::new(0));
    let selected = Arc::clone(&mode);
    let upstream = axum::Router::new().route(
        "/",
        axum::routing::get(move || {
            let mode = selected.load(Ordering::SeqCst);
            async move {
                match mode {
                    1 => StatusCode::NOT_MODIFIED.into_response(),
                    2 => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                    _ => (
                        [(http::header::ETAG, "\"fixture\"")],
                        if mode == 3 { NEXT } else { FIRST },
                    )
                        .into_response(),
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let running = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let server = Server::start().await;
    let created = server
        .put_json(
            "/api/providers/remote",
            json!({
                "type": "remote", "url": format!("http://{address}/"), "interval": 0
            }),
        )
        .await;
    assert_eq!(created.status(), 201);

    let initial = nodes(&server).await;
    assert_eq!(names(&initial), ["First", "Second"]);
    assert!(initial["updated_at"].as_i64().unwrap() > 0);
    assert!(initial.get("orphans").is_none());
    for node in initial["nodes"].as_array().unwrap() {
        assert!(node.get("first_seen").is_none());
        assert!(node.get("orphan").is_none());
        assert!(node["sources"][0].get("first_seen").is_none());
        assert!(node["sources"][0].get("serving").is_none());
    }
    let listed = body(
        server
            .authed(Method::GET, "/api/providers")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(listed["remote"]["updated_at"], initial["updated_at"]);
    let definition = body(
        server
            .authed(Method::GET, "/api/providers/remote")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert!(definition.get("updated_at").is_none());

    for (response_mode, status) in [(1, "not-modified"), (0, "unchanged")] {
        age_snapshot(&server);
        mode.store(response_mode, Ordering::SeqCst);
        let refreshed = server
            .authed(Method::POST, "/api/providers/remote/refresh")
            .send()
            .await
            .unwrap();
        assert_eq!(refreshed.status(), 200);
        assert_eq!(body(refreshed).await["status"], status);
        let current = nodes(&server).await;
        assert!(current["updated_at"].as_i64().unwrap() > 1);
        assert_eq!(names(&current), ["First", "Second"]);
        let persisted: Value = serde_json::from_slice(
            &std::fs::read(server.root.join("data/providers/remote.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted["fetched_at"], 1);
    }

    age_snapshot(&server);
    mode.store(2, Ordering::SeqCst);
    let failed = server
        .authed(Method::POST, "/api/providers/remote/refresh")
        .send()
        .await
        .unwrap();
    assert!(!failed.status().is_success());
    let current = nodes(&server).await;
    assert_eq!(current["updated_at"], 1);
    assert_eq!(names(&current), ["First", "Second"]);

    mode.store(3, Ordering::SeqCst);
    let refreshed = server
        .authed(Method::POST, "/api/providers/remote/refresh")
        .send()
        .await
        .unwrap();
    assert_eq!(refreshed.status(), 200);
    let current = nodes(&server).await;
    assert_eq!(names(&current), ["Second", "Third"]);
    assert!(current["updated_at"].as_i64().unwrap() > 1);
    let persisted: Value = serde_json::from_slice(
        &std::fs::read(server.root.join("data/providers/remote.json")).unwrap(),
    )
    .unwrap();
    assert!(persisted.get("sighting").is_none());
    running.abort();
}
