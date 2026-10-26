use reqwest::Method;
use serde_json::{json, Value};

use super::{body, Server};
use crate::config::AppConfig;

const USERS: &str = "/api/cores/sing-box/users";

async fn server(public_host: Option<&str>) -> Server {
    let server = Server::start_with(Some(AppConfig {
        public_host: public_host.map(str::to_owned),
        ..AppConfig::default()
    }))
    .await;

    let directory = server.root.join("config/sing-box");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("server.json"),
        serde_json::to_vec(&json!({"inbounds": [
            {"type": "trojan", "tag": "trojan-in", "listen_port": 8443,
             "tls": {"enabled": true},
             "users": [{"name": "guest", "password": "example-hand-written"}]},
            {"type": "mixed", "tag": "mixed-in", "listen_port": 2080}
        ]}))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        server
            .put_json(
                "/api/cores/sing-box",
                json!({"version": null, "config": "server", "privilege": "operator", "collections": []}),
            )
            .await
            .status(),
        200
    );
    assert_eq!(
        server
            .put_json(
                "/api/cores/sing-box/pools/standard",
                json!({"entries": [
                    {"config": "server", "inbound": "trojan-in"},
                    {"config": "server", "inbound": "mixed-in"},
                    {"config": "server", "inbound": "gone"}
                ]}),
            )
            .await
            .status(),
        204
    );
    assert_eq!(
        server
            .put_json(
                &format!("{USERS}/alice"),
                json!({"pools": ["standard", "missing"]})
            )
            .await
            .status(),
        204
    );

    server
}

async fn get(server: &Server, path: &str) -> reqwest::Response {
    server.authed(Method::GET, path).send().await.unwrap()
}

async fn alice(server: &Server) -> Value {
    body(get(server, USERS).await).await[0].clone()
}

fn secret(server: &Server) -> String {
    let file = std::fs::read_dir(server.root.join("config"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.file_stem().is_some_and(|stem| stem == "users"))
        .unwrap();
    let text = std::fs::read_to_string(file).unwrap();
    let at = text.find("secret").unwrap();

    text[at..]
        .chars()
        .skip_while(|c| !c.is_ascii_hexdigit())
        .take(64)
        .collect()
}

#[tokio::test]
async fn a_pool_user_gets_a_node_per_inbound_and_a_subscription_of_their_own() {
    let server = server(Some("proxy.example.com")).await;
    let minted = server
        .authed(Method::PUT, &format!("{USERS}/alice/tokens/phone"))
        .send()
        .await
        .unwrap();
    assert_eq!(minted.status(), 201);
    let token = body(minted).await["token"].as_str().unwrap().to_string();

    let listed = alice(&server).await;
    assert_eq!(listed["name"], "alice");
    assert_eq!(listed["missing_pools"], json!(["missing"]));
    assert_eq!(listed["links"][0]["path"], json!(format!("/s/{token}")));
    let grants = listed["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 3);
    let link = grants[0]["link"].as_str().unwrap().to_string();
    assert!(link.starts_with("trojan://"), "{link}");
    assert!(link.contains("@proxy.example.com:8443"), "{link}");
    assert!(link.ends_with("#trojan-in"), "{link}");
    assert_eq!(grants[0]["state"], "stopped");
    assert_eq!(grants[0]["outbound"].is_object(), cfg!(feature = "singbox"));
    assert!(grants[1]["reason"]
        .as_str()
        .unwrap()
        .starts_with("inbound: "));
    assert!(grants[1].get("state").is_none());
    assert_eq!(grants[2]["reason"], "inbound: no inbound has this tag");

    let delivered = server
        .get(&format!("/s/{token}?format=links"))
        .send()
        .await
        .unwrap();
    assert_eq!(delivered.status(), 200);
    assert_eq!(delivered.text().await.unwrap().trim(), link);

    let editor = body(get(&server, "/api/cores/sing-box/configs/server/exports").await).await;
    assert_eq!(editor["public_host"], "proxy.example.com");
    assert_eq!(editor["inbounds"][0]["managed"][0]["user"], "alice");
    assert_eq!(editor["inbounds"][0]["managed"][0]["link"], json!(link));
    assert!(editor["inbounds"][0]["users"][0]["link"]
        .as_str()
        .unwrap()
        .ends_with("#trojan-in-guest"));
    assert!(editor["inbounds"][1]["refused"].is_string());

    let secret = secret(&server);
    for answer in [
        get(&server, USERS).await.text().await.unwrap(),
        get(&server, "/api/cores/sing-box/configs/server/exports")
            .await
            .text()
            .await
            .unwrap(),
    ] {
        assert!(
            !answer.contains(&secret),
            "the secret is never answered with"
        );
    }

    let renewed = server
        .authed(Method::DELETE, &format!("{USERS}/alice/credentials"))
        .send()
        .await
        .unwrap();
    assert_eq!(renewed.status(), 204);
    let after = alice(&server).await["grants"][0]["link"].clone();
    assert_ne!(after, json!(link), "a new secret is a new credential");
    assert_eq!(
        server
            .get(&format!("/s/{token}"))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "the link that hands it out stays"
    );
}

#[tokio::test]
async fn without_a_public_host_a_node_says_why_and_the_subscription_leaves_it_out() {
    let server = server(None).await;

    let grant = &alice(&server).await["grants"][0];
    assert_eq!(grant["reason"], "public-host: not set in config.toml");
    assert!(grant.get("link").is_none());

    let preview = get(&server, &format!("{USERS}/alice/content?format=links")).await;
    assert_eq!(preview.status(), 200);
    assert_eq!(preview.headers()["x-suba-nodes"], "0");
    assert_eq!(preview.headers()["x-suba-skipped"], "1");
}

#[tokio::test]
async fn pools_say_what_each_entry_gives_and_who_is_in_them() {
    let server = server(Some("proxy.example.com")).await;

    let pools = body(get(&server, "/api/cores/sing-box/pools").await).await;

    assert_eq!(pools[0]["name"], "standard");
    assert_eq!(pools[0]["members"], json!(["alice"]));
    let entries = pools[0]["entries"].as_array().unwrap();
    assert!(entries[0].get("reason").is_none());
    assert!(
        entries[1]["reason"].is_string(),
        "a mixed inbound cannot be granted"
    );
    assert_eq!(entries[2]["reason"], "no inbound has this tag");
}

#[tokio::test]
async fn names_that_cannot_be_told_apart_are_refused_and_unknown_users_are_not_found() {
    let server = server(Some("proxy.example.com")).await;

    for name in ["a%20b", "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q"] {
        assert_eq!(
            server
                .put_json(&format!("{USERS}/{name}"), json!({}))
                .await
                .status(),
            422,
            "{name}"
        );
    }
    assert_eq!(
        server
            .authed(Method::PUT, &format!("{USERS}/nobody/tokens/phone"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        server
            .put_json(
                "/api/cores/sing-box/pools/broken",
                json!({"entries": [{"config": "../etc", "inbound": "x"}]}),
            )
            .await
            .status(),
        422
    );
}
