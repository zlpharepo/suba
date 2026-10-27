use reqwest::Method;
use serde_json::{json, Value};

use super::{body, Server};
use crate::config::AppConfig;

const USERS: &str = "/api/inbounds/users";
const ENDPOINTS: &str = "/api/inbounds/endpoints";

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
            {"type": "direct", "tag": "direct-in", "listen_port": 2080}
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
                &format!("{USERS}/alice"),
                json!({"inbounds": [
                    {"config": "server", "inbound": "trojan-in"},
                    {"config": "server", "inbound": "direct-in"},
                    {"config": "server", "inbound": "gone"}
                ]}),
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
async fn a_user_gets_a_node_per_inbound_and_a_subscription_of_their_own() {
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
    assert_eq!(listed["inbounds"][0]["inbound"], "trojan-in");
    assert_eq!(listed["missing_collections"], json!([]));
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

    let editor = body(get(&server, "/api/inbounds/configs/server/exports").await).await;
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
        get(&server, "/api/inbounds/configs/server/exports")
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
async fn an_address_override_is_what_a_client_dials() {
    let server = server(Some("proxy.example.com")).await;

    let set = server
        .put_json(
            &format!("{ENDPOINTS}/server/trojan-in"),
            json!({"address": "cdn.example.net", "port": 443}),
        )
        .await;
    assert_eq!(set.status(), 200);
    let answer = body(set).await;
    assert_eq!(answer["address"], "cdn.example.net");
    assert_eq!(answer["port"], 443);
    assert!(answer.get("reason").is_none());

    let grant = &alice(&server).await["grants"][0];
    assert!(
        grant["link"]
            .as_str()
            .unwrap()
            .contains("@cdn.example.net:443"),
        "{}",
        grant["link"]
    );

    // The inbound keeps listening where it did; only what a client dials
    // changed, and the operator's document is untouched.
    let editor = body(get(&server, "/api/inbounds/configs/server/exports").await).await;
    assert_eq!(editor["inbounds"][0]["index"], 0);

    // An omitted field keeps what is stored, an explicit null clears it.
    let kept = body(
        server
            .put_json(
                &format!("{ENDPOINTS}/server/trojan-in"),
                json!({"port": 8443}),
            )
            .await,
    )
    .await;
    assert_eq!(kept["address"], "cdn.example.net");
    assert_eq!(kept["port"], 8443);

    let cleared = body(
        server
            .put_json(
                &format!("{ENDPOINTS}/server/trojan-in"),
                json!({"address": null}),
            )
            .await,
    )
    .await;
    assert!(cleared.get("address").is_none());
    assert_eq!(cleared["port"], 8443);

    let removed = server
        .authed(Method::DELETE, &format!("{ENDPOINTS}/server/trojan-in"))
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 204);
    assert!(alice(&server).await["grants"][0]["link"]
        .as_str()
        .unwrap()
        .contains("@proxy.example.com:8443"));
}

#[tokio::test]
async fn endpoints_list_every_inbound_whether_or_not_one_is_stored() {
    let server = server(Some("proxy.example.com")).await;

    let listed = body(get(&server, ENDPOINTS).await).await;
    assert_eq!(listed["public_host"], "proxy.example.com");
    let entries = listed["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["config"], "server");
    assert_eq!(entries[0]["inbound"], "trojan-in");
    assert!(entries[0].get("address").is_none());
    assert!(entries[0].get("reason").is_none());
    assert!(
        entries[1]["reason"].is_string(),
        "an inbound users do not dial cannot be granted"
    );

    // An address belongs to one inbound: the other one keeps its own, so an
    // override cannot be read off whatever entry happens to be first.
    server
        .put_json(
            &format!("{ENDPOINTS}/server/trojan-in"),
            json!({"address": "cdn.example.net"}),
        )
        .await;
    server
        .put_json(
            &format!("{ENDPOINTS}/server/direct-in"),
            json!({"address": "other.example.net", "port": 1080}),
        )
        .await;

    let stored = body(get(&server, ENDPOINTS).await).await;
    let entries = stored["entries"].as_array().unwrap();
    assert_eq!(entries[0]["address"], "cdn.example.net");
    assert_eq!(entries[0]["port"], Value::Null);
    assert_eq!(entries[1]["address"], "other.example.net");
    assert_eq!(entries[1]["port"], 1080);

    // Only an inbound that exists can be addressed.
    for path in ["server/no-such-inbound", "no-such-config/trojan-in"] {
        assert_eq!(
            server
                .put_json(
                    &format!("{ENDPOINTS}/{path}"),
                    json!({"address": "cdn.example.net"}),
                )
                .await
                .status(),
            422,
            "{path}"
        );
    }
}

#[tokio::test]
async fn an_address_that_is_not_a_host_is_refused() {
    let server = server(Some("proxy.example.com")).await;

    for address in [
        "",
        "a b",
        "example.com/path",
        "2001:db8::1",
        "example.com:443",
    ] {
        assert_eq!(
            server
                .put_json(
                    &format!("{ENDPOINTS}/server/trojan-in"),
                    json!({"address": address}),
                )
                .await
                .status(),
            422,
            "{address}"
        );
    }
    for address in ["cdn.example.net", "10.0.0.1", "[2001:db8::1]"] {
        assert_eq!(
            server
                .put_json(
                    &format!("{ENDPOINTS}/server/trojan-in"),
                    json!({"address": address}),
                )
                .await
                .status(),
            200,
            "{address}"
        );
    }
    assert_eq!(
        server
            .put_json(
                &format!("{ENDPOINTS}/server/trojan-in"),
                json!({"port": 70000}),
            )
            .await
            .status(),
        422
    );
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
                &format!("{USERS}/alice"),
                json!({"inbounds": [{"config": "../etc", "inbound": "x"}]}),
            )
            .await
            .status(),
        422
    );
}
