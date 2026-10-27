use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::*;
use crate::state::access::{Access, Entry, User};

fn written() -> Value {
    json!({"inbounds": [
        {"type": "trojan", "tag": "trojan-in", "listen_port": 8443,
         "users": [{"name": "guest", "password": "hand-written"}]},
        {"type": "socks", "tag": "socks-in", "listen_port": 1080}
    ]})
}

fn contributions(user: &str) -> Contributions {
    Contributions {
        access: Access {
            users: BTreeMap::from([(
                user.to_string(),
                User {
                    inbounds: vec![Entry::local(NAME, "trojan-in")],
                    secret: "44".repeat(32),
                    ..User::default()
                },
            )]),
            ..Access::default()
        },
        ..Contributions::default()
    }
}

fn product(store: &SingboxStore) -> Value {
    serde_json::from_slice(&std::fs::read(store.dirs.config().join(CONFIG)).unwrap()).unwrap()
}

#[test]
fn a_start_runs_the_managed_users_without_writing_them_into_the_document() {
    let (_scratch, store) = store();
    store
        .write_document(NAME, written(), None, &Contributions::default())
        .unwrap();

    store.start(&contributions("alice")).unwrap();
    let _ = store.stop(Duration::from_secs(2));

    let users = &product(&store)["inbounds"][0]["users"];
    assert_eq!(users[0]["name"], json!("guest"));
    assert_eq!(users[1]["name"], json!("alice"));
    assert_eq!(users[1]["password"].as_str().map(str::len), Some(22));
    assert_eq!(store.config_document(NAME).unwrap().value, written());
}

#[test]
fn a_namesake_stops_a_start_and_is_a_warning_when_saved() {
    let (_scratch, store) = store();
    let mut clashing = written();
    clashing["inbounds"][1]["users"] = json!([{"username": "alice", "password": "x"}]);

    let saved = store
        .write_document(NAME, clashing, None, &contributions("alice"))
        .unwrap();
    assert_eq!(
        saved.warnings,
        ["inbounds[1].users[0].name: reserved for a managed user"]
    );

    let refused = store.start(&contributions("alice"));
    assert!(matches!(
        refused,
        Err(Error::Document(ref fault)) if fault == &saved.warnings[0]
    ));
    assert!(!store.assembled(), "nothing was written for the core");

    store.start(&contributions("bob")).unwrap();
    let _ = store.stop(Duration::from_secs(2));
}
