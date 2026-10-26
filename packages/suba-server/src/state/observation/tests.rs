use super::*;
use serde_json::json;

fn document() -> Value {
    json!({"services": [{"type": "api", "tag": "control", "listen": "127.0.0.1",
        "listen_port": 19090, "secret": "example-secret"}]})
}

fn run() -> Run {
    Run::new(42, "server".to_string(), &document())
}

#[test]
fn observation_only_uses_one_explicit_authenticated_loopback_api() {
    let api = endpoint(&document()).unwrap_or_else(|_| panic!("valid endpoint"));
    assert_eq!(api.address, "127.0.0.1:19090".parse().unwrap());
    assert!(api.secret.is_sensitive());
    assert_eq!(api.secret, "Bearer example-secret");
    let mut ipv6 = document();
    ipv6["services"][0]["listen"] = json!("::1");
    assert_eq!(
        endpoint(&ipv6)
            .unwrap_or_else(|_| panic!("loopback IPv6"))
            .address,
        "[::1]:19090".parse().unwrap()
    );
    assert_eq!(endpoint(&json!({})).err().unwrap().state, State::Disabled);
    for address in [
        "0.0.0.0",
        "::",
        "192.0.2.1",
        "localhost",
        "proxy.example.com",
    ] {
        let mut value = document();
        value["services"][0]["listen"] = json!(address);
        assert_eq!(endpoint(&value).err().unwrap().state, State::Unsupported);
    }
    let mut multiple = document();
    multiple["services"]
        .as_array_mut()
        .unwrap()
        .push(document()["services"][0].clone());
    assert_eq!(endpoint(&multiple).err().unwrap().state, State::Unsupported);
    let mut tls = document();
    tls["services"][0]["tls"] = json!({"enabled": true});
    assert_eq!(endpoint(&tls).err().unwrap().state, State::Unsupported);
    for secret in ["", "example\nsecret", "\u{80}"] {
        let mut value = document();
        value["services"][0]["secret"] = json!(secret);
        let issue = endpoint(&value).err().unwrap();
        assert_eq!(issue.state, State::InvalidConfig);
        assert_eq!(
            issue.reason,
            "services.api.secret: a nonempty ASCII secret is required"
        );
    }
    for port in [0, 65536] {
        let mut value = document();
        value["services"][0]["listen_port"] = json!(port);
        assert_eq!(endpoint(&value).err().unwrap().state, State::InvalidConfig);
    }
}

#[test]
fn a_stopped_or_different_run_never_returns_old_live_data() {
    let held = run();
    let observer = Observation::new();
    assert_eq!(
        observer.metrics(None, &Filter::default()).metadata.state,
        State::Stopped
    );
    assert!(observer.metrics(None, &Filter::default()).totals.is_none());
    assert_eq!(
        observer
            .metrics(Some(&held), &Filter::default())
            .metadata
            .state,
        State::Connecting
    );
    let encoded =
        serde_json::to_string(&observer.metrics(Some(&held), &Filter::default())).unwrap();
    assert!(!encoded.contains("example-secret"));
    assert!(!encoded.contains("19090"));
}

fn connection(id: &str, user: &str, total: i64, closed: bool) -> wire::Connection {
    wire::Connection {
        id: id.into(),
        user: user.into(),
        inbound: "vless-in".into(),
        uplink_total: total,
        downlink_total: total * 2,
        closed_at: if closed { 100 } else { 0 },
        ..Default::default()
    }
}

fn event(kind: i32, item: wire::Connection) -> wire::Event {
    wire::Event {
        kind,
        id: item.id.clone(),
        connection: Some(item),
        ..Default::default()
    }
}

fn batch(reset: bool, events: Vec<wire::Event>) -> wire::Events {
    wire::Events { reset, events }
}

#[test]
fn snapshots_are_baselines_and_closed_history_does_not_belong_to_the_window() {
    let run = run();
    let mut ledger = Ledger::new(Some(&run));
    let at = Instant::now();
    ledger
        .apply(
            batch(
                true,
                vec![
                    event(0, connection("live", "alice", 100, false)),
                    event(0, connection("old", "bob", 500, true)),
                ],
            ),
            at,
            1000,
        )
        .unwrap();
    ledger.tick(at + Duration::from_secs(1), 2000);
    let metrics = ledger.metrics(Some(&run), &Filter::default());
    assert_eq!(metrics.metadata.state, State::Live);
    assert_eq!(
        metrics.totals.unwrap(),
        Counters {
            connections: 1,
            ..Default::default()
        }
    );
    assert_eq!(metrics.groups.len(), 1);
    assert_eq!(metrics.groups[0].user.as_deref(), Some("alice"));
    let rows = ledger
        .connections(Some(&run), &Filter::default())
        .connections;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].uplink_total, 0);
}

#[test]
fn updates_are_deltas_and_a_duplicate_close_does_not_double_count_the_tail() {
    let run = run();
    let mut ledger = Ledger::new(Some(&run));
    let at = Instant::now();
    ledger
        .apply(
            batch(true, vec![event(0, connection("one", "alice", 100, false))]),
            at,
            1000,
        )
        .unwrap();
    ledger
        .apply(
            batch(
                false,
                vec![wire::Event {
                    kind: 1,
                    id: "one".into(),
                    uplink_delta: 30,
                    downlink_delta: 60,
                    ..Default::default()
                }],
            ),
            at,
            1000,
        )
        .unwrap();
    let closing = event(2, connection("one", "alice", 137, true));
    ledger
        .apply(batch(false, vec![closing.clone(), closing]), at, 1000)
        .unwrap();
    ledger.tick(at + Duration::from_secs(2), 3000);
    let counters = ledger
        .metrics(Some(&run), &Filter::default())
        .totals
        .unwrap();
    assert_eq!(counters.connections, 0);
    assert_eq!(counters.uplink_total, 37);
    assert_eq!(counters.downlink_total, 74);
    assert_eq!(counters.uplink, 18);
    assert_eq!(counters.downlink, 37);
    assert!(ledger
        .connections(Some(&run), &Filter::default())
        .connections
        .is_empty());
    ledger.tick(at + Duration::from_secs(3), 4000);
    assert_eq!(
        ledger
            .metrics(Some(&run), &Filter::default())
            .totals
            .unwrap()
            .uplink,
        0
    );
}

#[test]
fn short_flows_and_duplicate_new_events_preserve_user_attribution() {
    let run = run();
    let mut ledger = Ledger::new(Some(&run));
    let at = Instant::now();
    ledger.apply(batch(true, vec![]), at, 1000).unwrap();
    let first = event(0, connection("one", "alice", 5, false));
    ledger
        .apply(
            batch(
                false,
                vec![
                    first.clone(),
                    first,
                    event(2, connection("one", "alice", 37, true)),
                    event(0, connection("two", "bob", 12, false)),
                    event(0, connection("anonymous", "", 8, false)),
                ],
            ),
            at,
            1000,
        )
        .unwrap();
    ledger.tick(at + Duration::from_secs(1), 2000);
    let filter = Filter {
        user: Some("alice".into()),
        inbound: None,
    };
    assert_eq!(
        ledger
            .metrics(Some(&run), &filter)
            .totals
            .unwrap()
            .uplink_total,
        37
    );
    assert_eq!(
        ledger
            .metrics(Some(&run), &Filter::default())
            .totals
            .unwrap()
            .uplink_total,
        57
    );
    assert_eq!(
        ledger
            .connections(Some(&run), &Filter::default())
            .connections
            .iter()
            .filter(|row| row.user.is_none())
            .count(),
        1
    );
}

#[test]
fn reconnect_starts_a_new_window_and_a_new_run_never_inherits_the_old_one() {
    let run = run();
    let at = Instant::now();
    let mut ledger = Ledger::new(Some(&run));
    ledger.apply(batch(true, vec![]), at, 1000).unwrap();
    ledger
        .apply(
            batch(false, vec![event(0, connection("one", "alice", 40, false))]),
            at,
            1000,
        )
        .unwrap();
    ledger.tick(at + Duration::from_secs(1), 2000);
    ledger.fail(Issue::new(State::Disconnected, "observation: interrupted"));
    assert_eq!(
        ledger
            .metrics(Some(&run), &Filter::default())
            .metadata
            .state,
        State::Disconnected
    );
    ledger
        .apply(
            batch(true, vec![event(0, connection("one", "alice", 100, false))]),
            at + Duration::from_secs(2),
            3000,
        )
        .unwrap();
    let metrics = ledger.metrics(Some(&run), &Filter::default());
    assert!(metrics.metadata.gap);
    assert_eq!(metrics.metadata.window_started_at, Some(3000));
    assert_eq!(metrics.totals.unwrap().uplink_total, 0);
    let replacement = Run::new(43, "other".into(), &document());
    let metrics = ledger.metrics(Some(&replacement), &Filter::default());
    assert_eq!(metrics.metadata.state, State::Connecting);
    assert!(metrics.totals.is_none());
    assert!(metrics.groups.is_empty());
    assert!(ledger
        .connections(None, &Filter::default())
        .connections
        .is_empty());
    ledger.select(Some(&replacement));
    assert!(
        !ledger
            .metrics(Some(&replacement), &Filter::default())
            .metadata
            .gap
    );
}

#[test]
fn malformed_events_end_the_window_instead_of_looking_like_zero_traffic() {
    let run = run();
    let at = Instant::now();
    let mut ledger = Ledger::new(Some(&run));
    assert!(ledger.apply(batch(false, vec![]), at, 1000).is_err());
    ledger.apply(batch(true, vec![]), at, 1000).unwrap();
    assert!(ledger
        .apply(
            batch(
                false,
                vec![wire::Event {
                    kind: 1,
                    id: "unknown".into(),
                    ..Default::default()
                }]
            ),
            at,
            1000
        )
        .is_err());
    assert!(ledger
        .apply(
            batch(false, vec![event(0, connection("one", "alice", -1, false))]),
            at,
            1000
        )
        .is_err());
}

#[test]
fn query_filters_match_native_user_and_inbound_without_inventing_an_identity() {
    let filter = Filter {
        user: Some("alice".into()),
        inbound: Some("vless-in".into()),
    };
    assert!(filter.matches(Some("alice"), "vless-in"));
    assert!(!filter.matches(Some("bob"), "vless-in"));
    assert!(!filter.matches(Some("alice"), "trojan-in"));
    assert!(!filter.matches(None, "vless-in"));
    assert!(Filter::default().matches(None, "vless-in"));
}
