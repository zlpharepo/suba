//! What becomes of a parameter.
//!
//! A link carries more than the model holds: fields this build does not model, fields it models but
//! cannot read, duplicates, flags. The policy is stated on `Reader` — a parameter is consumed when the
//! read makes sense of it — and these are the cases that hold it, one per way a parameter can be
//! strange. Every case is a parse → write → parse that must come back to the same node, because that
//! is the promise the crate makes: nothing a provider sends is dropped — with one exception, a
//! duplicate. A model holds one value and the first occurrence is the one it holds, so what a
//! duplicate carries is a value the link does not mean; copying it to the extras would let the next
//! read take it wherever the model's own value never reaches the link.

use suba_proto::{parse_link, write_link, Client, Node, Outbound};

fn round_trip(link: &str) -> (Node<Client>, String) {
    let node = parse_link(link).unwrap_or_else(|error| panic!("{link}\n  {error}"));
    let written = write_link(&node).unwrap_or_else(|error| panic!("{link}\n  {error}"));
    let again = parse_link(&written).unwrap_or_else(|error| panic!("{written}\n  {error}"));

    assert_eq!(
        again, node,
        "the round trip changed the node\n  in: {link}\n out: {written}"
    );

    let twice = write_link(&again).expect("a second write");
    assert_eq!(
        twice, written,
        "writing twice is not writing once\n  {link}"
    );

    (node, written)
}

const VLESS: &str = "vless://11111111-1111-1111-1111-111111111111@example.com:443";

#[test]
fn a_value_the_model_cannot_interpret_is_kept_in_the_extras() {
    // A WebSocket host with a space in it is not a host, so the model has nothing to hold. A parameter
    // this build cannot read is not a parameter it gets to throw away: it travels with the extras and
    // comes out again, in the escaped shape the writer gives every value.
    let (node, written) = round_trip(&format!(
        "{VLESS}?encryption=none&type=ws&path=%2Fws&host=a%20b#Probe"
    ));

    let ws = match &node.transport {
        suba_proto::Transport::Ws(ws) => ws,
        other => panic!("a WebSocket carriage: {other:?}"),
    };

    assert_eq!(ws.host, None);
    assert_eq!(node.extra.get("host"), Some("a b"));
    assert!(written.contains("host=a%20b"), "{written}");
}

#[test]
fn a_short_id_that_is_not_one_stays_in_the_link() {
    let (node, written) = round_trip(&format!(
        "{VLESS}?security=reality&sni=www.apple.com&pbk=Ezm0e82bCKdD9md8dOv_sy86-Co9Y1iJb5JUfaiFCk8&sid=not-hex&type=tcp#Probe"
    ));

    let reality = node
        .tls
        .as_ref()
        .and_then(|tls| tls.reality.as_ref())
        .expect("a Reality node: the public key is the one thing that makes it one");

    assert_eq!(reality.short_id, None);
    assert_eq!(node.extra.get("sid"), Some("not-hex"));
    assert!(written.contains("sid=not-hex"), "{written}");
}

#[test]
fn a_security_mode_this_build_does_not_know_is_left_where_it_was() {
    // The TLS that a trojan link always has is still there; the mode this build cannot read travels
    // with the extras and comes out again.
    let (node, written) =
        round_trip("trojan://hunter2@example.com:443?security=meow&sni=example.com#Probe");

    assert_eq!(node.extra.get("security"), Some("meow"));
    assert!(
        node.tls.is_some(),
        "trojan terminates TLS whatever the mode says"
    );
    assert!(written.contains("security=meow"), "{written}");
}

#[test]
fn a_number_with_a_unit_is_read_and_a_value_that_is_not_a_number_is_kept() {
    // hysteria2's own documentation writes `up=100 mbps`: the number is read and the unit is not the
    // model's business. `up=fast` is something this build cannot use, and it says so by leaving the
    // parameter where it was instead of inventing a zero.
    let (read, written) =
        round_trip("hysteria2://hunter2@example.com:443?up=100%20mbps&down=50#Probe");
    let (kept, other) = round_trip("hysteria2://hunter2@example.com:443?up=fast#Probe");

    assert_eq!(read.extra.get("up"), None, "the number was read");
    assert!(written.contains("up=100"), "{written}");

    assert_eq!(kept.extra.get("up"), Some("fast"));
    assert!(other.contains("up=fast"), "{other}");
}

#[test]
fn a_duplicate_of_a_parameter_the_model_read_is_dropped() {
    // A model holds one value, so the first occurrence is the one a client reads — and the second is
    // not a value the link means. Keeping it in the extras was this crate's own bug, found by the
    // fuzzer rather than by a provider: the extra travels on under a name the model knows, and the
    // next read takes it wherever the model's value does not reach the link.
    let (node, written) =
        round_trip("trojan://hunter2@example.com:443?security=tls&security=meow#Probe");

    assert_eq!(node.extra.get("security"), None, "{:?}", node.extra);
    assert!(!written.contains("meow"), "{written}");

    // The shape that made it visible: `type=tcp` is the default, so the writer does not put it in the
    // link, and the duplicate is then the only `type` the next read can see.
    let (node, written) = round_trip(&format!("{VLESS}?encryption=none&type=tcp&type=grpc#Probe"));
    assert_eq!(
        node.transport,
        suba_proto::Transport::Tcp,
        "the first occurrence is what the model holds"
    );
    assert!(!written.contains("grpc"), "{written}");
}

#[test]
fn a_duplicate_of_a_value_the_model_could_not_read_keeps_only_the_first() {
    // The model cannot interpret `xtls-rpycp`, so it holds no flow and the first occurrence travels in
    // the extras. The second occurrence is valid — and it must not be the one that goes out, or the
    // next read would take a flow out of a link that meant none.
    let (node, written) = round_trip(&format!(
        "{VLESS}?security=reality&flow=xtls-rpycp&flow=xtls-rprx-vision&sni=example.com#Probe"
    ));

    assert_eq!(
        node.extra.get("flow"),
        Some("xtls-rpycp"),
        "{:?}",
        node.extra
    );
    assert!(written.contains("flow=xtls-rpycp"), "{written}");
    assert!(!written.contains("xtls-rprx-vision"), "{written}");
}

#[test]
fn a_flag_and_an_empty_value_are_one_parameter() {
    // `?tfo` and `?tfo=` are one parameter with one empty value, and an empty value is written back
    // as the bare name. A flag this build does not model is an extra like any other, and it survives.
    let (bare, written) = round_trip(&format!("{VLESS}?encryption=none&type=tcp&tfo#Probe"));
    let (stated, other) = round_trip(&format!("{VLESS}?encryption=none&type=tcp&tfo=#Probe"));

    assert_eq!(bare.extra.get("tfo"), Some(""));
    assert_eq!(bare.extra, stated.extra);
    assert_eq!(written, other);
    assert!(written.contains("&tfo"), "{written}");
    assert!(!written.contains("tfo="), "{written}");
}

#[test]
fn escapes_that_do_not_decode_are_kept_as_written() {
    // A provider's typo, and a truncated UTF-8 sequence. Decoding hands back what it cannot read
    // rather than a replacement character, so the value survives the round trip — the text does not,
    // because the writer re-escapes what it writes.
    for (value, expected) in [
        ("%zz", "%zz"),
        ("%E4%BD", "%E4%BD"),
        ("100%", "100%"),
        // A well-formed escape is decoded, and what follows it is not: `%41%` is an `A` and a stray `%`.
        ("%41%", "A%"),
    ] {
        let (node, _) = round_trip(&format!(
            "{VLESS}?encryption=none&type=tcp&odd={value}#Probe"
        ));

        assert_eq!(node.extra.get("odd"), Some(expected), "{value}");
    }
}

#[test]
fn a_transport_the_model_does_not_know_is_a_transport() {
    // Not an extra: the model has somewhere to put a carriage it does not recognise, and the link it
    // writes says exactly what the provider said.
    let (node, written) = round_trip(&format!(
        "{VLESS}?encryption=none&type=meow&path=%2Fx#Probe"
    ));

    match &node.transport {
        suba_proto::Transport::Other(other) => assert_eq!(other.name.as_ref(), "meow"),
        other => panic!("an unknown carriage is kept by name: {other:?}"),
    }
    assert!(written.contains("type=meow"), "{written}");
}

#[test]
fn the_default_transport_is_read_and_not_written_back() {
    // `type=tcp` says what an absent parameter says. The read makes sense of it, so the parameter is
    // consumed and there is nothing left to write — and the node is the same either way, which is what
    // the round trip in the helper above asserts.
    let (node, written) = round_trip(&format!("{VLESS}?encryption=none&type=tcp#Probe"));

    assert_eq!(node.extra.get("type"), None);
    assert!(!written.contains("type="), "{written}");
}

#[test]
fn an_unmodelled_link_without_an_address_is_refused_by_name() {
    // The crate's promise about unknown schemes has a floor: a node has an address, and one that cannot
    // be read is refused rather than invented. The error names what is missing.
    let error = parse_link("snell://example.com#Probe").expect_err("no port, no node");

    assert_eq!(error.kind(), suba_proto::ErrorKind::MissingField);
    assert!(error.reason().contains("port"), "{error}");
}

#[test]
fn an_unmodelled_carriage_goes_back_out_under_its_own_name_in_a_json_dialect() {
    // The query dialects write an unmodelled carriage as `type=<name>`, and the JSON dialect has to do
    // the same with `net`. It wrote `tcp` instead, which the fuzzer found: a node whose identity
    // depends on whether it has been written out yet is not a node. The carriage is built from JSON
    // rather than inlined as base64, so the case is readable.
    use base64::Engine as _;

    let json = r#"{"v":"2","ps":"Tokyo","add":"example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"us","path":"/ws"}"#;
    let link = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(json)
    );

    let (node, written) = round_trip(&link);
    let after = parse_link(&written).unwrap();

    assert_eq!(node.transport.name(), "us", "{written}");
    assert_eq!(node.transport, after.transport, "{written}");

    // The link is a base64 blob, so the carriage is checked where it is written: in the JSON.
    let blob = written.trim_start_matches("vmess://");
    let json = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(blob)
            .expect("the JSON blob"),
    )
    .expect("JSON is text");

    assert!(json.contains(r#""net":"us""#), "{json}");
}

#[test]
fn a_host_that_ends_in_dots_does_not_change_every_time_it_is_written() {
    // A trailing dot is the root label, so it goes — but *every* trailing dot, and before the IP literal
    // is recognised. Stripping one per parse meant a value ending in two dots lost one on every round
    // trip, and `192.0.2.1.` — stripped after the IP parse had already failed — became a domain that
    // says `192.0.2.1`, which the next read took as an IP literal: the host changed just by being
    // written out. Both shapes are fuzzer findings.
    let (node, written) = round_trip("ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.1.:1080#Plain");
    assert_eq!(node.endpoint.to_string(), "192.0.2.1:1080", "{written}");
    assert!(!written.contains("192.0.2.1."), "{written}");

    let (node, written) = round_trip(
        "vless://11111111-2222-3333-4444-555555555555@example.com:8443?encryption=none&type=grpc&authority=e%3Dtls...&mode=multi#Dots",
    );
    assert_eq!(node.transport.name(), "grpc", "{written}");
    assert!(!written.contains("..."), "{written}");
}

#[test]
fn a_plugin_with_no_name_is_not_a_plugin() {
    // `plugin=;;;;;` parsed into a plugin whose name is empty, and the writer had no way to write it back
    // as anything the reader would keep: a bare `plugin`, dropped on the way in. A plugin with no name
    // has nothing to dial with. Fuzzer finding.
    let (node, written) = round_trip("ss://YWVzLTI1Ni1nY206UEFQ@192.0.2.1:8010?plugin=;;;;;#Empty");

    match &node.protocol {
        Outbound::Shadowsocks(client) => assert!(client.plugin.is_none(), "{written}"),
        other => panic!("not a Shadowsocks node: {other:?}"),
    }
    assert!(!written.contains("plugin"), "{written}");
}

#[test]
fn a_tls_request_that_carries_nothing_is_not_a_request() {
    // A bare `alpn` — an empty list — used to set "TLS wanted" while the writer had nothing to write back
    // for it. Next to an unreadable `security`, which the TLS writer declines to write as well, the
    // request then vanished the first time the link was written out: `Some(empty)` came back as `None`.
    // Fuzzer finding.
    let (node, written) = round_trip(
        "vless://11111111-2222-3333-4444-555555555555@example.com:8443?security=tl%3As&alpn#Go",
    );

    assert!(node.tls.is_none(), "{written}");
    assert!(written.contains("alpn"), "{written}");
}
