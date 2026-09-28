//! Identity: what a node *is*, and what it deliberately is not.
//!
//! Two nodes with the same identity are one node, and that sentence has two halves. The table of
//! one-field changes below must move the identity — every field that decides how a node behaves is in
//! the hash — and the table after it must not: a name, a parameter nobody models, the order a link was
//! spelled in. A field that is missing from the hash is how two different nodes become one, which is
//! the failure mode this whole file exists against.

use suba_proto::{parse_link, write_link, Client, ListenerMaterial, Node, Server};

const VLESS_TLS: &str = "vless://11111111-1111-1111-1111-111111111111@example.com:443\
?encryption=none&security=tls&sni=www.apple.com&alpn=h2&fp=chrome&type=ws&path=%2Fws\
&host=cdn.example.com&ed=2048#Tokyo";

const VLESS_REALITY: &str = "vless://11111111-1111-1111-1111-111111111111@example.com:443\
?encryption=none&security=reality&sni=www.apple.com&pbk=Ezm0e82bCKdD9md8dOv_sy86-Co9Y1iJb5JUfaiFCk8\
&sid=ab12&spx=%2Fprobe&type=grpc&serviceName=GunService&authority=grpc.example.com#Tokyo";

const TROJAN: &str = "trojan://hunter2@example.com:443?sni=example.com#Tokyo";

fn client(link: &str) -> Node<Client> {
    parse_link(link).unwrap_or_else(|error| panic!("{link}\n  {error}"))
}

fn listener(link: &str) -> Node<Server> {
    client(link)
        .into_server(ListenerMaterial::default())
        .unwrap_or_else(|error| panic!("{link}\n  {error}"))
}

/// A link with exactly one thing replaced, which is the only difference the pair may have.
fn changed(link: &str, from: &str, to: &str) -> String {
    assert!(
        link.contains(from),
        "the case is stale: {from} is not in {link}"
    );

    link.replace(from, to)
}

#[test]
fn every_field_that_decides_behaviour_is_in_the_identity() {
    let cases: &[(&str, String, String)] = &[
        (
            "the host",
            VLESS_TLS.to_string(),
            changed(VLESS_TLS, "example.com:443", "example.net:443"),
        ),
        (
            "the port",
            VLESS_TLS.to_string(),
            changed(VLESS_TLS, "example.com:443", "example.com:8443"),
        ),
        (
            "the credential",
            VLESS_TLS.to_string(),
            changed(VLESS_TLS, "11111111-1111", "22222222-2222"),
        ),
        (
            "the encryption",
            VLESS_TLS.to_string(),
            changed(VLESS_TLS, "encryption=none", "encryption=auto"),
        ),
        (
            "the name to verify",
            VLESS_TLS.to_string(),
            changed(VLESS_TLS, "sni=www.apple.com", "sni=www.apple.net"),
        ),
        (
            "the ALPN list",
            VLESS_TLS.to_string(),
            changed(VLESS_TLS, "alpn=h2", "alpn=h2%2Chttp%2F1.1"),
        ),
        (
            "the fingerprint",
            VLESS_TLS.to_string(),
            changed(VLESS_TLS, "fp=chrome", "fp=firefox"),
        ),
        (
            "the carriage path",
            VLESS_TLS.to_string(),
            changed(VLESS_TLS, "path=%2Fws", "path=%2Fother"),
        ),
        (
            "the carriage host",
            VLESS_TLS.to_string(),
            changed(VLESS_TLS, "host=cdn.example.com", "host=cdn.example.net"),
        ),
        (
            "the early data length",
            VLESS_TLS.to_string(),
            changed(VLESS_TLS, "ed=2048", "ed=4096"),
        ),
        (
            "the early data header name",
            changed(VLESS_TLS, "&ed=2048", "&ed=2048&eh=Sec-WebSocket-Protocol"),
            VLESS_TLS.to_string(),
        ),
        (
            "having early data at all",
            changed(VLESS_TLS, "&ed=2048", ""),
            VLESS_TLS.to_string(),
        ),
        (
            "the Reality public key",
            VLESS_REALITY.to_string(),
            changed(VLESS_REALITY, "pbk=Ezm0e82b", "pbk=Fzm0e82b"),
        ),
        (
            "the Reality short id",
            VLESS_REALITY.to_string(),
            changed(VLESS_REALITY, "sid=ab12", "sid=cd34"),
        ),
        (
            "the Reality spider path",
            VLESS_REALITY.to_string(),
            changed(VLESS_REALITY, "spx=%2Fprobe", "spx=%2Fother"),
        ),
        (
            "the gRPC service name",
            VLESS_REALITY.to_string(),
            changed(VLESS_REALITY, "serviceName=GunService", "serviceName=Other"),
        ),
        (
            "the gRPC authority",
            VLESS_REALITY.to_string(),
            changed(
                VLESS_REALITY,
                "authority=grpc.example.com",
                "authority=grpc.example.net",
            ),
        ),
        (
            "an httpupgrade path",
            "trojan://hunter2@example.com:443?type=httpupgrade&path=%2Fup&host=cdn.example.com#T"
                .to_string(),
            "trojan://hunter2@example.com:443?type=httpupgrade&path=%2Fother&host=cdn.example.com#T"
                .to_string(),
        ),
        (
            "an httpupgrade host",
            "trojan://hunter2@example.com:443?type=httpupgrade&path=%2Fup&host=cdn.example.com#T"
                .to_string(),
            "trojan://hunter2@example.com:443?type=httpupgrade&path=%2Fup&host=cdn.example.net#T"
                .to_string(),
        ),
        (
            "a QUIC key",
            "trojan://hunter2@example.com:443?type=quic&quicSecurity=aes-128-gcm&key=one&headerType=srtp#T"
                .to_string(),
            "trojan://hunter2@example.com:443?type=quic&quicSecurity=aes-128-gcm&key=two&headerType=srtp#T"
                .to_string(),
        ),
        (
            "a QUIC header",
            "trojan://hunter2@example.com:443?type=quic&quicSecurity=aes-128-gcm&key=one&headerType=srtp#T"
                .to_string(),
            "trojan://hunter2@example.com:443?type=quic&quicSecurity=aes-128-gcm&key=one&headerType=utp#T"
                .to_string(),
        ),
        (
            "a QUIC security mode",
            "trojan://hunter2@example.com:443?type=quic&quicSecurity=aes-128-gcm&key=one&headerType=srtp#T"
                .to_string(),
            "trojan://hunter2@example.com:443?type=quic&quicSecurity=chacha20-poly1305&key=one&headerType=srtp#T"
                .to_string(),
        ),
        (
            "a Shadowsocks plugin option",
            "ss://YWVzLTI1Ni1nY206aHVudGVyMg==@example.com:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket#T"
                .to_string(),
            "ss://YWVzLTI1Ni1nY206aHVudGVyMg==@example.com:8388?plugin=v2ray-plugin%3Bmode%3Dquic#T"
                .to_string(),
        ),
        (
            "a Hysteria2 port range",
            "hysteria2://hunter2@example.com:443?ports=443-8443#T".to_string(),
            "hysteria2://hunter2@example.com:443?ports=443-9443#T".to_string(),
        ),
    ];

    for (what, left, right) in cases {
        let left = client(left);
        let right = client(right);

        assert_ne!(
            left.id(),
            right.id(),
            "changing {what} did not change the identity"
        );
    }
}

#[test]
fn a_listeners_own_material_is_in_its_identity() {
    // The listener direction has fields a link cannot carry, and they are the ones that decide what it
    // serves: the bind address, the certificates, how clients authenticate, the Reality short ids.
    let base =
        listener("vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none#T");
    let identity = base.id();

    let mut moved = base.clone();
    moved.listen = suba_proto::Endpoint::parse("127.0.0.1:8443").unwrap();
    assert_ne!(identity, moved.id(), "moving the listener changed nothing");

    // And a client and its own listener are not one node: the direction is part of what a node is.
    assert_ne!(
        base.id(),
        listener("vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none#T")
            .into_client_for(0)
            .unwrap()
            .id(),
        "a listener and a client hashed alike"
    );
}

#[test]
fn what_a_node_is_spelled_like_is_not_in_the_identity() {
    let base = client(VLESS_TLS);

    for (what, link) in [
        ("its name", changed(VLESS_TLS, "#Tokyo", "#Osaka")),
        (
            "a parameter nobody models",
            changed(VLESS_TLS, "#Tokyo", "&tfo#Tokyo"),
        ),
        (
            "the order of its parameters",
            // The same parameters, written in a different order.
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=ws&host=cdn.example.com&path=%2Fws&ed=2048&fp=chrome&alpn=h2&sni=www.apple.com&security=tls&encryption=none#Tokyo"
                .to_string(),
        ),
    ] {
        let other = client(&link);

        assert_eq!(
            base.id(),
            other.id(),
            "{what} changed the identity, and it decides nothing"
        );
    }

    // The carriage a link says explicitly and the one it leaves out are the same carriage.
    let plain = client(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&type=tcp#T",
    );
    let implied =
        client("vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none#T");

    assert_eq!(plain.id(), implied.id());
}

#[test]
fn the_encoding_is_a_contract() {
    // A pinned identity. If this assertion fails, the canonical encoding changed, which means every
    // identity written by an older build now describes a different node. That is allowed — it is what
    // `ENCODING_VERSION` is for — but it must be a decision, made by bumping the version and updating
    // this value, rather than something that happens to a stored subscription.
    assert_eq!(
        suba_proto::identity::ENCODING_VERSION,
        "suba.node.v2",
        "the version moved: update the pinned identity below with it"
    );

    assert_eq!(
        client(TROJAN).id().to_string(),
        "2e5ef0b9d0eccda87825d83f236844b7"
    );
}

#[test]
fn writing_a_node_back_does_not_change_its_identity() {
    // The check that would have caught a missing field in the round trip, run over the whole corpus:
    // a node written out and read back is the same node, and it says so by hashing the same.
    for line in include_str!("golden/links.txt").lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Ok(node) = parse_link(line) else {
            continue;
        };

        let written = write_link(&node).expect("a link");
        let again = parse_link(&written).expect("the link we just wrote");

        assert_eq!(again.id(), node.id(), "{line}\n  became {written}");
    }
}
