//! The registry, seen from the outside.
//!
//! Every dialect in the golden corpus must survive the trip a subscription makes: parse, identify,
//! write back, and convert to the other role. The corpus is the input, so this fails the moment a
//! protocol stops being reachable — and it fails loudly if a *known* scheme falls through to `Opaque`,
//! which is the one failure that announces itself nowhere else: the subscription keeps working and
//! quietly drops nodes.
//!
//! The corpus is deliberately mixed: modelled dialects, one scheme nobody models (`snell`, kept whole
//! on purpose), and one line that is not a link at all.

use suba_proto::protocol::Kind;
use suba_proto::{parse_link, write_link, ErrorKind, ListenerMaterial};

const LINKS: &str = include_str!("golden/links.txt");

fn links() -> Vec<&'static str> {
    LINKS
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

fn scheme_of(link: &str) -> &str {
    link.split("://").next().unwrap_or_default()
}

/// What this crate claims to model, by the schemes providers actually write.
///
/// Written out here rather than asked of the crate: the point is to catch a payload that is *supposed*
/// to be typed and is not, so the expectation has to come from outside the code under test.
fn known(scheme: &str) -> Option<Kind> {
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => Some(Kind::Vless),
        "trojan" => Some(Kind::Trojan),
        "ss" => Some(Kind::Shadowsocks),
        "hysteria2" | "hy2" => Some(Kind::Hysteria2),
        "vmess" => Some(Kind::Vmess),
        "ssr" => Some(Kind::ShadowsocksR),
        "tuic" => Some(Kind::Tuic),
        "anytls" => Some(Kind::AnyTls),
        "socks" | "socks4" | "socks4a" | "socks5" | "socks5h" => Some(Kind::Socks),
        "http" | "https" => Some(Kind::Http),
        _ => None,
    }
}

/// Every kind this crate models, `Other` aside: `Other` is what holds the protocols it does not.
const MODELLED: [Kind; 10] = [
    Kind::Vless,
    Kind::Trojan,
    Kind::Shadowsocks,
    Kind::Hysteria2,
    Kind::Vmess,
    Kind::ShadowsocksR,
    Kind::Tuic,
    Kind::AnyTls,
    Kind::Socks,
    Kind::Http,
];

#[test]
fn a_known_scheme_never_falls_through_to_opaque() {
    for link in links() {
        let Ok(node) = parse_link(link) else {
            assert!(
                known(scheme_of(link)).is_none(),
                "{link} is a dialect this crate claims to model and it does not parse"
            );

            continue;
        };

        match known(scheme_of(link)) {
            Some(kind) => assert_eq!(
                node.protocol.kind(),
                kind,
                "{link} is a known scheme, so a dispatch site in protocol/mod.rs is missing it"
            ),
            // An unmodelled scheme is a supported state: it is kept whole, not guessed at.
            None => assert_eq!(node.protocol.kind(), Kind::Other, "{link}"),
        }
    }
}

#[test]
fn every_corpus_link_survives_a_round_trip() {
    for link in links() {
        let Ok(node) = parse_link(link) else {
            continue;
        };

        let written = write_link(&node).expect("everything in the corpus has a link form");
        let again = parse_link(&written).expect("what was written parses back");

        assert_eq!(again.protocol, node.protocol, "protocol drifted: {link}");
        assert_eq!(again.id(), node.id(), "identity drifted: {link}");
        assert_eq!(again.endpoint, node.endpoint, "endpoint drifted: {link}");
    }
}

#[test]
fn the_corpus_covers_every_modelled_protocol() {
    let seen: Vec<Kind> = links()
        .into_iter()
        .filter_map(|link| parse_link(link).ok())
        .map(|node| node.protocol.kind())
        .collect();

    for kind in MODELLED {
        assert!(
            seen.contains(&kind),
            "the corpus has no {kind:?}: add a golden line so the dialect stays covered"
        );
    }
}

#[test]
fn every_corpus_node_becomes_a_listener_or_says_what_it_needs() {
    for link in links() {
        let Ok(node) = parse_link(link) else {
            continue;
        };

        match node.clone().into_server(ListenerMaterial::default()) {
            Ok(server) => {
                let credentials = server.client_count();

                // A listener is one dialler, and every shape the corpus produces has a credential to
                // dial with. This used to accept an error here, which is exactly what hid a listener
                // whose only credential sat in a field nobody read.
                let back = server
                    .clone()
                    .into_client()
                    .unwrap_or_else(|error| panic!("{link}: {error}"));

                assert_eq!(
                    back.protocol, node.protocol,
                    "role conversion lost the payload: {link}"
                );

                // Every credential a listener accepts is reachable by index, and there is nothing
                // past the last one.
                for index in 0..credentials {
                    let indexed = server
                        .clone()
                        .into_client_for(index)
                        .unwrap_or_else(|error| panic!("{link}: credential {index}: {error}"));

                    assert_eq!(
                        indexed.protocol, back.protocol,
                        "{link}: credential {index} is not the one `into_client` returns"
                    );
                }

                assert!(
                    server.into_client_for(credentials).is_err(),
                    "{link}: there is no credential {credentials}"
                );
            }
            // Refusing is allowed: a listener needs a certificate or a Reality key that a share link
            // never carries (`MissingField`), and a protocol this build keeps whole cannot be served
            // at all (`UnsupportedRole`). Refusing without saying which is not.
            Err(error) => {
                assert!(
                    matches!(
                        error.kind(),
                        ErrorKind::MissingField | ErrorKind::UnsupportedRole
                    ),
                    "{link}: {error}"
                );
                assert!(!error.reason().is_empty(), "{link}: {error}");
            }
        }
    }
}
