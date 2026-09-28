//! The golden corpus.
//!
//! Every link in `tests/golden/links.txt` is parsed, written back and parsed again. This is the test
//! that catches the class of bug a converter cannot afford: a parameter that is silently dropped, a
//! password that is unescaped on the way out, an address that changes meaning.

use suba_proto::{parse_link, write_link, Kind};

const CORPUS: &str = include_str!("golden/links.txt");

fn lines() -> impl Iterator<Item = &'static str> {
    CORPUS
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

#[test]
fn every_link_parses() {
    for line in lines() {
        let node = parse_link(line).unwrap_or_else(|error| panic!("{line}\n  {error}"));

        assert!(!node.id().is_empty(), "{line}");
        assert!(!node.name.is_empty(), "{line} has no name");
    }
}

#[test]
fn every_link_survives_a_round_trip() {
    for line in lines() {
        let node = parse_link(line).unwrap();
        let written = write_link(&node).unwrap();
        let again = parse_link(&written).unwrap_or_else(|error| panic!("{written}\n  {error}"));

        assert_eq!(
            again, node,
            "a round trip changed the node\n  in: {line}\n out: {written}"
        );
        assert_eq!(again.id(), node.id(), "{line}");
    }
}

#[test]
fn writing_twice_is_writing_once() {
    for line in lines() {
        let node = parse_link(line).unwrap();
        let once = write_link(&node).unwrap();
        let twice = write_link(&parse_link(&once).unwrap()).unwrap();

        assert_eq!(once, twice, "{line}");
    }
}

#[test]
fn no_credential_is_ever_printed() {
    // Every placeholder this corpus uses, which must not appear in a debug print of the node tree.
    const SECRETS: &[&str] = &[
        "PASSWORD",
        "P@SSW0RD/=",
        "11111111-2222-3333-4444-555555555555",
        "PUBKEY",
        "PSK",
        // From the real, sanitized subscription at the end of the corpus.
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000005",
        "00000000-0000-4000-8000-000000000013",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "S0ME+c3VwZXIvbG9uZy9rZXk=",
    ];

    for line in lines() {
        let node = parse_link(line).unwrap();
        let rendered = format!("{node:?}");

        for secret in SECRETS {
            assert!(!rendered.contains(secret), "{secret} leaked in {rendered}");
        }
    }
}

#[test]
fn the_corpus_covers_what_it_says_it_does() {
    let kinds = lines()
        .map(|line| parse_link(line).unwrap().protocol.kind())
        .collect::<Vec<_>>();

    for kind in [Kind::Vless, Kind::Trojan, Kind::Shadowsocks, Kind::Other] {
        assert!(kinds.contains(&kind), "{kind} is not covered by the corpus");
    }
}
