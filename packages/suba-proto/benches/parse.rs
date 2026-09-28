//! What the crate costs.
//!
//! Run with `cargo bench -p suba-proto`. The numbers that matter are the parse paths: a converter
//! parses every link a provider ever served, on every refresh, on a box that is usually a router.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use suba_proto::{parse_link, write_link};

/// A corpus shaped like what providers actually serve.
const CORPUS: &[&str] = &[
    "trojan://PASSWORD@example.com:443?sni=example.com#Trojan",
    "trojan://PASSWORD@example.com:443?sni=www.apple.com&type=ws&path=%2Fws&host=cdn.example.com#TrojanWS",
    "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision#Reality",
    "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=grpc&serviceName=grpc&mode=multi&alpn=h2#Grpc",
    "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=ws&path=%2F&host=cdn.example.com&weird=1&flag#Plain",
    "ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080#Shadowsocks",
    "ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#Obfs",
];

fn parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_link");
    group.throughput(Throughput::Elements(CORPUS.len() as u64));
    group.bench_function("corpus", |bencher| {
        bencher.iter(|| {
            let mut parsed = 0usize;

            for link in CORPUS {
                if parse_link(black_box(link)).is_ok() {
                    parsed += 1;
                }
            }

            parsed
        })
    });
    group.finish();
}

fn identity(c: &mut Criterion) {
    let nodes = CORPUS
        .iter()
        .filter_map(|link| parse_link(link).ok())
        .collect::<Vec<_>>();

    c.bench_function("node_id", |bencher| {
        bencher.iter(|| {
            for node in &nodes {
                black_box(node.id());
            }
        })
    });
}

fn write(c: &mut Criterion) {
    let nodes = CORPUS
        .iter()
        .filter_map(|link| parse_link(link).ok())
        .collect::<Vec<_>>();

    c.bench_function("write_link", |bencher| {
        bencher.iter(|| {
            let mut total = 0usize;

            for node in &nodes {
                total += write_link(black_box(node))
                    .map(|link| link.len())
                    .unwrap_or(0);
            }

            total
        })
    });
}

fn round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("round_trip");
    group.throughput(Throughput::Elements(CORPUS.len() as u64));
    group.bench_function("parse_then_write", |bencher| {
        bencher.iter(|| {
            let mut total = 0usize;

            for link in CORPUS {
                if let Ok(node) = parse_link(black_box(link)) {
                    total += write_link(&node).map(|link| link.len()).unwrap_or(0);
                }
            }

            total
        })
    });
    group.finish();
}

criterion_group!(benches, parse, identity, write, round_trip);
criterion_main!(benches);
