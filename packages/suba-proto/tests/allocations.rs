//! How many allocations a parse makes.
//!
//! The crate claims that parsing copies exactly what it stores, and that a parameter the model knows
//! is never boxed on the way past. That claim is only worth making if it is measured, so this test
//! counts allocations with a global allocator and fails when one of these paths grows.
//!
//! The counter is per thread, not global: `cargo test` runs test functions in parallel, and a global
//! counter would make these numbers depend on whatever the other tests happen to be doing.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use suba_proto::{parse_link, write_link};

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();

        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();

        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();

        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

/// Bump the counter, without allocating or panicking: the allocator is the last place that may do
/// either, and `try_with` handles the thread that has no counter yet.
fn count() {
    let _ = ALLOCATIONS.try_with(|counter| counter.set(counter.get() + 1));
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// How many allocations `body` makes on this thread.
fn allocations(body: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.with(Cell::get);
    body();
    ALLOCATIONS.with(Cell::get) - before
}

/// One small link: the credential, the name and the host. Nothing else has to be copied.
const MINIMAL: &str = "trojan://PASSWORD@example.com:443#Trojan";

/// A link with every field the model names, plus two it does not.
const FULL: &str = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision&type=ws&path=%2Fws&host=cdn.example.com&weird=1&flag#Tokyo";

#[test]
fn reading_a_link_takes_no_memory_at_all() {
    // The claim the whole design rests on: a link is taken apart into slices of itself.
    let count = allocations(|| {
        for _ in 0..100 {
            let _ = suba_proto::Link::parse(FULL).unwrap();
        }
    });

    assert_eq!(count, 0, "reading a link allocated {count} times");
}

#[test]
fn a_minimal_link_costs_a_handful() {
    let count = allocations(|| {
        let _ = parse_link(MINIMAL).unwrap();
    });

    // The reader's index, the credential, the name and the host.
    assert!(count <= 10, "a minimal parse made {count} allocations");
}

#[test]
fn a_full_link_costs_about_one_per_stored_field() {
    let count = allocations(|| {
        let _ = parse_link(FULL).unwrap();
    });

    // Fourteen named fields, two unmodelled parameters, and the reader's index.
    assert!(count <= 32, "a full parse made {count} allocations");
}

#[test]
fn writing_is_one_allocation() {
    let node = parse_link(FULL).unwrap();
    let count = allocations(|| {
        let _ = write_link(&node).unwrap();
    });

    assert!(count <= 3, "writing a link made {count} allocations");
}

#[test]
fn an_unmodelled_link_costs_its_raw_payload() {
    let count = allocations(|| {
        let _ = parse_link("snell://1.2.3.4:443?psk=PSK&version=4#Snell").unwrap();
    });

    // The scheme, the raw link, the name, the host, and four strings for the two parameters.
    assert!(count <= 14, "an unmodelled parse made {count} allocations");
}

#[test]
fn identity_is_computed_without_copying_the_node() {
    let node = parse_link(FULL).unwrap();
    let count = allocations(|| {
        let _ = node.id();
    });

    // The one text buffer the canonical encoding builds for the host.
    assert!(count <= 4, "hashing a node made {count} allocations");
}
