# suba-proto

The protocol layer of SubA, on its own.

Share links and proxy protocol models, with no database, no HTTP, no configuration files and no
sing-box. It reads the things providers publish, keeps them honest about which credentials they
carry, and writes them back out.

```toml
[dependencies]
suba-proto = "0.1"
```

## The rules

These are the rules the crate is built on. Every one of them is enforced by a test.

1. **Nothing here knows about sing-box.** The dependency only ever points the other way. The
   protocol layer is what the protocols say it is; a renderer is a consumer.
2. **Fields are named after the protocol, not after an implementation.** `method` and `password`
   rather than whatever a particular core calls them; `plugin_opts` as SIP002 spells it, `obfs_param`
   as ShadowsocksR does.
3. **Both roles are modelled, separately.** A VLESS listener takes `users: [{uuid, flow}]`; a VLESS
   client has one `uuid` and one `flow`. Flattening them into one shape loses exactly the part that
   matters (`security/deployment.md`).
4. **A link only ever describes a client.** Links are what a provider hands you; there is no listener
   behind them. Turning a listener into a link is refused, not approximated.
5. **Credentials have a type.** A password is a `Secret<Box<str>>`. It cannot be logged by accident,
   `Debug` prints a placeholder, and the redaction tests exist to keep it that way.
6. **Reading borrows.** A link is taken apart into slices of itself; parsing a link allocates nothing.
   What the model keeps is copied once, and nothing else is.
7. **An unknown protocol is carried, not dropped.** A scheme this build does not model parses into an
   `Opaque` node that writes back byte for byte, so a provider's new protocol does not disappear from
   a subscription because a library is older than it is.
8. **`no_std` from the start.** `alloc` only, no `std`, so the same crate can be the protocol layer of
   a client running where there is no operating system to speak of.
9. **A protocol's types live in its own module, named after the role.** `vless::Client`,
   `shadowsocks::Server`, `trojan::User` — not `VlessClient`, `ShadowsocksServer`, `TrojanUser`. The
   protocol name is already in the path, and a crate with a dozen protocols should not have a dozen
   three-word type names. The enum variants carry the protocol instead: `Outbound::Vless(vless::Client)`.

## Layout

| Module | What it owns |
| --- | --- |
| `link` | The share-link grammar: scheme, authority, query, fragment. Borrowed, plus the `Reader` that claims parameters. |
| `percent` | Percent-encoding, as strict as it needs to be to stay unambiguous. |
| `uuid` | A UUID in sixteen bytes, parsed without a dependency. |
| `params` | `RawParams`: what a provider sent and the model did not name. |
| `addr` | `Host`, `Port`, `Endpoint`. |
| `tls` | TLS and Reality options, by role. |
| `transport` | TCP, WebSocket, gRPC, HTTP upgrade, HTTP/2, QUIC. |
| `protocol` | One module per protocol, plus the `Outbound`/`Inbound` enums, `Kind`, `Role` and the
`ClientLink` trait. Modelled today: vless, trojan, shadowsocks, hysteria2, vmess, shadowsocksr, tuic,
anytls, socks, http; anything else is `Opaque`, kept whole. |
| `identity` | Content hashing: what makes two nodes the same node. |
| `node` | `Node<D>`: endpoint, transport, TLS, protocol payload, role. |
| `error` | One error type, with the field that failed. |

## Reading a link

```rust
use suba_proto::{parse_link, write_link};

let node = parse_link("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=www.apple.com&pbk=PUBKEY&sid=ab12&type=ws&path=%2Fws#Tokyo").unwrap();

assert_eq!(node.endpoint.host.domain(), Some("example.com"));
assert_eq!(node.transport.name(), "ws");
assert_eq!(node.id(), node.id());                            // stable across parses
assert!(write_link(&node).unwrap().starts_with("vless://"));  // writes the client form back
```

A protocol this build does not model still parses, still hashes, and still writes back:

```rust
# use suba_proto::parse_link;
let node = parse_link("snell://1.2.3.4:443?psk=SECRET#Snell").unwrap();
assert_eq!(node.protocol.scheme(), "snell");
assert!(node.extra.get("psk").is_some()); // kept, not modelled, not printed with its value
```

## Roles

The two directions are two types, not one type with an optional field:

```rust
# use suba_proto::{parse_link, Role};
let client = parse_link("trojan://PASSWORD@example.com:443#Trojan").unwrap();
assert_eq!(client.direction(), Role::Client);

// Node<Client>:  protocol is Outbound, tls is TlsClient, listen is ()
// Node<Server>:  protocol is Inbound,  tls is TlsServer, listen is Endpoint
```

`Direction` is a sealed trait with exactly two implementations, so the compiler will not let a
renderer treat the halves as one. Inside a listener the shapes genuinely differ — a client has one
credential, a listener has a user list — and each direction's payload type is the one the wire
actually uses.

The conversions between the two are what `convert` implements (requirements N-8):

```rust
use suba_proto::{parse_link, ListenerMaterial};
use suba_proto::tls::Certificate;
use suba_proto::addr::Endpoint;

let client = parse_link("trojan://PASSWORD@example.com:443?sni=example.com#Trojan").unwrap();

// What a listener needs and a link cannot carry, asked for before it is demanded.
assert_eq!(client.required_material(), vec!["certificate_path and key_path"]);

let listener = client.clone().into_server(ListenerMaterial {
    listen: Some(Endpoint::parse("127.0.0.1:8443").unwrap()),
    certificates: vec![Certificate::new("/etc/ssl/fullchain.pem", "/etc/ssl/key.pem")],
    ..ListenerMaterial::default()
}).unwrap();

assert_eq!(listener.listen.to_string(), "127.0.0.1:8443");
assert_eq!(listener.endpoint.to_string(), "example.com:443");
assert_eq!(listener.client_count(), 1);

// And back, taking the one credential the listener holds.
let again = listener.into_client().unwrap();
assert_eq!(again.protocol, client.protocol);
```

`required_material()` lists what a listener needs, in the order it is checked, so a caller can ask for
it instead of discovering it through an error. `into_server` then refuses to invent anything: a
Reality listener cannot be built from a public key, so it asks for the private key and says so. In the
other direction `into_client` refuses to invent a name or a credential either — with a listener that
accepts several users it will not guess which one you meant, and `into_client_for(index)` is how you
say.

## Numbers

Measured with `cargo bench -p suba-proto` on a 22-link corpus, release, this machine:

| | |
| --- | --- |
| parse a link | ~0.44 µs |
| write a link | ~0.11 µs |
| hash a node for identity | ~62 ns |
| allocations to read a link | 0 |
| allocations to parse a link | ~1.7 per stored field |
| allocations to write a link | 1 |

Those last three are asserted by `tests/allocations.rs`, which counts with a thread-local counter in
a global allocator. A parameter the model recognises is never boxed on the way past; a parameter it
does not is kept, because that is the point of carrying it.

## Features

| Feature | Default | What it adds |
| --- | --- | --- |
| `std` | yes | `std::error::Error` for the error type |
| `serde` | yes | `Serialize`/`Deserialize`, with text types as strings |

```toml
suba-proto = { version = "0.1", default-features = false }          # no_std
suba-proto = { version = "0.1", default-features = false, features = ["serde"] }
```

Minimum supported Rust version: 1.98 (`core::net`, `core::error::Error`).

## Testing

- `cargo test -p suba-proto` — unit tests per module, a golden corpus of real-world links, the
  allocation budget, and round-trip properties.
- `tests/golden/links.txt` — every link in there must parse, hash stably and write back to the same
  node. Adding a protocol's link to it is the cheapest regression test there is.
- Every protocol module has a test that a credential never reaches a rendering.

## What is not here

Deliberately: subscriptions (parsing a whole provider payload, or deciding what to do about its
headers), groups, targets, caches, and every storage question. Those belong to the service. This
crate answers one question — *what is this node* — and answers it in one place.
