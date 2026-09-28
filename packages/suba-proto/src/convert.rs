//! Turning a node into the other direction.
//!
//! A link describes a client. A listener is the same node seen from the other side, and the two are
//! not the same shape: a client holds one credential where a listener holds a user list, a client
//! holds a public key where a listener holds a private one, and only a listener binds an address.
//!
//! The rule this module is built on (requirements N-8) is asymmetric on purpose:
//!
//! * **A client becomes a listener** once the material a link cannot carry is supplied — a bind
//!   address, a certificate, a Reality private key. Missing material is refused, item by item, never
//!   invented: [`Node::required_material`] is the list, and it is what a UI should show.
//! * **A listener becomes a client** by throwing away what only a listener has, and by deriving what
//!   it can. Nothing is guessed.
//!
//! Nothing here opens a socket or reads a clock: a conversion is a pure function of a node and, at
//! most, the material handed to it.

use crate::addr::{Endpoint, Host, Port};
use crate::error::{Error, ErrorKind, Result};
use crate::node::{Client, Node, Server};
use crate::params::RawParams;
use crate::prelude::*;
use crate::protocol::{
    anytls, http, hysteria2, shadowsocks, shadowsocksr, socks, trojan, tuic, vless, vmess, Inbound,
    Outbound, Protocol as _,
};
use crate::secret::Secret;
use crate::tls::{Certificate, ClientAuth, RealityClient, RealityServer, TlsClient, TlsServer};

/// What a listener needs that a share link cannot carry.
///
/// Handed to [`Node::into_server`]. Everything in it is optional, and everything that is needed but
/// missing is named in the error rather than defaulted.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ListenerMaterial {
    /// Where the listener binds.
    ///
    /// Not the advertised address: a listener behind a reverse proxy binds `127.0.0.1` while clients
    /// are told to dial something else. When unset, the node's own endpoint is used, which is right
    /// for the simple case and wrong for every other one.
    pub listen: Option<Endpoint>,
    /// TLS material, for a node that terminates TLS itself.
    pub certificates: Vec<Certificate>,
    /// The Reality private key. Nothing a client has can stand in for it.
    pub reality_private_key: Option<Secret<Box<str>>>,
    /// The site a Reality listener borrows its handshake from, when the client did not name one.
    pub reality_handshake: Option<Endpoint>,
}

impl Node<Client> {
    /// Everything a listener for this node needs and a link cannot carry.
    ///
    /// The order is the order [`Node::into_server`] checks them in, so the first entry is the first
    /// thing a user has to supply.
    pub fn required_material(&self) -> Vec<&'static str> {
        let mut needed = Vec::new();

        match &self.tls {
            Some(client) if client.reality.is_some() => {
                needed.push("reality private_key");

                if client.server_name.is_none() {
                    needed.push("reality handshake");
                }
            }
            Some(_) => needed.push("certificate_path and key_path"),
            None => {}
        }

        needed
    }

    /// The same node, served instead of dialled.
    ///
    /// The advertised address is this node's endpoint — that is what a client was told to dial, and a
    /// listener has to keep saying it. `material.listen` is where it binds, which is a different
    /// question and a different answer.
    pub fn into_server(self, material: ListenerMaterial) -> Result<Node<Server>> {
        if !self.protocol.supports_inbound() {
            return Err(Error::field(
                ErrorKind::UnsupportedRole,
                "protocol (this build cannot serve it)",
            ));
        }

        let protocol = to_inbound(self.protocol)?;
        let tls = match self.tls {
            None => None,
            Some(client) => Some(to_tls_server(client, &material)?),
        };
        let listen = material.listen.unwrap_or_else(|| self.endpoint.clone());

        Ok(Node::<Server> {
            name: self.name,
            endpoint: self.endpoint,
            listen,
            transport: self.transport,
            tls,
            protocol,
            extra: self.extra,
        })
    }
}

impl Node<Server> {
    /// How many credentials the listener accepts.
    pub fn client_count(&self) -> usize {
        self.protocol.user_count()
    }

    /// The same node, dialled instead of served, for a listener that has exactly one credential.
    pub fn into_client(self) -> Result<Node<Client>> {
        let users = self.client_count();

        if users != 1 {
            return Err(Error::owned(
                ErrorKind::InvalidValue,
                format!("the listener has {users} credentials; choose one with into_client_for"),
            ));
        }

        self.into_client_for(0)
    }

    /// The same node, dialled instead of served, as the `index`-th credential.
    ///
    /// What only a listener has is dropped rather than carried along: the bind address, the
    /// certificate paths, the private key. What a client needs and the listener can answer is derived
    /// — a Reality public key from its private key, the name to verify from the advertised address —
    /// and what it cannot is refused.
    ///
    /// One thing is lost on the way, and it is worth knowing: a client's own `sni` is not a listener
    /// field, so the name to verify is taken from Reality's handshake or from the advertised address.
    /// A node whose clients verified a different name than they dialled cannot be described by its
    /// listener alone, and this is the one conversion that says so by changing a value rather than by
    /// failing.
    pub fn into_client_for(self, index: usize) -> Result<Node<Client>> {
        let users = self.client_count();

        if index >= users {
            return Err(Error::owned(
                ErrorKind::InvalidValue,
                format!("the listener has {users} credentials; there is no credential {index}"),
            ));
        }

        let protocol = to_outbound(self.protocol, index)?;
        let tls = match &self.tls {
            None => None,
            Some(server) => Some(to_tls_client(server, &self.endpoint)?),
        };

        Ok(Node::<Client> {
            name: self.name,
            endpoint: self.endpoint,
            listen: (),
            transport: self.transport,
            tls,
            protocol,
            extra: self.extra,
        })
    }
}

/// The listener half of a payload.
fn to_inbound(protocol: Outbound) -> Result<Inbound> {
    Ok(match protocol {
        Outbound::Vless(client) => Inbound::Vless(vless::Server {
            users: vec![vless::User {
                id: client.id,
                flow: client.flow,
                level: None,
            }],
            // The listener's counterpart of the client's encryption is its decryption.
            decryption: client.encryption,
        }),
        Outbound::Trojan(client) => Inbound::Trojan(trojan::Server {
            users: vec![trojan::User {
                password: client.password,
                level: None,
            }],
            fallback: None,
        }),
        Outbound::Shadowsocks(client) => Inbound::Shadowsocks(shadowsocks::Server {
            method: client.method,
            password: client.password,
            users: Vec::new(),
            plugin: client.plugin,
        }),
        Outbound::Hysteria2(client) => Inbound::Hysteria2(hysteria2::Server {
            users: vec![hysteria2::User {
                password: client.password,
            }],
            obfs: client.obfs,
            // The obfuscator authenticates with a password both ends share, so the listener is told it.
            obfs_password: client.obfs_password,
            up: client.up,
            down: client.down,
        }),
        Outbound::Vmess(client) => Inbound::Vmess(vmess::Server {
            users: vec![vmess::User {
                id: client.id,
                alter_id: client.alter_id,
                security: client.security,
                level: None,
            }],
        }),
        Outbound::ShadowsocksR(client) => Inbound::ShadowsocksR(shadowsocksr::Server {
            method: client.method,
            password: client.password,
            protocol: client.protocol,
            protocol_param: client.protocol_param,
            obfs: client.obfs,
            obfs_param: client.obfs_param,
        }),
        Outbound::Tuic(client) => Inbound::Tuic(tuic::Server {
            users: vec![tuic::User {
                uuid: client.uuid,
                password: client.password,
                level: None,
            }],
            congestion_control: client.congestion_control,
            zero_rtt_handshake: client.zero_rtt_handshake,
        }),
        Outbound::AnyTls(client) => Inbound::AnyTls(anytls::Server {
            users: vec![anytls::User {
                password: client.password,
            }],
        }),
        // A dialer with no credential becomes an open local listener, not a listener with an empty
        // password: those are different things on the wire.
        Outbound::Socks(client) => Inbound::Socks(socks::Server {
            version: client.version,
            users: client
                .username
                .map(|username| {
                    vec![socks::User {
                        username,
                        password: client
                            .password
                            .clone()
                            .unwrap_or_else(|| Secret::new(Box::from(""))),
                    }]
                })
                .unwrap_or_default(),
        }),
        Outbound::Http(client) => Inbound::Http(http::Server {
            users: client
                .username
                .map(|username| {
                    vec![http::User {
                        username,
                        password: client
                            .password
                            .clone()
                            .unwrap_or_else(|| Secret::new(Box::from(""))),
                    }]
                })
                .unwrap_or_default(),
        }),
        Outbound::Other(_) => {
            return Err(Error::field(
                ErrorKind::UnsupportedRole,
                "protocol (this build cannot serve it)",
            ))
        }
    })
}

/// The client half of a payload, as one of the listener's credentials.
fn to_outbound(protocol: Inbound, index: usize) -> Result<Outbound> {
    let missing = |what: &'static str| Error::field(ErrorKind::MissingField, what);

    Ok(match protocol {
        Inbound::ShadowsocksR(server) => Outbound::ShadowsocksR(shadowsocksr::Client {
            method: server.method.clone(),
            password: server.password.clone(),
            protocol: server.protocol.clone(),
            protocol_param: server.protocol_param.clone(),
            obfs: server.obfs.clone(),
            obfs_param: server.obfs_param.clone(),
        }),
        Inbound::Tuic(server) => {
            let user = server.users.get(index).ok_or_else(|| missing("users"))?;

            Outbound::Tuic(tuic::Client {
                uuid: user.uuid.clone(),
                password: user.password.clone(),
                congestion_control: server.congestion_control,
                // A listener has nothing to say about this: it is how a client may send UDP, and the
                // listener does not know which its clients chose.
                udp_relay_mode: None,
                zero_rtt_handshake: server.zero_rtt_handshake,
            })
        }
        Inbound::AnyTls(server) => {
            let user = server.users.get(index).ok_or_else(|| missing("users"))?;

            Outbound::AnyTls(anytls::Client {
                password: user.password.clone(),
            })
        }
        // An open local listener becomes a dialer with no credential.
        Inbound::Socks(server) => Outbound::Socks(match server.users.get(index) {
            Some(user) => socks::Client {
                version: server.version,
                username: Some(user.username.clone()),
                password: Some(user.password.clone()),
            },
            None => socks::Client {
                version: server.version,
                ..socks::Client::default()
            },
        }),
        Inbound::Http(server) => Outbound::Http(match server.users.get(index) {
            Some(user) => http::Client {
                username: Some(user.username.clone()),
                password: Some(user.password.clone()),
            },
            None => http::Client::default(),
        }),
        Inbound::Vless(server) => {
            let user = server.users.get(index).ok_or_else(|| missing("users"))?;

            Outbound::Vless(vless::Client {
                id: user.id.clone(),
                flow: user.flow,
                encryption: server.decryption,
            })
        }
        Inbound::Trojan(server) => {
            let user = server.users.get(index).ok_or_else(|| missing("users"))?;

            Outbound::Trojan(trojan::Client {
                password: user.password.clone(),
            })
        }
        Inbound::Shadowsocks(server) => Outbound::Shadowsocks(shadowsocks::Client {
            method: server.method.clone(),
            // The two credential modes are not the same shape: a user list is indexed, and the
            // single password is what a listener with no list has. Reading the password field in
            // both cases is how `into_client_for(0)` and `into_client_for(1)` returned one credential.
            password: match server.users.get(index) {
                Some(user) => user.password.clone(),
                None => server.password.clone(),
            },
            plugin: server.plugin.clone(),
        }),
        Inbound::Vmess(server) => {
            let user = server.users.get(index).ok_or_else(|| missing("users"))?;

            Outbound::Vmess(vmess::Client {
                id: user.id.clone(),
                alter_id: user.alter_id,
                security: user.security,
            })
        }
        Inbound::Hysteria2(server) => {
            let user = server.users.get(index).ok_or_else(|| missing("users"))?;

            Outbound::Hysteria2(hysteria2::Client {
                password: user.password.clone(),
                obfs: server.obfs,
                obfs_password: server.obfs_password.clone(),
                // Port hopping and certificate pinning are the client's own business: a listener never
                // had them to give back.
                ports: None,
                hop_interval: None,
                up: server.up,
                down: server.down,
                pin_sha256: None,
            })
        }
    })
}

/// The listener half of a node's TLS.
fn to_tls_server(client: TlsClient, material: &ListenerMaterial) -> Result<TlsServer> {
    let reality = match &client.reality {
        Some(reality) => {
            let private_key = material
                .reality_private_key
                .clone()
                .ok_or_else(|| Error::field(ErrorKind::MissingField, "reality private_key"))?;

            let handshake = material
                .reality_handshake
                .clone()
                .or_else(|| {
                    client.server_name.as_ref().map(|host| Endpoint {
                        host: host.clone(),
                        port: Port::parse("443").expect("443 is a port"),
                    })
                })
                .ok_or_else(|| Error::field(ErrorKind::MissingField, "reality handshake"))?;

            Some(RealityServer {
                private_key,
                short_ids: reality.short_id.clone().into_iter().collect(),
                handshake,
                max_time_diff_ms: None,
            })
        }
        None => None,
    };

    // Reality authenticates with its own key pair and borrows a real site's certificate; anything
    // else that terminates TLS needs its own.
    let certificates = if reality.is_none() && material.certificates.is_empty() {
        return Err(Error::field(
            ErrorKind::MissingField,
            "certificate_path and key_path",
        ));
    } else {
        material.certificates.clone()
    };

    Ok(TlsServer {
        certificates,
        alpn: client.alpn.clone(),
        client_auth: ClientAuth::NoClientCert,
        reality,
        extra: RawParams::new(),
    })
}

/// The client half of a node's TLS.
fn to_tls_client(server: &TlsServer, endpoint: &Endpoint) -> Result<TlsClient> {
    let reality = match &server.reality {
        Some(reality) => Some(RealityClient {
            public_key: Secret::new(derived_public_key(reality)?),
            short_id: reality.short_ids.first().cloned(),
            spider_x: None,
        }),
        None => None,
    };

    // The name to verify: what a Reality listener borrows, or the address the client was told to
    // dial. An IP literal is not a name, so it is not put where a name belongs.
    let server_name = match &server.reality {
        Some(reality) => Some(reality.handshake.host.clone()),
        None => match &endpoint.host {
            Host::Domain(_) => Some(endpoint.host.clone()),
            Host::Ip(_) => None,
        },
    };

    Ok(TlsClient {
        server_name,
        alpn: server.alpn.clone(),
        insecure: false,
        fingerprint: None,
        reality,
        extra: RawParams::new(),
    })
}

/// The public key a client needs, from the private key a listener holds.
fn derived_public_key(server: &RealityServer) -> Result<Box<str>> {
    #[cfg(feature = "derive")]
    {
        server.derive_public_key()
    }

    #[cfg(not(feature = "derive"))]
    {
        let _ = server;

        Err(Error::field(
            ErrorKind::MissingField,
            "public_key (this build has no key derivation)",
        ))
    }
}

#[cfg(feature = "derive")]
impl RealityServer {
    /// Derive the public key a client needs from the private key a listener holds.
    ///
    /// Reality's key pair is X25519, so the client's half is a scalar multiplication away — which is
    /// the whole reason a server node can publish a subscription for itself (requirements D-7).
    pub fn derive_public_key(&self) -> Result<Box<str>> {
        use base64::Engine as _;

        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.private_key.as_str())
            .map_err(|_| Error::field(ErrorKind::InvalidBase64, "reality private_key"))?;

        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| Error::field(ErrorKind::InvalidValue, "reality private_key"))?;

        let secret = x25519_dalek::StaticSecret::from(bytes);
        let public = x25519_dalek::PublicKey::from(&secret);

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(public.as_bytes())
            .into_boxed_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::parse_link;

    const TROJAN: &str = "trojan://letmein@example.com:443?sni=example.com#Tokyo";
    const REALITY: &str = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=www.apple.com&pbk=Ezm0e82bCKdD9md8dOv_sy86-Co9Y1iJb5JUfaiFCk8&sid=ab12&flow=xtls-rprx-vision#Tokyo";

    fn client(link: &str) -> Node<Client> {
        parse_link(link).unwrap()
    }

    /// A certificate, which every node that terminates TLS itself has to be given.
    fn material_with_certificate() -> ListenerMaterial {
        ListenerMaterial {
            certificates: vec![Certificate::new(
                "/etc/ssl/fullchain.pem",
                "/etc/ssl/key.pem",
            )],
            ..ListenerMaterial::default()
        }
    }

    /// A single-password Shadowsocks link, and the same listener configured the 2022 way with a user
    /// list. The two shapes are what the conversion has to tell apart.
    const SHADOWSOCKS: &str = "ss://YWVzLTI1Ni1nY206aHVudGVyMg==@example.com:8388#Tokyo";

    fn password_of(node: Node<Client>) -> String {
        match node.protocol {
            Outbound::Shadowsocks(client) => client.password.as_str().to_string(),
            other => panic!("a Shadowsocks client: {other:?}"),
        }
    }

    #[test]
    fn a_single_password_listener_gives_back_the_password_it_holds() {
        // The classic shape keeps its credential in `password` and has no user list at all. A listener
        // whose only credential is in that field is still a listener with one credential.
        let listener = client(SHADOWSOCKS)
            .into_server(ListenerMaterial::default())
            .expect("a listener");

        assert_eq!(listener.client_count(), 1);

        let back = listener.into_client().expect("one credential, one client");

        assert_eq!(back.protocol, client(SHADOWSOCKS).protocol);
    }

    #[test]
    fn a_user_list_listener_gives_each_index_its_own_credential() {
        // A user list is indexed. Reading the password field in both cases is how `into_client_for(0)`
        // and `into_client_for(1)` came back with the same credential.
        let mut listener = client(SHADOWSOCKS)
            .into_server(ListenerMaterial::default())
            .expect("a listener");

        listener.protocol = Inbound::Shadowsocks(shadowsocks::Server {
            method: Box::from("2022-blake3-aes-128-gcm"),
            password: Secret::new(Box::from("server-key")),
            users: vec![
                shadowsocks::User {
                    password: Secret::new(Box::from("first")),
                    user_key: None,
                },
                shadowsocks::User {
                    password: Secret::new(Box::from("second")),
                    user_key: None,
                },
            ],
            plugin: None,
        });

        assert_eq!(listener.client_count(), 2);
        assert!(
            listener.clone().into_client().is_err(),
            "two credentials are not one"
        );

        assert_eq!(
            password_of(listener.clone().into_client_for(0).unwrap()),
            "first"
        );
        assert_eq!(
            password_of(listener.clone().into_client_for(1).unwrap()),
            "second"
        );
    }

    #[test]
    fn an_index_past_the_last_credential_is_refused() {
        let listener = client(TROJAN)
            .into_server(material_with_certificate())
            .expect("a listener");

        let error = listener
            .into_client_for(1)
            .expect_err("one credential, so there is no second");

        assert_eq!(error.kind(), ErrorKind::InvalidValue);
        assert!(error.reason().contains('1'), "{error}");
    }

    #[test]
    fn a_client_becomes_a_listener() {
        let original = client(TROJAN);
        let listener = original
            .clone()
            .into_server(material_with_certificate())
            .unwrap();

        assert_eq!(
            listener.endpoint, original.endpoint,
            "the advertised address is kept"
        );
        assert_eq!(
            listener.listen, original.endpoint,
            "and binds it when told nothing else"
        );
        assert_eq!(listener.client_count(), 1);

        let back = listener.into_client().unwrap();
        assert_eq!(back, original, "a trojan node survives the round trip");
        assert_eq!(back.id(), original.id());
    }

    #[test]
    fn a_listener_binds_where_it_is_told() {
        let material = ListenerMaterial {
            listen: Some(Endpoint::parse("127.0.0.1:8443").unwrap()),
            ..material_with_certificate()
        };

        let listener = client(TROJAN).into_server(material).unwrap();

        assert_eq!(listener.listen.to_string(), "127.0.0.1:8443");
        assert_eq!(listener.endpoint.to_string(), "example.com:443");
    }

    #[test]
    fn reality_asks_for_the_key_it_cannot_be_given() {
        let original = client(REALITY);

        assert_eq!(original.required_material(), vec!["reality private_key"]);

        let error = original
            .clone()
            .into_server(ListenerMaterial::default())
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingField);
        assert!(error.reason().contains("private_key"), "{}", error.reason());
    }

    #[test]
    #[cfg(feature = "derive")]
    fn a_public_key_derives_from_the_private_key() {
        // Both halves generated with `openssl genpkey -algorithm X25519`; the crate is not asked to
        // agree with itself here, only with openssl.
        let material = ListenerMaterial {
            reality_private_key: Some(Secret::new(Box::from(
                "KLZIViR1e4KCFx6gowgbpVv9W1IeOpwD0fLGOAYih20",
            ))),
            ..ListenerMaterial::default()
        };

        let original = client(REALITY);
        let listener = original.clone().into_server(material).unwrap();
        let back = listener.into_client().unwrap();

        assert_eq!(
            back, original,
            "the derived key is the one the link carried"
        );
        assert_eq!(back.id(), original.id());
    }

    #[test]
    fn a_plain_tls_listener_needs_a_certificate() {
        let original = client("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&sni=www.apple.com#Tokyo");

        assert_eq!(
            original.required_material(),
            vec!["certificate_path and key_path"]
        );

        let error = original
            .clone()
            .into_server(ListenerMaterial::default())
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingField);
        assert!(
            error.reason().contains("certificate_path"),
            "{}",
            error.reason()
        );

        let material = ListenerMaterial {
            certificates: vec![Certificate::new(
                "/etc/ssl/fullchain.pem",
                "/etc/ssl/key.pem",
            )],
            ..ListenerMaterial::default()
        };

        let listener = original.into_server(material).unwrap();
        let back = listener.into_client().unwrap();

        // The certificate paths stay where they belong — with the listener — and the name to verify
        // comes from the advertised address, because a listener has nowhere else to keep it. The
        // client's own `sni` is the one thing this conversion cannot carry back.
        let tls = back.tls.unwrap();
        assert_eq!(tls.server_name.unwrap().domain(), Some("example.com"));
        assert!(tls.reality.is_none());
        assert!(!tls.insecure);
    }

    #[test]
    fn a_protocol_that_cannot_be_served_says_so() {
        let error = client("snell://1.2.3.4:443?psk=PSK#Snell")
            .into_server(ListenerMaterial::default())
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnsupportedRole);
    }

    #[test]
    fn a_listener_with_several_credentials_needs_a_choice() {
        let listener = client("hysteria2://one@example.com:443#Tokyo")
            .into_server(material_with_certificate())
            .unwrap();

        let mut two = listener.clone();
        if let Inbound::Hysteria2(server) = &mut two.protocol {
            server.users.push(hysteria2::User {
                password: Secret::new(Box::from("two")),
            });
        }

        assert_eq!(two.client_count(), 2);
        assert_eq!(
            two.clone().into_client().unwrap_err().kind(),
            ErrorKind::InvalidValue
        );
        assert_eq!(
            two.into_client_for(1)
                .unwrap()
                .protocol
                .as_hysteria2()
                .unwrap()
                .password
                .as_str(),
            "two"
        );
    }

    #[test]
    #[cfg(feature = "derive")]
    fn only_a_listener_keeps_its_own_material() {
        let material = ListenerMaterial {
            reality_private_key: Some(Secret::new(Box::from(
                "KLZIViR1e4KCFx6gowgbpVv9W1IeOpwD0fLGOAYih20",
            ))),
            certificates: vec![Certificate::new(
                "/etc/ssl/fullchain.pem",
                "/etc/ssl/key.pem",
            )],
            ..ListenerMaterial::default()
        };

        let listener = client(REALITY).into_server(material).unwrap();
        let back = listener.into_client().unwrap();

        let tls = back.tls.unwrap();
        assert!(tls.reality.is_some(), "the public key came back");
        assert!(
            tls.fingerprint.is_none(),
            "a client's fingerprint is its own choice"
        );
        assert!(!tls.insecure);
    }
}
