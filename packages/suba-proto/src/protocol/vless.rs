//! VLESS.
//!
//! Field names are Xray's: `id`, `flow`, `encryption`. A listener holds `users` where a client holds
//! a single `id`, because that is what the protocol actually does — and the two directions share the
//! `Flow` type, because that part really is the same.

use core::fmt;

use crate::error::{Error, ErrorKind, Result};
use crate::identity::{Encode, Hasher};
use crate::link::{self, Reader};
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{write_extra, write_shared, ClientLink, Kind, Protocol};
use crate::secret::Secret;
use crate::uuid::Uuid;

/// The XTLS flow a VLESS user is allowed to use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Flow {
    /// No flow.
    #[default]
    None,
    /// `xtls-rprx-vision`, what a Reality node uses.
    XtlsRprxVision,
    /// `xtls-rprx-direct`, the older splice.
    XtlsRprxDirect,
}

impl Flow {
    /// The spelling a link uses.
    pub const fn as_str(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::XtlsRprxVision => Some("xtls-rprx-vision"),
            Self::XtlsRprxDirect => Some("xtls-rprx-direct"),
        }
    }

    /// Parse a link spelling. An unknown flow is kept as [`Flow::None`] by [`Flow::parse`]'s caller:
    /// a node with a flow this build does not know is a node to dial without one, not a parse error.
    pub fn parse(input: &str) -> Option<Self> {
        match input {
            "" | "none" => Some(Self::None),
            "xtls-rprx-vision" => Some(Self::XtlsRprxVision),
            "xtls-rprx-direct" => Some(Self::XtlsRprxDirect),
            _ => None,
        }
    }
}

impl fmt::Display for Flow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str().unwrap_or("none"))
    }
}

/// A client's VLESS credentials.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// The user id.
    pub id: Secret<Uuid>,
    /// The flow.
    pub flow: Flow,
    /// The encryption method. `None` means what every modern link means by it: `none`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub encryption: Option<Box<str>>,
}

/// One user of a VLESS listener.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    /// The user id.
    pub id: Secret<Uuid>,
    /// The flow this user may use.
    pub flow: Flow,
    /// The Xray user level, which decides policy.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub level: Option<u8>,
}

/// A VLESS listener.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Server {
    /// The users the listener accepts.
    pub users: Vec<User>,
    /// The decryption method a listener announces.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub decryption: Option<Box<str>>,
}

impl Client {
    /// Build one.
    pub fn new(id: Uuid) -> Self {
        Self {
            id: Secret::new(id),
            flow: Flow::None,
            encryption: None,
        }
    }

    /// The UUID, for the places that need it.
    pub fn uuid(&self) -> &Uuid {
        self.id.expose()
    }
}

// No `Default`: an empty listener is a legitimate state, but it is a decision, and a derive would
// let it happen by accident.
#[allow(clippy::new_without_default)]
impl Server {
    /// Build one with no users.
    pub fn new() -> Self {
        Self {
            users: Vec::new(),
            decryption: None,
        }
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::Vless
    }

    fn scheme(&self) -> &str {
        <Self as ClientLink>::SCHEME
    }

    fn has_credentials(&self) -> bool {
        !self.id.expose().is_nil()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl Protocol for Server {
    fn kind(&self) -> Kind {
        Kind::Vless
    }

    fn scheme(&self) -> &str {
        <Client as ClientLink>::SCHEME
    }

    fn has_credentials(&self) -> bool {
        !self.users.is_empty()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl ClientLink for Client {
    const KIND: Kind = Kind::Vless;
    const SCHEME: &'static str = "vless";

    fn from_query(reader: &mut Reader<'_>, userinfo: &str) -> Result<Self> {
        // VLESS puts the id in the userinfo; a few dialects repeat it as `id`.
        let id = reader.owned("id").unwrap_or_else(|| Box::from(userinfo));

        if id.is_empty() {
            return Err(Error::field(ErrorKind::MissingField, "id"));
        }

        Ok(Self {
            id: Secret::new(Uuid::parse(&id)?),
            flow: match reader.owned("flow") {
                Some(value) => match Flow::parse(&value) {
                    Some(flow) => flow,
                    None => {
                        // A flow from a newer client is not a flow to drop: the parameter goes back
                        // unclaimed and travels in the extras, written out as the provider wrote it.
                        reader.release("flow");

                        Flow::None
                    }
                },
                None => Flow::None,
            },
            encryption: reader.owned("encryption").filter(|value| !value.is_empty()),
        })
    }

    fn write_params(&self, out: &mut String, first: &mut bool) -> Result<()> {
        link::param(out, first, "encryption", self.encryption.as_deref());
        link::param(out, first, "flow", self.flow.as_str());

        Ok(())
    }

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        let mut first = true;

        link::begin_display(out, Self::SCHEME, self.id.expose(), &node.endpoint);
        self.write_params(out, &mut first)?;
        write_shared(node, out, &mut first);
        write_extra(&node.extra, out, &mut first);
        link::finish(out, node.name.as_str());

        Ok(())
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.display(self.id.expose());
        out.optional(self.flow.as_str());
        out.optional(self.encryption.as_deref());
    }
}

impl Encode for Server {
    fn encode(&self, out: &mut Hasher) {
        out.each(&self.users, |out, user| {
            out.display(user.id.expose());
            out.optional(user.flow.as_str());
            out.number(user.level.unwrap_or(0) as u64);
        });
        out.optional(self.decryption.as_deref());
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("id", &self.id)
            .field("flow", &self.flow)
            .field("encryption", &self.encryption)
            .finish()
    }
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("users", &self.users)
            .field("decryption", &self.decryption)
            .finish()
    }
}

impl crate::identity::private::Sealed for Client {}
impl crate::identity::private::Sealed for Server {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{parse_link, write_link};

    const REALITY: &str = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision&type=ws&path=%2Fws#Tokyo";

    #[test]
    fn a_reality_link_parses_into_both_halves_of_the_model() {
        let node = parse_link(REALITY).unwrap();

        let vless = node.protocol.as_vless().unwrap();
        assert_eq!(
            vless.uuid().to_string(),
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(vless.flow, Flow::XtlsRprxVision);

        let tls = node.tls.as_ref().unwrap();
        let reality = tls.reality.as_ref().unwrap();
        assert_eq!(reality.public_key.as_str(), "PUBKEY");
        assert_eq!(reality.short_id.as_ref().unwrap().as_str(), "ab12");
        assert_eq!(tls.fingerprint.as_ref().unwrap().as_str(), "chrome");
        assert_eq!(node.name.as_str(), "Tokyo");
    }

    #[test]
    fn a_reality_node_hashes_and_prints_without_leaking() {
        let node = parse_link(REALITY).unwrap();
        let rendered = format!("{node:?}");

        assert!(
            !rendered.contains("11111111-2222-3333-4444-555555555555"),
            "{rendered}"
        );
        assert!(!rendered.contains("PUBKEY"), "{rendered}");
        assert!(!node.id().is_empty());
    }

    #[test]
    fn a_link_survives_a_round_trip() {
        let node = parse_link(REALITY).unwrap();
        let again = parse_link(&write_link(&node).unwrap()).unwrap();

        assert_eq!(again, node);
    }

    #[test]
    fn a_listener_holds_users_and_a_client_holds_one_id() {
        let server = Server {
            users: vec![
                User {
                    id: Secret::new(Uuid::parse("11111111-2222-3333-4444-555555555555").unwrap()),
                    flow: Flow::XtlsRprxVision,
                    level: None,
                },
                User {
                    id: Secret::new(Uuid::parse("99999999-2222-3333-4444-555555555555").unwrap()),
                    flow: Flow::None,
                    level: Some(1),
                },
            ],
            decryption: None,
        };

        assert_eq!(server.users.len(), 2);
        assert!(Protocol::has_credentials(&server));
        assert_eq!(
            core::mem::size_of::<Secret<Uuid>>(),
            core::mem::size_of::<Uuid>(),
            "a secret is not bigger than the value it wraps"
        );
    }

    #[test]
    fn a_link_without_a_uuid_is_reported() {
        let error = parse_link("vless://example.com:443#Tokyo").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingField);
    }
}
