//! Shadowsocks, including SIP002 and the 2022 ciphers.
//!
//! Two dialects live in the wild and both are parsed: SIP002, which carries `base64(method:password)`
//! in the userinfo, and the older form, which carries `base64(method:password@host:port)` as the
//! whole payload. The cipher list is not validated — it grows — so `method` is kept as the provider
//! spelled it.

use core::fmt;

use base64::{engine::general_purpose, Engine as _};

use crate::addr::Endpoint;
use crate::error::{Error, ErrorKind, Result};
use crate::identity::{Encode, Hasher};
use crate::link::{self, Link, Reader};
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{write_extra, write_shared, ClientLink, Kind, Protocol};
use crate::secret::Secret;

/// A Shadowsocks plugin, as SIP002 spells it: `obfs-local;obfs=http`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Plugin {
    /// The plugin's name.
    pub name: Box<str>,
    /// The plugin's options, in order.
    pub options: Vec<(Box<str>, Box<str>)>,
}

impl Plugin {
    /// Parse `name;key=value;key=value`.
    pub fn parse(input: &str) -> Self {
        let mut parts = input.split(';');
        let name = parts.next().unwrap_or_default().trim();
        let mut options = Vec::new();

        for option in parts {
            match option.split_once('=') {
                // `=` with nothing on either side is not an option, and the writer has no way to write
                // it back (it writes `;` and stops), so keeping it here would make the plugin change
                // the first time it is written out. The fuzzer found that shape — `obfs;;=http…` — and
                // an option that carries nothing is worth less than an identity that holds.
                Some((key, value)) if key.trim().is_empty() && value.trim().is_empty() => {}
                Some((key, value)) => options.push((key.trim().into(), value.trim().into())),
                None if !option.trim().is_empty() => {
                    options.push((option.trim().into(), Box::from("")))
                }
                None => {}
            }
        }

        Self {
            name: name.into(),
            options,
        }
    }

    /// The value of an option.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(key, _)| key.as_ref() == name)
            .map(|(_, value)| value.as_ref())
    }
}

impl fmt::Display for Plugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;

        for (key, value) in &self.options {
            // An empty option is not written, because the reader drops it: one rule on both sides.
            if key.is_empty() && value.is_empty() {
                continue;
            }

            write!(f, ";{key}")?;

            if !value.is_empty() {
                write!(f, "={value}")?;
            }
        }

        Ok(())
    }
}

/// A client's Shadowsocks credentials.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// The cipher.
    pub method: Box<str>,
    /// The password, the pre-shared key for the 2022 ciphers.
    pub password: Secret<Box<str>>,
    /// The plugin, when the node uses one.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub plugin: Option<Plugin>,
}

/// One password a Shadowsocks listener accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    /// The password.
    pub password: Secret<Box<str>>,
    /// The user's own pre-shared key, for the 2022 ciphers.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub user_key: Option<Secret<Box<str>>>,
}

/// A Shadowsocks listener.
///
/// Both shapes exist and both are modelled: older cores take a single `password`, newer ones take
/// `users`. A listener configured one way must not be silently rewritten into the other.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Server {
    /// The cipher.
    pub method: Box<str>,
    /// The single password, when the listener is configured that way.
    pub password: Secret<Box<str>>,
    /// The users, when the listener is configured that way.
    pub users: Vec<User>,
    /// The plugin the listener expects.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub plugin: Option<Plugin>,
}

impl Client {
    /// Build one.
    pub fn new(method: impl Into<Box<str>>, password: impl Into<Box<str>>) -> Self {
        Self {
            method: method.into(),
            password: Secret::new(password.into()),
            plugin: None,
        }
    }

    /// Whether the node can be dialled at all.
    pub fn is_complete(&self) -> bool {
        !self.method.is_empty() && !self.password.is_empty()
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::Shadowsocks
    }

    fn scheme(&self) -> &str {
        <Self as ClientLink>::SCHEME
    }

    fn has_credentials(&self) -> bool {
        !self.password.is_empty()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl Protocol for Server {
    fn kind(&self) -> Kind {
        Kind::Shadowsocks
    }

    fn scheme(&self) -> &str {
        <Client as ClientLink>::SCHEME
    }

    fn has_credentials(&self) -> bool {
        !self.password.is_empty() || !self.users.is_empty()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl ClientLink for Client {
    const KIND: Kind = Kind::Shadowsocks;
    const SCHEME: &'static str = "ss";

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        if !self.is_complete() {
            return Err(Error::field(ErrorKind::MissingField, "method or password"));
        }

        let mut first = true;
        let mut userinfo =
            String::with_capacity(self.method.len() + self.password.as_str().len() + 1);
        userinfo.push_str(&self.method);
        userinfo.push(':');
        userinfo.push_str(self.password.as_str());

        // SIP002: the userinfo is base64, so that a password may contain anything.
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(userinfo.as_bytes());

        link::begin(out, Self::SCHEME, &encoded, &node.endpoint);

        if let Some(plugin) = self
            .plugin
            .as_ref()
            .filter(|plugin| !plugin.name.is_empty())
        {
            let mut text = String::new();
            let _ = fmt::Write::write_fmt(&mut text, format_args!("{plugin}"));
            link::param(out, &mut first, "plugin", Some(&text));
        }

        write_shared(node, out, &mut first);
        write_extra(&node.extra, out, &mut first);
        link::finish(out, node.name.as_str());

        Ok(())
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.text(&self.method);
        out.text(self.password.as_str());
        out.optional(self.plugin.as_ref().map(|plugin| plugin.name.as_ref()));

        // The options are as much of the plugin as its name: `v2ray-plugin?mode=websocket` and
        // `v2ray-plugin?mode=quic` do not dial the same way.
        if let Some(plugin) = &self.plugin {
            out.each(&plugin.options, |out, (name, value)| {
                out.text(name);
                out.text(value);
            });
        }
    }
}

impl Encode for Server {
    fn encode(&self, out: &mut Hasher) {
        out.text(&self.method);
        out.text(self.password.as_str());
        out.each(&self.users, |out, user| out.text(user.password.as_str()));
        // The listener knows which plugin it expects; a node without one is a different node.
        out.optional(self.plugin.as_ref().map(|plugin| plugin.name.as_ref()));

        if let Some(plugin) = &self.plugin {
            out.each(&plugin.options, |out, (name, value)| {
                out.text(name);
                out.text(value);
            });
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("method", &self.method)
            .field("password", &self.password)
            .field("plugin", &self.plugin)
            .finish()
    }
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("method", &self.method)
            .field("password", &self.password)
            .field("users", &self.users)
            .finish()
    }
}

/// Parse either dialect. Returns an endpoint when the link kept it inside the payload.
pub(crate) fn parse(
    link: &Link<'_>,
    reader: &mut Reader<'_>,
    userinfo: &str,
) -> Result<(Option<Endpoint>, Client)> {
    let plugin = reader.owned("plugin").filter(|value| !value.is_empty());

    let client = |decoded: &str| -> Result<Client> {
        let (method, password) = decoded
            .split_once(':')
            .ok_or_else(|| Error::field(ErrorKind::MissingField, "method and password"))?;

        Ok(Client {
            method: method.trim().into(),
            password: Secret::new(password.into()),
            // A plugin with no name is not a plugin: there is nothing to dial with, and the writer has
            // no way to write it back that the reader would keep — `plugin=;;;;;` parsed into one, went
            // out as a bare `plugin`, and was dropped on the way back in. The fuzzer found it.
            plugin: plugin
                .as_ref()
                .map(|value| Plugin::parse(value))
                .filter(|plugin| !plugin.name.is_empty()),
        })
    };

    // SIP002 with a plain address: the credentials are the userinfo, and the address parses as one.
    if link.port().is_some() {
        return Ok((None, client(&decode_credentials(userinfo)?)?));
    }

    // No port, so something is base64. Decoding the host part is enough for SIP002, which may encode
    // the address; the older dialect puts the address inside the blob instead, and its blob can
    // contain a slash, which the link reader has already cut off — hence the second attempt.
    let decoded =
        decode_credentials(link.host()).or_else(|_| decode_credentials(legacy_payload(link)))?;

    match decoded.rsplit_once('@') {
        Some((credentials, address)) => Ok((Some(Endpoint::parse(address)?), client(credentials)?)),
        None => Ok((
            Some(Endpoint::parse(&decoded)?),
            client(&decode_credentials(userinfo)?)?,
        )),
    }
}

/// The payload of the older dialect: everything after the scheme, without the name.
fn legacy_payload<'a>(link: &'a Link<'_>) -> &'a str {
    let raw = link.raw();
    let start = raw.find("://").map(|index| index + 3).unwrap_or(0);
    let rest = &raw[start..];

    match rest.split_once('#') {
        Some((payload, _)) => payload,
        None => rest,
    }
}

/// Base64, in whichever alphabet the provider used, with or without padding.
fn decode_credentials(input: &str) -> Result<String> {
    let input = input.trim();

    for engine in [
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::STANDARD,
        &general_purpose::URL_SAFE_NO_PAD,
        &general_purpose::URL_SAFE,
    ] {
        if let Ok(bytes) = engine.decode(input) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Ok(text);
            }
        }
    }

    Err(Error::new(
        ErrorKind::InvalidBase64,
        "the credentials are not base64",
    ))
}

impl crate::identity::private::Sealed for Client {}
impl crate::identity::private::Sealed for Server {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{parse_link, write_link, Kind};

    /// `aes-256-gcm:secret` and `192.0.2.10:1080`, in SIP002's alphabet, without a fragment.
    fn sip002_base() -> String {
        let credentials = general_purpose::URL_SAFE_NO_PAD.encode(b"aes-256-gcm:secret");
        let address = general_purpose::URL_SAFE_NO_PAD.encode(b"192.0.2.10:1080");

        format!("ss://{credentials}@{address}")
    }

    #[test]
    fn sip002_is_parsed() {
        let node = parse_link(&format!("{}#SIP002", sip002_base())).unwrap();
        let shadowsocks = node.protocol.as_shadowsocks().unwrap();

        assert_eq!(node.protocol.kind(), Kind::Shadowsocks);
        assert_eq!(shadowsocks.method.as_ref(), "aes-256-gcm");
        assert_eq!(shadowsocks.password.as_str(), "secret");
        assert_eq!(node.endpoint.to_string(), "192.0.2.10:1080");
    }

    #[test]
    fn the_older_dialect_is_parsed_too() {
        let payload =
            general_purpose::STANDARD_NO_PAD.encode(b"aes-256-gcm:secret@192.0.2.10:1080");
        let node = parse_link(&format!("ss://{payload}#Legacy")).unwrap();
        let shadowsocks = node.protocol.as_shadowsocks().unwrap();

        assert_eq!(shadowsocks.method.as_ref(), "aes-256-gcm");
        assert_eq!(shadowsocks.password.as_str(), "secret");
        assert_eq!(node.endpoint.to_string(), "192.0.2.10:1080");
        assert_eq!(node.name.as_str(), "Legacy");
    }

    #[test]
    fn an_option_that_carries_nothing_does_not_change_the_plugin() {
        // `obfs;;=http` — an empty segment and an `=` with nothing on either side. The empty `=` was
        // kept as an option the writer could not write back, so the plugin changed the first time it
        // was written out (a fuzzer finding). An option with no key and no value is not an option.
        let plugin = Plugin::parse("obfs-local;obfs;;=;=http%25TU");
        assert_eq!(
            plugin.options,
            vec![
                (Box::from("obfs"), Box::from("")),
                (Box::from(""), Box::from("http%25TU")),
            ]
        );
        assert_eq!(Plugin::parse(&plugin.to_string()), plugin);
    }

    #[test]
    fn a_plugin_survives_a_round_trip() {
        let text = format!(
            "{}?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#Obfs",
            sip002_base()
        );
        let node = parse_link(&text).unwrap();

        let plugin = node
            .protocol
            .as_shadowsocks()
            .unwrap()
            .plugin
            .as_ref()
            .unwrap();
        assert_eq!(plugin.name.as_ref(), "obfs-local");
        assert_eq!(plugin.get("obfs"), Some("http"));

        let again = parse_link(&write_link(&node).unwrap()).unwrap();

        assert_eq!(again, node);
    }

    #[test]
    fn a_link_that_is_not_base64_is_reported() {
        let error = parse_link("ss://not-base64!!@1.2.3.4:443#X").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidBase64);
    }

    #[test]
    fn a_listener_can_be_either_shape() {
        let single = Server {
            method: "2022-blake3-aes-128-gcm".into(),
            password: Secret::new("KEY".into()),
            users: Vec::new(),
            plugin: None,
        };
        let multi = Server {
            users: vec![User {
                password: Secret::new("KEY".into()),
                user_key: Some(Secret::new("USERKEY".into())),
            }],
            ..single.clone()
        };

        assert!(Protocol::has_credentials(&single));
        assert!(Protocol::has_credentials(&multi));
        assert_ne!(
            single, multi,
            "the two shapes are not the same configuration"
        );
    }
}
