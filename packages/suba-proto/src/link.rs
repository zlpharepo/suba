//! The share-link grammar, borrowed.
//!
//! A share link is
//!
//! ```text
//! scheme://[userinfo@]host[:port][/path][?query][#fragment]
//! ```
//!
//! with two dialect quirks the model has to live with: some schemes put a base64 blob where the
//! userinfo goes, and some put the whole payload there and no authority at all. [`Link`] therefore
//! only takes the text apart — it never decodes, validates or allocates. Each protocol module reads
//! the pieces it recognises and hands back what it did not, so a provider's parameters survive a
//! round trip even when this build has never heard of them.

use core::fmt::{self, Write as _};

use crate::addr::{Endpoint, Host, Port};
use crate::error::{Error, ErrorKind, Result};
use crate::params::RawParams;
use crate::percent;
use crate::prelude::*;

/// A share link, taken apart without allocating.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Link<'a> {
    raw: &'a str,
    scheme: &'a str,
    userinfo: &'a str,
    host: &'a str,
    port: Option<&'a str>,
    path: &'a str,
    query: &'a str,
    fragment: &'a str,
}

impl<'a> Link<'a> {
    /// Take a link apart.
    ///
    /// The only thing required is a scheme: everything else is optional, because the dialects
    /// disagree about which parts must be present.
    pub fn parse(input: &'a str) -> Result<Self> {
        let input = input.trim();
        let (scheme, rest) = input
            .split_once("://")
            .ok_or_else(|| Error::new(ErrorKind::MalformedLink, "the text has no scheme"))?;

        if !scheme.starts_with(|byte: char| byte.is_ascii_alphabetic())
            || !scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        {
            return Err(Error::owned(
                ErrorKind::MalformedLink,
                format!("'{scheme}' is not a scheme"),
            ));
        }

        let (before_fragment, fragment) = split_once_or(rest, '#', "");
        let (before_query, query) = split_once_or(before_fragment, '?', "");
        let (userinfo, authority) = match before_query.split_once('@') {
            Some((userinfo, authority)) => (userinfo, authority),
            None => ("", before_query),
        };
        let (authority, path) = split_once_or(authority, '/', "");

        let (host, port) = match authority.strip_prefix('[') {
            Some(rest) => match rest.split_once(']') {
                Some((inside, after)) => {
                    let port = after.strip_prefix(':').filter(|port| !port.is_empty());

                    (inside, port)
                }
                None => (authority, None),
            },
            None => match authority.rsplit_once(':') {
                Some((host, port))
                    if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
                {
                    (host, Some(port))
                }
                _ => (authority, None),
            },
        };

        Ok(Self {
            raw: input,
            scheme,
            userinfo,
            host,
            port,
            path,
            query,
            fragment,
        })
    }

    /// The scheme, lowercased by comparison only: [`Link::scheme_is`] is the case-insensitive test.
    pub const fn scheme(&self) -> &'a str {
        self.scheme
    }

    /// Whether the scheme is `name`, ignoring case.
    pub fn scheme_is(&self, name: &str) -> bool {
        self.scheme.len() == name.len() && self.scheme.eq_ignore_ascii_case(name)
    }

    /// Everything before the host, which some dialects use for a payload.
    pub const fn userinfo(&self) -> &'a str {
        self.userinfo
    }

    /// The host, without brackets and without the port.
    pub const fn host(&self) -> &'a str {
        self.host
    }

    /// The port, as written.
    pub const fn port(&self) -> Option<&'a str> {
        self.port
    }

    /// The path, if the link has one.
    pub const fn path(&self) -> &'a str {
        self.path
    }

    /// The query.
    pub fn query(&self) -> Query<'a> {
        Query { raw: self.query }
    }

    /// The fragment, which is where the display name lives.
    pub const fn fragment(&self) -> &'a str {
        self.fragment
    }

    /// The link as it arrived.
    pub const fn raw(&self) -> &'a str {
        self.raw
    }

    /// The address, when the link states one.
    pub fn endpoint(&self) -> Result<Endpoint> {
        let port = self
            .port
            .ok_or_else(|| Error::new(ErrorKind::MissingField, "the link states no port"))?;

        Ok(Endpoint {
            host: Host::parse(self.host)?,
            port: Port::parse(port)?,
        })
    }

    /// The display name: the fragment, decoded, borrowed when it needs no decoding.
    pub fn name(&self) -> Cow<'a, str> {
        percent::decode(self.fragment)
    }
}

impl fmt::Debug for Link<'_> {
    /// Deliberately thin: a link carries credentials, so a debug print shows the scheme and nothing
    /// else.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Link")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

/// The query string of a link.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Query<'a> {
    raw: &'a str,
}

impl<'a> Query<'a> {
    /// Every pair, in order, with the values still percent-encoded.
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.raw
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((name, value)) => (name, value),
                None => (pair, ""),
            })
    }

    /// A value, still percent-encoded. `None` means absent; `Some("")` means present and empty,
    /// which in these dialects is how a flag is spelled.
    pub fn raw(&self, name: &str) -> Option<&'a str> {
        self.iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value)
    }

    /// A value, decoded, borrowed when it needs no decoding.
    pub fn get(&self, name: &str) -> Option<Cow<'a, str>> {
        self.raw(name).map(percent::decode)
    }

    /// A value decoded into a string, or the default when it is absent or empty.
    pub fn string(&self, name: &str, default: &str) -> String {
        match self.raw(name) {
            Some(value) if !value.is_empty() => percent::decode_to_string(value),
            _ => default.to_string(),
        }
    }

    /// Whether the name is present at all.
    pub fn contains(&self, name: &str) -> bool {
        self.raw(name).is_some()
    }

    /// A flag: present with no value, or present with a truthy one.
    pub fn flag(&self, names: &[&str]) -> bool {
        names.iter().any(|name| match self.raw(name) {
            None => false,
            Some(value) => !matches!(value, "0" | "false" | "no"),
        })
    }

    /// The first present value among `names`, decoded.
    pub fn any(&self, names: &[&str]) -> Option<Cow<'a, str>> {
        names.iter().find_map(|name| self.get(name))
    }

    /// Take every parameter into owned pairs, in order.
    pub fn to_params(&self) -> RawParams {
        let mut params = RawParams::new();

        for (name, value) in self.iter() {
            params.push(
                &percent::decode_to_string(name),
                &percent::decode_to_string(value),
            );
        }

        params
    }
}

impl fmt::Debug for Query<'_> {
    /// Names only: a query can carry a key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();

        for (name, _) in self.iter() {
            list.entry(&name);
        }

        list.finish()
    }
}

/// Reads a link's parameters, remembering which it was asked for.
///
/// The reason this exists rather than a map: a parameter some protocol does claim is read straight
/// out of the link, borrowed, and only the ones nobody claimed are copied into a [`RawParams`]. A
/// trojan link with six known parameters therefore allocates for its password and for nothing else.
#[derive(Clone)]
pub struct Reader<'a> {
    query: Query<'a>,
    taken: Vec<&'a str>,
}

impl<'a> Reader<'a> {
    /// A reader over a query.
    pub fn new(query: Query<'a>) -> Self {
        Self {
            query,
            // Reserved up front: a link with more parameters than this is rare, and one predictable
            // allocation is cheaper to reason about than a vector that grows.
            taken: Vec::with_capacity(12),
        }
    }

    /// A value by name, still encoded, marked as claimed.
    pub fn raw(&mut self, name: &str) -> Option<&'a str> {
        let (key, value) = self.query.iter().find(|(key, _)| *key == name)?;

        if !self.taken.contains(&key) {
            self.taken.push(key);
        }

        Some(value)
    }

    /// The first present value among `names`, still encoded.
    pub fn any_raw(&mut self, names: &[&str]) -> Option<&'a str> {
        names.iter().find_map(|name| self.raw(name))
    }

    /// A value by name, decoded.
    pub fn text(&mut self, name: &str) -> Option<Cow<'a, str>> {
        self.raw(name).map(percent::decode)
    }

    /// A value as an owned, immutable string, which is what the model stores.
    ///
    /// `Box<str>` rather than `String`: these values are never appended to again, and the box is one
    /// word smaller than a string with a capacity. Borrowed values are boxed directly rather than
    /// going through `into_owned`, which would allocate a `String` and then move it again.
    ///
    /// ### What a read consumes
    ///
    /// A parameter is consumed when the read makes sense of it, and not otherwise: a recognised name whose
    /// value this build cannot interpret — `up=fast`, `fp=chrome999` — is [released](Self::release) at
    /// the call site and travels in the extras, so the link keeps saying what the provider wrote and
    /// the model says it does not know. A duplicate name is read in the order it arrived, and only its
    /// first occurrence is consumed; the rest are extras. `?flag` and `?flag=` are one parameter with
    /// an empty value, and an empty value is written back as the bare name: `?flag`.
    pub fn owned(&mut self, name: &str) -> Option<Box<str>> {
        self.raw(name).map(|value| match percent::decode(value) {
            Cow::Borrowed(value) => Box::from(value),
            Cow::Owned(value) => value.into_boxed_str(),
        })
    }

    /// The first present value among `names`, owned.
    pub fn any_owned(&mut self, names: &[&str]) -> Option<Box<str>> {
        names
            .iter()
            .find_map(|name| self.raw(name).map(|value| (*name, value)))
            .map(|(_, value)| match percent::decode(value) {
                Cow::Borrowed(value) => Box::from(value),
                Cow::Owned(value) => value.into_boxed_str(),
            })
    }

    /// A number by name, claiming the parameter only if the value reads as one.
    ///
    /// A value that is not a number reads as absent — `up=fast` is a provider saying something this
    /// build cannot use, and inventing a zero would be worse than admitting it — but absent is not the
    /// same as thrown away: the parameter stays unclaimed, so it is copied into the extras and written
    /// back in the shape it arrived in.
    pub fn number(&mut self, name: &str) -> Option<u64> {
        let value = self.raw(name)?;

        match Self::number_at(value) {
            Some(number) => Some(number),
            None => {
                self.release(name);

                None
            }
        }
    }

    /// The number at the start of a value, ignoring whatever unit follows it.
    ///
    /// Links are written by hand and by other tools: hysteria2's own documentation writes
    /// `up=100 mbps`, and port hopping is written as `hop-interval=30s`. The model stores the number,
    /// so a unit is stripped rather than the parameter dropped — dropping it would make the round
    /// trip lossy for the links most likely to carry it.
    fn number_at(value: &str) -> Option<u64> {
        let digits: String = value
            .trim()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();

        if digits.is_empty() {
            return None;
        }

        digits.parse().ok()
    }

    /// Whether a flag is set, under any of its spellings.
    pub fn flag(&mut self, names: &[&str]) -> bool {
        names.iter().any(|name| match self.raw(name) {
            None => false,
            Some(value) => !matches!(value, "0" | "false" | "no"),
        })
    }

    /// Give a name back.
    ///
    /// For a value that read as text but not as anything the model can hold — a fingerprint profile
    /// from a newer client, a short id that is not hex, a name that is not a name. The parameter is not
    /// this build's to drop, so the occurrence goes back to being unclaimed and travels with the
    /// extras, where it is written out in the shape it arrived in.
    pub fn release(&mut self, name: &str) {
        self.taken.retain(|key| *key != name);
    }

    /// Give back whichever of `names` was read.
    pub fn release_any(&mut self, names: &[&str]) {
        self.taken.retain(|key| !names.contains(key));
    }

    /// Whatever no one claimed.
    ///
    /// This is what makes a round trip lossless: a provider's parameters are copied here rather than
    /// dropped, in the order they arrived, with one rule that is not about loss. A name contributes
    /// **one occurrence at most, its first**, because the first is the one a later read interprets: a
    /// read name is left out — the model now expresses it — and the duplicates of it are dropped
    /// rather than copied.
    ///
    /// Copying a duplicate is what makes writing a link change what it says. A provider writes
    /// `type=tcp&type=grpc`: the model holds `tcp` and the leftover says `grpc`, and the link that
    /// comes back out means gRPC to whoever reads it next — the same node, a different node. The
    /// reverse case is quieter and worse: `flow=xtls-rpycp&flow=xtls-rprx-vision` reads as no flow at
    /// all (the first value is not one this build knows), so the model holds nothing — and writing it
    /// back with the second value would hand the next read a flow it takes. An unread name keeps its
    /// first occurrence and loses its later ones for the same reason: what a duplicate carries is
    /// something the link does not mean.
    pub fn leftover(&self) -> RawParams {
        let mut params = RawParams::new();
        // Only allocated for a duplicate name, which a link should not have.
        let mut seen: Vec<&str> = Vec::new();

        for (key, value) in self.query.iter() {
            if seen.contains(&key) {
                continue;
            }

            seen.push(key);

            if self.taken.contains(&key) {
                continue;
            }

            params.push_owned(
                percent::decode_owned(key).into_boxed_str(),
                percent::decode_owned(value).into_boxed_str(),
            );
        }

        params
    }
}

/// Start a link: `scheme://userinfo@host:port`.
pub fn begin(out: &mut String, scheme: &str, userinfo: &str, endpoint: &Endpoint) {
    out.push_str(scheme);
    out.push_str("://");

    if !userinfo.is_empty() {
        percent::encode_into(userinfo, out);
        out.push('@');
    }

    endpoint.write_to(out);
}

/// Start a link whose userinfo the caller has already percent-encoded.
///
/// For a dialect whose userinfo is two fields joined by a separator — `user:pass` — the separator must
/// survive while the fields are encoded, so the caller encodes each half and this writes the pair as
/// it is. An empty userinfo writes no `@`, which is what a link without credentials looks like.
pub fn begin_encoded(out: &mut String, scheme: &str, encoded_userinfo: &str, endpoint: &Endpoint) {
    out.push_str(scheme);
    out.push_str("://");

    if !encoded_userinfo.is_empty() {
        out.push_str(encoded_userinfo);
        out.push('@');
    }

    endpoint.write_to(out);
}

/// Start a link whose userinfo is not a `&str`: a UUID, a [`Secret`](crate::Secret)'s contents.
///
/// Encoded exactly like [`begin`], through a [`percent::Encoder`] so the value never needs a
/// temporary. There is no unencoded way to start a link: a userinfo written verbatim is how a
/// password containing `@` moves the host, or one containing `%26` grows a parameter.
pub fn begin_display(
    out: &mut String,
    scheme: &str,
    userinfo: &dyn fmt::Display,
    endpoint: &Endpoint,
) {
    out.push_str(scheme);
    out.push_str("://");
    percent::encode_display(userinfo, out);
    out.push('@');
    endpoint.write_to(out);
}

/// Append a parameter whose value is a `Display`: a host, an ALPN list, a number.
///
/// Name and value are both percent-encoded, through a [`percent::Encoder`] so neither needs a
/// temporary. Nothing is written verbatim: a host is not a safe value — `Host::parse` accepts `&`
/// and `=` — and a value written as it stands is how `sni=good%26insecure%3D1` turns into an SNI of
/// `good` plus a flag that disables certificate verification.
pub fn param_display(out: &mut String, first: &mut bool, name: &str, value: &dyn fmt::Display) {
    out.push(if *first { '?' } else { '&' });
    *first = false;
    percent::encode_into(name, out);
    out.push('=');
    let _ = write!(percent::Encoder::new(out), "{value}");
}

/// Append a numeric parameter, if there is one.
pub fn number(out: &mut String, first: &mut bool, name: &str, value: Option<u64>) {
    if let Some(value) = value {
        param_display(out, first, name, &value);
    }
}

/// Append a query parameter: `?name=value`, or `?name` when the value is empty.
///
/// Name and value are both percent-encoded. The name matters as much as the value: an unmodelled
/// parameter keeps the provider's spelling, and a key containing `&` written verbatim turns one
/// parameter into two on the way back in.
pub fn param(out: &mut String, first: &mut bool, name: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };

    out.push(if *first { '?' } else { '&' });
    *first = false;
    percent::encode_into(name, out);

    if !value.is_empty() {
        out.push('=');
        percent::encode_into(value, out);
    }
}

/// Finish a link with its display name.
pub fn finish(out: &mut String, name: &str) {
    if name.is_empty() {
        return;
    }

    out.push('#');
    percent::encode_into(name, out);
}

fn split_once_or<'a>(
    input: &'a str,
    separator: char,
    fallback: &'static str,
) -> (&'a str, &'a str) {
    match input.split_once(separator) {
        Some((before, after)) => (before, after),
        None => (input, fallback),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_a_full_link_apart() {
        let link = Link::parse("vless://uuid@example.com:443/path?a=1&b=two#Tokyo%20Two").unwrap();

        assert!(link.scheme_is("VLESS"));
        assert_eq!(link.userinfo(), "uuid");
        assert_eq!(link.host(), "example.com");
        assert_eq!(link.port(), Some("443"));
        assert_eq!(link.path(), "path");
        assert_eq!(link.query().raw("b"), Some("two"));
        assert_eq!(link.name(), "Tokyo Two");
    }

    #[test]
    fn a_bracketed_ipv6_does_not_lose_its_port() {
        let link = Link::parse("trojan://pw@[2605:52c0:2:129::1]:8443#Node").unwrap();

        assert_eq!(link.host(), "2605:52c0:2:129::1");
        assert_eq!(link.port(), Some("8443"));
        assert_eq!(
            link.endpoint().unwrap().to_string(),
            "[2605:52c0:2:129::1]:8443"
        );
    }

    #[test]
    fn a_link_with_nothing_but_a_scheme_still_parses() {
        let link = Link::parse("snell://host:443#x").unwrap();

        assert_eq!(link.host(), "host");
        assert_eq!(link.query().raw("anything"), None);
    }

    #[test]
    fn text_that_is_not_a_link_is_refused() {
        assert_eq!(
            Link::parse("this line is not a link").unwrap_err().kind(),
            ErrorKind::MalformedLink
        );
        assert_eq!(
            Link::parse("://host").unwrap_err().kind(),
            ErrorKind::MalformedLink
        );
        assert_eq!(
            Link::parse("1http://host").unwrap_err().kind(),
            ErrorKind::MalformedLink
        );
    }

    #[test]
    fn the_borrowed_pieces_still_point_into_the_input() {
        let text = String::from("trojan://pw@example.com:443#Node");
        let link = Link::parse(&text).unwrap();
        let start = text.find("example.com").unwrap();

        assert_eq!(link.host().as_ptr(), text[start..].as_ptr());
        assert_eq!(link.raw(), text.as_str());
        assert_eq!(link.scheme().as_ptr(), text.as_ptr());
    }

    #[test]
    fn writing_round_trips_through_the_helpers() {
        let mut out = String::new();
        let endpoint = Endpoint::parse("example.com:443").unwrap();
        let mut first = true;

        begin(&mut out, "trojan", "pw", &endpoint);
        param(&mut out, &mut first, "sni", Some("example.com"));
        param(&mut out, &mut first, "allowInsecure", None);
        finish(&mut out, "Tokyo Two");

        assert_eq!(
            out,
            "trojan://pw@example.com:443?sni=example.com#Tokyo%20Two"
        );
    }
}
