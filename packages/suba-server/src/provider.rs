//! Where a provider's nodes come from.
//!
//! A provider is one source of nodes and the settings that say how to read it.
//! The three kinds differ in one thing only: where the payload is read from.
//! Everything after that — parsing, comparing against what was held, storing —
//! is the same for all of them, which is why this is one type with three shapes
//! rather than three unrelated documents.
//!
//! A hand-written node list is the [`Inline`] kind, not a resource of its own:
//! editing nodes is editing a provider, and it goes through the same refresh
//! path as a subscribed one.
//!
//! This is a module of its own rather than a part of `config` because it is a
//! domain, not a configuration-file concern: [`crate::config`] owns the format,
//! the atomic write and the instance's own documents (administrator, key pair),
//! and knows nothing about nodes.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

use http::{header, HeaderMap};
use serde::{Deserialize, Serialize};
use suba_core::{Fetched, FilterError, NodeFilter, Pattern};

/// The largest payload this hub will buffer from a provider.
///
/// A subscription is a list of share links: ten thousand nodes is a few
/// megabytes. A payload far past that is a mistake or an attack, and either way
/// it must not become this process's memory. The limit is enforced while
/// reading, not after the body is in hand.
pub const MAX_PAYLOAD_BYTES: u64 = 32 * 1024 * 1024;

/// The file the provider definitions live in, without the format extension.
pub(crate) const PROVIDERS_BASENAME: &str = "providers";

/// Where a provider's nodes come from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Provider {
    /// A subscription served over HTTP by a remote host.
    Remote(Remote),
    /// A file on disk, maintained by the operator.
    Local(Local),
    /// Nodes written into the configuration file itself.
    Inline(Inline),
}

/// The fields every provider has, whatever its source.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SharedFields {
    #[serde(default)]
    pub disabled: bool,

    /// Nodes to keep, as [`Pattern`]s read against a node's name. Empty means
    /// every node the provider serves.
    ///
    /// Skipped when empty, so a provider that filters nothing has neither key
    /// rather than an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<Pattern>,

    /// Nodes to drop, in the same shape.
    ///
    /// Takes precedence over [`includes`](Self::includes): a node that matches
    /// both is dropped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excludes: Vec<Pattern>,
}

impl SharedFields {
    /// Compile the two lists into the decision they describe.
    ///
    /// Called whenever a provider definition is written, so a pattern that
    /// cannot be used is refused at the point it is stored rather than
    /// discovered by a filter that quietly does less than it says.
    pub fn filter(&self) -> Result<NodeFilter, FilterError> {
        NodeFilter::compile(&self.includes, &self.excludes)
    }
}

impl Provider {
    /// Whether the provider is excluded from automatic refreshing.
    pub fn disabled(&self) -> bool {
        match self {
            Self::Remote(remote) => remote.shared.disabled,
            Self::Local(local) => local.shared.disabled,
            Self::Inline(inline) => inline.shared.disabled,
        }
    }

    /// The delay between two automatic refreshes.
    ///
    /// `None` for a provider there is nothing to poll for: an [`Inline`]
    /// provider carries its nodes in the document the caller is already holding,
    /// so re-reading it would only ever produce bytes that are already in hand;
    /// an interval of `0` is the operator saying the same thing about a remote
    /// or local one, which then changes only when it is refreshed by hand.
    pub fn interval(&self) -> Option<Duration> {
        let seconds = match self {
            Self::Remote(remote) => remote.interval,
            Self::Local(local) => local.interval,
            Self::Inline(_) => return None,
        };

        (seconds > 0).then(|| Duration::from_secs(seconds))
    }

    /// What this provider serves right now.
    ///
    /// `conditions` are the validators from what this hub already holds, and a
    /// caller passes them only when it does hold something: asking a server
    /// conditionally for a version this hub does not have is a way of talking
    /// itself out of the one it needs.
    ///
    /// The payload is returned verbatim. Interpreting it is the job of whatever
    /// consumes the subscription, not of the provider. `base` is the
    /// configuration directory, which is what a [`Local`] provider's relative
    /// path is resolved against.
    pub async fn fetch(
        &self,
        client: &reqwest::Client,
        base: &Path,
        conditions: Option<(&str, Option<&str>)>,
    ) -> Result<Fetched, FetchError> {
        match self {
            Self::Remote(remote) => remote.fetch(client, conditions).await,
            Self::Local(local) => local.read(base).await.map(Fetched::from_payload),
            // Nothing to read: the nodes are in the document the caller is
            // already holding.
            Self::Inline(inline) => Ok(Fetched::from_payload(inline.payload.clone())),
        }
    }

    /// The node filter this definition asks for.
    pub fn filter(&self) -> Result<NodeFilter, FilterError> {
        match self {
            Self::Remote(remote) => remote.shared.filter(),
            Self::Local(local) => local.shared.filter(),
            Self::Inline(inline) => inline.shared.filter(),
        }
    }

    /// Whether every optional field is unset.
    ///
    /// Used by the round-trip test, which exists because an unset optional field
    /// is the case that lost its value when the configuration was written and
    /// read back in one of the two notations.
    #[cfg(test)]
    pub(crate) fn is_none_of_the_optional_fields(&self) -> bool {
        let unfiltered =
            |shared: &SharedFields| shared.includes.is_empty() && shared.excludes.is_empty();

        match self {
            Self::Remote(remote) => {
                remote.headers.is_none() && remote.timeout.is_none() && unfiltered(&remote.shared)
            }
            Self::Local(local) => unfiltered(&local.shared),
            Self::Inline(inline) => unfiltered(&inline.shared),
        }
    }
}

/// A provider that did not produce a payload.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The request failed.
    ///
    /// The text is scrubbed rather than passed through: a transport error quotes
    /// the request URL, and a provider URL carries a subscription token.
    /// Keeping the credential out is a property of this variant, not of every
    /// caller remembering to redact.
    #[error("the provider could not be reached: {reason}")]
    Request { reason: String },

    /// The payload is larger than this hub will read.
    #[error("the provider served more than {limit} bytes, which is more than suba will buffer")]
    TooLarge { limit: u64 },

    /// A local provider's file could not be read.
    #[error("cannot read the local provider `{}`: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl FetchError {
    /// A transport failure, with the credential-bearing text removed.
    fn from_request(error: &reqwest::Error) -> Self {
        Self::Request {
            reason: redact(&error.to_string()),
        }
    }
}

/// A subscription served over HTTP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Remote {
    #[serde(flatten)]
    pub shared: SharedFields,

    pub url: url::Url,

    /// Extra request headers, as a map of header name to value.
    ///
    /// `http_serde`'s option serializer writes `None` as `null`, but its option
    /// deserializer forwards that `null` to the `HeaderMap` visitor, which
    /// rejects it — so its own output cannot be read back in JSON. Skipping the
    /// field when it is absent avoids the round trip entirely: a provider with
    /// no headers simply has no `headers` key, in both notations.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "http_serde::option::header_map"
    )]
    pub headers: Option<HeaderMap>,

    /// Timeout in milliseconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,

    /// Seconds between automatic refreshes; `0` never refreshes on its own.
    #[serde(default = "default_interval")]
    pub interval: u64,
}

impl Remote {
    pub fn timeout_duration(&self) -> Option<Duration> {
        self.timeout.map(Duration::from_millis)
    }

    pub fn build_request(
        &self,
        client: &reqwest::Client,
        conditions: Option<(&str, Option<&str>)>,
    ) -> reqwest::RequestBuilder {
        let mut request = client.get(self.url.to_string());

        if let Some(headers) = self.headers.as_ref() {
            request = request.headers(headers.clone());
        }

        if let Some(timeout) = self.timeout_duration() {
            request = request.timeout(timeout);
        }

        if let Some((etag, last_modified)) = conditions {
            request = request.header(header::IF_NONE_MATCH, etag);

            if let Some(last_modified) = last_modified {
                request = request.header(header::IF_MODIFIED_SINCE, last_modified);
            }
        }

        request
    }

    /// Download the payload, or learn that what this hub holds is current.
    ///
    /// A `304` is an answer rather than a body, and it is returned before any
    /// body is read. The size ceiling is checked from the declared length when
    /// there is one and while reading in every case, so a response that declares
    /// nothing is still bounded.
    pub async fn fetch(
        &self,
        client: &reqwest::Client,
        conditions: Option<(&str, Option<&str>)>,
    ) -> Result<Fetched, FetchError> {
        let response = self
            .build_request(client, conditions)
            .send()
            .await
            .map_err(|error| FetchError::from_request(&error))?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            // A provider may rotate its validator while answering `304`; the one
            // it just sent is the one to send next time.
            return Ok(Fetched::NotModified {
                etag: header_value(&response, header::ETAG),
            });
        }

        let etag = header_value(&response, header::ETAG);
        let last_modified = header_value(&response, header::LAST_MODIFIED);

        let mut response = response
            .error_for_status()
            .map_err(|error| FetchError::from_request(&error))?;

        if let Some(length) = response.content_length() {
            if length > MAX_PAYLOAD_BYTES {
                return Err(FetchError::TooLarge {
                    limit: MAX_PAYLOAD_BYTES,
                });
            }
        }

        let mut body = Vec::new();

        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| FetchError::from_request(&error))?
        {
            if body.len() as u64 + chunk.len() as u64 > MAX_PAYLOAD_BYTES {
                return Err(FetchError::TooLarge {
                    limit: MAX_PAYLOAD_BYTES,
                });
            }

            body.extend_from_slice(&chunk);
        }

        // A subscription is text; invalid UTF-8 is a broken payload, not a
        // reason to lose the fact that it arrived. Replacing the bad bytes keeps
        // the rest, which is what a reader works from.
        Ok(
            Fetched::from_payload(String::from_utf8_lossy(&body).into_owned())
                .with_validators(etag, last_modified),
        )
    }
}

/// A payload read from a file the operator maintains.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Local {
    #[serde(flatten)]
    pub shared: SharedFields,

    /// The file to read.
    ///
    /// A relative path is resolved against the configuration directory, so a
    /// provider document that travels with the file it names keeps working.
    pub path: PathBuf,

    /// Seconds between automatic refreshes; `0` never refreshes on its own.
    #[serde(default = "default_interval")]
    pub interval: u64,
}

impl Local {
    /// Read the file.
    ///
    /// The file is read on every refresh rather than watched: a refresh is
    /// already the moment the operator asked about, and a watcher would be a
    /// second clock to keep in step with the schedule.
    async fn read(&self, base: &Path) -> Result<String, FetchError> {
        let path = match self.path.is_absolute() {
            true => self.path.clone(),
            false => base.join(&self.path),
        };

        // The same ceiling as a remote payload, for the same reason: a file that
        // is far past a subscription's size is a mistake, and it must not become
        // this process's memory. Checked on the length, so the bytes are never
        // read.
        let length = tokio::fs::metadata(&path)
            .await
            .map_err(|source| FetchError::Read {
                path: path.clone(),
                source,
            })?
            .len();

        if length > MAX_PAYLOAD_BYTES {
            return Err(FetchError::TooLarge {
                limit: MAX_PAYLOAD_BYTES,
            });
        }

        tokio::fs::read_to_string(&path)
            .await
            .map_err(|source| FetchError::Read { path, source })
    }
}

/// Nodes written into the configuration file itself.
///
/// The payload is written the way a subscription payload would be written — the
/// same links, one per line — and read by the same parser, so a hand-typed
/// provider and a subscription are the same thing once they are read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Inline {
    #[serde(flatten)]
    pub shared: SharedFields,

    /// The nodes, as they would arrive from a provider.
    pub payload: String,
}

pub fn default_interval() -> u64 {
    3600
}

/// The document every provider definition is stored in, keyed by name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvidersConfig {
    #[serde(flatten)]
    pub providers: HashMap<String, Provider>,
}

/// Refuse a provider name that is not a name.
///
/// A provider is named by a URL path segment, so it must not be able to become a
/// path, a `.`/`..`, or an empty filename. This is checked where a name is about
/// to become a file — the store and the filesystem layer — rather than only
/// where it is parsed, because a name also arrives from a stored document that
/// never went through a request.
pub(crate) fn provider_name(name: &str) -> std::io::Result<()> {
    let usable = !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0']);

    match usable {
        true => Ok(()),
        false => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a provider name may not be a path, a dot, or empty",
        )),
    }
}

/// A response header as an owned string, if it is there and is valid text.
fn header_value(response: &reqwest::Response, name: header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Remove anything credential-shaped from a message.
///
/// One shape matters here: a URL, because that is what a transport error quotes
/// and what a provider URL is. Its credentials — a token in a path segment, a
/// sensitive query value — are cut, while the host and the readable part of the
/// path stay, because those are what make the message useful.
fn redact(message: &str) -> String {
    let mut redacted = String::with_capacity(message.len());
    let mut rest = message;

    while let Some(start) = find_url_start(rest) {
        let end = rest[start..]
            .find(|character: char| character.is_whitespace() || character == ')')
            .map(|at| start + at)
            .unwrap_or(rest.len());

        redacted.push_str(&rest[..start]);
        redacted.push_str(&cut_url(&rest[start..end]));
        rest = &rest[end..];
    }

    redacted.push_str(rest);
    redacted
}

/// Where a URL begins in `message`, if one does.
///
/// Recognised by its scheme, which may be preceded by anything: a parenthesis, a
/// quote, or nothing at all.
fn find_url_start(message: &str) -> Option<usize> {
    let scheme_end = message.find("://")?;

    Some(
        message[..scheme_end]
            .rfind(|character: char| {
                !character.is_ascii_alphanumeric() && !matches!(character, '+' | '-' | '.')
            })
            .map(|at| at + 1)
            .unwrap_or(0),
    )
}

/// Keep a URL's scheme, authority and readable path; cut its credentials.
fn cut_url(url: &str) -> String {
    let (head, query) = match url.split_once('?') {
        Some((head, query)) => (head, Some(query)),
        None => (url, None),
    };

    let cut = match head.split_once("://") {
        Some((scheme, rest)) => {
            let rest = match rest.split_once('@') {
                Some((_userinfo, rest)) => rest,
                None => rest,
            };

            let (authority, path) = match rest.find('/') {
                Some(at) => (&rest[..at], &rest[at..]),
                None => (rest, ""),
            };

            let path = path
                .split('/')
                .map(|segment| match looks_like_a_token(segment) {
                    true => "<token>",
                    false => segment,
                })
                .collect::<Vec<_>>()
                .join("/");

            format!("{scheme}://{authority}{path}")
        }
        None => head.to_string(),
    };

    match query {
        Some(query) => {
            let query = query
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    Some((key, _)) if is_sensitive(key) => format!("{key}=<redacted>"),
                    _ => pair.to_string(),
                })
                .collect::<Vec<_>>()
                .join("&");

            format!("{cut}?{query}")
        }
        None => cut,
    }
}

/// Whether a path segment is a credential rather than a word.
///
/// A shape, not a list of names: a path segment of 32 or more base64url
/// characters with nothing else in it is a key. That is what a subscription URL
/// looks like — the token lives in the path.
fn looks_like_a_token(segment: &str) -> bool {
    segment.len() >= 32
        && segment.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '_'
        })
}

/// Query parameters whose value is a credential.
fn is_sensitive(key: &str) -> bool {
    let key = key.trim().to_ascii_lowercase();

    matches!(
        key.as_str(),
        "token"
            | "access_token"
            | "share_token"
            | "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "key"
            | "api_key"
            | "apikey"
            | "uuid"
            | "sub"
    ) || key.ends_with("_token")
        || key.ends_with("_key")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::{config_path, read_config, write_config, APP_CONFIG_BASENAME};

    fn client() -> reqwest::Client {
        reqwest::Client::new()
    }

    fn remote() -> Remote {
        Remote {
            shared: SharedFields::default(),
            url: "https://example.com/subscription".parse().unwrap(),
            headers: None,
            timeout: None,
            interval: default_interval(),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("suba-provider-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        dir
    }

    fn load_providers(path: &Path) -> ProvidersConfig {
        read_config(path.to_str().unwrap(), PROVIDERS_BASENAME).unwrap()
    }

    #[test]
    fn each_kind_carries_its_own_interval() {
        let inline = Provider::Inline(Inline {
            shared: SharedFields::default(),
            payload: String::new(),
        });

        // An inline provider is never polled: its nodes are in the document the
        // caller is already holding.
        assert_eq!(inline.interval(), None);
        assert_eq!(
            Provider::Remote(remote()).interval(),
            Some(Duration::from_secs(3600))
        );
    }

    /// Zero is "do not poll", not "poll as fast as possible".
    #[test]
    fn an_interval_of_zero_is_never_polled() {
        let manual = Provider::Remote(Remote {
            interval: 0,
            ..remote()
        });

        assert_eq!(manual.interval(), None);
    }

    #[tokio::test]
    async fn inline_serves_its_own_payload() {
        let link = "trojan://hunter2@example.com:443#Node\n";
        let provider = Provider::Inline(Inline {
            shared: SharedFields::default(),
            payload: link.to_string(),
        });

        let fetched = provider
            .fetch(&client(), Path::new("."), None)
            .await
            .unwrap();

        assert_eq!(
            fetched,
            Fetched::Modified {
                payload: link.to_string(),
                etag: None,
                last_modified: None,
            }
        );
    }

    #[tokio::test]
    async fn a_local_path_is_resolved_against_the_configuration_directory() {
        let base = scratch("local");
        tokio::fs::create_dir_all(&base).await.unwrap();
        tokio::fs::write(
            base.join("nodes.txt"),
            "trojan://hunter2@example.com:443#Node\n",
        )
        .await
        .unwrap();

        let provider = Provider::Local(Local {
            shared: SharedFields::default(),
            path: PathBuf::from("nodes.txt"),
            interval: default_interval(),
        });

        let fetched = provider.fetch(&client(), &base, None).await.unwrap();

        assert!(fetched.is_modified());

        tokio::fs::remove_dir_all(&base).await.unwrap();
    }

    #[tokio::test]
    async fn a_local_file_that_cannot_be_read_names_itself() {
        let base = scratch("local-missing");
        let provider = Provider::Local(Local {
            shared: SharedFields::default(),
            path: PathBuf::from("absent.txt"),
            interval: default_interval(),
        });

        let error = provider
            .fetch(&client(), &base, None)
            .await
            .expect_err("no file");

        assert!(
            error.to_string().contains("absent.txt"),
            "{error} is a puzzle without the path"
        );
    }

    /// A local file is bounded by the same ceiling as a remote payload.
    ///
    /// The file is created sparse, so its length is what is checked and the
    /// bytes are never written or read.
    #[tokio::test]
    async fn a_local_file_far_larger_than_a_subscription_is_refused_unread() {
        let base = scratch("local-huge");
        tokio::fs::create_dir_all(&base).await.unwrap();
        tokio::fs::File::create(base.join("huge.txt"))
            .await
            .unwrap()
            .set_len(MAX_PAYLOAD_BYTES + 1)
            .await
            .unwrap();

        let provider = Provider::Local(Local {
            shared: SharedFields::default(),
            path: PathBuf::from("huge.txt"),
            interval: default_interval(),
        });

        assert!(matches!(
            provider.fetch(&client(), &base, None).await,
            Err(FetchError::TooLarge { .. })
        ));

        tokio::fs::remove_dir_all(&base).await.unwrap();
    }

    #[test]
    fn a_request_carries_the_validators_it_was_given() {
        let request = remote()
            .build_request(
                &client(),
                Some(("\"v1\"", Some("Wed, 21 Oct 2015 07:28:00 GMT"))),
            )
            .build()
            .unwrap();

        let header_of = |name: header::HeaderName| {
            request
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };

        assert_eq!(header_of(header::IF_NONE_MATCH).as_deref(), Some("\"v1\""));
        assert_eq!(
            header_of(header::IF_MODIFIED_SINCE).as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );
    }

    #[test]
    fn a_request_with_nothing_held_asks_for_everything() {
        // Nothing to compare against, so no condition: a `304` would tell this
        // hub that the version it does not have is current.
        let request = remote().build_request(&client(), None).build().unwrap();

        assert!(request.headers().get(header::IF_NONE_MATCH).is_none());
        assert!(request.headers().get(header::IF_MODIFIED_SINCE).is_none());
    }

    /// A provider URL carries a subscription token in its path, and a transport
    /// error quotes the URL it failed on.
    #[test]
    fn a_transport_error_cannot_carry_a_subscription_token() {
        let token = "9zWwztV5diwK2LUcwsHhtNbJCvQDgpm9bEfL7Js2sf2TzbSx8vvvWQWP72EfaQ8j";
        let message = format!(
            "error sending request for url (https://store.example.com/{token}/download/edge?token=abc123)"
        );

        let scrubbed = redact(&message);

        assert!(!scrubbed.contains(token), "{scrubbed}");
        assert!(!scrubbed.contains("abc123"), "{scrubbed}");
        assert!(scrubbed.contains("<token>"), "{scrubbed}");
        assert!(scrubbed.contains("token=<redacted>"), "{scrubbed}");
        assert!(
            scrubbed.contains("store.example.com"),
            "the host is not a credential: {scrubbed}"
        );
        assert!(
            scrubbed.contains("download/edge"),
            "a path made of words stays: {scrubbed}"
        );
    }

    #[test]
    fn a_credential_in_the_userinfo_is_cut_too() {
        let scrubbed = redact("failed for trojan://hunter2@example.com:443");

        assert!(!scrubbed.contains("hunter2"), "{scrubbed}");
        assert!(scrubbed.contains("example.com:443"), "{scrubbed}");
    }

    #[test]
    fn a_message_with_no_url_is_left_alone() {
        assert_eq!(
            redact("the provider refused the connection"),
            "the provider refused the connection"
        );
    }

    #[test]
    fn an_oversized_payload_says_the_limit_and_not_the_body() {
        let error = FetchError::TooLarge {
            limit: MAX_PAYLOAD_BYTES,
        };
        let printed = error.to_string();

        assert!(
            printed.contains(&MAX_PAYLOAD_BYTES.to_string()),
            "{printed}"
        );
        assert!(printed.contains("buffer"), "{printed}");
    }

    #[test]
    fn missing_providers_load_as_defaults() {
        assert!(load_providers(&scratch("absent")).providers.is_empty());
    }

    /// A provider document lives in its own file, named for what it holds.
    ///
    /// The two documents of the instance — its own settings and its provider
    /// definitions — must not be the same file: one holds the administrator's
    /// password hash and the signing key, and a store that could overwrite it by
    /// getting a basename wrong would take the instance with it.
    #[tokio::test]
    async fn a_provider_document_does_not_share_a_file_with_the_instance() {
        let path = scratch("separate-files");
        let config = ProvidersConfig::default();

        write_config(path.to_str().unwrap(), PROVIDERS_BASENAME, &config)
            .await
            .unwrap();

        assert!(config_path(&path, PROVIDERS_BASENAME).is_file());
        assert!(!config_path(&path, APP_CONFIG_BASENAME).exists());
        assert!(load_providers(&path).providers.is_empty());

        tokio::fs::remove_dir_all(path).await.unwrap();
    }

    /// A provider with its optional fields left unset must survive a write and a
    /// read in whichever format is compiled in.
    ///
    /// This is the round trip that used to fail under the JSON format:
    /// `http_serde`'s option serializer writes `None` as `null`, and its own
    /// deserializer then refuses that `null`, so what the store wrote it could
    /// not read back. Skipping the absent field is the fix, and this test holds
    /// it for every format.
    #[tokio::test]
    async fn a_provider_with_no_optional_fields_round_trips() {
        let path = scratch("no-optionals");
        let mut config = ProvidersConfig::default();
        config
            .providers
            .insert("airport".to_string(), Provider::Remote(remote()));

        write_config(path.to_str().unwrap(), PROVIDERS_BASENAME, &config)
            .await
            .unwrap();

        let reloaded = load_providers(&path);
        let stored = reloaded.providers.get("airport").expect("the provider");

        assert!(stored.is_none_of_the_optional_fields());

        tokio::fs::remove_dir_all(path).await.unwrap();
    }

    /// Node filters are written and read back as the operator typed them.
    ///
    /// The fields are skipped when empty, which is the same shape that lost its
    /// value in the round trip the test above guards — so the case where they
    /// are *set* is checked here in both notations.
    #[tokio::test]
    async fn a_provider_keeps_its_node_filters() {
        let path = scratch("filters");
        let mut config = ProvidersConfig::default();
        config.providers.insert(
            "airport".to_string(),
            Provider::Remote(Remote {
                shared: SharedFields {
                    disabled: false,
                    includes: vec![
                        suba_core::Pattern::Name("HK-01".to_string()),
                        suba_core::Pattern::Regex("^US".to_string()),
                    ],
                    excludes: vec![suba_core::Pattern::Keyword("2x".to_string())],
                },
                ..remote()
            }),
        );

        write_config(path.to_str().unwrap(), PROVIDERS_BASENAME, &config)
            .await
            .unwrap();

        let reloaded = load_providers(&path);
        let stored = reloaded.providers.get("airport").expect("the provider");
        let Provider::Remote(remote) = stored else {
            panic!("a remote provider comes back remote");
        };

        assert_eq!(
            remote.shared.includes,
            [
                Pattern::Name("HK-01".to_string()),
                Pattern::Regex("^US".to_string())
            ]
        );
        assert_eq!(remote.shared.excludes, [Pattern::Keyword("2x".to_string())]);
        assert!(
            !stored.is_none_of_the_optional_fields(),
            "a filter is not nothing"
        );

        // The names the two lists are written under are part of the document,
        // not an implementation detail: an operator edits these keys.
        let written = std::fs::read_to_string(config_path(&path, PROVIDERS_BASENAME)).unwrap();
        assert!(written.contains("includes"), "{written}");
        assert!(written.contains("excludes"), "{written}");
        assert!(written.contains("regex"), "{written}");
        assert!(written.contains("keyword"), "{written}");
        assert!(
            !written.contains("keyword:"),
            "no kind is spelled inside a pattern: {written}"
        );

        tokio::fs::remove_dir_all(path).await.unwrap();
    }

    #[test]
    fn a_provider_name_that_is_a_path_is_refused() {
        for name in ["../config", "a/b", "..", "", "back\\slash"] {
            assert!(provider_name(name).is_err(), "accepted {name:?}");
        }

        assert!(provider_name("airport").is_ok());
        assert!(provider_name("US.LAX-01").is_ok());
    }
}
