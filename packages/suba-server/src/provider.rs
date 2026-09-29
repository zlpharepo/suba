//! Where a provider's nodes come from.
//!
//! A provider is one source of nodes and the settings that say how to read it.
//! The document is stored beside the other configuration files because the
//! operator authors it, and the payloads it yields are cached in the data
//! directory because the program writes those — the same split every other
//! store here follows.
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

use http::HeaderMap;
use serde::{Deserialize, Serialize};

/// Where a provider's nodes come from.
///
/// The three kinds differ in one thing only: where the payload is read from.
/// Everything after that — parsing, caching, filtering — is the same for all of
/// them, which is why this is one type with three shapes rather than three
/// unrelated documents.
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

    /// Nodes to keep, as regular expressions matched against a node's name.
    ///
    /// Empty means every node the provider serves. When both lists are set, a
    /// node must match one of `include` and none of `exclude`.
    ///
    /// Not applied yet: node filtering is not implemented, so these are stored
    /// and round-tripped, and a provider still serves every node it is given.
    ///
    /// Skipped when empty, so a provider that filters nothing has neither key
    /// rather than an empty list — the same reason the optional fields above
    /// are skipped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,

    /// Nodes to drop, as regular expressions matched against a node's name.
    ///
    /// Takes precedence over [`include`](Self::include): a node that matches
    /// both is dropped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
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
    /// provider carries its nodes in the configuration, so re-reading it would
    /// only ever produce bytes that are already in hand.
    pub fn interval(&self) -> Option<Duration> {
        match self {
            Self::Remote(remote) => Some(Duration::from_secs(remote.interval)),
            Self::Local(local) => Some(Duration::from_secs(local.interval)),
            Self::Inline(_) => None,
        }
    }

    /// What this provider serves right now.
    ///
    /// The content is returned verbatim: interpreting it is the job of whatever
    /// consumes the subscription, not of the provider. `base` is the
    /// configuration directory, which is what a [`Local`] provider's relative
    /// path is resolved against.
    pub async fn payload(
        &self,
        client: &reqwest::Client,
        base: &Path,
    ) -> Result<String, FetchError> {
        match self {
            Self::Remote(remote) => Ok(remote.fetch(client).await?),
            Self::Local(local) => local.read(base).await,
            // Nothing to read: the nodes are in the document the caller is
            // already holding.
            Self::Inline(inline) => Ok(inline.payload.clone()),
        }
    }

    /// Whether every optional field is unset.
    ///
    /// Used by the round-trip test, which exists because an unset optional
    /// field is the case that lost its value when the configuration was
    /// written and read back in one of the two notations.
    #[cfg(test)]
    pub(crate) fn is_none_of_the_optional_fields(&self) -> bool {
        let unfiltered =
            |shared: &SharedFields| shared.include.is_empty() && shared.exclude.is_empty();

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
    /// The subscription could not be requested.
    #[error(transparent)]
    Request(#[from] reqwest::Error),

    /// A local provider's file could not be read.
    #[error("cannot read the local provider `{}`: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
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

    #[serde(default = "default_interval")]
    pub interval: u64,
}

pub fn default_interval() -> u64 {
    3600
}

impl Remote {
    pub fn timeout_duration(&self) -> Option<Duration> {
        self.timeout.map(Duration::from_millis)
    }

    pub fn build_request(&self, client: &reqwest::Client) -> reqwest::RequestBuilder {
        let mut request = client.get(self.url.to_string());

        if let Some(headers) = self.headers.as_ref() {
            request = request.headers(headers.clone());
        }

        if let Some(timeout) = self.timeout_duration() {
            request = request.timeout(timeout);
        }

        request
    }

    /// Download the payload, exactly as it was served.
    pub async fn fetch(&self, client: &reqwest::Client) -> Result<String, reqwest::Error> {
        self.build_request(client)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
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

/// The document every provider definition is stored in, keyed by name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvidersConfig {
    #[serde(flatten)]
    pub providers: HashMap<String, Provider>,
}

/// The file the provider definitions live in, without the format extension.
pub(crate) const PROVIDERS_BASENAME: &str = "providers";

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::{config_path, read_config, write_config, APP_CONFIG_BASENAME};

    fn client() -> reqwest::Client {
        reqwest::Client::new()
    }

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("suba-provider-{}-{name}", std::process::id()))
    }

    fn load_providers(path: &Path) -> ProvidersConfig {
        read_config(path.to_str().unwrap(), PROVIDERS_BASENAME).unwrap()
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
            Some(Duration::from_secs(default_interval()))
        );
    }

    #[tokio::test]
    async fn inline_serves_its_own_payload() {
        let link = "trojan://hunter2@example.com:443#Node\n";
        let provider = Provider::Inline(Inline {
            shared: SharedFields::default(),
            payload: link.to_string(),
        });

        assert_eq!(
            provider.payload(&client(), Path::new(".")).await.unwrap(),
            link
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

        assert_eq!(
            provider.payload(&client(), &base).await.unwrap(),
            "trojan://hunter2@example.com:443#Node\n"
        );

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
            .payload(&client(), &base)
            .await
            .expect_err("no file");

        assert!(
            error.to_string().contains("absent.txt"),
            "{error} is a puzzle without the path"
        );
    }

    #[test]
    fn missing_providers_load_as_defaults() {
        let path = scratch("absent");

        assert!(load_providers(&path).providers.is_empty());
    }

    /// A provider document lives in its own file, named for what it holds.
    ///
    /// The two documents of the instance — its own settings and its provider
    /// definitions — must not be the same file: one holds the administrator's
    /// password hash and the signing key, and a store that could overwrite it
    /// by getting a basename wrong would take the instance with it.
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

    /// A provider with its optional fields left unset must survive a write and
    /// a read in whichever format is compiled in.
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
                    include: vec!["^US".to_string(), "^(HK|TW)$".to_string()],
                    exclude: vec!["-2x$".to_string()],
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

        assert_eq!(remote.shared.include, ["^US", "^(HK|TW)$"]);
        assert_eq!(remote.shared.exclude, ["-2x$"]);
        assert!(
            !stored.is_none_of_the_optional_fields(),
            "a filter is not nothing"
        );

        tokio::fs::remove_dir_all(path).await.unwrap();
    }
}
