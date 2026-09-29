use std::time::Duration;

use http::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Provider {
    Http(Http),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFields {
    #[serde(default)]
    pub disabled: bool,
}

impl Provider {
    /// Whether the provider is excluded from automatic refreshing.
    pub fn disabled(&self) -> bool {
        match self {
            Self::Http(http) => http.shared.disabled,
        }
    }

    /// The delay between two automatic refreshes.
    pub fn interval(&self) -> Duration {
        match self {
            Self::Http(http) => Duration::from_secs(http.interval),
        }
    }

    /// Download the subscription payload.
    ///
    /// The content is returned verbatim: interpreting it is the job of
    /// whatever consumes the subscription, not of the provider.
    pub async fn fetch(&self, client: &reqwest::Client) -> Result<String, reqwest::Error> {
        match self {
            Self::Http(http) => http.fetch(client).await,
        }
    }

    /// Whether every optional field is unset.
    ///
    /// Used by the round-trip test, which exists because an unset optional
    /// field is the case that lost its value when the configuration was
    /// written and read back in one of the two notations.
    #[cfg(test)]
    pub(crate) fn is_none_of_the_optional_fields(&self) -> bool {
        match self {
            Self::Http(http) => http.headers.is_none() && http.timeout.is_none(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Http {
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

impl Http {
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

    pub async fn fetch(&self, client: &reqwest::Client) -> Result<String, reqwest::Error> {
        self.build_request(client)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    }
}
