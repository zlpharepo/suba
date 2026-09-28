use std::time::Duration;

use http::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ProxyProvider {
    Http(Http),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFields {
    #[serde(default)]
    pub disabled: bool,
}

impl ProxyProvider {
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Http {
    #[serde(flatten)]
    pub shared: SharedFields,

    pub url: url::Url,

    #[serde(default, with = "http_serde::option::header_map")]
    pub headers: Option<HeaderMap>,

    /// Timeout in milliseconds
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
