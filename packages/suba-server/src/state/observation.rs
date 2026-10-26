//! One read-only observation session per actual core run, never per HTTP caller.
//!
//! Native API credentials come from the launch snapshot, not a newly selected
//! or edited configuration. A reconnect starts a new accounting window: the
//! native snapshot is a baseline, not a complete history or a billing ledger.

mod client;
mod ledger;
mod wire;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tonic::metadata::{Ascii, MetadataValue};

use super::singbox::SingboxStore;
use ledger::Ledger;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum State {
    Stopped,
    Disabled,
    Unsupported,
    Connecting,
    Live,
    Disconnected,
    Unauthorized,
    InvalidConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Issue {
    state: State,
    reason: &'static str,
}

impl Issue {
    fn new(state: State, reason: &'static str) -> Self {
        Self { state, reason }
    }
}

#[derive(Clone)]
struct Api {
    address: SocketAddr,
    secret: MetadataValue<Ascii>,
}

/// Kept only while the process it describes is alive. Never serialized.
#[derive(Clone)]
pub(crate) struct Run {
    pub id: String,
    pub pid: u32,
    pub config: String,
    api: Result<Api, Issue>,
}

impl Run {
    pub(crate) fn new(pid: u32, config: String, document: &Value) -> Self {
        Self {
            id: uuid::Uuid::now_v7().to_string(),
            pid,
            config,
            api: endpoint(document),
        }
    }
}

fn endpoint(document: &Value) -> Result<Api, Issue> {
    let services = document.get("services").and_then(Value::as_array);
    let mut apis = services
        .into_iter()
        .flatten()
        .filter(|item| item["type"] == "api");
    let api = apis.next().ok_or_else(|| {
        Issue::new(
            State::Disabled,
            "services: observation API is not configured",
        )
    })?;
    if apis.next().is_some() {
        return Err(Issue::new(
            State::Unsupported,
            "services: observation requires exactly one API service",
        ));
    }
    if api
        .get("tls")
        .is_some_and(|tls| !tls.is_null() && tls["enabled"] != false)
    {
        return Err(Issue::new(
            State::Unsupported,
            "services.api.tls: TLS observation is not supported",
        ));
    }
    let address = api["listen"]
        .as_str()
        .and_then(|address| address.parse::<IpAddr>().ok())
        .filter(IpAddr::is_loopback)
        .ok_or_else(|| {
            Issue::new(
                State::Unsupported,
                "services.api.listen: an explicit loopback IP address is required",
            )
        })?;
    let port = api["listen_port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port > 0)
        .ok_or_else(|| {
            Issue::new(
                State::InvalidConfig,
                "services.api.listen_port: a fixed nonzero port is required",
            )
        })?;
    let mut secret = api["secret"]
        .as_str()
        .filter(|secret| {
            !secret.is_empty()
                && secret
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        })
        .and_then(|secret| MetadataValue::try_from(format!("Bearer {secret}")).ok())
        .ok_or_else(|| {
            Issue::new(
                State::InvalidConfig,
                "services.api.secret: a nonempty ASCII secret is required",
            )
        })?;
    secret.set_sensitive(true);
    Ok(Api {
        address: SocketAddr::new(address, port),
        secret,
    })
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Metadata {
    pub state: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_started_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    pub gap: bool,
}

impl Metadata {
    fn for_run(run: Option<&Run>) -> Self {
        let (state, reason) = match run.map(|run| &run.api) {
            None => (State::Stopped, None),
            Some(Ok(_)) => (State::Connecting, None),
            Some(Err(issue)) => (issue.state, Some(issue.reason)),
        };
        Self {
            state,
            reason,
            config: run.map(|run| run.config.clone()),
            run_id: run.map(|run| run.id.clone()),
            window_started_at: None,
            updated_at: None,
            gap: false,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub(crate) struct Counters {
    pub connections: usize,
    pub uplink: u64,
    pub downlink: u64,
    pub uplink_total: u64,
    pub downlink_total: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Group {
    pub user: Option<String>,
    pub inbound: String,
    #[serde(flatten)]
    pub counters: Counters,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Connection {
    pub id: String,
    pub inbound: String,
    pub user: Option<String>,
    pub network: String,
    pub source: String,
    pub destination: String,
    pub domain: String,
    pub created_at: i64,
    pub uplink_total: u64,
    pub downlink_total: u64,
}

#[derive(Default, Deserialize)]
pub(crate) struct Filter {
    pub user: Option<String>,
    pub inbound: Option<String>,
}

impl Filter {
    fn matches(&self, user: Option<&str>, inbound: &str) -> bool {
        self.user
            .as_deref()
            .is_none_or(|wanted| Some(wanted) == user)
            && self
                .inbound
                .as_deref()
                .is_none_or(|wanted| wanted == inbound)
    }
}

#[derive(Serialize)]
pub(crate) struct Metrics {
    #[serde(flatten)]
    pub metadata: Metadata,
    pub totals: Option<Counters>,
    pub groups: Vec<Group>,
}

#[derive(Serialize)]
pub(crate) struct Connections {
    #[serde(flatten)]
    pub metadata: Metadata,
    pub connections: Vec<Connection>,
}

pub(crate) struct Observation {
    ledger: Mutex<Ledger>,
}

impl Observation {
    pub(crate) fn new() -> Self {
        Self {
            ledger: Mutex::new(Ledger::new(None)),
        }
    }

    pub(crate) fn metrics(&self, run: Option<&Run>, filter: &Filter) -> Metrics {
        self.ledger
            .lock()
            .expect("observation")
            .metrics(run, filter)
    }

    pub(crate) fn connections(&self, run: Option<&Run>, filter: &Filter) -> Connections {
        self.ledger
            .lock()
            .expect("observation")
            .connections(run, filter)
    }

    pub(crate) async fn run(self: Arc<Self>, core: Arc<SingboxStore>) {
        loop {
            let run = core.observation_run();
            self.ledger
                .lock()
                .expect("observation")
                .select(run.as_ref());
            if let Some(run) = run.filter(|run| run.api.is_ok()) {
                let sampling = client::collect(&self, &run);
                tokio::pin!(sampling);
                let mut monitor = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tokio::select! {
                        result = &mut sampling => {
                            self.ledger.lock().expect("observation").fail(result);
                            break;
                        }
                        _ = monitor.tick() => {
                            if core.observation_run().as_ref().map(|next| &next.id) != Some(&run.id) {
                                break;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    fn events(&self, events: wire::Events) -> Result<(), Issue> {
        self.ledger
            .lock()
            .expect("observation")
            .apply(events, Instant::now(), now())
    }

    fn heartbeat(&self) {
        self.ledger
            .lock()
            .expect("observation")
            .tick(Instant::now(), now());
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests;
