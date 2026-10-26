use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::{
    wire, Connection, Connections, Counters, Filter, Group, Issue, Metadata, Metrics, Run, State,
};

type Key = (Option<String>, String);

struct Active {
    view: Connection,
    native_up: u64,
    native_down: u64,
}

#[derive(Default)]
struct Accumulator {
    counters: Counters,
    sampled_up: u64,
    sampled_down: u64,
}

pub(super) struct Ledger {
    metadata: Metadata,
    active: BTreeMap<String, Active>,
    groups: BTreeMap<Key, Accumulator>,
    sampled_at: Option<Instant>,
    heartbeat_at: Option<Instant>,
}

impl Ledger {
    pub(super) fn new(run: Option<&Run>) -> Self {
        Self {
            metadata: Metadata::for_run(run),
            active: BTreeMap::new(),
            groups: BTreeMap::new(),
            sampled_at: None,
            heartbeat_at: None,
        }
    }

    pub(super) fn select(&mut self, run: Option<&Run>) {
        if self.metadata.run_id.as_deref() != run.map(|run| run.id.as_str()) {
            *self = Self::new(run);
        }
    }

    fn metadata(&self, run: Option<&Run>) -> Metadata {
        if self.metadata.run_id.as_deref() != run.map(|run| run.id.as_str()) {
            return Metadata::for_run(run);
        }
        let mut metadata = self.metadata.clone();
        if metadata.state == State::Live
            && self
                .heartbeat_at
                .is_none_or(|at| at.elapsed() > Duration::from_secs(5))
        {
            metadata.state = State::Disconnected;
            metadata.reason = Some("observation: the last heartbeat is stale");
            metadata.gap = true;
        }
        metadata
    }

    pub(super) fn metrics(&self, run: Option<&Run>, filter: &Filter) -> Metrics {
        let metadata = self.metadata(run);
        let groups: Vec<Group> = if metadata.window_started_at.is_some() {
            self.groups
                .iter()
                .filter(|((user, inbound), _)| filter.matches(user.as_deref(), inbound))
                .map(|((user, inbound), held)| Group {
                    user: user.clone(),
                    inbound: inbound.clone(),
                    counters: held.counters.clone(),
                })
                .collect()
        } else {
            Vec::new()
        };
        let totals = metadata.window_started_at.map(|_| {
            groups.iter().fold(Counters::default(), |mut total, group| {
                let held = &group.counters;
                total.connections = total.connections.saturating_add(held.connections);
                total.uplink = total.uplink.saturating_add(held.uplink);
                total.downlink = total.downlink.saturating_add(held.downlink);
                total.uplink_total = total.uplink_total.saturating_add(held.uplink_total);
                total.downlink_total = total.downlink_total.saturating_add(held.downlink_total);
                total
            })
        });
        Metrics {
            metadata,
            totals,
            groups,
        }
    }

    pub(super) fn connections(&self, run: Option<&Run>, filter: &Filter) -> Connections {
        let metadata = self.metadata(run);
        let connections = if metadata.window_started_at.is_some() {
            self.active
                .values()
                .filter(|held| filter.matches(held.view.user.as_deref(), &held.view.inbound))
                .map(|held| held.view.clone())
                .collect()
        } else {
            Vec::new()
        };
        Connections {
            metadata,
            connections,
        }
    }

    pub(super) fn fail(&mut self, issue: Issue) {
        self.metadata.state = issue.state;
        self.metadata.reason = Some(issue.reason);
        self.metadata.gap |= self.metadata.window_started_at.is_some();
    }

    pub(super) fn tick(&mut self, at: Instant, wall: i64) {
        let Some(previous) = self.sampled_at else {
            return;
        };
        let seconds = at.saturating_duration_since(previous).as_secs_f64();
        if seconds > 0.0 {
            for held in self.groups.values_mut() {
                held.counters.uplink = ((held.counters.uplink_total.saturating_sub(held.sampled_up))
                    as f64
                    / seconds) as u64;
                held.counters.downlink = ((held
                    .counters
                    .downlink_total
                    .saturating_sub(held.sampled_down))
                    as f64
                    / seconds) as u64;
                held.sampled_up = held.counters.uplink_total;
                held.sampled_down = held.counters.downlink_total;
            }
            self.sampled_at = Some(at);
        }
        self.heartbeat_at = Some(at);
        self.metadata.updated_at = Some(wall);
        self.metadata.state = State::Live;
        self.metadata.reason = None;
    }

    pub(super) fn apply(
        &mut self,
        events: wire::Events,
        at: Instant,
        wall: i64,
    ) -> Result<(), Issue> {
        if events.reset {
            self.metadata.gap |= self.metadata.window_started_at.is_some();
            self.metadata.window_started_at = Some(wall);
            self.metadata.updated_at = None;
            self.metadata.state = State::Connecting;
            self.metadata.reason = None;
            self.active.clear();
            self.groups.clear();
            self.heartbeat_at = None;
            self.sampled_at = Some(at);
        } else if self.sampled_at.is_none() {
            return Err(protocol(
                "observation.connections: a reset snapshot is required",
            ));
        }
        for event in events.events {
            if event.id.is_empty() {
                return Err(protocol(
                    "observation.connections.id: an identifier is required",
                ));
            }
            match event.kind {
                0 => {
                    let connection = event.connection.ok_or_else(|| {
                        protocol(
                            "observation.connections: a new connection is missing its metadata",
                        )
                    })?;
                    if connection.id != event.id {
                        return Err(protocol(
                            "observation.connections.id: identifiers do not match",
                        ));
                    }
                    // Reset snapshots include closed history as NEW. It predates this window.
                    if events.reset && connection.closed_at > 0 {
                        continue;
                    }
                    if self.active.contains_key(&event.id) {
                        continue;
                    }
                    let native_up = nonnegative(connection.uplink_total)?;
                    let native_down = nonnegative(connection.downlink_total)?;
                    let mut active = Active {
                        view: Connection {
                            id: event.id.clone(),
                            inbound: connection.inbound,
                            user: (!connection.user.is_empty()).then_some(connection.user),
                            network: connection.network,
                            source: connection.source,
                            destination: connection.destination,
                            domain: connection.domain,
                            created_at: connection.created_at,
                            uplink_total: 0,
                            downlink_total: 0,
                        },
                        native_up,
                        native_down,
                    };
                    let held = self.groups.entry(key(&active)).or_default();
                    held.counters.connections = held.counters.connections.saturating_add(1);
                    if !events.reset {
                        credit(&mut active, held, native_up, native_down);
                    }
                    self.active.insert(event.id, active);
                }
                1 => {
                    let up = nonnegative(event.uplink_delta)?;
                    let down = nonnegative(event.downlink_delta)?;
                    let active = self.active.get_mut(&event.id).ok_or_else(|| {
                        protocol("observation.connections: an update has no known connection")
                    })?;
                    let held = self
                        .groups
                        .get_mut(&key(active))
                        .expect("active connection group");
                    active.native_up = active.native_up.saturating_add(up);
                    active.native_down = active.native_down.saturating_add(down);
                    credit(active, held, up, down);
                }
                2 => {
                    // Native ticker reconciliation and queued events can both close the same ID.
                    let Some(mut active) = self.active.remove(&event.id) else {
                        continue;
                    };
                    let connection = event.connection.ok_or_else(|| {
                        protocol("observation.connections: final counters are missing")
                    })?;
                    let up = nonnegative(connection.uplink_total)?.saturating_sub(active.native_up);
                    let down =
                        nonnegative(connection.downlink_total)?.saturating_sub(active.native_down);
                    let held = self
                        .groups
                        .get_mut(&key(&active))
                        .expect("active connection group");
                    credit(&mut active, held, up, down);
                    held.counters.connections = held.counters.connections.saturating_sub(1);
                }
                _ => {
                    return Err(protocol(
                        "observation.connections.type: an unknown event was received",
                    ))
                }
            }
        }
        Ok(())
    }
}

fn key(active: &Active) -> Key {
    (active.view.user.clone(), active.view.inbound.clone())
}

fn credit(active: &mut Active, group: &mut Accumulator, up: u64, down: u64) {
    active.view.uplink_total = active.view.uplink_total.saturating_add(up);
    active.view.downlink_total = active.view.downlink_total.saturating_add(down);
    group.counters.uplink_total = group.counters.uplink_total.saturating_add(up);
    group.counters.downlink_total = group.counters.downlink_total.saturating_add(down);
}

fn nonnegative(value: i64) -> Result<u64, Issue> {
    u64::try_from(value)
        .map_err(|_| protocol("observation.traffic: a negative counter was received"))
}

fn protocol(reason: &'static str) -> Issue {
    Issue::new(State::Disconnected, reason)
}
