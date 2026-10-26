//! Reverse peer transport, without changing resource ownership or replay protection.
//!
//! A session carries only manager-initiated, signed resource operations. Disconnecting
//! cancels waiting futures, not committed effects; no operation is queued for reconnect.

mod session;
mod wire;

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};
use uuid::Uuid;

use super::{Challenge, ChallengeRequest, ResourceReply, ResourceRequest, Signed};
use crate::error::Error;

pub(crate) use session::{accept, run};

const CALL_LIMIT: usize = 16;
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const STALE_TIMEOUT: Duration = Duration::from_secs(30);
const VALIDATE_INTERVAL: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
// JSON escaping may expand request strings sixfold; replies contain base64 bodies.
pub(crate) const FRAME_LIMIT: usize = super::REPLY_LIMIT * 4 / 3 + 64 * 1024;
const REQUEST_LIMIT: usize = super::BODY_LIMIT * 6 + 64 * 1024;

#[derive(Serialize, Deserialize)]
pub(crate) enum EdgeCall {
    Challenge(ChallengeRequest),
    Resource(Signed<ResourceRequest>),
}

impl EdgeCall {
    fn mutation(&self) -> bool {
        matches!(self, Self::Resource(proof) if proof.payload.method != "GET")
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) enum EdgeAnswer {
    Challenge(Signed<Challenge>),
    Resource(Signed<ResourceReply>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EdgeState {
    Disabled,
    Connecting,
    Online,
    Offline,
    Unauthorized,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct EdgeStatus {
    pub state: EdgeState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<i64>,
}

impl EdgeStatus {
    fn new(state: EdgeState, reason: Option<&'static str>) -> Self {
        Self {
            state,
            reason,
            connected_at: None,
            last_seen: None,
        }
    }

    fn online() -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            state: EdgeState::Online,
            reason: None,
            connected_at: Some(now),
            last_seen: Some(now),
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Control {
    revision: u64,
    stopped: bool,
}

struct HubState {
    hosts: HashMap<Uuid, Arc<Session>>,
    local: EdgeStatus,
}

pub(crate) struct EdgeHub {
    inner: Mutex<HubState>,
    control: watch::Sender<Control>,
}

impl EdgeHub {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(HubState {
                hosts: HashMap::new(),
                local: EdgeStatus::new(EdgeState::Disabled, None),
            }),
            control: watch::channel(Control::default()).0,
        }
    }

    pub(crate) fn host_status(&self, id: Uuid) -> EdgeStatus {
        self.inner.lock().unwrap().hosts.get(&id).map_or_else(
            || EdgeStatus::new(EdgeState::Offline, Some("edge.disconnected")),
            |session| session.inner.lock().unwrap().status.clone(),
        )
    }

    pub(crate) fn local_status(&self) -> EdgeStatus {
        self.inner.lock().unwrap().local.clone()
    }

    pub(crate) fn disconnect(&self, id: Uuid) {
        if let Some(session) = self.inner.lock().unwrap().hosts.remove(&id) {
            session.close();
        }
    }

    pub(crate) fn reconnect(&self) {
        self.control
            .send_modify(|control| control.revision = control.revision.wrapping_add(1));
    }

    pub(crate) fn shutdown(&self) {
        self.control.send_modify(|control| control.stopped = true);
        let mut inner = self.inner.lock().unwrap();
        for (_, session) in inner.hosts.drain() {
            session.close();
        }
        inner.local = EdgeStatus::new(EdgeState::Offline, Some("edge.shutdown"));
    }

    pub(crate) async fn exchange(&self, id: Uuid, call: EdgeCall) -> Result<EdgeAnswer, Error> {
        let session = self
            .inner
            .lock()
            .unwrap()
            .hosts
            .get(&id)
            .cloned()
            .ok_or(Error::PeerUnavailable)?;
        let mutation = call.mutation();
        let (id, receiver) = session.enqueue(call)?;
        let _pending = PendingCall { session, id };
        match tokio::time::timeout(CALL_TIMEOUT, receiver).await {
            Ok(Ok(Ok(answer))) => Ok(answer),
            Ok(Ok(Err(failure))) => Err(failure.error(mutation)),
            _ => Err(if mutation {
                Error::PeerUncertain
            } else {
                Error::PeerUnavailable
            }),
        }
    }

    fn attach(&self, host: Uuid, session: Arc<Session>) -> Result<(), Error> {
        let mut inner = self.inner.lock().unwrap();
        if self.control.borrow().stopped {
            session.close();
            return Err(Error::PeerUnavailable);
        }
        if let Some(old) = inner.hosts.insert(host, session) {
            old.close();
        }
        Ok(())
    }

    fn detach(&self, host: Uuid, session: &Session) {
        let mut inner = self.inner.lock().unwrap();
        session.close();
        if inner
            .hosts
            .get(&host)
            .is_some_and(|current| current.id == session.id)
        {
            inner.hosts.remove(&host);
        }
    }

    fn local(&self, status: EdgeStatus) {
        self.inner.lock().unwrap().local = status;
    }

    fn local_seen(&self) {
        self.inner.lock().unwrap().local.last_seen = Some(chrono::Utc::now().timestamp_millis());
    }
}

type Answer = Result<EdgeAnswer, wire::Failure>;

struct Pending {
    reply: oneshot::Sender<Answer>,
    resource: bool,
}

struct SessionState {
    active: bool,
    pending: HashMap<u64, Pending>,
    sequence: u64,
    status: EdgeStatus,
}

struct Session {
    id: Uuid,
    inner: Mutex<SessionState>,
    commands: mpsc::Sender<wire::Command>,
    closed: watch::Sender<bool>,
}

impl Session {
    fn new(id: Uuid) -> (Arc<Self>, mpsc::Receiver<wire::Command>) {
        let (commands, receiver) = mpsc::channel(CALL_LIMIT);
        (
            Arc::new(Self {
                id,
                inner: Mutex::new(SessionState {
                    active: true,
                    pending: HashMap::new(),
                    sequence: 0,
                    status: EdgeStatus::online(),
                }),
                commands,
                closed: watch::channel(false).0,
            }),
            receiver,
        )
    }

    fn enqueue(&self, call: EdgeCall) -> Result<(u64, oneshot::Receiver<Answer>), Error> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.active || inner.pending.len() >= CALL_LIMIT {
            return Err(Error::PeerUnavailable);
        }
        let id = inner
            .sequence
            .checked_add(1)
            .ok_or(Error::PeerUnavailable)?;
        inner.sequence = id;
        let resource = matches!(call, EdgeCall::Resource(_));
        let (reply, receiver) = oneshot::channel();
        self.commands
            .try_send(wire::Command { id, call })
            .map_err(|_| Error::PeerUnavailable)?;
        inner.pending.insert(id, Pending { reply, resource });
        Ok((id, receiver))
    }

    fn wants(&self, id: u64) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.active && inner.pending.contains_key(&id)
    }

    fn answer(&self, session: Uuid, id: u64, answer: Answer) -> Result<(), Error> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.active || session != self.id || id == 0 || id > inner.sequence {
            return Err(Error::PeerUnavailable);
        }
        // Timed-out calls may still complete remotely; their replies cannot satisfy another call.
        if let Some(pending) = inner.pending.remove(&id) {
            if let Ok(answer) = &answer {
                if pending.resource != matches!(answer, EdgeAnswer::Resource(_)) {
                    return Err(Error::PeerUnavailable);
                }
            }
            let _ = pending.reply.send(answer);
        }
        inner.status.last_seen = Some(chrono::Utc::now().timestamp_millis());
        Ok(())
    }

    fn seen(&self) {
        self.inner.lock().unwrap().status.last_seen = Some(chrono::Utc::now().timestamp_millis());
    }

    fn close(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.active = false;
        inner.pending.clear();
        inner.status.state = EdgeState::Offline;
        inner.status.reason = Some("edge.disconnected");
        self.closed.send_replace(true);
    }
}

struct PendingCall {
    session: Arc<Session>,
    id: u64,
}

impl Drop for PendingCall {
    fn drop(&mut self) {
        self.session.inner.lock().unwrap().pending.remove(&self.id);
    }
}
