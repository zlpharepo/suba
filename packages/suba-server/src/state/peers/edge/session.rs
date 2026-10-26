use std::sync::Arc;

use futures_util::{stream::FuturesUnordered, Sink, Stream, StreamExt};
use reqwest_websocket::Message;
use tokio::{
    sync::watch,
    time::{Instant, MissedTickBehavior},
};

use super::{
    wire::{self, AgentFrame, Failure, ManagerFrame, Ready},
    *,
};
use crate::{
    state::peers::{EdgeSessionProof, EdgeUpstream, Host, Identity, IdentitySigner},
    AppState,
};

pub(crate) async fn accept(state: AppState, id: Uuid, socket: axum::extract::ws::WebSocket) {
    let mut control = state.peers().edge.control.subscribe();
    let mut socket = wire::server_socket(socket);
    tokio::select! {
        _ = stopped(&mut control) => {},
        _ = manager(state, id, &mut socket) => {},
    }
}

async fn stopped(control: &mut watch::Receiver<Control>) {
    loop {
        if control.borrow_and_update().stopped || control.changed().await.is_err() {
            return;
        }
    }
}

struct Attached {
    state: AppState,
    host: Uuid,
    session: Arc<Session>,
}

impl Drop for Attached {
    fn drop(&mut self) {
        self.state.peers().edge.detach(self.host, &self.session);
    }
}

async fn manager<S>(state: AppState, id: Uuid, socket: &mut S) -> Result<(), Error>
where
    S: Stream<Item = Result<Message, Error>> + Sink<Message, Error = Error> + Unpin,
{
    let (host, signer, session_id) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let signer = state.settings().existing_peer_signer().await?;
        let expected = state.peers().edge_host(id).await?;
        let challenge = state.peers().edge_challenge(&signer, id).await?;
        let nonce = challenge.payload.nonce.clone();
        wire::send(socket, &ManagerFrame::Challenge { proof: challenge }).await?;
        let AgentFrame::Proof { proof } = wire::receive(socket, 16 * 1024).await? else {
            return Err(Error::Unauthorized);
        };
        if proof.payload.challenge.nonce != nonce {
            return Err(Error::Unauthorized);
        }
        let host = state
            .peers()
            .authorize_edge_session(&signer, &proof)
            .await?;
        if host.id != id || host.identity != expected.identity {
            return Err(Error::Unauthorized);
        }
        let session_id = Uuid::now_v7();
        wire::send(
            socket,
            &ManagerFrame::Ready {
                proof: signer.sign(
                    "edge-ready",
                    Ready {
                        nonce,
                        session: session_id,
                        agent: id,
                        manager: signer.identity.id,
                    },
                )?,
            },
        )
        .await?;
        valid_host(&state, &host, &signer.identity).await?;
        Ok((host, signer, session_id))
    })
    .await
    .map_err(|_| Error::PeerUnavailable)??;
    let (session, mut commands) = Session::new(session_id);
    state.peers().edge.attach(id, session.clone())?;
    let _attached = Attached {
        state: state.clone(),
        host: id,
        session: session.clone(),
    };
    let mut closed = session.closed.subscribe();
    let mut heartbeat = Heartbeat::new();
    let mut tick = interval(HEARTBEAT_INTERVAL);
    let mut validation = interval(VALIDATE_INTERVAL);
    loop {
        if *closed.borrow() {
            return Err(Error::PeerUnavailable);
        }
        tokio::select! {
            biased;
            _ = closed.changed() => return Err(Error::PeerUnavailable),
            _ = validation.tick() => valid_host(&state, &host, &signer.identity).await?,
            _ = tick.tick() => {
                if let Some(id) = heartbeat.ping(Instant::now())? {
                    wire::send(socket, &ManagerFrame::Ping { session: session_id, id }).await?;
                }
            },
            frame = wire::receive::<_, AgentFrame>(socket, FRAME_LIMIT) => {
                match frame? {
                    AgentFrame::Answer { session: received, id, answer } => session.answer(received, id, answer)?,
                    AgentFrame::Pong { session: received, id } if received == session_id => {
                        heartbeat.pong(id)?;
                        session.seen();
                    },
                    _ => return Err(Error::PeerUnavailable),
                }
            },
            command = commands.recv() => {
                let command = command.ok_or(Error::PeerUnavailable)?;
                if session.wants(command.id) {
                    valid_host(&state, &host, &signer.identity).await?;
                    wire::send(socket, &ManagerFrame::Call { session: session_id, id: command.id, call: Box::new(command.call) }).await?;
                }
            },
        }
    }
}

async fn valid_host(state: &AppState, host: &Host, own: &Identity) -> Result<(), Error> {
    let current = state.peers().edge_host(host.id).await?;
    if current.identity != host.identity
        || state.settings().existing_peer_signer().await?.identity != *own
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

pub(crate) async fn run(state: AppState) {
    let hub = &state.peers().edge;
    let mut control = hub.control.subscribe();
    let mut failures = 0_u32;
    loop {
        if control.borrow_and_update().stopped {
            return;
        }
        let Some(upstream) = state.peers().edge_upstream().await else {
            hub.local(EdgeStatus::new(EdgeState::Disabled, None));
            tokio::select! {
                _ = control.changed() => {},
                _ = tokio::time::sleep(VALIDATE_INTERVAL) => {},
            }
            failures = 0;
            continue;
        };
        hub.local(EdgeStatus::new(EdgeState::Connecting, None));
        let (result, healthy) = tokio::select! {
            _ = control.changed() => { failures = 0; continue; },
            result = agent_connect(&state, &upstream) => result,
        };
        if healthy {
            failures = 0;
        }
        hub.local(EdgeStatus::new(
            if matches!(result, Err(Error::Unauthorized | Error::PeerIdentity)) {
                EdgeState::Unauthorized
            } else {
                EdgeState::Offline
            },
            Some(
                if matches!(result, Err(Error::Unauthorized | Error::PeerIdentity)) {
                    "edge.unauthorized"
                } else {
                    "edge.disconnected"
                },
            ),
        ));
        let delay = backoff(failures);
        failures = failures.saturating_add(1);
        tokio::select! {
            _ = control.changed() => { failures = 0; },
            _ = tokio::time::sleep(delay) => {},
        }
    }
}

async fn agent_connect(state: &AppState, upstream: &EdgeUpstream) -> (Result<(), Error>, bool) {
    let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        state
            .peers()
            .edge_manager_authorized(&upstream.manager)
            .await?;
        let signer = state.settings().existing_peer_signer().await?;
        let client = crate::state::peers::outbound_builder(upstream.proxy.as_deref())?
            .http1_only()
            .build()
            .map_err(|_| Error::PeerUnavailable)?;
        let socket = wire::dial(
            &client,
            wire::address(&upstream.endpoint, signer.identity.id)?,
        )
        .await?;
        let mut socket = wire::client_socket(socket);
        let session = agent_handshake(&mut socket, &signer, &upstream.manager).await?;
        valid_upstream(state, upstream, &signer.identity).await?;
        Ok((socket, signer, session))
    })
    .await;
    let (mut socket, signer, session) = match handshake {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => return (Err(error), false),
        Err(_) => return (Err(Error::PeerUnavailable), false),
    };
    state.peers().edge.local(EdgeStatus::online());
    let started = Instant::now();
    let result = agent(state, upstream, &signer.identity, session, &mut socket).await;
    (result, started.elapsed() >= STALE_TIMEOUT)
}

async fn agent_handshake<S>(
    socket: &mut S,
    signer: &IdentitySigner,
    manager: &Identity,
) -> Result<Uuid, Error>
where
    S: Stream<Item = Result<Message, Error>> + Sink<Message, Error = Error> + Unpin,
{
    let ManagerFrame::Challenge { proof } = wire::receive(socket, 16 * 1024).await? else {
        return Err(Error::Unauthorized);
    };
    wire::verify_challenge(&proof, &signer.identity, manager)?;
    let challenge = proof.payload;
    wire::send(
        socket,
        &AgentFrame::Proof {
            proof: signer.sign(
                "edge-session",
                EdgeSessionProof {
                    challenge: challenge.clone(),
                },
            )?,
        },
    )
    .await?;
    let ManagerFrame::Ready { proof } = wire::receive(socket, 16 * 1024).await? else {
        return Err(Error::Unauthorized);
    };
    wire::verify_ready(&proof, &challenge, manager)
}

async fn valid_upstream(
    state: &AppState,
    upstream: &EdgeUpstream,
    own: &Identity,
) -> Result<(), Error> {
    if state.peers().edge_upstream().await.as_ref() != Some(upstream)
        || state.settings().existing_peer_signer().await?.identity != *own
    {
        return Err(Error::Unauthorized);
    }
    state
        .peers()
        .edge_manager_authorized(&upstream.manager)
        .await
}

async fn agent<S>(
    state: &AppState,
    upstream: &EdgeUpstream,
    own: &Identity,
    session: Uuid,
    socket: &mut S,
) -> Result<(), Error>
where
    S: Stream<Item = Result<Message, Error>> + Sink<Message, Error = Error> + Unpin,
{
    let mut jobs = FuturesUnordered::new();
    let mut last_call = 0;
    let mut last_ping = 0;
    let mut seen_ping = Instant::now();
    let mut validation = interval(VALIDATE_INTERVAL);
    loop {
        // Dropping this scope cancels unfinished request futures. Effects already committed,
        // including work on blocking store threads, may finish; this is never rollback.
        tokio::select! {
            _ = validation.tick() => {
                if seen_ping.elapsed() >= STALE_TIMEOUT { return Err(Error::PeerUnavailable); }
                valid_upstream(state, upstream, own).await?;
            },
            frame = wire::receive::<_, ManagerFrame>(socket, REQUEST_LIMIT) => {
                match frame? {
                    ManagerFrame::Ping { session: received, id } if received == session && id > last_ping => {
                        last_ping = id;
                        seen_ping = Instant::now();
                        state.peers().edge.local_seen();
                        wire::send(socket, &AgentFrame::Pong { session, id }).await?;
                    },
                    ManagerFrame::Call { session: received, id, call } if received == session && id > last_call => {
                        last_call = id;
                        if jobs.len() >= CALL_LIMIT {
                            wire::send(socket, &AgentFrame::Answer { session, id, answer: Err(Failure::Busy) }).await?;
                        } else {
                            jobs.push(async move {
                                let mutation = call.mutation();
                                let answer = match tokio::time::timeout(CALL_TIMEOUT, execute(state, upstream, own, *call)).await {
                                    Ok(result) => result.map_err(Failure::from_error),
                                    Err(_) => Err(if mutation { Failure::Uncertain } else { Failure::Unavailable }),
                                };
                                AgentFrame::Answer { session, id, answer }
                            });
                        }
                    },
                    _ => return Err(Error::PeerUnavailable),
                }
            },
            Some(answer) = jobs.next(), if !jobs.is_empty() => {
                wire::send(socket, &answer).await?;
            },
        }
    }
}

async fn execute(
    state: &AppState,
    upstream: &EdgeUpstream,
    own: &Identity,
    call: EdgeCall,
) -> Result<EdgeAnswer, Error> {
    valid_upstream(state, upstream, own).await?;
    match call {
        EdgeCall::Challenge(request) => {
            if request.actor != upstream.manager || request.invitation.is_some() {
                return Err(Error::Unauthorized);
            }
            let signer = state.settings().existing_peer_signer().await?;
            Ok(EdgeAnswer::Challenge(
                state.peers().challenge(&signer, request).await?,
            ))
        }
        EdgeCall::Resource(proof) => {
            if proof.payload.challenge.actor != upstream.manager
                || proof.payload.challenge.target != *own
            {
                return Err(Error::Unauthorized);
            }
            Ok(EdgeAnswer::Resource(
                crate::handlers::peers::execute_resource(state.clone(), proof).await?,
            ))
        }
    }
}

fn interval(duration: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval_at(Instant::now() + duration, duration);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

fn backoff(failures: u32) -> Duration {
    let ceiling = (1_u64 << failures.min(6)).min(60) * 1000;
    let mut entropy = [128];
    let _ = getrandom::fill(&mut entropy);
    Duration::from_millis(ceiling / 2 + ceiling * u64::from(entropy[0]) / 510)
}

struct Heartbeat {
    sequence: u64,
    pending: Option<(u64, Instant)>,
}

impl Heartbeat {
    fn new() -> Self {
        Self {
            sequence: 0,
            pending: None,
        }
    }

    fn ping(&mut self, now: Instant) -> Result<Option<u64>, Error> {
        if let Some((_, sent)) = self.pending {
            if now.duration_since(sent) >= STALE_TIMEOUT {
                return Err(Error::PeerUnavailable);
            }
            return Ok(None);
        }
        self.sequence = self.sequence.checked_add(1).ok_or(Error::PeerUnavailable)?;
        self.pending = Some((self.sequence, now));
        Ok(Some(self.sequence))
    }

    fn pong(&mut self, id: u64) -> Result<(), Error> {
        if !self.pending.is_some_and(|(expected, _)| expected == id) {
            return Err(Error::PeerUnavailable);
        }
        self.pending = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_requires_matching_pongs_and_a_monotonic_deadline() {
        let mut heartbeat = Heartbeat::new();
        let now = Instant::now();
        let id = heartbeat.ping(now).unwrap().unwrap();
        assert!(heartbeat.pong(id + 1).is_err());
        assert!(heartbeat.ping(now + STALE_TIMEOUT).is_err());
        heartbeat.pong(id).unwrap();
        assert!(heartbeat.pong(id).is_err());
        assert!(heartbeat.ping(now + STALE_TIMEOUT).unwrap().unwrap() > id);
    }

    #[test]
    fn backoff_is_bounded_even_after_many_failures() {
        for failures in [0, 1, 4, 8, u32::MAX] {
            let delay = backoff(failures);
            assert!(delay >= Duration::from_millis(500));
            assert!(delay <= Duration::from_secs(60));
        }
    }
}
