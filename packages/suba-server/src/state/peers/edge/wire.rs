use futures_util::{Sink, SinkExt, Stream, StreamExt};
use reqwest_websocket::{Message, Upgrade};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

use super::{EdgeAnswer, EdgeCall, Error, FRAME_LIMIT, REQUEST_LIMIT, WRITE_TIMEOUT};
use crate::state::peers::{Challenge, EdgeSessionProof, Identity, Purpose, Signed};

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum ManagerFrame {
    Challenge {
        proof: Signed<Challenge>,
    },
    Ready {
        proof: Signed<Ready>,
    },
    Call {
        session: Uuid,
        id: u64,
        call: Box<EdgeCall>,
    },
    Ping {
        session: Uuid,
        id: u64,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum AgentFrame {
    Proof {
        proof: Signed<EdgeSessionProof>,
    },
    Answer {
        session: Uuid,
        id: u64,
        answer: Result<EdgeAnswer, Failure>,
    },
    Pong {
        session: Uuid,
        id: u64,
    },
}

pub(super) struct Command {
    pub id: u64,
    pub call: EdgeCall,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Ready {
    pub nonce: String,
    pub session: Uuid,
    pub agent: Uuid,
    pub manager: Uuid,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Failure {
    Unauthorized,
    NotFound,
    Rejected,
    Busy,
    Uncertain,
    Unavailable,
}

impl Failure {
    pub fn from_error(error: Error) -> Self {
        match error {
            Error::Unauthorized | Error::PeerIdentity => Self::Unauthorized,
            Error::PeerNotFound => Self::NotFound,
            Error::PeerRequest { .. } => Self::Rejected,
            Error::PeerBusy => Self::Busy,
            Error::PeerUncertain => Self::Uncertain,
            _ => Self::Unavailable,
        }
    }

    pub fn error(self, mutation: bool) -> Error {
        match self {
            Self::Uncertain | Self::Unavailable if mutation => Error::PeerUncertain,
            Self::NotFound => Error::PeerNotFound,
            // Remote authentication failures must not sign out the local administrator.
            _ => Error::PeerUnavailable,
        }
    }
}

pub(super) fn address(endpoint: &str, host: Uuid) -> Result<url::Url, Error> {
    let base = crate::state::peers::endpoint(endpoint)?;
    let mut url = url::Url::parse(&format!("{base}/api/peers/edge/connect"))
        .map_err(|_| Error::PeerUnavailable)?;
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme).map_err(|_| Error::PeerUnavailable)?;
    url.query_pairs_mut().append_pair("host", &host.to_string());
    Ok(url)
}

pub(super) async fn dial(
    client: &reqwest::Client,
    url: url::Url,
) -> Result<reqwest_websocket::WebSocket, Error> {
    configured(
        |config| client.get(url).upgrade().web_socket_config(config),
        |config| {
            config.max_message_size = Some(REQUEST_LIMIT);
            config.max_frame_size = Some(REQUEST_LIMIT);
            config.max_write_buffer_size = FRAME_LIMIT + 128 * 1024;
        },
    )
    .send()
    .await
    .map_err(|_| Error::PeerUnavailable)?
    .into_websocket()
    .await
    .map_err(|_| Error::PeerUnavailable)
}

// Infer the library's configuration type without adding a second WebSocket dependency.
fn configured<T: Default, R>(make: impl FnOnce(T) -> R, configure: impl FnOnce(&mut T)) -> R {
    let mut value = T::default();
    configure(&mut value);
    make(value)
}

pub(super) fn verify_challenge(
    proof: &Signed<Challenge>,
    agent: &Identity,
    manager: &Identity,
) -> Result<(), Error> {
    proof.verify("challenge", manager)?;
    if proof.payload.actor != *agent
        || proof.payload.target != *manager
        || proof.payload.purpose != Purpose::EdgeSession
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

pub(super) fn verify_ready(
    proof: &Signed<Ready>,
    challenge: &Challenge,
    manager: &Identity,
) -> Result<Uuid, Error> {
    proof.verify("edge-ready", manager)?;
    if proof.payload.nonce != challenge.nonce
        || proof.payload.agent != challenge.actor.id
        || proof.payload.manager != manager.id
        || proof.payload.session.is_nil()
    {
        return Err(Error::Unauthorized);
    }
    Ok(proof.payload.session)
}

pub(super) fn decode<T: DeserializeOwned>(message: Message, limit: usize) -> Result<T, Error> {
    let bytes = match &message {
        Message::Text(text) => text.as_bytes(),
        Message::Binary(bytes) => bytes,
        _ => return Err(Error::PeerUnavailable),
    };
    if bytes.len() > limit {
        return Err(Error::PeerUnavailable);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::PeerUnavailable)
}

pub(super) async fn send<S, T>(socket: &mut S, value: &T) -> Result<(), Error>
where
    S: Sink<Message, Error = Error> + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(value).map_err(|_| Error::PeerUnavailable)?;
    if bytes.len() > FRAME_LIMIT {
        return Err(Error::PeerUnavailable);
    }
    tokio::time::timeout(WRITE_TIMEOUT, socket.send(Message::Binary(bytes.into())))
        .await
        .map_err(|_| Error::PeerUnavailable)?
}

pub(super) async fn receive<S, T>(socket: &mut S, limit: usize) -> Result<T, Error>
where
    S: Stream<Item = Result<Message, Error>> + Unpin,
    T: DeserializeOwned,
{
    decode(socket.next().await.ok_or(Error::PeerUnavailable)??, limit)
}

pub(super) fn client_socket(
    socket: reqwest_websocket::WebSocket,
) -> impl Stream<Item = Result<Message, Error>> + Sink<Message, Error = Error> + Unpin {
    socket
        .sink_map_err(|_| Error::PeerUnavailable)
        .map(|message| message.map_err(|_| Error::PeerUnavailable))
}

pub(super) fn server_socket(
    socket: axum::extract::ws::WebSocket,
) -> impl Stream<Item = Result<Message, Error>> + Sink<Message, Error = Error> + Unpin {
    use axum::extract::ws::Message as Axum;
    socket
        .sink_map_err(|_| Error::PeerUnavailable)
        .with(|message| {
            std::future::ready(Ok(match message {
                Message::Text(text) => Axum::Text(text.into()),
                Message::Binary(bytes) => Axum::Binary(bytes),
                Message::Ping(bytes) => Axum::Ping(bytes),
                Message::Pong(bytes) => Axum::Pong(bytes),
                Message::Close { .. } => Axum::Close(None),
            }))
        })
        .map(
            |message| match message.map_err(|_| Error::PeerUnavailable)? {
                Axum::Text(text) => Ok(Message::Text(text.to_string())),
                Axum::Binary(bytes) => Ok(Message::Binary(bytes)),
                Axum::Ping(bytes) => Ok(Message::Ping(bytes)),
                Axum::Pong(bytes) => Ok(Message::Pong(bytes)),
                Axum::Close(_) => Err(Error::PeerUnavailable),
            },
        )
}
