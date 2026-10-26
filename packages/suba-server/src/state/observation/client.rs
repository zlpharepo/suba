use std::time::Duration;

use http::uri::PathAndQuery;
use tonic::{client::Grpc, transport::Endpoint, Code, Request};
use tonic_prost::ProstCodec;

use super::{wire, Api, Issue, Observation, Run, State};

const CALL_TIMEOUT: Duration = Duration::from_secs(3);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(5);

fn disconnected() -> Issue {
    Issue::new(
        State::Disconnected,
        "observation: the native API connection is unavailable",
    )
}

fn failure(status: tonic::Status) -> Issue {
    match status.code() {
        Code::Unauthenticated | Code::PermissionDenied => Issue::new(
            State::Unauthorized,
            "services.api.secret: the native API refused authentication",
        ),
        Code::Unimplemented => Issue::new(
            State::Unsupported,
            "observation: the running core does not support this API capability",
        ),
        _ => disconnected(),
    }
}

fn request<T>(api: &Api, body: T) -> Request<T> {
    let mut request = Request::new(body);
    request
        .metadata_mut()
        .insert("authorization", api.secret.clone());
    request
}

pub(super) async fn collect(observation: &Observation, run: &Run) -> Issue {
    match collect_inner(observation, run).await {
        Ok(()) => disconnected(),
        Err(issue) => issue,
    }
}

async fn collect_inner(observation: &Observation, run: &Run) -> Result<(), Issue> {
    let api = run.api.as_ref().map_err(|issue| *issue)?;
    let endpoint = Endpoint::from_shared(format!("http://{}", api.address))
        .map_err(|_| disconnected())?
        .connect_timeout(CALL_TIMEOUT);
    let channel = endpoint.connect().await.map_err(|_| disconnected())?;
    let mut client = Grpc::new(channel);
    client.ready().await.map_err(|_| disconnected())?;
    let version: tonic::Response<wire::Version> = tokio::time::timeout(
        CALL_TIMEOUT,
        client.unary(
            request(api, wire::Empty {}),
            PathAndQuery::from_static("/daemon.StartedService/GetVersion"),
            ProstCodec::default(),
        ),
    )
    .await
    .map_err(|_| disconnected())?
    .map_err(failure)?;
    if version.into_inner().api_version != 4 {
        return Err(Issue::new(
            State::Unsupported,
            "observation.api_version: this native API version is not supported",
        ));
    }
    client.ready().await.map_err(|_| disconnected())?;
    let connections: tonic::Response<tonic::Streaming<wire::Events>> = tokio::time::timeout(
        CALL_TIMEOUT,
        client.server_streaming(
            request(
                api,
                wire::Interval {
                    interval: 1_000_000_000,
                },
            ),
            PathAndQuery::from_static("/daemon.StartedService/SubscribeConnections"),
            ProstCodec::default(),
        ),
    )
    .await
    .map_err(|_| disconnected())?
    .map_err(failure)?;
    let mut connections = connections.into_inner();
    client.ready().await.map_err(|_| disconnected())?;
    let status: tonic::Response<tonic::Streaming<wire::Status>> = tokio::time::timeout(
        CALL_TIMEOUT,
        client.server_streaming(
            request(
                api,
                wire::Interval {
                    interval: 1_000_000_000,
                },
            ),
            PathAndQuery::from_static("/daemon.StartedService/SubscribeStatus"),
            ProstCodec::default(),
        ),
    )
    .await
    .map_err(|_| disconnected())?
    .map_err(failure)?;
    let mut status = status.into_inner();
    let initial = tokio::time::timeout(HEARTBEAT_TIMEOUT, connections.message())
        .await
        .map_err(|_| disconnected())?
        .map_err(failure)?
        .ok_or_else(disconnected)?;
    if !initial.reset {
        return Err(Issue::new(
            State::Disconnected,
            "observation.connections: the initial snapshot is missing",
        ));
    }
    observation.events(initial)?;
    let mut deadline = tokio::time::Instant::now() + HEARTBEAT_TIMEOUT;
    loop {
        tokio::select! {
            event = connections.message() => {
                observation.events(event.map_err(failure)?.ok_or_else(disconnected)?)?;
            }
            update = status.message() => {
                let update = update.map_err(failure)?.ok_or_else(disconnected)?;
                if !update.traffic_available {
                    return Err(Issue::new(State::Unsupported, "observation.traffic: connection tracking is unavailable"));
                }
                observation.heartbeat();
                deadline = tokio::time::Instant::now() + HEARTBEAT_TIMEOUT;
            }
            _ = tokio::time::sleep_until(deadline) => return Err(disconnected()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_errors_use_status_codes_and_never_echo_the_message() {
        let issue = failure(tonic::Status::unauthenticated("example-private-value"));
        assert_eq!(issue.state, State::Unauthorized);
        assert!(!issue.reason.contains("example-private-value"));
        assert_eq!(
            failure(tonic::Status::unimplemented("example")).state,
            State::Unsupported
        );
        assert_eq!(
            failure(tonic::Status::unavailable("example")).state,
            State::Disconnected
        );
    }
}
