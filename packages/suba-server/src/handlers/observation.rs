//! Operator views of the shared collector, without forwarding native credentials.

use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use http::header;

use crate::{dto::Operator, state::observation::Filter, AppState};

pub async fn metrics(
    State(state): State<AppState>,
    _auth: Operator,
    Query(filter): Query<Filter>,
) -> impl IntoResponse {
    let run = state.singbox().observation_run();
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(state.observation().metrics(run.as_ref(), &filter)),
    )
}

pub async fn connections(
    State(state): State<AppState>,
    _auth: Operator,
    Query(filter): Query<Filter>,
) -> impl IntoResponse {
    let run = state.singbox().observation_run();
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(state.observation().connections(run.as_ref(), &filter)),
    )
}
