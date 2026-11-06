//! Edge resources keep desired documents on the manager and runtime facts on
//! the node. Direct requests retain their independent-instance ownership.

use axum::{
    body::{to_bytes, Body},
    response::{IntoResponse, Response},
};
use http::{header, HeaderMap, Request, StatusCode};
use serde_json::{json, Value};
use suba_singbox::core::Version;
use tower::ServiceExt;

use crate::{
    error::Error,
    state::{
        peers::{Host, BODY_LIMIT, REPLY_LIMIT},
        singbox::Deployment,
    },
    AppState,
};

use super::peers;

async fn value(response: Response) -> Result<Value, Error> {
    if !response.status().is_success() {
        return Err(Error::PeerUnavailable);
    }
    let bytes = to_bytes(response.into_body(), REPLY_LIMIT)
        .await
        .map_err(|_| Error::PeerUnavailable)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::PeerUnavailable)
}

async fn schema(state: &AppState, host: &Host, version: &Version) -> Result<Response, Error> {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("version", version.as_str())
        .finish();
    peers::call(
        state,
        host,
        "GET".into(),
        format!("/cores/sing-box/schema?{query}"),
        None,
        None,
    )
    .await
}

async fn ensure_schema(
    state: &AppState,
    scoped: &AppState,
    host: &Host,
    version: Version,
) -> Result<(), Error> {
    let store = scoped.singbox();
    if store.has_remote_schema(&version) {
        return Ok(());
    }
    let response = schema(state, host, &version).await?;
    if !response.status().is_success() {
        return Err(Error::PeerUnavailable);
    }
    let bytes = to_bytes(response.into_body(), REPLY_LIMIT)
        .await
        .map_err(|_| Error::PeerUnavailable)?;
    tokio::task::spawn_blocking(move || store.accept_schema(version, bytes.to_vec())).await?
}

pub(crate) async fn deployment(scoped: &AppState) -> Result<Deployment, Error> {
    let generated = super::singbox::generated(scoped).await?;
    let store = scoped.singbox();
    tokio::task::spawn_blocking(move || store.runtime_snapshot(&generated)).await?
}

pub(crate) async fn forward(
    state: AppState,
    host: Host,
    method: String,
    path: String,
    headers: HeaderMap,
    body: Option<String>,
) -> Result<Response, Error> {
    let resource = path.split('?').next().unwrap_or(&path);
    if resource.starts_with("/system/") {
        return peers::call(&state, &host, method, path, None, body).await;
    }
    let scoped = state.for_agent(host.id).await?;
    let store = scoped.singbox();
    let reading = store.clone();
    let mut desired = tokio::task::spawn_blocking(move || reading.settings()).await??;
    if resource == "/cores/sing-box" || resource == "/cores/sing-box/" {
        if method == "GET" {
            let mut runtime =
                value(peers::call(&state, &host, method, path, None, None).await?).await?;
            if desired.version.is_none() {
                if let Some(version) = runtime["version"].as_str() {
                    let version = Version::from_tag(version);
                    let selecting = store.clone();
                    desired =
                        tokio::task::spawn_blocking(move || selecting.bootstrap_version(&version))
                            .await??;
                }
            }
            if let Some(version) = &desired.version {
                ensure_schema(&state, &scoped, &host, version.clone()).await?;
            }
            runtime["version"] = json!(desired.version.as_ref().map(Version::as_str));
            runtime["managed"] = json!(true);
            runtime["config"] = json!(desired
                .config
                .as_deref()
                .unwrap_or(crate::state::singbox::DEFAULT_CONFIG));
            runtime["privilege"] = json!(desired.privilege);
            runtime["collections"] = json!(desired.collections);
            runtime["autostart"] = json!(desired.autostart);
            runtime["installed"] = json!(desired.version.is_some());
            if runtime["running"] == true
                && deployment(&scoped)
                    .await
                    .ok()
                    .and_then(|snapshot| snapshot.id().ok())
                    .as_deref()
                    != runtime["applied"].as_str()
            {
                runtime["note"] = json!("restart to apply the manager's saved configuration");
            }
            return Ok(axum::Json(runtime).into_response());
        }
        if method == "PUT" {
            let choice: super::singbox::Choose =
                serde_json::from_str(body.as_deref().unwrap_or("{}")).map_err(|_| {
                    Error::PeerRequest {
                        reason: "settings: invalid module settings",
                    }
                })?;
            let version = match choice.version {
                Some(version) => version.map(|version| Version::from_tag(&version)),
                None => desired.version,
            };
            if let Some(version) = version {
                ensure_schema(&state, &scoped, &host, version).await?;
            }
            let runtime = value(
                peers::call(
                    &state,
                    &host,
                    "GET".into(),
                    "/cores/sing-box".into(),
                    None,
                    None,
                )
                .await?,
            )
            .await?;
            let response = local(scoped, method, path, headers, body).await?;
            if !response.status().is_success() {
                return Ok(response);
            }
            let mut saved = value(response).await?;
            saved["managed"] = json!(true);
            for key in ["running", "assembled", "applied"] {
                saved[key] = runtime[key].clone();
            }
            saved["installed"] = json!(saved["version"].is_string());
            return Ok(axum::Json(saved).into_response());
        }
        return Err(Error::PeerNotFound);
    }
    if resource == "/cores/sing-box/status" && method == "PUT" {
        let mut action: Value =
            serde_json::from_str(body.as_deref().unwrap_or("{}")).map_err(|_| {
                Error::PeerRequest {
                    reason: "action: invalid runtime action",
                }
            })?;
        match action["action"].as_str() {
            Some("start" | "restart") => {
                action["deployment"] = serde_json::to_value(deployment(&scoped).await?)?;
            }
            Some("stop") => {
                action = json!({ "action": "stop" });
            }
            _ => {
                return Err(Error::PeerRequest {
                    reason: "action: expected start, stop or restart",
                })
            }
        }
        let body = serde_json::to_string(&action)?;
        if body.len() > BODY_LIMIT {
            return Err(Error::PeerRequest {
                reason: "deployment: the runtime snapshot is too large",
            });
        }
        return peers::call(&state, &host, method, path, None, Some(body)).await;
    }
    if resource == "/cores/sing-box/schema" && method == "GET" {
        let version = desired.version.clone().ok_or(Error::NoVersion)?;
        return schema(&state, &host, &version).await;
    }
    if resource == "/cores/sing-box/generate" && method == "POST" {
        let version = desired.version.clone().ok_or(Error::NoVersion)?;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("version", version.as_str())
            .finish();
        return peers::call(
            &state,
            &host,
            method,
            format!("{resource}?{query}"),
            None,
            body,
        )
        .await;
    }
    let authored =
        resource == "/cores/sing-box/configs" || resource.starts_with("/cores/sing-box/configs/");
    let addresses = resource == "/inbounds/endpoints"
        || resource.starts_with("/inbounds/endpoints/")
        || resource.starts_with("/inbounds/configs/");
    if authored || addresses {
        if authored && method == "PUT" {
            let version = desired.version.clone().ok_or(Error::NoVersion)?;
            ensure_schema(&state, &scoped, &host, version).await?;
        }
        return local(scoped, method, path, headers, body).await;
    }
    if resource.starts_with("/inbounds/")
        || resource.starts_with("/providers")
        || resource.starts_with("/collections")
    {
        return Err(Error::PeerNotFound);
    }
    if resource.starts_with("/cores/sing-box/") {
        if method == "DELETE" && resource.starts_with("/cores/sing-box/versions/") {
            let requested = resource.rsplit('/').next().unwrap_or_default();
            if desired
                .version
                .is_some_and(|version| version.as_str() == requested)
            {
                return Err(Error::PeerConflict {
                    reason: "version: selected by the managed instance",
                });
            }
        }
        return peers::call(&state, &host, method, path, None, body).await;
    }
    Err(Error::PeerNotFound)
}

async fn local(
    state: AppState,
    method: String,
    path: String,
    headers: HeaderMap,
    body: Option<String>,
) -> Result<Response, Error> {
    let mut request = Request::builder().method(method.as_str()).uri(path);
    *request.headers_mut().expect("resource headers") = headers;
    if body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let request = request
        .body(body.map_or_else(Body::empty, Body::from))
        .map_err(|_| Error::PeerRequest {
            reason: "resource: invalid request",
        })?;
    let response = crate::routers::AppRouter::resources()
        .with_state(state)
        .oneshot(request)
        .await
        .expect("infallible manager resource router");
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(Error::Unauthorized);
    }
    Ok(response)
}
