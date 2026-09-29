use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::{
    dto::{Authenticated, ResponseResult, ValidatedJson},
    tracing, AppState,
};

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct PasswordAuthRequest {
    #[garde(ascii, length(min = 3, max = 64))]
    username: String,
    #[garde(length(min = 6, max = 128))]
    password: String,
}

#[derive(Debug, Serialize)]
pub struct Token {
    pub access_token: String,
}

pub async fn password_login(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<PasswordAuthRequest>,
) -> ResponseResult<impl IntoResponse> {
    let user = state
        .settings()
        .login_or_register(&payload.username, &payload.password)
        .await?;

    let key_pair = state.settings().key_pair().await?;
    let (claims, access_token) = user.create_session(&key_pair)?;
    state.sessions().add(claims.jti, claims.exp).await?;
    tracing::info!(
        "User '{}' logged in with session ID: {}",
        user.username,
        claims.jti
    );

    Ok((StatusCode::CREATED, Json(Token { access_token })))
}

pub async fn logout(
    State(state): State<AppState>,
    Authenticated(claims): Authenticated,
) -> ResponseResult<impl IntoResponse> {
    state.sessions().remove(claims.jti).await?;
    Ok(StatusCode::NO_CONTENT)
}
