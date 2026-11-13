//! Local administrator account operations; peer resource grants cannot change credentials.

use axum::{extract::State, http::StatusCode, Json};
use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::{
    dto::{Authenticated, ResponseResult, ValidatedJson},
    AppState,
};

/// The account identity returned without its credential material.
#[derive(Serialize)]
pub struct AccountView {
    username: String,
}

/// Current credentials authorize the replacement of the administrator password.
#[derive(Deserialize, Validate)]
pub struct ChangePassword {
    #[garde(length(min = 6, max = 128))]
    current_password: String,
    #[garde(length(min = 6, max = 128))]
    new_password: String,
}

/// A username edit requires the existing account password.
#[derive(Deserialize, Validate)]
pub struct ChangeUsername {
    #[garde(ascii, length(min = 3, max = 64))]
    username: String,
    #[garde(length(min = 6, max = 128))]
    current_password: String,
}

/// Read the local account, never a selected environment's administrator.
pub async fn account(Authenticated(claims): Authenticated) -> Json<AccountView> {
    Json(AccountView {
        username: claims.sub,
    })
}

/// Change the local login name and revoke every issued session.
pub async fn change_username(
    Authenticated(claims): Authenticated,
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<ChangeUsername>,
) -> ResponseResult<StatusCode> {
    let _auth_lock = state.auth_lock().lock().await;
    state
        .settings()
        .change_username(
            state.sessions(),
            &claims.sub,
            &payload.current_password,
            &payload.username,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Replace the hash and revoke every session under the issuance lock.
pub async fn change_password(
    Authenticated(claims): Authenticated,
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<ChangePassword>,
) -> ResponseResult<StatusCode> {
    let _auth_lock = state.auth_lock().lock().await;
    state
        .settings()
        .change_password(
            state.sessions(),
            &claims.sub,
            &payload.current_password,
            &payload.new_password,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
