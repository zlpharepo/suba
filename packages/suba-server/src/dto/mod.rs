mod request;
mod response;

use crate::{config::Claims, AppState};
use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, HeaderMap},
};

pub use request::*;
pub use response::*;

pub struct Authenticated(pub Claims);

fn bearer_token(headers: &HeaderMap) -> Result<String, crate::error::Error> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(crate::error::Error::Unauthorized)?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or(crate::error::Error::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || token.trim().is_empty() {
        return Err(crate::error::Error::Unauthorized);
    }
    Ok(token.trim().to_owned())
}

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = crate::error::Error;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let token = bearer_token(&parts.headers);
        let state = state.clone();
        async move {
            let claims = crate::Claims::decode(&token?, &state.settings().key_pair().await?)?;
            if state.sessions().contains(claims.jti).await {
                Ok(Self(claims))
            } else {
                Err(crate::error::Error::Unauthorized)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "bearer token".parse().unwrap());
        assert_eq!(bearer_token(&headers).unwrap(), "token");
    }

    #[test]
    fn malformed_authorization_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic token".parse().unwrap());
        assert!(matches!(
            bearer_token(&headers),
            Err(crate::error::Error::Unauthorized)
        ));
    }
}
