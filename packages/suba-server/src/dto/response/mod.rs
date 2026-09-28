use axum::{
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::error::{Error, IntoHttpError};

pub type ResponseResult<T = ()> = std::result::Result<T, Error>;

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let http_error = self.into_http_error();

        (
            http_error.status_code,
            Json(ErrorResponse {
                message: http_error.message,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ErrorResponse {
    pub message: String,
}
