//! Gateway error type and gRPC→HTTP status mapping.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use tonic::{Code, Status};

pub struct ApiError {
    pub code: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: StatusCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn forbidden(perm: &str) -> Self {
        Self::new(StatusCode::FORBIDDEN, format!("permission denied: {perm}"))
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
}

/// Map a tonic Status to an HTTP error.
impl From<Status> for ApiError {
    fn from(s: Status) -> Self {
        let code = match s.code() {
            Code::InvalidArgument => StatusCode::BAD_REQUEST,
            Code::Unauthenticated => StatusCode::UNAUTHORIZED,
            Code::PermissionDenied => StatusCode::FORBIDDEN,
            Code::NotFound => StatusCode::NOT_FOUND,
            Code::AlreadyExists => StatusCode::CONFLICT,
            Code::FailedPrecondition => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        // Only surface the service message for codes we deliberately map to a 4xx
        // (those are written for clients). For Internal/Unknown/Unavailable etc.
        // return a generic message so a wrapped SQL/driver/connection error can't
        // leak schema or infra detail to the client.
        let message = if code == StatusCode::INTERNAL_SERVER_ERROR {
            "internal error".to_string()
        } else {
            s.message().to_string()
        };
        Self::new(code, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.code, Json(json!({ "error": self.message }))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
