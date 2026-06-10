//! Authentication middleware, the CurrentUser extractor, and identity propagation.

use axum::async_trait;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tonic::metadata::MetadataValue;

use proto::auth::v1::{ValidateApiKeyRequest, ValidateTokenRequest};

use crate::clients::AppState;
use crate::error::ApiError;

/// The authenticated caller, resolved by the auth middleware.
#[derive(Clone)]
pub struct Identity {
    pub user_id: String,
    pub email: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

impl Identity {
    pub fn has_permission(&self, perm: &str) -> bool {
        self.permissions.iter().any(|p| p == perm)
    }

    pub fn require(&self, perm: &str) -> Result<(), ApiError> {
        if self.has_permission(perm) {
            Ok(())
        } else {
            Err(ApiError::forbidden(perm))
        }
    }
}

/// Middleware: validate the bearer token via the Auth service and stash the Identity.
pub async fn auth(
    State(mut state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = bearer(&req).ok_or_else(|| {
        ApiError::new(StatusCode::UNAUTHORIZED, "missing bearer token")
    })?;

    // API keys (iamk_...) authenticate via ValidateApiKey; their scopes act as
    // the caller's permissions. Everything else is a JWT access token.
    let identity = if token.starts_with("iamk_") {
        let res = state
            .auth
            .validate_api_key(ValidateApiKeyRequest { api_key: token })
            .await
            .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "invalid api key"))?
            .into_inner();
        Identity { user_id: res.user_id, email: res.email, roles: vec![], permissions: res.scopes }
    } else {
        let res = state
            .auth
            .validate_token(ValidateTokenRequest { access_token: token })
            .await
            .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "invalid or expired token"))?
            .into_inner();
        Identity { user_id: res.user_id, email: res.email, roles: res.roles, permissions: res.permissions }
    };

    req.extensions_mut().insert(identity);
    Ok(next.run(req).await)
}

fn bearer(req: &Request) -> Option<String> {
    let h = req.headers().get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, value) = h.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        Some(value.trim().to_string())
    } else {
        None
    }
}

/// Extractor that yields the Identity inserted by the auth middleware.
#[async_trait]
impl<S> FromRequestParts<S> for Identity
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Identity>()
            .cloned()
            .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated"))
    }
}

/// Attach the caller identity to an outgoing gRPC request's metadata so internal
/// services can read it (they trust the gateway on the internal network).
pub fn attach_identity<T>(req: &mut tonic::Request<T>, id: &Identity) {
    let md = req.metadata_mut();
    if let Ok(v) = MetadataValue::try_from(&id.user_id) {
        md.insert("x-user-id", v);
    }
    if let Ok(v) = MetadataValue::try_from(&id.email) {
        md.insert("x-user-email", v);
    }
    if let Ok(v) = MetadataValue::try_from(id.permissions.join(",")) {
        md.insert("x-user-permissions", v);
    }
}
