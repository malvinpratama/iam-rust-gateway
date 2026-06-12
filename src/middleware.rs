//! Authentication middleware, the CurrentUser extractor, and identity propagation.

use axum::async_trait;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{header::AUTHORIZATION, HeaderValue, StatusCode};
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
    pub tenant_id: String,  // M6: active tenant the token is bound to
    pub project_id: String, // M6: active project (empty = tenant-wide)
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
        Identity { user_id: res.user_id, email: res.email, roles: vec![], permissions: res.scopes, tenant_id: String::new(), project_id: String::new() }
    } else {
        let res = state
            .auth
            .validate_token(ValidateTokenRequest { access_token: token })
            .await
            .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "invalid or expired token"))?
            .into_inner();
        Identity { user_id: res.user_id, email: res.email, roles: res.roles, permissions: res.permissions, tenant_id: res.tenant_id, project_id: res.project_id }
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
    // M6: forward the active tenant/project so internal services can scope.
    if let Ok(v) = MetadataValue::try_from(&id.tenant_id) {
        md.insert("x-tenant-id", v);
    }
    if let Ok(v) = MetadataValue::try_from(&id.project_id) {
        md.insert("x-project-id", v);
    }
}

/// Set conservative security headers on every response: stop MIME sniffing,
/// forbid framing (clickjacking guard for the OIDC login/consent HTML), and trim
/// referrer leakage. HSTS is added only when the edge terminated TLS
/// (X-Forwarded-Proto=https) so local HTTP dev is unaffected.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let https = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.eq_ignore_ascii_case("https"));
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    h.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    if https {
        h.insert(
            "Strict-Transport-Security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    resp
}
