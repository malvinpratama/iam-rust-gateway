//! OIDC discovery + JWKS endpoints (public). Lets external relying parties
//! discover the provider and verify tokens via the published RS256 keys.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

use proto::auth::v1 as authpb;

use crate::clients::AppState;
use crate::error::ApiResult;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
}

/// Issuer URL: OIDC_ISSUER env if set, else derived from the request.
fn issuer(headers: &HeaderMap) -> String {
    if let Ok(v) = std::env::var("OIDC_ISSUER") {
        if !v.is_empty() {
            return v.trim_end_matches('/').to_string();
        }
    }
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    format!("{scheme}://{host}")
}

async fn discovery(headers: HeaderMap) -> Json<Value> {
    let iss = issuer(&headers);
    Json(json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/authorize"),
        "token_endpoint": format!("{iss}/token"),
        "userinfo_endpoint": format!("{iss}/userinfo"),
        "jwks_uri": format!("{iss}/.well-known/jwks.json"),
        "end_session_endpoint": format!("{iss}/logout"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"]
    }))
}

async fn jwks(State(mut state): State<AppState>) -> ApiResult<Json<Value>> {
    let res = state.auth.get_jwks(authpb::GetJwksRequest {}).await?.into_inner();
    let keys: Vec<Value> = res
        .keys
        .into_iter()
        .map(|k| {
            json!({ "kty": k.kty, "use": k.r#use, "alg": k.alg, "kid": k.kid, "n": k.n, "e": k.e })
        })
        .collect();
    Ok(Json(json!({ "keys": keys })))
}
