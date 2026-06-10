//! OIDC Authorization Code + PKCE browser flow: login form → signed session
//! cookie → consent → authorization code. Mirrors the Go gateway.

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;

use proto::auth::v1 as authpb;

use crate::clients::AppState;

type HmacSha256 = Hmac<Sha256>;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize))
        .route("/authorize/login", post(authorize_login))
        .route("/authorize/consent", post(authorize_consent))
        .route("/token", post(token))
}

#[derive(Deserialize)]
struct TokenForm {
    #[serde(default)]
    grant_type: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret: String,
    #[serde(default)]
    code_verifier: String,
    #[serde(default)]
    refresh_token: String,
}

// client_creds: client_secret_post (form) or client_secret_basic (Authorization header).
fn client_creds(headers: &HeaderMap, f: &TokenForm) -> (String, String) {
    if !f.client_id.is_empty() {
        return (f.client_id.clone(), f.client_secret.clone());
    }
    if let Some(b64) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|a| a.strip_prefix("Basic "))
    {
        if let Some((u, p)) = STANDARD
            .decode(b64)
            .ok()
            .and_then(|d| String::from_utf8(d).ok())
            .and_then(|s| s.split_once(':').map(|(u, p)| (u.to_string(), p.to_string())))
        {
            return (u, p);
        }
    }
    (f.client_id.clone(), f.client_secret.clone())
}

async fn token(State(mut state): State<AppState>, headers: HeaderMap, Form(f): Form<TokenForm>) -> Response {
    let mut resp = match f.grant_type.as_str() {
        "authorization_code" => {
            let (client_id, client_secret) = client_creds(&headers, &f);
            match state
                .auth
                .exchange_authorization_code(authpb::ExchangeAuthorizationCodeRequest {
                    client_id,
                    client_secret,
                    code: f.code,
                    redirect_uri: f.redirect_uri,
                    code_verifier: f.code_verifier,
                })
                .await
            {
                Ok(r) => {
                    let t = r.into_inner();
                    Json(json!({"access_token":t.access_token,"id_token":t.id_token,"refresh_token":t.refresh_token,"token_type":"Bearer","expires_in":t.expires_in,"scope":t.scope})).into_response()
                }
                Err(_) => (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))).into_response(),
            }
        }
        "refresh_token" => match state.auth.refresh(authpb::RefreshRequest { refresh_token: f.refresh_token }).await {
            Ok(r) => {
                let t = r.into_inner();
                Json(json!({"access_token":t.access_token,"refresh_token":t.refresh_token,"token_type":"Bearer","expires_in":t.expires_in})).into_response()
            }
            Err(_) => (StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))).into_response(),
        },
        _ => (StatusCode::BAD_REQUEST, Json(json!({"error":"unsupported_grant_type"}))).into_response(),
    };
    // OIDC: token responses must not be cached.
    resp.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    resp
}

// ── session (stateless signed cookie) ───────────────────────

fn session_secret() -> String {
    std::env::var("SESSION_SECRET").unwrap_or_else(|_| "dev-session-secret-change-me-please".into())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Serialize, Deserialize)]
struct Session {
    uid: String,
    email: String,
    exp: i64,
}

fn sign_session(uid: &str, email: &str) -> String {
    let payload = serde_json::to_vec(&Session {
        uid: uid.to_string(),
        email: email.to_string(),
        exp: now() + 3600,
    })
    .unwrap_or_default();
    let p = URL_SAFE_NO_PAD.encode(&payload);
    let mut mac = HmacSha256::new_from_slice(session_secret().as_bytes()).expect("hmac key");
    mac.update(p.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{p}.{sig}")
}

fn parse_session(headers: &HeaderMap) -> Option<Session> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    let val = cookie
        .split(';')
        .find_map(|c| c.trim().strip_prefix("iam_session="))?;
    let (p, sig) = val.split_once('.')?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig).ok()?;
    let mut mac = HmacSha256::new_from_slice(session_secret().as_bytes()).ok()?;
    mac.update(p.as_bytes());
    mac.verify_slice(&sig_bytes).ok()?; // constant-time
    let s: Session = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()?;
    if s.exp < now() {
        return None;
    }
    Some(s)
}

fn session_cookie(value: &str, secure: bool) -> String {
    let mut c = format!("iam_session={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600");
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn is_secure(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s == "https")
        .unwrap_or(false)
}

// ── params ──────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Default)]
struct AuthzParams {
    #[serde(default)]
    response_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: String,
    #[serde(default)]
    nonce: String,
}

// Forms are flat (serde_urlencoded can't deserialize #[serde(flatten)]).
#[derive(Deserialize)]
struct LoginForm {
    email: String,
    password: String,
    #[serde(default)]
    response_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: String,
    #[serde(default)]
    nonce: String,
}

impl LoginForm {
    fn params(&self) -> AuthzParams {
        AuthzParams {
            response_type: self.response_type.clone(),
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            scope: self.scope.clone(),
            state: self.state.clone(),
            code_challenge: self.code_challenge.clone(),
            code_challenge_method: self.code_challenge_method.clone(),
            nonce: self.nonce.clone(),
        }
    }
}

#[derive(Deserialize)]
struct ConsentForm {
    #[serde(default)]
    action: String,
    #[serde(default)]
    response_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: String,
    #[serde(default)]
    nonce: String,
}

impl ConsentForm {
    fn params(&self) -> AuthzParams {
        AuthzParams {
            response_type: self.response_type.clone(),
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            scope: self.scope.clone(),
            state: self.state.clone(),
            code_challenge: self.code_challenge.clone(),
            code_challenge_method: self.code_challenge_method.clone(),
            nonce: self.nonce.clone(),
        }
    }
}

fn redirect_with(redirect_uri: &str, pairs: &[(&str, String)]) -> Response {
    let qs = serde_urlencoded::to_string(pairs).unwrap_or_default();
    let sep = if redirect_uri.contains('?') { "&" } else { "?" };
    Redirect::to(&format!("{redirect_uri}{sep}{qs}")).into_response()
}

fn redirect_error(p: &AuthzParams, code: &str) -> Response {
    let mut pairs = vec![("error", code.to_string())];
    if !p.state.is_empty() {
        pairs.push(("state", p.state.clone()));
    }
    redirect_with(&p.redirect_uri, &pairs)
}

fn scopes_covered(granted: &[String], scope: &str) -> bool {
    let req: Vec<&str> = scope.split_whitespace().collect();
    !req.is_empty() && req.iter().all(|r| granted.iter().any(|g| g == r))
}

// ── handlers ────────────────────────────────────────────────

async fn authorize(
    State(mut state): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<AuthzParams>,
) -> Response {
    if p.response_type != "code" {
        return (StatusCode::BAD_REQUEST, Html("unsupported response_type (only 'code')")).into_response();
    }
    let client = match state.auth.get_client(authpb::GetClientRequest { client_id: p.client_id.clone() }).await {
        Ok(r) => r.into_inner(),
        Err(_) => return (StatusCode::BAD_REQUEST, Html("unknown client")).into_response(),
    };
    if !client.redirect_uris.iter().any(|u| u == &p.redirect_uri) {
        return (StatusCode::BAD_REQUEST, Html("invalid redirect_uri")).into_response();
    }
    let sess = match parse_session(&headers) {
        Some(s) => s,
        None => return Html(login_page(&p, "")).into_response(),
    };
    let granted = state
        .auth
        .get_consent(authpb::GetConsentRequest { user_id: sess.uid.clone(), client_id: p.client_id.clone() })
        .await
        .map(|r| r.into_inner().scopes)
        .unwrap_or_default();
    if scopes_covered(&granted, &p.scope) {
        return issue_code(&mut state, &p, &sess.uid).await;
    }
    Html(consent_page(&p, &client.name)).into_response()
}

async fn authorize_login(
    State(mut state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<LoginForm>,
) -> Response {
    let p = f.params();
    let tp = match state.auth.login(authpb::LoginRequest { email: f.email, password: f.password }).await {
        Ok(r) => r.into_inner(),
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Html(login_page(&p, "Invalid email or password"))).into_response()
        }
    };
    let vt = match state.auth.validate_token(authpb::ValidateTokenRequest { access_token: tp.access_token }).await {
        Ok(r) => r.into_inner(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Html("login failed")).into_response(),
    };
    let cookie = sign_session(&vt.user_id, &vt.email);
    let qs = serde_urlencoded::to_string(&p).unwrap_or_default();
    let mut resp = Redirect::to(&format!("/authorize?{qs}")).into_response();
    if let Ok(v) = session_cookie(&cookie, is_secure(&headers)).parse() {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

async fn authorize_consent(
    State(mut state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<ConsentForm>,
) -> Response {
    let p = f.params();
    let sess = match parse_session(&headers) {
        Some(s) => s,
        None => {
            let qs = serde_urlencoded::to_string(&p).unwrap_or_default();
            return Redirect::to(&format!("/authorize?{qs}")).into_response();
        }
    };
    // Re-validate client + redirect_uri before issuing/redirecting (open-redirect guard).
    let client = match state.auth.get_client(authpb::GetClientRequest { client_id: p.client_id.clone() }).await {
        Ok(r) => r.into_inner(),
        Err(_) => return (StatusCode::BAD_REQUEST, Html("invalid client")).into_response(),
    };
    if !client.redirect_uris.iter().any(|u| u == &p.redirect_uri) {
        return (StatusCode::BAD_REQUEST, Html("invalid redirect_uri")).into_response();
    }
    if f.action != "allow" {
        return redirect_error(&p, "access_denied");
    }
    let scopes: Vec<String> = p.scope.split_whitespace().map(String::from).collect();
    let _ = state
        .auth
        .save_consent(authpb::SaveConsentRequest { user_id: sess.uid.clone(), client_id: p.client_id.clone(), scopes })
        .await;
    issue_code(&mut state, &p, &sess.uid).await
}

async fn issue_code(state: &mut AppState, p: &AuthzParams, uid: &str) -> Response {
    let res = match state
        .auth
        .create_authorization_code(authpb::CreateAuthorizationCodeRequest {
            client_id: p.client_id.clone(),
            user_id: uid.to_string(),
            redirect_uri: p.redirect_uri.clone(),
            scope: p.scope.clone(),
            code_challenge: p.code_challenge.clone(),
            code_challenge_method: p.code_challenge_method.clone(),
            nonce: p.nonce.clone(),
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(_) => return redirect_error(p, "server_error"),
    };
    let mut pairs = vec![("code", res.code)];
    if !p.state.is_empty() {
        pairs.push(("state", p.state.clone()));
    }
    redirect_with(&p.redirect_uri, &pairs)
}

// ── minimal HTML ────────────────────────────────────────────

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn hidden_fields(p: &AuthzParams) -> String {
    let f = |k: &str, v: &str| format!(r#"<input type="hidden" name="{}" value="{}">"#, k, esc(v));
    [
        f("response_type", &p.response_type),
        f("client_id", &p.client_id),
        f("redirect_uri", &p.redirect_uri),
        f("scope", &p.scope),
        f("state", &p.state),
        f("code_challenge", &p.code_challenge),
        f("code_challenge_method", &p.code_challenge_method),
        f("nonce", &p.nonce),
    ]
    .concat()
}

const PAGE_CSS: &str = r#"<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#1e293b;padding:2rem 2.25rem;border-radius:14px;width:340px;box-shadow:0 10px 40px rgba(0,0,0,.4)}
h1{font-size:1.15rem;margin:0 0 .25rem}p{color:#94a3b8;font-size:.85rem;margin:.25rem 0 1.25rem}
label{display:block;font-size:.8rem;margin:.6rem 0 .2rem;color:#cbd5e1}
input[type=email],input[type=password]{width:100%;padding:.6rem .7rem;border:1px solid #334155;border-radius:8px;background:#0f172a;color:#e2e8f0;box-sizing:border-box}
button{margin-top:1.1rem;width:100%;padding:.65rem;border:0;border-radius:8px;background:#6366f1;color:#fff;font-weight:600;cursor:pointer}
button.ghost{background:#334155}.row{display:flex;gap:.6rem}.err{color:#f87171;font-size:.8rem;margin:.4rem 0}
.scopes{list-style:none;padding:0;margin:.5rem 0}.scopes li{padding:.35rem 0;border-bottom:1px solid #334155;font-size:.9rem}</style>"#;

fn login_page(p: &AuthzParams, err: &str) -> String {
    let e = if err.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="err">{}</div>"#, esc(err))
    };
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>Sign in · IAM</title>{css}</head><body>
<form class="card" method="post" action="/authorize/login">
<h1>🔐 Sign in to IAM</h1><p>An application is requesting access to your account.</p>{err}
<label>Email</label><input type="email" name="email" required autofocus>
<label>Password</label><input type="password" name="password" required>
{hidden}<button type="submit">Sign in</button></form></body></html>"#,
        css = PAGE_CSS,
        err = e,
        hidden = hidden_fields(p),
    )
}

fn consent_page(p: &AuthzParams, client_name: &str) -> String {
    let items: String = p
        .scope
        .split_whitespace()
        .map(|s| format!("<li>{}</li>", esc(s)))
        .collect();
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>Authorize · IAM</title>{css}</head><body>
<form class="card" method="post" action="/authorize/consent">
<h1>Authorize {name}</h1><p>This application wants access to:</p>
<ul class="scopes">{items}</ul>{hidden}
<div class="row"><button class="ghost" type="submit" name="action" value="deny">Deny</button>
<button type="submit" name="action" value="allow">Allow</button></div></form></body></html>"#,
        css = PAGE_CSS,
        name = esc(client_name),
        items = items,
        hidden = hidden_fields(p),
    )
}
