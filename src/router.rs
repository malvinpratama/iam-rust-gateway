//! REST routes wired to the gRPC backend services.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tonic::Request;

use proto::auth::v1 as authpb;
use proto::user::v1 as userpb;


use axum::extract::DefaultBodyLimit;

use crate::clients::AppState;
use crate::error::{ApiError, ApiResult};
use crate::middleware::{attach_identity, auth, Identity};
use crate::ratelimit::{self, RateLimiter};

pub fn build(state: AppState, limiter: RateLimiter) -> Router {
    let protected = Router::new()
        .route("/auth/logout", post(logout))
        .route("/auth/password", post(change_password)) // self-service password change
        .route("/me", get(get_identity))
        .route("/me/memberships", get(list_memberships))
        .route("/auth/switch", post(switch_tenant))
        // M6.4: tenant / project / member administration.
        .route("/tenants", get(list_tenants).post(create_tenant))
        .route("/projects", get(list_projects).post(create_project))
        .route("/members", get(list_members).post(add_member))
        .route("/members/:user_id", delete(remove_member))
        .route("/userinfo", get(userinfo))
        .route("/oauth/clients", post(register_client))
        .route("/permissions", get(list_permissions))
        .route("/audit", get(list_audit))
        .route("/users/me", get(get_me))
        .route("/users/:id", get(get_user).patch(update_user).delete(delete_user))
        .route("/users", get(list_users))
        .route("/roles", get(list_roles).post(create_role))
        .route("/roles/:name", patch(update_role).delete(delete_role))
        .route("/roles/:name/permissions", post(grant_permission))
        .route("/roles/:name/permissions/:perm", delete(revoke_permission))
        .route("/users/:id/roles", get(get_user_role_assignments).post(assign_role))
        .route("/users/:id/roles/:role", delete(revoke_role))
        .route("/roles/:name/assignments", post(assign_role_bulk))
        .route("/users/:id/restore", post(restore_user))
        // 2FA (self-service)
        .route("/auth/2fa", get(totp_status))
        .route("/auth/2fa/enroll", post(enroll_totp))
        .route("/auth/2fa/activate", post(activate_totp))
        .route("/auth/2fa/disable", post(disable_totp))
        // API keys (self-service)
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api-keys/:id", delete(revoke_api_key))
        .route_layer(from_fn_with_state(state.clone(), auth));

    // Public auth endpoints — rate limited per IP (limiter built in main:
    // Redis-backed across replicas when REDIS_URL is set, else in-memory).
    let auth_public = Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/login/totp", post(login_totp))
        .route("/auth/refresh", post(refresh))
        .route("/auth/verify-email/request", post(request_email_verification))
        .route("/auth/verify-email", post(verify_email))
        .route("/auth/password-reset/request", post(request_password_reset))
        .route("/auth/password-reset", post(reset_password))
        .route_layer(from_fn_with_state(limiter.clone(), ratelimit::limit));

    let public = Router::new()
        .route("/healthz", get(|| async { Json(json!({"status": "ok"})) }))
        .merge(crate::docs::routes())
        .merge(crate::oidc::routes())
        .merge(crate::authorize::routes(limiter))
        .merge(auth_public);

    public
        .merge(protected)
        .layer(from_fn(crate::middleware::security_headers)) // nosniff/frame/referrer/HSTS
        .layer(DefaultBodyLimit::max(1 << 20)) // 1 MiB request-body cap (DoS guard)
        .with_state(state)
}

// ── request bodies ──────────────────────────────────────────

#[derive(Deserialize)]
struct Credentials {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct RefreshBody {
    refresh_token: String,
}

#[derive(Deserialize)]
struct SwitchBody {
    tenant_id: String,
    #[serde(default)]
    project_id: Option<String>,
}

#[derive(Deserialize)]
struct EmailBody {
    email: String,
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

#[derive(Deserialize)]
struct ResetPasswordBody {
    token: String,
    new_password: String,
}

#[derive(Deserialize)]
struct ChangePasswordBody {
    old_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct AssignRoleBody {
    role: String,
    #[serde(default)]
    project_id: String, // empty = tenant-wide
}

#[derive(Deserialize)]
struct CreateRoleBody {
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct UpdateRoleBody {
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct GrantPermissionBody {
    permission: String,
}

#[derive(Deserialize)]
struct UpdateBody {
    display_name: Option<String>,
    bio: Option<String>,
    avatar_url: Option<String>,
    phone: Option<String>,
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<i32>,
}

// ── auth handlers ───────────────────────────────────────────

async fn register(
    State(mut state): State<AppState>,
    Json(body): Json<Credentials>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let reg = state
        .auth
        .register(authpb::RegisterRequest {
            email: body.email.clone(),
            password: body.password,
        })
        .await?
        .into_inner();

    // Profile creation is now driven asynchronously by a UserRegistered event
    // (transactional outbox in auth → NATS → user service). The gateway no
    // longer calls the user service here; GET /users/me heals lazily if a read
    // arrives before the event is processed.
    Ok((
        StatusCode::CREATED,
        Json(json!({ "user_id": reg.user_id, "email": reg.email })),
    ))
}

async fn login(
    State(mut state): State<AppState>,
    Json(body): Json<Credentials>,
) -> ApiResult<Json<Value>> {
    let tp = state
        .auth
        .login(authpb::LoginRequest { email: body.email, password: body.password })
        .await?
        .into_inner();
    Ok(Json(token_pair_json(tp)))
}

async fn refresh(
    State(mut state): State<AppState>,
    Json(body): Json<RefreshBody>,
) -> ApiResult<Json<Value>> {
    let tp = state
        .auth
        .refresh(authpb::RefreshRequest { refresh_token: body.refresh_token })
        .await?
        .into_inner();
    Ok(Json(token_pair_json(tp)))
}

async fn logout(
    State(mut state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RefreshBody>,
) -> ApiResult<Json<Value>> {
    // Pass the access token so the auth service can denylist it (by jti).
    let access = bearer_from(&headers);
    state
        .auth
        .logout(authpb::LogoutRequest {
            refresh_token: body.refresh_token,
            access_token: access,
        })
        .await?;
    Ok(Json(json!({ "success": true })))
}

// ── account recovery & verification (v0.2) ──────────────────

async fn request_email_verification(
    State(mut state): State<AppState>,
    Json(body): Json<EmailBody>,
) -> ApiResult<Json<Value>> {
    let res = state
        .auth
        .request_email_verification(authpb::EmailRequest { email: body.email })
        .await?
        .into_inner();
    Ok(Json(dev_token_json(res)))
}

async fn verify_email(
    State(mut state): State<AppState>,
    Json(body): Json<TokenBody>,
) -> ApiResult<Json<Value>> {
    state.auth.verify_email(authpb::TokenRequest { token: body.token }).await?;
    Ok(Json(json!({ "success": true })))
}

async fn request_password_reset(
    State(mut state): State<AppState>,
    Json(body): Json<EmailBody>,
) -> ApiResult<Json<Value>> {
    let res = state
        .auth
        .request_password_reset(authpb::EmailRequest { email: body.email })
        .await?
        .into_inner();
    Ok(Json(dev_token_json(res)))
}

async fn reset_password(
    State(mut state): State<AppState>,
    Json(body): Json<ResetPasswordBody>,
) -> ApiResult<Json<Value>> {
    state
        .auth
        .reset_password(authpb::ResetPasswordRequest { token: body.token, new_password: body.new_password })
        .await?;
    Ok(Json(json!({ "success": true })))
}

// Authenticated self-service password change; attach_identity carries the caller
// so the auth service knows whose password to rotate.
async fn change_password(
    State(mut state): State<AppState>,
    identity: Identity,
    Json(body): Json<ChangePasswordBody>,
) -> ApiResult<Json<Value>> {
    let mut req = Request::new(authpb::ChangePasswordRequest {
        old_password: body.old_password,
        new_password: body.new_password,
    });
    attach_identity(&mut req, &identity);
    state.auth.change_password(req).await?;
    Ok(Json(json!({ "success": true })))
}

fn dev_token_json(res: authpb::DevTokenResponse) -> Value {
    if res.dev_token.is_empty() {
        json!({ "success": res.success })
    } else {
        json!({ "success": res.success, "dev_token": res.dev_token })
    }
}

async fn list_audit(
    State(mut state): State<AppState>,
    identity: Identity,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    identity.require("audit:read")?;
    let mut req = Request::new(authpb::ListAuditEventsRequest { limit: q.limit.unwrap_or(0) });
    attach_identity(&mut req, &identity);
    let res = state.auth.list_audit_events(req).await?.into_inner();
    let events: Vec<Value> = res
        .events
        .into_iter()
        .map(|e| json!({
            "id": e.id, "actor_id": e.actor_id, "actor_email": e.actor_email,
            "action": e.action, "target": e.target, "detail": e.detail, "created_at": e.created_at,
        }))
        .collect();
    Ok(Json(json!({ "events": events })))
}

fn bearer_from(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, tok)| tok.trim().to_string())
        .unwrap_or_default()
}

// ── user handlers ───────────────────────────────────────────

// Returns the caller's own identity, roles and permissions.
async fn get_identity(identity: Identity) -> ApiResult<Json<Value>> {
    Ok(Json(json!({
        "user_id": identity.user_id,
        "email": identity.email,
        "roles": identity.roles,
        "permissions": identity.permissions,
    })))
}

// OIDC UserInfo: claims for the bearer token.
async fn userinfo(identity: Identity) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "sub": identity.user_id, "email": identity.email })))
}

#[derive(Deserialize)]
struct RegisterClientBody {
    name: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    confidential: bool,
}

// Register a new OAuth client (admin only).
async fn register_client(
    State(mut state): State<AppState>,
    identity: Identity,
    Json(body): Json<RegisterClientBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    identity.require("role:write")?;
    let mut req = Request::new(authpb::RegisterClientRequest {
        name: body.name,
        redirect_uris: body.redirect_uris,
        scopes: body.scopes,
        is_confidential: body.confidential,
    });
    attach_identity(&mut req, &identity);
    let res = state.auth.register_client(req).await?.into_inner();
    Ok((StatusCode::CREATED, Json(json!({ "client_id": res.client_id, "client_secret": res.client_secret }))))
}

// M6: tenants the caller is an active member of (feeds the console switcher).
async fn list_memberships(
    State(mut state): State<AppState>,
    identity: Identity,
) -> ApiResult<Json<Value>> {
    let mut req = Request::new(authpb::ListMembershipsRequest {});
    attach_identity(&mut req, &identity);
    let res = state.auth.list_my_memberships(req).await?.into_inner();
    let memberships: Vec<Value> = res
        .memberships
        .into_iter()
        .map(|m| json!({
            "tenant_id": m.tenant_id,
            "tenant_slug": m.tenant_slug,
            "tenant_name": m.tenant_name,
            "status": m.status,
        }))
        .collect();
    Ok(Json(json!({ "memberships": memberships })))
}

// M6: re-issue a token pair bound to another tenant/project the caller belongs to.
async fn switch_tenant(
    State(mut state): State<AppState>,
    identity: Identity,
    Json(body): Json<SwitchBody>,
) -> ApiResult<Json<Value>> {
    let mut req = Request::new(authpb::SwitchTenantRequest {
        tenant_id: body.tenant_id,
        project_id: body.project_id.unwrap_or_default(),
    });
    attach_identity(&mut req, &identity);
    let tp = state.auth.switch_tenant(req).await?.into_inner();
    Ok(Json(token_pair_json(tp)))
}

// ── M6.4: tenant / project / member administration ──────────

#[derive(Deserialize)]
struct SlugNameBody {
    slug: String,
    name: String,
}

#[derive(Deserialize)]
struct EmailMemberBody {
    email: String,
}

async fn create_tenant(
    State(mut state): State<AppState>,
    identity: Identity,
    Json(body): Json<SlugNameBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    identity.require("tenant:write")?;
    let mut req = Request::new(authpb::CreateTenantRequest { slug: body.slug, name: body.name });
    attach_identity(&mut req, &identity);
    let t = state.auth.create_tenant(req).await?.into_inner();
    Ok((StatusCode::CREATED, Json(json!({ "id": t.id, "slug": t.slug, "name": t.name, "status": t.status }))))
}

async fn list_tenants(
    State(mut state): State<AppState>,
    identity: Identity,
) -> ApiResult<Json<Value>> {
    identity.require("tenant:read")?;
    let mut req = Request::new(authpb::ListTenantsRequest {});
    attach_identity(&mut req, &identity);
    let res = state.auth.list_tenants(req).await?.into_inner();
    let tenants: Vec<Value> = res
        .tenants
        .into_iter()
        .map(|t| json!({ "id": t.id, "slug": t.slug, "name": t.name, "status": t.status }))
        .collect();
    Ok(Json(json!({ "tenants": tenants })))
}

async fn create_project(
    State(mut state): State<AppState>,
    identity: Identity,
    Json(body): Json<SlugNameBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    identity.require("project:write")?;
    let mut req = Request::new(authpb::CreateProjectRequest { slug: body.slug, name: body.name });
    attach_identity(&mut req, &identity);
    let p = state.auth.create_project(req).await?.into_inner();
    Ok((StatusCode::CREATED, Json(json!({ "id": p.id, "tenant_id": p.tenant_id, "slug": p.slug, "name": p.name }))))
}

async fn list_projects(
    State(mut state): State<AppState>,
    identity: Identity,
) -> ApiResult<Json<Value>> {
    identity.require("project:read")?;
    let mut req = Request::new(authpb::ListProjectsRequest {});
    attach_identity(&mut req, &identity);
    let res = state.auth.list_projects(req).await?.into_inner();
    let projects: Vec<Value> = res
        .projects
        .into_iter()
        .map(|p| json!({ "id": p.id, "tenant_id": p.tenant_id, "slug": p.slug, "name": p.name }))
        .collect();
    Ok(Json(json!({ "projects": projects })))
}

async fn list_members(
    State(mut state): State<AppState>,
    identity: Identity,
) -> ApiResult<Json<Value>> {
    identity.require("member:read")?;
    let mut req = Request::new(authpb::ListMembersRequest {});
    attach_identity(&mut req, &identity);
    let res = state.auth.list_members(req).await?.into_inner();
    let members: Vec<Value> = res
        .members
        .into_iter()
        .map(|m| json!({ "user_id": m.user_id, "email": m.email, "status": m.status }))
        .collect();
    Ok(Json(json!({ "members": members })))
}

async fn add_member(
    State(mut state): State<AppState>,
    identity: Identity,
    Json(body): Json<EmailMemberBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    identity.require("member:write")?;
    let mut req = Request::new(authpb::AddMemberRequest { email: body.email });
    attach_identity(&mut req, &identity);
    let m = state.auth.add_member(req).await?.into_inner();
    Ok((StatusCode::CREATED, Json(json!({ "user_id": m.user_id, "email": m.email, "status": m.status }))))
}

async fn remove_member(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(user_id): Path<String>,
) -> ApiResult<Json<Value>> {
    identity.require("member:write")?;
    let mut req = Request::new(authpb::RemoveMemberRequest { user_id });
    attach_identity(&mut req, &identity);
    state.auth.remove_member(req).await?;
    Ok(Json(json!({ "success": true })))
}

// Returns every permission defined in the system.
async fn list_permissions(
    State(mut state): State<AppState>,
    identity: Identity,
) -> ApiResult<Json<Value>> {
    identity.require("role:read")?;
    let res = state
        .auth
        .list_permissions(authpb::ListPermissionsRequest {})
        .await?
        .into_inner();
    let perms: Vec<Value> = res
        .permissions
        .into_iter()
        .map(|p| json!({ "id": p.id, "name": p.name, "description": p.description }))
        .collect();
    Ok(Json(json!({ "permissions": perms })))
}

async fn get_me(
    State(mut state): State<AppState>,
    identity: Identity,
) -> ApiResult<Json<Value>> {
    let mut req = Request::new(userpb::GetProfileRequest { user_id: identity.user_id.clone() });
    attach_identity(&mut req, &identity);
    match state.user.get_profile(req).await {
        Ok(resp) => Ok(Json(profile_json(resp.into_inner()))),
        // Heal ghost users: create the profile if registration left it missing.
        Err(s) if s.code() == tonic::Code::NotFound => {
            let display = identity
                .email
                .split('@')
                .next()
                .unwrap_or(&identity.email)
                .to_string();
            let mut creq = Request::new(userpb::CreateProfileRequest {
                user_id: identity.user_id.clone(),
                display_name: display,
            });
            attach_identity(&mut creq, &identity);
            let p = state.user.create_profile(creq).await?.into_inner();
            Ok(Json(profile_json(p)))
        }
        Err(s) => Err(s.into()),
    }
}

async fn get_user(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    identity.require("user:read")?;
    // Tenant-scope the lookup: a profile is only visible to admins of a tenant the
    // target belongs to. ListMembers is already scoped to the caller's active
    // tenant, so an id outside it returns 404 rather than leaking another tenant's
    // user (its very existence included).
    let mut mreq = Request::new(authpb::ListMembersRequest {});
    attach_identity(&mut mreq, &identity);
    let members = state.auth.list_members(mreq).await?.into_inner().members;
    if !members.iter().any(|m| m.user_id == id) {
        return Err(tonic::Status::not_found("user not found").into());
    }
    let mut req = Request::new(userpb::GetProfileRequest { user_id: id });
    attach_identity(&mut req, &identity);
    let p = state.user.get_profile(req).await?.into_inner();
    Ok(Json(profile_json(p)))
}

// The user directory is the active tenant's members (from auth) joined with
// their profiles (one batch GetProfiles call — no N+1), so it stays tenant-
// scoped: a tenant admin never sees other tenants' users.
async fn list_users(
    State(mut state): State<AppState>,
    identity: Identity,
) -> ApiResult<Json<Value>> {
    identity.require("user:read")?;
    let mut mreq = Request::new(authpb::ListMembersRequest {});
    attach_identity(&mut mreq, &identity);
    let members = state.auth.list_members(mreq).await?.into_inner().members;

    let ids: Vec<String> = members.iter().map(|m| m.user_id.clone()).collect();
    let mut prof: std::collections::HashMap<String, userpb::Profile> = std::collections::HashMap::new();
    if !ids.is_empty() {
        let mut preq = Request::new(userpb::GetProfilesRequest { user_ids: ids });
        attach_identity(&mut preq, &identity);
        for p in state.user.get_profiles(preq).await?.into_inner().profiles {
            prof.insert(p.user_id.clone(), p);
        }
    }
    let profiles: Vec<Value> = members
        .into_iter()
        .map(|m| {
            let p = prof.get(&m.user_id);
            json!({
                "user_id": m.user_id,
                "email": m.email,
                "status": m.status,
                "display_name": p.map(|x| x.display_name.clone()).unwrap_or_default(),
                "bio": p.map(|x| x.bio.clone()).unwrap_or_default(),
                "created_at": p.map(|x| x.created_at.clone()).unwrap_or_default(),
            })
        })
        .collect();
    let total = profiles.len();
    Ok(Json(json!({ "profiles": profiles, "total": total, "page": 1, "page_size": total })))
}

async fn update_user(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(id): Path<String>,
    Json(body): Json<UpdateBody>,
) -> ApiResult<Json<Value>> {
    // Own profile needs only authentication (profile:write); editing SOMEONE
    // ELSE's profile requires the admin-only user:write permission.
    if id == identity.user_id {
        if !identity.has_permission("profile:write") {
            return Err(ApiError::forbidden("profile:write"));
        }
    } else if !identity.has_permission("user:write") {
        return Err(ApiError::forbidden("user:write"));
    }
    let mut req = Request::new(userpb::UpdateProfileRequest {
        user_id: id,
        display_name: body.display_name,
        bio: body.bio,
        avatar_url: body.avatar_url,
        phone: body.phone,
    });
    attach_identity(&mut req, &identity);
    let p = state.user.update_profile(req).await?.into_inner();
    Ok(Json(profile_json(p)))
}

async fn delete_user(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    identity.require("user:delete")?;
    // Soft-delete by default (recoverable via /users/:id/restore); ?hard=true
    // removes the identity permanently. The matching profile is updated
    // asynchronously via a UserDeleted event.
    let hard = params.get("hard").map(|v| v == "true").unwrap_or(false);
    let mut areq = Request::new(authpb::DeleteUserRequest { user_id: id, hard });
    attach_identity(&mut areq, &identity);
    state.auth.delete_user(areq).await?;
    Ok(Json(json!({ "success": true, "hard": hard })))
}

async fn restore_user(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    identity.require("user:delete")?;
    let mut areq = Request::new(authpb::RestoreUserRequest { user_id: id });
    attach_identity(&mut areq, &identity);
    state.auth.restore_user(areq).await?;
    Ok(Json(json!({ "success": true })))
}

// ── 2FA handlers ────────────────────────────────────────────

#[derive(Deserialize)]
struct LoginTotpBody {
    mfa_token: String,
    code: String,
}

#[derive(Deserialize)]
struct CodeBody {
    code: String,
}

async fn login_totp(
    State(mut state): State<AppState>,
    Json(body): Json<LoginTotpBody>,
) -> ApiResult<Json<Value>> {
    let tp = state
        .auth
        .login_totp(authpb::LoginTotpRequest { mfa_token: body.mfa_token, code: body.code })
        .await?
        .into_inner();
    Ok(Json(token_pair_json(tp)))
}

async fn totp_status(
    State(mut state): State<AppState>,
    identity: Identity,
) -> ApiResult<Json<Value>> {
    let mut req = Request::new(authpb::GetTotpStatusRequest {});
    attach_identity(&mut req, &identity);
    let res = state.auth.get_totp_status(req).await?.into_inner();
    Ok(Json(json!({ "enabled": res.enabled })))
}

async fn enroll_totp(
    State(mut state): State<AppState>,
    identity: Identity,
) -> ApiResult<Json<Value>> {
    let mut req = Request::new(authpb::EnrollTotpRequest {});
    attach_identity(&mut req, &identity);
    let res = state.auth.enroll_totp(req).await?.into_inner();
    Ok(Json(json!({
        "secret": res.secret,
        "otpauth_uri": res.otpauth_uri,
        "recovery_codes": res.recovery_codes,
    })))
}

async fn activate_totp(
    State(mut state): State<AppState>,
    identity: Identity,
    Json(body): Json<CodeBody>,
) -> ApiResult<Json<Value>> {
    let mut req = Request::new(authpb::ActivateTotpRequest { code: body.code });
    attach_identity(&mut req, &identity);
    state.auth.activate_totp(req).await?;
    Ok(Json(json!({ "success": true })))
}

async fn disable_totp(
    State(mut state): State<AppState>,
    identity: Identity,
    Json(body): Json<CodeBody>,
) -> ApiResult<Json<Value>> {
    let mut req = Request::new(authpb::DisableTotpRequest { code: body.code });
    attach_identity(&mut req, &identity);
    state.auth.disable_totp(req).await?;
    Ok(Json(json!({ "success": true })))
}

// ── API key handlers ────────────────────────────────────────

#[derive(Deserialize)]
struct CreateApiKeyBody {
    name: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    ttl_seconds: i64,
}

async fn create_api_key(
    State(mut state): State<AppState>,
    identity: Identity,
    Json(body): Json<CreateApiKeyBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let mut req = Request::new(authpb::CreateApiKeyRequest {
        name: body.name,
        scopes: body.scopes,
        ttl_seconds: body.ttl_seconds,
    });
    attach_identity(&mut req, &identity);
    let res = state.auth.create_api_key(req).await?.into_inner();
    let key = res.key.as_ref().map(api_key_json).unwrap_or(Value::Null);
    Ok((StatusCode::CREATED, Json(json!({ "secret": res.secret, "key": key }))))
}

async fn list_api_keys(
    State(mut state): State<AppState>,
    identity: Identity,
) -> ApiResult<Json<Value>> {
    let mut req = Request::new(authpb::ListApiKeysRequest {});
    attach_identity(&mut req, &identity);
    let res = state.auth.list_api_keys(req).await?.into_inner();
    let keys: Vec<Value> = res.keys.iter().map(api_key_json).collect();
    Ok(Json(json!({ "keys": keys })))
}

async fn revoke_api_key(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let mut req = Request::new(authpb::RevokeApiKeyRequest { id });
    attach_identity(&mut req, &identity);
    state.auth.revoke_api_key(req).await?;
    Ok(Json(json!({ "success": true })))
}

// ── RBAC handlers ───────────────────────────────────────────

async fn list_roles(
    State(mut state): State<AppState>,
    identity: Identity,
) -> ApiResult<Json<Value>> {
    identity.require("role:read")?;
    let res = state.auth.list_roles(authpb::ListRolesRequest {}).await?.into_inner();
    let roles: Vec<Value> = res
        .roles
        .into_iter()
        .map(|r| json!({
            "id": r.id, "name": r.name, "description": r.description, "permissions": r.permissions,
        }))
        .collect();
    Ok(Json(json!({ "roles": roles })))
}

async fn create_role(
    State(mut state): State<AppState>,
    identity: Identity,
    Json(body): Json<CreateRoleBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    identity.require("role:write")?;
    let mut req = Request::new(authpb::CreateRoleRequest { name: body.name, description: body.description });
    attach_identity(&mut req, &identity);
    let r = state.auth.create_role(req).await?.into_inner();
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": r.id, "name": r.name, "description": r.description })),
    ))
}

async fn update_role(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(name): Path<String>,
    Json(body): Json<UpdateRoleBody>,
) -> ApiResult<Json<Value>> {
    identity.require("role:write")?;
    let mut req = Request::new(authpb::UpdateRoleRequest { name, description: body.description });
    attach_identity(&mut req, &identity);
    let r = state.auth.update_role(req).await?.into_inner();
    Ok(Json(json!({ "id": r.id, "name": r.name, "description": r.description })))
}

async fn delete_role(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    identity.require("role:write")?;
    let mut req = Request::new(authpb::DeleteRoleRequest { name });
    attach_identity(&mut req, &identity);
    state.auth.delete_role(req).await?;
    Ok(Json(json!({ "success": true })))
}

async fn grant_permission(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(name): Path<String>,
    Json(body): Json<GrantPermissionBody>,
) -> ApiResult<Json<Value>> {
    identity.require("role:write")?;
    let mut req = Request::new(authpb::GrantPermissionRequest { role_name: name, permission_name: body.permission });
    attach_identity(&mut req, &identity);
    state.auth.grant_permission(req).await?;
    Ok(Json(json!({ "success": true })))
}

async fn revoke_permission(
    State(mut state): State<AppState>,
    identity: Identity,
    Path((name, perm)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    identity.require("role:write")?;
    let mut req = Request::new(authpb::RevokePermissionRequest { role_name: name, permission_name: perm });
    attach_identity(&mut req, &identity);
    state.auth.revoke_permission(req).await?;
    Ok(Json(json!({ "success": true })))
}

async fn assign_role(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(id): Path<String>,
    Json(body): Json<AssignRoleBody>,
) -> ApiResult<Json<Value>> {
    identity.require("role:assign")?;
    let mut req = Request::new(authpb::AssignRoleRequest {
        user_id: id,
        role_name: body.role,
        project_id: body.project_id,
    });
    attach_identity(&mut req, &identity);
    state.auth.assign_role(req).await?;
    Ok(Json(json!({ "success": true })))
}

#[derive(Deserialize)]
struct BulkAssignBody {
    user_ids: Vec<String>,
    #[serde(default)]
    project_id: String,
}

async fn assign_role_bulk(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(name): Path<String>,
    Json(body): Json<BulkAssignBody>,
) -> ApiResult<Json<Value>> {
    identity.require("role:assign")?;
    let mut req = Request::new(authpb::AssignRoleBulkRequest {
        role_name: name,
        user_ids: body.user_ids,
        project_id: body.project_id,
    });
    attach_identity(&mut req, &identity);
    let res = state.auth.assign_role_bulk(req).await?.into_inner();
    Ok(Json(json!({ "assigned": res.assigned, "failed": res.failed })))
}

async fn revoke_role(
    State(mut state): State<AppState>,
    identity: Identity,
    Path((id, role)): Path<(String, String)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    identity.require("role:assign")?;
    let mut req = Request::new(authpb::RevokeRoleRequest {
        user_id: id,
        role_name: role,
        project_id: q.get("project_id").cloned().unwrap_or_default(),
    });
    attach_identity(&mut req, &identity);
    state.auth.revoke_role(req).await?;
    Ok(Json(json!({ "success": true })))
}

// M6: a user's role assignments in the active tenant (role + project scope).
async fn get_user_role_assignments(
    State(mut state): State<AppState>,
    identity: Identity,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    identity.require("role:read")?;
    let mut req = Request::new(authpb::GetUserRoleAssignmentsRequest { user_id: id });
    attach_identity(&mut req, &identity);
    let res = state.auth.get_user_role_assignments(req).await?.into_inner();
    let assignments: Vec<Value> = res
        .assignments
        .into_iter()
        .map(|a| json!({ "role": a.role, "project_id": a.project_id, "project_slug": a.project_slug }))
        .collect();
    Ok(Json(json!({ "assignments": assignments })))
}

// ── JSON shaping ────────────────────────────────────────────

fn token_pair_json(tp: authpb::TokenPair) -> Value {
    // 2FA: a password-only login may return a challenge instead of tokens.
    if tp.mfa_required {
        return json!({
            "mfa_required": true,
            "mfa_token": tp.mfa_token,
            "token_type": tp.token_type,
        });
    }
    json!({
        "access_token": tp.access_token,
        "refresh_token": tp.refresh_token,
        "expires_in": tp.expires_in,
        "token_type": tp.token_type,
    })
}

fn api_key_json(k: &authpb::ApiKey) -> Value {
    json!({
        "id": k.id,
        "name": k.name,
        "scopes": k.scopes,
        "created_at": k.created_at,
        "expires_at": k.expires_at,
        "last_used_at": k.last_used_at,
    })
}

fn profile_json(p: userpb::Profile) -> Value {
    json!({
        "user_id": p.user_id,
        "display_name": p.display_name,
        "bio": p.bio,
        "avatar_url": p.avatar_url,
        "phone": p.phone,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
    })
}
