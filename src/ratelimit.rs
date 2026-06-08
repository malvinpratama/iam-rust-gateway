//! Simple in-memory per-IP fixed-window rate limiter (single-instance demo).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>,
    limit: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())), limit, window }
    }

    fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry(ip).or_insert((0, now + self.window));
        if now >= entry.1 {
            *entry = (0, now + self.window);
        }
        entry.0 += 1;
        entry.0 <= self.limit
    }
}

/// Axum middleware enforcing the per-IP limit. Use with from_fn_with_state.
pub async fn limit(
    State(rl): State<RateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if rl.check(addr.ip()) {
        next.run(req).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "rate limit exceeded, slow down" })),
        )
            .into_response()
    }
}
