//! Per-IP fixed-window rate limiter. Redis-backed (shared across replicas) when
//! REDIS_URL is set, otherwise an in-memory fallback for single-instance/dev.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

type Memory = Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>;

#[derive(Clone)]
enum Backend {
    Memory(Memory),
    Redis(redis::aio::ConnectionManager),
}

#[derive(Clone)]
pub struct RateLimiter {
    backend: Backend,
    limit: u32,
    window: Duration,
}

impl RateLimiter {
    /// Build from env: Redis-backed when REDIS_URL is set, else in-memory.
    pub async fn from_env(limit: u32, window: Duration) -> Self {
        let backend = match std::env::var("REDIS_URL") {
            Ok(url) if !url.is_empty() => match connect_redis(&url).await {
                Some(cm) => {
                    tracing::info!("rate limiter: redis-backed (shared across replicas)");
                    Backend::Redis(cm)
                }
                None => {
                    tracing::warn!("REDIS_URL set but unreachable — using in-memory rate limiter");
                    Backend::Memory(Arc::new(Mutex::new(HashMap::new())))
                }
            },
            _ => Backend::Memory(Arc::new(Mutex::new(HashMap::new()))),
        };
        Self { backend, limit, window }
    }

    async fn check(&self, ip: IpAddr) -> bool {
        if self.limit == 0 {
            return true; // disabled
        }
        match &self.backend {
            Backend::Memory(map) => {
                let now = Instant::now();
                let mut map = map.lock().unwrap();
                let entry = map.entry(ip).or_insert((0, now + self.window));
                if now >= entry.1 {
                    *entry = (0, now + self.window);
                }
                entry.0 += 1;
                entry.0 <= self.limit
            }
            Backend::Redis(cm) => {
                let secs = self.window.as_secs().max(1);
                let bucket = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) / secs;
                let key = format!("rl:{ip}:{bucket}");
                let script = redis::Script::new(
                    "local c = redis.call('INCR', KEYS[1]) \
                     if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end \
                     return c",
                );
                let mut conn = cm.clone();
                match script.key(&key).arg(secs).invoke_async::<i64>(&mut conn).await {
                    Ok(n) => n <= self.limit as i64,
                    Err(_) => true, // fail-open if Redis errors
                }
            }
        }
    }
}

async fn connect_redis(url: &str) -> Option<redis::aio::ConnectionManager> {
    let client = redis::Client::open(url).ok()?;
    redis::aio::ConnectionManager::new(client).await.ok()
}

/// Axum middleware enforcing the per-IP limit. Use with from_fn_with_state.
pub async fn limit(
    State(rl): State<RateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if rl.check(addr.ip()).await {
        next.run(req).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "rate limit exceeded, slow down" })),
        )
            .into_response()
    }
}
