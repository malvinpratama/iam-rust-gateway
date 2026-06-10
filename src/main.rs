mod authorize;
mod clients;
mod docs;
mod error;
mod middleware;
mod oidc;
mod ratelimit;
mod router;

use std::net::SocketAddr;

use axum::routing::get;
use axum_prometheus::PrometheusMetricLayer;
use axum_tracing_opentelemetry::middleware::{OtelAxumLayer, OtelInResponseLayer};
use tokio::net::TcpListener;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

use crate::clients::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::telemetry::init("gateway");

    if let Err(e) = common::config::validate_security() {
        anyhow::bail!("insecure configuration: {e}");
    }
    let app_env = common::env_or("APP_ENV", "");
    if (app_env == "production" || app_env == "prod") && common::env_or("SESSION_SECRET", "").is_empty() {
        anyhow::bail!("SESSION_SECRET must be set in production (signs OIDC browser sessions)");
    }

    let auth_addr = common::env_or("AUTH_GRPC_ADDR", "http://localhost:50051");
    let user_addr = common::env_or("USER_GRPC_ADDR", "http://localhost:50052");
    let port = common::env_or("GATEWAY_HTTP_PORT", "8080");

    let state = AppState::connect(&auth_addr, &user_addr, common::config::internal_token()).await?;

    // Per-IP rate limiter — Redis-backed (shared across replicas) when REDIS_URL
    // is set, else in-memory. Built here because the Redis connection is async.
    let rl_limit: u32 = common::env_or("AUTH_RATE_LIMIT", "60").parse().unwrap_or(60);
    let rl_window: u64 = common::env_or("AUTH_RATE_WINDOW_SECONDS", "60").parse().unwrap_or(60);
    let limiter =
        ratelimit::RateLimiter::from_env(rl_limit, std::time::Duration::from_secs(rl_window)).await;

    // Prometheus HTTP metrics (matched-path labels), exposed at /metrics.
    let (prometheus_layer, metric_handle) = PrometheusMetricLayer::pair();

    let app = router::build(state, limiter)
        .route("/metrics", get(move || std::future::ready(metric_handle.render())))
        .layer(prometheus_layer)
        // Distributed tracing: a server span per request + trace id in the
        // response; exported to OTLP (Jaeger) when OTEL endpoint is set.
        .layer(OtelInResponseLayer)
        .layer(OtelAxumLayer::default())
        // Correlation id: accept or generate X-Request-Id and echo it back.
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    tracing::info!(port, "gateway listening");
    // into_make_service_with_connect_info exposes the client IP to the rate limiter.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
