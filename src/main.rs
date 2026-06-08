mod clients;
mod error;
mod middleware;
mod ratelimit;
mod router;

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use crate::clients::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::telemetry::init("gateway");

    if let Err(e) = common::config::validate_security() {
        anyhow::bail!("insecure configuration: {e}");
    }

    let auth_addr = common::env_or("AUTH_GRPC_ADDR", "http://localhost:50051");
    let user_addr = common::env_or("USER_GRPC_ADDR", "http://localhost:50052");
    let port = common::env_or("GATEWAY_HTTP_PORT", "8080");

    let state = AppState::connect(&auth_addr, &user_addr, common::config::internal_token()).await?;
    let app = router::build(state).layer(TraceLayer::new_for_http());

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
