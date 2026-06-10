//! Interactive API docs: OpenAPI spec at /openapi.yaml + Swagger UI at /docs.
//! Assets are embedded (self-contained, no CDN). Public, no auth.

use axum::{http::header, response::Html, response::IntoResponse, routing::get, Router};

use crate::clients::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/openapi.yaml", get(openapi))
        .route("/docs", get(index))
        .route("/docs/", get(index))
        .route("/docs/swagger-ui.css", get(css))
        .route("/docs/swagger-ui-bundle.js", get(bundle))
        .route("/docs/swagger-ui-standalone-preset.js", get(preset))
}

async fn openapi() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/yaml")], include_str!("../openapi.yaml"))
}
async fn index() -> Html<&'static str> {
    Html(include_str!("../swaggerui/index.html"))
}
async fn css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css")], include_str!("../swaggerui/swagger-ui.css"))
}
async fn bundle() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        include_str!("../swaggerui/swagger-ui-bundle.js"),
    )
}
async fn preset() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        include_str!("../swaggerui/swagger-ui-standalone-preset.js"),
    )
}
