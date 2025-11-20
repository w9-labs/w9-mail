use axum::{
    routing::{get, patch, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tower_http::cors::CorsLayer;

mod email;
mod handlers;

use handlers::*;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailAccount {
    pub id: String,
    pub email: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub is_active: bool,
}

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    pub email: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub password: String,
    pub is_active: bool,
}

#[derive(Deserialize)]
pub struct UpdateAccountRequest {
    pub is_active: Option<bool>,
}

#[derive(Deserialize)]
pub struct SendEmailRequest {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body: String,
}

#[derive(Deserialize)]
pub struct InboxQuery {
    pub account: String,
    pub limit: Option<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file for local development (ignored if not present)
    dotenv::dotenv().ok();
    
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()?;
    let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "w9mail.db".to_string());
    
    let db_url = format!("sqlite:{}", db_path);
    let db = SqlitePool::connect(&db_url).await?;
    
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            password TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1
        )
        "#,
    )
    .execute(&db)
    .await?;

    let state = AppState { db };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/accounts", get(get_accounts).post(create_account))
        .route("/api/accounts/:id", patch(update_account))
        .route("/api/send", post(send_email))
        .route("/api/inbox", get(get_inbox))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("Server running on http://{}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "ok"
}

