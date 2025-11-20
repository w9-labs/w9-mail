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
pub struct MicrosoftOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub client_value: Option<String>,
    pub tenant_id: String,
    pub redirect_uri: String,
    pub scope: String,
}

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub microsoft_oauth: MicrosoftOAuthConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailAccount {
    pub id: String,
    pub email: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "isActive")]
    pub is_active: bool,
}

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    pub email: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub password: String,
    #[serde(rename = "isActive")]
    pub is_active: bool,
}

#[derive(Deserialize)]
pub struct UpdateAccountRequest {
    #[serde(rename = "isActive")]
    pub is_active: Option<bool>,
}

#[derive(Deserialize)]
pub struct SendEmailRequest {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub cc: Option<String>,
    #[serde(default)]
    pub bcc: Option<String>,
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

    // Load Microsoft OAuth2 configuration
    let microsoft_oauth = MicrosoftOAuthConfig {
        client_id: std::env::var("MICROSOFT_CLIENT_ID")
            .unwrap_or_else(|_| String::new()),
        client_secret: std::env::var("MICROSOFT_CLIENT_SECRET_ID")
            .or_else(|_| std::env::var("MICROSOFT_CLIENT_SECRET"))
            .unwrap_or_else(|_| String::new()),
        client_value: std::env::var("MICROSOFT_CLIENT_VALUE").ok(),
        tenant_id: std::env::var("MICROSOFT_TENANT_ID")
            .unwrap_or_else(|_| String::new()),
        redirect_uri: std::env::var("MICROSOFT_REDIRECT_URI")
            .unwrap_or_else(|_| "https://w9.nu/api/auth/callback".to_string()),
        scope: std::env::var("MICROSOFT_SCOPE")
            .unwrap_or_else(|_| "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send".to_string()),
    };

    let state = AppState { 
        db,
        microsoft_oauth,
    };

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

