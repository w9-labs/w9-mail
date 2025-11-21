use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tower_http::cors::CorsLayer;

mod email;
mod handlers;
mod auth;
mod mailer;

use handlers::*;
use auth::{
    change_password, confirm_password_reset, create_user, delete_user, ensure_default_admin,
    list_users, login, me, request_password_reset, signup, update_user, verify_signup,
};
use mailer::SenderKind;

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
    pub jwt_secret: String,
    pub app_base_url: String,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailAlias {
    pub id: String,
    #[serde(rename = "aliasEmail")]
    pub alias_email: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "isActive")]
    pub is_active: bool,
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "accountEmail")]
    pub account_email: String,
    #[serde(rename = "accountDisplayName")]
    pub account_display_name: String,
    #[serde(rename = "accountIsActive")]
    pub account_is_active: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DefaultSenderResponse {
    #[serde(rename = "senderType")]
    pub sender_type: SenderKind,
    #[serde(rename = "senderId")]
    pub sender_id: String,
    pub email: String,
    #[serde(rename = "displayLabel")]
    pub display_label: String,
    #[serde(rename = "viaDisplay")]
    pub via_display: Option<String>,
    #[serde(rename = "isActive")]
    pub is_active: bool,
}

#[derive(Deserialize)]
pub struct UpdateDefaultSenderRequest {
    #[serde(rename = "senderType")]
    pub sender_type: SenderKind,
    #[serde(rename = "senderId")]
    pub sender_id: String,
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
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateAliasRequest {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "aliasEmail")]
    pub alias_email: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "isActive")]
    pub is_active: bool,
}

#[derive(Deserialize)]
pub struct UpdateAliasRequest {
    #[serde(rename = "accountId")]
    pub account_id: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
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
    #[serde(default, rename = "isHtml")]
    pub is_html: bool,
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

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS aliases (
            id TEXT PRIMARY KEY,
            alias_email TEXT UNIQUE NOT NULL,
            display_name TEXT,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            account_id TEXT NOT NULL,
            FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(&db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS default_sender (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            sender_type TEXT NOT NULL CHECK(sender_type IN ('account','alias')),
            sender_id TEXT NOT NULL
        )
        "#,
    )
    .execute(&db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','dev','user')),
            must_change_password BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS pending_users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            verification_token TEXT UNIQUE NOT NULL,
            expires_at INTEGER NOT NULL
        )
        "#,
    )
    .execute(&db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(&db)
    .await?;

    ensure_default_admin(&db).await?;

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

    let jwt_secret =
        std::env::var("JWT_SECRET").unwrap_or_else(|_| "change-me-in-production".to_string());
    let app_base_url =
        std::env::var("APP_WEB_BASE_URL").unwrap_or_else(|_| "https://w9.nu".to_string());

    let state = AppState {
        db,
        microsoft_oauth,
        jwt_secret,
        app_base_url,
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/auth/login", post(login))
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/signup/verify", post(verify_signup))
        .route("/api/auth/password-reset", post(request_password_reset))
        .route(
            "/api/auth/password-reset/confirm",
            post(confirm_password_reset),
        )
        .route("/api/auth/change-password", post(change_password))
        .route("/api/auth/me", get(me))
        .route("/api/users", get(list_users).post(create_user))
        .route(
            "/api/users/:id",
            patch(update_user).delete(delete_user),
        )
        .route("/api/accounts", get(get_accounts).post(create_account))
        .route(
            "/api/accounts/:id",
            patch(update_account).delete(delete_account),
        )
        .route("/api/aliases", get(get_aliases).post(create_alias))
        .route(
            "/api/aliases/:id",
            patch(update_alias).delete(delete_alias),
        )
        .route(
            "/api/settings/default-sender",
            get(get_default_sender).put(update_default_sender),
        )
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

