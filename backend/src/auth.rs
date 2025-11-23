use std::fmt;

use anyhow::anyhow;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    async_trait,
    extract::{FromRequestParts, Path, State},
    http::{request::Parts, StatusCode},
    response::Json,
};
use chrono::{Duration, Utc};
use rand_core::OsRng;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;
use rand::Rng;

use crate::{email::EmailService, mailer, AppState};

const TOKEN_TTL_HOURS: i64 = 12;

async fn verify_turnstile(secret: &str, token: &str) -> Result<bool, String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "secret": secret,
        "response": token,
    });
    
    match client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            match resp.json::<serde_json::Value>().await {
                Ok(data) => {
                    let success = data.get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    Ok(success)
                }
                Err(e) => Err(format!("Failed to parse Turnstile response: {}", e))
            }
        }
        Err(e) => Err(format!("Failed to verify Turnstile token: {}", e))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    Dev,
    User,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::Dev => "dev",
            UserRole::User => "user",
        }
    }
}

impl TryFrom<String> for UserRole {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "admin" => Ok(UserRole::Admin),
            "dev" => Ok(UserRole::Dev),
            "user" => Ok(UserRole::User),
            other => Err(anyhow::anyhow!("Unknown user role: {}", other)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: String,
    pub email: String,
    pub role: UserRole,
    pub must_change_password: bool,
}

impl AuthUser {
    pub fn ensure_password_updated(&self) -> Result<(), StatusCode> {
        if self.must_change_password {
            Err(StatusCode::FORBIDDEN)
        } else {
            Ok(())
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    email: String,
    role: String,
    exp: usize,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub turnstile_token: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub id: String,
    pub email: String,
    pub role: UserRole,
    #[serde(rename = "mustChangePassword")]
    pub must_change_password: bool,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(rename = "currentPassword")]
    pub current_password: String,
    #[serde(rename = "newPassword")]
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<UserRole>,
}

#[derive(Serialize)]
pub struct UserSummary {
    pub id: String,
    pub email: String,
    pub role: UserRole,
    #[serde(rename = "mustChangePassword")]
    pub must_change_password: bool,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub password: Option<String>,
    pub role: Option<UserRole>,
    #[serde(rename = "mustChangePassword")]
    pub must_change_password: Option<bool>,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub turnstile_token: Option<String>,
}

#[derive(Deserialize)]
pub struct SignupVerifyRequest {
    pub token: String,
}

#[derive(Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
    #[serde(default)]
    pub turnstile_token: Option<String>,
}

#[derive(Deserialize)]
pub struct PasswordResetConfirmRequest {
    pub token: String,
    #[serde(rename = "newPassword")]
    pub new_password: String,
    #[serde(default)]
    pub turnstile_token: Option<String>,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    State<AppState>: FromRequestParts<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().map(|s| s.to_owned()).ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing authorization header"))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid authorization header"))?
            .to_string();

        let State(app_state) =
            State::<AppState>::from_request_parts(parts, state).await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to extract application state",
                )
            })?;

        // First, try to authenticate as API token (hash the token with SHA256 and check against database)
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = format!("{:x}", hasher.finalize());
        
        let api_token_row = sqlx::query(
            "SELECT u.id, u.email, u.role, u.must_change_password FROM api_tokens at
             INNER JOIN users u ON at.user_id = u.id
             WHERE at.token_hash = ?"
        )
        .bind(&token_hash)
        .fetch_optional(&app_state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to check API token"))?;

        if let Some(row) = api_token_row {
            // Update last_used_at
            let _ = sqlx::query(
                "UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token_hash = ?"
            )
            .bind(&token_hash)
            .execute(&app_state.db)
            .await;

            let role = row
                .get::<String, _>(2)
                .try_into()
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid role"))?;

            return Ok(AuthUser {
                id: row.get::<String, _>(0),
                email: row.get::<String, _>(1),
                role,
                must_change_password: row.get::<bool, _>(3),
            });
        }

        // If not an API token, try JWT token
        let decoding_key = DecodingKey::from_secret(app_state.jwt_secret.as_bytes());
        let token_data = decode::<Claims>(&token, &decoding_key, &Validation::default())
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

        let row = sqlx::query(
            "SELECT id, email, role, must_change_password FROM users WHERE id = ?",
        )
        .bind(&token_data.claims.sub)
        .fetch_optional(&app_state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load user"))?
        .ok_or((StatusCode::UNAUTHORIZED, "User not found"))?;

        let role = row
            .get::<String, _>(2)
            .try_into()
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid role"))?;

        Ok(AuthUser {
            id: row.get::<String, _>(0),
            email: row.get::<String, _>(1),
            role,
            must_change_password: row.get::<bool, _>(3),
        })
    }
}

pub async fn ensure_default_admin(db: &SqlitePool) -> anyhow::Result<()> {
    const ADMIN_EMAIL: &str = "shayneeo@0.id.vn";
    const ADMIN_PASSWORD: &str = "Admin@123";

    let count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM users WHERE email = ?")
        .bind(ADMIN_EMAIL)
        .fetch_one(db)
        .await?;

    if count == 0 {
        let password_hash = hash_password(ADMIN_PASSWORD)?;
        sqlx::query(
            r#"
            INSERT INTO users (id, email, password_hash, role, must_change_password)
            VALUES (?, ?, ?, 'admin', 1)
        "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(ADMIN_EMAIL)
        .bind(password_hash)
        .execute(db)
        .await?;
    }

    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, anyhow::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!(e.to_string()))?;
    Ok(hash.to_string())
}

fn verify_password(password_hash: &str, password: &str) -> Result<bool, anyhow::Error> {
    let parsed_hash = PasswordHash::new(password_hash).map_err(|e| anyhow!(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

fn encode_token(user_id: &str, email: &str, role: &UserRole, secret: &str) -> anyhow::Result<String> {
    let exp = Utc::now()
        .checked_add_signed(Duration::hours(TOKEN_TTL_HOURS))
        .ok_or_else(|| anyhow::anyhow!("Failed to calculate token expiration"))?
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.as_str().to_string(),
        exp,
    };

    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    Ok(encode(&Header::default(), &claims, &encoding_key)?)
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    // Verify Turnstile token if secret is configured
    if let Some(secret) = &state.turnstile_secret {
        if let Some(token) = &payload.turnstile_token {
            match verify_turnstile(secret, token).await {
                Ok(true) => {},
                Ok(false) => return Err(StatusCode::BAD_REQUEST),
                Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        } else {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let row = sqlx::query(
        "SELECT id, email, password_hash, role, must_change_password FROM users WHERE email = ?",
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::UNAUTHORIZED)?;

    let password_hash = row.get::<String, _>(2);
    if !verify_password(&password_hash, &payload.password).map_err(|_| StatusCode::UNAUTHORIZED)? {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let role: UserRole = row
        .get::<String, _>(3)
        .try_into()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let token = encode_token(&row.get::<String, _>(0), &payload.email, &role, &state.jwt_secret)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(LoginResponse {
        token,
        id: row.get::<String, _>(0),
        email: payload.email,
        role,
        must_change_password: row.get::<bool, _>(4),
    }))
}

pub async fn signup(
    State(state): State<AppState>,
    Json(payload): Json<SignupRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let email = normalize_email(&payload.email);
    if email.is_empty() || payload.password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let existing: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM users WHERE email = ?")
        .bind(&email)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if existing > 0 {
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "Email already registered"
        })));
    }

    let password_hash =
        hash_password(&payload.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token = Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::minutes(30))
        .timestamp();

    sqlx::query("DELETE FROM pending_users WHERE email = ?")
        .bind(&email)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query(
        r#"
        INSERT INTO pending_users (id, email, password_hash, verification_token, expires_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&email)
    .bind(&password_hash)
    .bind(&token)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let default_sender = match mailer::get_default_sender_summary(&state.db).await {
        Ok(Some(summary)) => summary,
        Ok(None) => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": "Registration is temporarily unavailable. Ask an admin to set a default sender."
            })));
        }
        Err(e) => {
            eprintln!("Failed to load default sender: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let base_url = state.app_base_url.trim_end_matches('/').to_string();
    let verify_url = format!("{}/signup/verify?token={}", base_url, token);
    let body_lines = vec![
        format!("Welcome! Confirm that {} should send through W9 Mail.", email),
        "This link expires in 30 minutes.".to_string(),
    ];
    let email_body = build_system_email_html(
        "Verify your W9 Mail account",
        &body_lines,
        "Verify account",
        &verify_url,
    );

    let email_service = EmailService::new();
    if let Err(e) = email_service
        .send_email(
            &default_sender.credentials.header_from,
            &default_sender.credentials.auth_email,
            &default_sender.credentials.auth_password,
            &email,
            "Verify your W9 Mail account",
            &email_body,
            None,
            None,
            true,
        )
        .await
    {
        eprintln!("Failed to send verification email: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(serde_json::json!({
        "status": "pending",
        "message": "Check your inbox for a verification link."
    })))
}

pub async fn verify_signup(
    State(state): State<AppState>,
    Json(payload): Json<SignupVerifyRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let row = sqlx::query(
        "SELECT id, email, password_hash, expires_at FROM pending_users WHERE verification_token = ?",
    )
    .bind(&payload.token)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(row) = row else {
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "Invalid or expired verification link."
        })));
    };

    let expires_at = row.get::<i64, _>(3);
    if expires_at < Utc::now().timestamp() {
        sqlx::query("DELETE FROM pending_users WHERE id = ?")
            .bind(row.get::<String, _>(0))
            .execute(&state.db)
            .await
            .ok();
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "Verification link expired. Please register again."
        })));
    }

    let email = row.get::<String, _>(1);
    let password_hash = row.get::<String, _>(2);
    let user_id = Uuid::new_v4().to_string();

    let insert_result = sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, role, must_change_password)
        VALUES (?, ?, ?, 'user', 0)
        "#,
    )
    .bind(&user_id)
    .bind(&email)
    .bind(&password_hash)
    .execute(&state.db)
    .await;

    if let Err(e) = insert_result {
        eprintln!("Failed to finalize signup: {}", e);
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "This email is already activated. Try signing in."
        })));
    }

    sqlx::query("DELETE FROM pending_users WHERE id = ?")
        .bind(row.get::<String, _>(0))
        .execute(&state.db)
        .await
        .ok();

    Ok(Json(serde_json::json!({
        "status": "verified",
        "message": "Account verified. You can sign in now."
    })))
}

pub async fn request_password_reset(
    State(state): State<AppState>,
    Json(payload): Json<PasswordResetRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Verify Turnstile token if secret is configured
    if let Some(secret) = &state.turnstile_secret {
        if let Some(token) = &payload.turnstile_token {
            match verify_turnstile(secret, token).await {
                Ok(true) => {},
                Ok(false) => return Err(StatusCode::BAD_REQUEST),
                Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        } else {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let email = normalize_email(&payload.email);
    if email.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let row = sqlx::query("SELECT id FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(row) = row else {
        // Always hide whether the user exists
        return Ok(Json(serde_json::json!({
            "status": "ok",
            "message": "If the email exists, a reset link was sent."
        })));
    };

    let user_id = row.get::<String, _>(0);
    let token = Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::minutes(30)).timestamp();

    sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = ?")
        .bind(&user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query(
        r#"
        INSERT INTO password_reset_tokens (id, user_id, token, expires_at)
        VALUES (?, ?, ?, ?)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&user_id)
    .bind(&token)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let default_sender = match mailer::get_default_sender_summary(&state.db).await {
        Ok(Some(summary)) => summary,
        _ => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": "Password reset is unavailable. Contact an admin."
            })));
        }
    };

    let base_url = state.app_base_url.trim_end_matches('/').to_string();
    let reset_url = format!("{}/reset-password?token={}", base_url, token);
    let body_lines = vec![
        format!("We received a reset request for {}.", email),
        "This link expires in 30 minutes. If you didn't request it, you can ignore this email.".to_string(),
    ];
    let email_body =
        build_system_email_html("Reset your W9 Mail password", &body_lines, "Reset password", &reset_url);

    let email_service = EmailService::new();
    if let Err(e) = email_service
        .send_email(
            &default_sender.credentials.header_from,
            &default_sender.credentials.auth_email,
            &default_sender.credentials.auth_password,
            &email,
            "Reset your W9 Mail password",
            &email_body,
            None,
            None,
            true,
        )
        .await
    {
        eprintln!("Failed to send reset email: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": "If the email exists, a reset link was sent."
    })))
}

pub async fn confirm_password_reset(
    State(state): State<AppState>,
    Json(payload): Json<PasswordResetConfirmRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Verify Turnstile token if secret is configured
    if let Some(secret) = &state.turnstile_secret {
        if let Some(token) = &payload.turnstile_token {
            match verify_turnstile(secret, token).await {
                Ok(true) => {},
                Ok(false) => return Err(StatusCode::BAD_REQUEST),
                Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        } else {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    if payload.new_password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let row = sqlx::query(
        "SELECT user_id, expires_at FROM password_reset_tokens WHERE token = ?",
    )
    .bind(&payload.token)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(row) = row else {
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "Invalid or expired reset link."
        })));
    };

    if row.get::<i64, _>(1) < Utc::now().timestamp() {
        sqlx::query("DELETE FROM password_reset_tokens WHERE token = ?")
            .bind(&payload.token)
            .execute(&state.db)
            .await
            .ok();
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "Reset link expired. Request a new one."
        })));
    }

    let user_id = row.get::<String, _>(0);
    let new_hash =
        hash_password(&payload.new_password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?")
        .bind(new_hash)
        .bind(&user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = ?")
        .bind(&user_id)
        .execute(&state.db)
        .await
        .ok();

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Password updated. You can sign in now."
    })))
}

fn normalize_email(input: &str) -> String {
    input.trim().to_lowercase()
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn build_system_email_html(
    title: &str,
    body_lines: &[String],
    button_text: &str,
    button_url: &str,
) -> String {
    let paragraphs = body_lines
        .iter()
        .map(|line| {
            format!(
                "<p style=\"margin:0 0 16px;color:#ffffff;font-size:14px;line-height:1.5;font-family:'Courier New',Courier,monospace;\">{}</p>",
                html_escape(line)
            )
        })
        .collect::<String>();

    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title}</title>
</head>
<body style="background:#000;padding:32px;font-family:'Courier New',Courier,monospace;">
  <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
    <tr>
      <td align="center">
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="max-width:640px;border:2px solid #ffffff;padding:28px;background:#000;">
          <tr><td style="text-align:center;">
            <h1 style="margin:0 0 20px;font-size:20px;letter-spacing:0.05em;text-transform:uppercase;color:#ffffff;font-family:'Courier New',Courier,monospace;">{title}</h1>
            {paragraphs}
            <div style="margin:32px 0;text-align:center;">
              <a href="{button_url}" style="text-decoration:none;display:inline-block;border:2px solid #ffffff;padding:12px 24px;color:#ffffff;background:#000;text-transform:uppercase;font-weight:bold;font-family:'Courier New',Courier,monospace;">{button_text}</a>
            </div>
            <p style="margin:0 0 12px;color:#ffffff;font-size:12px;line-height:1.4;font-family:'Courier New',Courier,monospace;word-break:break-word;">If the button doesn't work, copy and paste this link:<br />{button_url}</p>
            <hr style="border:none;border-top:2px solid #ffffff;margin:32px 0;" />
            <p style="margin:0;color:#ffffff;font-size:11px;opacity:0.7;font-family:'Courier New',Courier,monospace;line-height:1.4;">Automated message from W9 Mail. Replies are not monitored.</p>
          </td></tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"#,
        title = html_escape(title),
        paragraphs = paragraphs,
        button_text = html_escape(button_text),
        button_url = html_escape(button_url),
    )
}

pub async fn change_password(
    State(state): State<AppState>,
    user: AuthUser,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if payload.new_password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let current_hash = sqlx::query("SELECT password_hash FROM users WHERE id = ?")
        .bind(&user.id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .get::<String, _>(0);

    if !verify_password(&current_hash, &payload.current_password)
        .map_err(|_| StatusCode::UNAUTHORIZED)?
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let new_hash =
        hash_password(&payload.new_password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?")
        .bind(new_hash)
        .bind(&user.id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Password updated"
    })))
}

pub async fn me(user: AuthUser) -> Result<Json<UserSummary>, StatusCode> {
    Ok(Json(UserSummary {
        id: user.id,
        email: user.email,
        role: user.role,
        must_change_password: user.must_change_password,
    }))
}

pub async fn create_user(
    State(state): State<AppState>,
    user: AuthUser,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<UserSummary>, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    if payload.password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let role = payload.role.unwrap_or(UserRole::User);
    let password_hash =
        hash_password(&payload.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, role, must_change_password)
        VALUES (?, ?, ?, ?, 0)
    "#,
    )
    .bind(&id)
    .bind(&payload.email)
    .bind(password_hash)
    .bind(role.as_str())
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(UserSummary {
        id,
        email: payload.email,
        role,
        must_change_password: false,
    }))
}

pub async fn list_users(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<UserSummary>>, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    let rows = sqlx::query("SELECT id, email, role, must_change_password FROM users ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let users = rows
        .into_iter()
        .map(|row| {
            let role: UserRole = row
                .get::<String, _>(2)
                .try_into()
                .unwrap_or(UserRole::User);
            UserSummary {
                id: row.get::<String, _>(0),
                email: row.get::<String, _>(1),
                role,
                must_change_password: row.get::<bool, _>(3),
            }
        })
        .collect();

    Ok(Json(users))
}

pub async fn update_user(
    State(state): State<AppState>,
    user: AuthUser,
    Path(target_id): Path<String>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserSummary>, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    if payload.password.is_none() && payload.role.is_none() && payload.must_change_password.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Some(role) = &payload.role {
        sqlx::query("UPDATE users SET role = ? WHERE id = ?")
            .bind(role.as_str())
            .bind(&target_id)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    if let Some(flag) = payload.must_change_password {
        sqlx::query("UPDATE users SET must_change_password = ? WHERE id = ?")
            .bind(flag)
            .bind(&target_id)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    if let Some(password) = &payload.password {
        if password.len() < 8 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let new_hash =
            hash_password(password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        sqlx::query("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?")
            .bind(new_hash)
            .bind(&target_id)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let row = sqlx::query("SELECT id, email, role, must_change_password FROM users WHERE id = ?")
        .bind(&target_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let role: UserRole = row
        .get::<String, _>(2)
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(UserSummary {
        id: row.get::<String, _>(0),
        email: row.get::<String, _>(1),
        role,
        must_change_password: row.get::<bool, _>(3),
    }))
}

pub async fn delete_user(
    State(state): State<AppState>,
    user: AuthUser,
    Path(target_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }
    if user.id == target_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&target_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::NO_CONTENT)
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// API Token management

#[derive(Serialize, Deserialize)]
pub struct ApiTokenSummary {
    pub id: String,
    #[serde(rename = "name")]
    pub name: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "lastUsedAt")]
    pub last_used_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateApiTokenRequest {
    #[serde(rename = "name")]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateApiTokenResponse {
    pub id: String,
    #[serde(rename = "token")]
    pub token: String,
    #[serde(rename = "name")]
    pub name: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "message")]
    pub message: String,
}

fn generate_api_token() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..64)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

pub async fn create_api_token(
    State(state): State<AppState>,
    user: AuthUser,
    Json(payload): Json<CreateApiTokenRequest>,
) -> Result<Json<CreateApiTokenResponse>, StatusCode> {
    user.ensure_password_updated()?;
    
    // Generate a random token
    let token = generate_api_token();
    
    // Hash the token with SHA256
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());
    
    let token_id = Uuid::new_v4().to_string();
    let created_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    sqlx::query(
        "INSERT INTO api_tokens (id, user_id, token_hash, name, created_at) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&token_id)
    .bind(&user.id)
    .bind(&token_hash)
    .bind(payload.name.as_deref())
    .bind(&created_at)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(CreateApiTokenResponse {
        id: token_id,
        token,
        name: payload.name,
        created_at,
        message: "API token created. Save this token now - you won't be able to see it again!".to_string(),
    }))
}

pub async fn list_api_tokens(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<ApiTokenSummary>>, StatusCode> {
    user.ensure_password_updated()?;
    
    let rows = sqlx::query(
        "SELECT id, name, created_at, last_used_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(&user.id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let tokens: Vec<ApiTokenSummary> = rows
        .into_iter()
        .map(|row| ApiTokenSummary {
            id: row.get::<String, _>(0),
            name: row.get::<Option<String>, _>(1),
            created_at: row.get::<String, _>(2),
            last_used_at: row.get::<Option<String>, _>(3),
        })
        .collect();
    
    Ok(Json(tokens))
}

pub async fn delete_api_token(
    State(state): State<AppState>,
    user: AuthUser,
    Path(token_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    user.ensure_password_updated()?;
    
    let result = sqlx::query(
        "DELETE FROM api_tokens WHERE id = ? AND user_id = ?"
    )
    .bind(&token_id)
    .bind(&user.id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    
    Ok(StatusCode::NO_CONTENT)
}

