use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use sqlx::Row;
use uuid::Uuid;

use crate::{AppState, CreateAccountRequest, EmailAccount, InboxQuery, SendEmailRequest, UpdateAccountRequest};
use crate::email::EmailService;

pub async fn get_accounts(State(state): State<AppState>) -> Result<Json<Vec<EmailAccount>>, StatusCode> {
    let rows = sqlx::query("SELECT id, email, display_name, is_active FROM accounts")
        .fetch_all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let accounts: Vec<EmailAccount> = rows
        .into_iter()
        .map(|row| EmailAccount {
            id: row.get::<String, _>(0),
            email: row.get::<String, _>(1),
            display_name: row.get::<String, _>(2),
            is_active: row.get::<bool, _>(3),
        })
        .collect();

    Ok(Json(accounts))
}

pub async fn create_account(
    State(state): State<AppState>,
    Json(req): Json<CreateAccountRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Check if email already exists
    let existing = sqlx::query("SELECT email FROM accounts WHERE email = ?")
        .bind(&req.email)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if existing.is_some() {
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "Email address already exists"
        })));
    }

    let id = Uuid::new_v4().to_string();
    
    match sqlx::query(
        "INSERT INTO accounts (id, email, display_name, password, is_active) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&req.email)
    .bind(&req.display_name)
    .bind(&req.password)
    .bind(req.is_active)
    .execute(&state.db)
    .await {
        Ok(_) => {
            let account = EmailAccount {
                id,
                email: req.email,
                display_name: req.display_name,
                is_active: req.is_active,
            };
            Ok(Json(serde_json::json!({
                "status": "success",
                "message": "Account created successfully",
                "account": account
            })))
        }
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(Json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to create account: {}", e)
            })))
        }
    }
}

pub async fn update_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAccountRequest>,
) -> Result<Json<EmailAccount>, StatusCode> {
    // Return error if neither field was provided
    if req.is_active.is_none() && req.password.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Update is_active if provided
    if let Some(is_active) = req.is_active {
        sqlx::query("UPDATE accounts SET is_active = ? WHERE id = ?")
            .bind(is_active)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|e| {
                eprintln!("Database update error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    // Update password if provided
    if let Some(password) = req.password {
        if password.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        sqlx::query("UPDATE accounts SET password = ? WHERE id = ?")
            .bind(&password)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|e| {
                eprintln!("Database update error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    // Fetch and return updated account
    let row = sqlx::query("SELECT id, email, display_name, is_active FROM accounts WHERE id = ?")
        .bind(&id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let account = EmailAccount {
        id: row.get::<String, _>(0),
        email: row.get::<String, _>(1),
        display_name: row.get::<String, _>(2),
        is_active: row.get::<bool, _>(3),
    };

    Ok(Json(account))
}

pub async fn send_email(
    State(state): State<AppState>,
    Json(req): Json<SendEmailRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Look up the sender account in the database
    let row = sqlx::query("SELECT email, password FROM accounts WHERE email = ? AND is_active = 1")
        .bind(&req.from)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let (sender_email, sender_password) = match row {
        Some(row) => (
            row.get::<String, _>(0),
            row.get::<String, _>(1),
        ),
        None => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": "Sender account not found or inactive"
            })));
        }
    };

    // Create email service and send email
    let email_service = EmailService::new();
    match email_service.send_email(
        &sender_email,
        &sender_password,
        &req.to,
        &req.subject,
        &req.body,
        req.cc.as_deref(),
        req.bcc.as_deref(),
    ).await {
        Ok(_) => {
            Ok(Json(serde_json::json!({
                "status": "sent",
                "message": "Email sent successfully"
            })))
        }
        Err(e) => {
            eprintln!("Failed to send email: {}", e);
            Ok(Json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to send email: {}", e)
            })))
        }
    }
}

pub async fn get_inbox(
    State(_state): State<AppState>,
    Query(_params): Query<InboxQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // TODO: Implement IMAP inbox retrieval
    Ok(Json(serde_json::json!([])))
}

