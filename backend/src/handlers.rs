use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::{AuthUser, UserRole},
    mailer::{self, SenderKind, SenderSummary},
    AppState, CreateAccountRequest, CreateAliasRequest, DefaultSenderResponse, EmailAccount,
    EmailAlias, InboxQuery, SendEmailRequest, UpdateAccountRequest, UpdateAliasRequest,
    UpdateDefaultSenderRequest,
};
use crate::email::EmailService;

pub async fn get_accounts(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<EmailAccount>>, StatusCode> {
    user.ensure_password_updated()?;
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
    user: AuthUser,
    Json(req): Json<CreateAccountRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

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
    user: AuthUser,
    Json(req): Json<UpdateAccountRequest>,
) -> Result<Json<EmailAccount>, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

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

pub async fn delete_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> Result<StatusCode, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    let result = sqlx::query("DELETE FROM accounts WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    if let Err(e) = mailer::delete_default_if_matches(&state.db, SenderKind::Account, &id).await {
        eprintln!("Failed to clear default sender after account deletion: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_aliases(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<EmailAlias>>, StatusCode> {
    user.ensure_password_updated()?;

    let rows = sqlx::query(
        r#"
        SELECT 
            aliases.id,
            aliases.alias_email,
            aliases.display_name,
            aliases.is_active,
            aliases.account_id,
            accounts.email,
            accounts.display_name,
            accounts.is_active
        FROM aliases
        JOIN accounts ON aliases.account_id = accounts.id
        ORDER BY aliases.alias_email ASC
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let aliases = rows
        .into_iter()
        .map(|row| EmailAlias {
            id: row.get::<String, _>(0),
            alias_email: row.get::<String, _>(1),
            display_name: row.get::<Option<String>, _>(2),
            is_active: row.get::<bool, _>(3),
            account_id: row.get::<String, _>(4),
            account_email: row.get::<String, _>(5),
            account_display_name: row.get::<String, _>(6),
            account_is_active: row.get::<bool, _>(7),
        })
        .collect();

    Ok(Json(aliases))
}

pub async fn create_alias(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateAliasRequest>,
) -> Result<Json<EmailAlias>, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    let CreateAliasRequest {
        account_id,
        alias_email,
        display_name,
        is_active,
    } = req;

    let account_row = sqlx::query(
        "SELECT id, email, display_name, is_active FROM accounts WHERE id = ?",
    )
    .bind(&account_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let account = match account_row {
        Some(row) => (
            row.get::<String, _>(0),
            row.get::<String, _>(1),
            row.get::<String, _>(2),
            row.get::<bool, _>(3),
        ),
        None => {
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let existing = sqlx::query("SELECT alias_email FROM aliases WHERE alias_email = ?")
        .bind(&alias_email)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if existing.is_some() {
        return Err(StatusCode::CONFLICT);
    }

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO aliases (id, alias_email, display_name, is_active, account_id)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&alias_email)
    .bind(&display_name)
    .bind(is_active)
    .bind(&account_id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let alias = EmailAlias {
        id,
        alias_email,
        display_name,
        is_active,
        account_id: account.0,
        account_email: account.1,
        account_display_name: account.2,
        account_is_active: account.3,
    };

    Ok(Json(alias))
}

pub async fn update_alias(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<UpdateAliasRequest>,
) -> Result<Json<EmailAlias>, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    let UpdateAliasRequest {
        account_id,
        display_name,
        is_active,
    } = req;

    if account_id.is_none() && display_name.is_none() && is_active.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Some(account_id) = &account_id {
        let exists = sqlx::query("SELECT id FROM accounts WHERE id = ?")
            .bind(account_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if exists.is_none() {
            return Err(StatusCode::BAD_REQUEST);
        }

        sqlx::query("UPDATE aliases SET account_id = ? WHERE id = ?")
            .bind(account_id)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    if let Some(display_name) = &display_name {
        sqlx::query("UPDATE aliases SET display_name = ? WHERE id = ?")
            .bind(display_name)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    if let Some(is_active) = is_active {
        sqlx::query("UPDATE aliases SET is_active = ? WHERE id = ?")
            .bind(is_active)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let row = sqlx::query(
        r#"
        SELECT 
            aliases.id,
            aliases.alias_email,
            aliases.display_name,
            aliases.is_active,
            aliases.account_id,
            accounts.email,
            accounts.display_name,
            accounts.is_active
        FROM aliases
        JOIN accounts ON aliases.account_id = accounts.id
        WHERE aliases.id = ?
        "#,
    )
    .bind(&id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    let alias = EmailAlias {
        id: row.get::<String, _>(0),
        alias_email: row.get::<String, _>(1),
        display_name: row.get::<Option<String>, _>(2),
        is_active: row.get::<bool, _>(3),
        account_id: row.get::<String, _>(4),
        account_email: row.get::<String, _>(5),
        account_display_name: row.get::<String, _>(6),
        account_is_active: row.get::<bool, _>(7),
    };

    Ok(Json(alias))
}

pub async fn delete_alias(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> Result<StatusCode, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    let result = sqlx::query("DELETE FROM aliases WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    if let Err(e) = mailer::delete_default_if_matches(&state.db, SenderKind::Alias, &id).await {
        eprintln!("Failed to clear default sender after alias deletion: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_default_sender(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Option<DefaultSenderResponse>>, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    match mailer::get_default_sender_summary(&state.db).await {
        Ok(Some(summary)) => Ok(Json(Some(sender_summary_to_response(&summary)))),
        Ok(None) => Ok(Json(None)),
        Err(e) => {
            eprintln!("Failed to load default sender: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn update_default_sender(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpdateDefaultSenderRequest>,
) -> Result<Json<DefaultSenderResponse>, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    match mailer::upsert_default_sender(&state.db, req.sender_type, &req.sender_id).await {
        Ok(summary) => Ok(Json(sender_summary_to_response(&summary))),
        Err(e) => {
            eprintln!("Failed to set default sender: {}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

fn sender_summary_to_response(summary: &SenderSummary) -> DefaultSenderResponse {
    DefaultSenderResponse {
        sender_type: summary.sender_type,
        sender_id: summary.sender_id.clone(),
        email: summary.email.clone(),
        display_label: summary.display_label.clone(),
        via_display: summary.via_display.clone(),
        is_active: summary.is_active,
    }
}

pub async fn send_email(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<SendEmailRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    user.ensure_password_updated()?;
    if !matches!(user.role, UserRole::User | UserRole::Dev | UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    let SendEmailRequest {
        from,
        to,
        subject,
        body,
        cc,
        bcc,
        is_html,
    } = req;

    let from_address = from.trim().to_string();
    if from_address.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let resolved = match mailer::resolve_sender_by_email(&state.db, &from_address).await {
        Ok(sender) => sender,
        Err(_) => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": "Sender account or alias not found or inactive"
            })));
        }
    };

    // Create email service and send email
    let email_service = EmailService::new();
    match email_service.send_email(
        &from_address,
        &resolved.auth_email,
        &resolved.auth_password,
        &to,
        &subject,
        &body,
        cc.as_deref(),
        bcc.as_deref(),
        is_html,
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
    user: AuthUser,
    Query(_params): Query<InboxQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    user.ensure_password_updated()?;
    // TODO: Implement IMAP inbox retrieval
    Ok(Json(serde_json::json!([])))
}

