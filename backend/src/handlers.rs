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
    if !matches!(user.role, UserRole::Admin | UserRole::Dev) {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Admin sees all, others see their own + public
    let query = if matches!(user.role, UserRole::Admin) {
        "SELECT id, email, display_name, is_active, owner_id, is_public FROM accounts"
    } else {
        "SELECT id, email, display_name, is_active, owner_id, is_public FROM accounts WHERE owner_id = ? OR is_public = 1"
    };
    
    let mut query_builder = sqlx::query(query);
    if !matches!(user.role, UserRole::Admin) {
        query_builder = query_builder.bind(&user.id);
    }
    
    let rows = query_builder
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
            owner_id: row.get::<Option<String>, _>(4),
            is_public: row.get::<bool, _>(5),
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
    if !matches!(user.role, UserRole::Admin | UserRole::Dev) {
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
        "INSERT INTO accounts (id, email, display_name, password, is_active, owner_id, is_public) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&req.email)
    .bind(&req.display_name)
    .bind(&req.password)
    .bind(req.is_active)
    .bind(&user.id)
    .bind(req.is_public)
    .execute(&state.db)
    .await {
        Ok(_) => {
            let account = EmailAccount {
                id,
                email: req.email,
                display_name: req.display_name,
                is_active: req.is_active,
                owner_id: Some(user.id),
                is_public: req.is_public,
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
    
    // Check ownership or admin
    let owner_row = sqlx::query("SELECT owner_id FROM accounts WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let owner_id = owner_row.and_then(|row| row.get::<Option<String>, _>(0));
    let is_owner = owner_id.as_ref().map(|oid| oid == &user.id).unwrap_or(false);
    let is_admin = matches!(user.role, UserRole::Admin);
    
    if !is_owner && !is_admin {
        return Err(StatusCode::FORBIDDEN);
    }

    // Return error if no field was provided
    if req.is_active.is_none() && req.password.is_none() && req.owner_id.is_none() && req.is_public.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Only admin can change ownership
    if req.owner_id.is_some() && !is_admin {
        return Err(StatusCode::FORBIDDEN);
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

    // Update owner_id if provided (admin only)
    if let Some(owner_id) = req.owner_id {
        sqlx::query("UPDATE accounts SET owner_id = ? WHERE id = ?")
            .bind(&owner_id)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|e| {
                eprintln!("Database update error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    // Update is_public if provided
    if let Some(is_public) = req.is_public {
        sqlx::query("UPDATE accounts SET is_public = ? WHERE id = ?")
            .bind(is_public)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|e| {
                eprintln!("Database update error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    // Fetch and return updated account
    let row = sqlx::query("SELECT id, email, display_name, is_active, owner_id, is_public FROM accounts WHERE id = ?")
        .bind(&id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let account = EmailAccount {
        id: row.get::<String, _>(0),
        email: row.get::<String, _>(1),
        display_name: row.get::<String, _>(2),
        is_active: row.get::<bool, _>(3),
        owner_id: row.get::<Option<String>, _>(4),
        is_public: row.get::<bool, _>(5),
    };

    Ok(Json(account))
}

pub async fn delete_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> Result<StatusCode, StatusCode> {
    user.ensure_password_updated()?;
    
    // Check ownership or admin
    let owner_row = sqlx::query("SELECT owner_id FROM accounts WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let owner_id = owner_row.and_then(|row| row.get::<Option<String>, _>(0));
    let is_owner = owner_id.as_ref().map(|oid| oid == &user.id).unwrap_or(false);
    let is_admin = matches!(user.role, UserRole::Admin);
    
    if !is_owner && !is_admin {
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
    if !matches!(user.role, UserRole::Admin | UserRole::Dev) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Admin sees all, others see their own + public
    let query = if matches!(user.role, UserRole::Admin) {
        r#"
        SELECT 
            aliases.id,
            aliases.alias_email,
            aliases.display_name,
            aliases.is_active,
            aliases.account_id,
            accounts.email,
            accounts.display_name,
            accounts.is_active,
            aliases.owner_id,
            aliases.is_public
        FROM aliases
        JOIN accounts ON aliases.account_id = accounts.id
        ORDER BY aliases.alias_email ASC
        "#
    } else {
        r#"
        SELECT 
            aliases.id,
            aliases.alias_email,
            aliases.display_name,
            aliases.is_active,
            aliases.account_id,
            accounts.email,
            accounts.display_name,
            accounts.is_active,
            aliases.owner_id,
            aliases.is_public
        FROM aliases
        JOIN accounts ON aliases.account_id = accounts.id
        WHERE aliases.owner_id = ? OR aliases.is_public = 1
        ORDER BY aliases.alias_email ASC
        "#
    };

    let mut query_builder = sqlx::query(query);
    if !matches!(user.role, UserRole::Admin) {
        query_builder = query_builder.bind(&user.id);
    }

    let rows = query_builder
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
            owner_id: row.get::<Option<String>, _>(8),
            is_public: row.get::<bool, _>(9),
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
    if !matches!(user.role, UserRole::Admin | UserRole::Dev) {
        return Err(StatusCode::FORBIDDEN);
    }

    let CreateAliasRequest {
        account_id,
        alias_email,
        display_name,
        is_active,
        is_public,
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
        INSERT INTO aliases (id, alias_email, display_name, is_active, account_id, owner_id, is_public)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&alias_email)
    .bind(&display_name)
    .bind(is_active)
    .bind(&account_id)
    .bind(&user.id)
    .bind(req.is_public)
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
        owner_id: Some(user.id),
        is_public: req.is_public,
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
    
    // Check ownership or admin
    let owner_row = sqlx::query("SELECT owner_id FROM aliases WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let owner_id = owner_row.and_then(|row| row.get::<Option<String>, _>(0));
    let is_owner = owner_id.as_ref().map(|oid| oid == &user.id).unwrap_or(false);
    let is_admin = matches!(user.role, UserRole::Admin);
    
    if !is_owner && !is_admin {
        return Err(StatusCode::FORBIDDEN);
    }

    let UpdateAliasRequest {
        account_id,
        display_name,
        is_active,
        owner_id: req_owner_id,
        is_public,
    } = req;

    if account_id.is_none() && display_name.is_none() && is_active.is_none() && req_owner_id.is_none() && is_public.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Only admin can change ownership
    if req_owner_id.is_some() && !is_admin {
        return Err(StatusCode::FORBIDDEN);
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

    // Update owner_id if provided (admin only)
    if let Some(owner_id) = req_owner_id {
        sqlx::query("UPDATE aliases SET owner_id = ? WHERE id = ?")
            .bind(&owner_id)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // Update is_public if provided
    if let Some(is_public) = is_public {
        sqlx::query("UPDATE aliases SET is_public = ? WHERE id = ?")
            .bind(is_public)
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
            accounts.is_active,
            aliases.owner_id,
            aliases.is_public
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
        owner_id: row.get::<Option<String>, _>(8),
        is_public: row.get::<bool, _>(9),
    };

    Ok(Json(alias))
}

pub async fn delete_alias(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> Result<StatusCode, StatusCode> {
    user.ensure_password_updated()?;
    
    // Check ownership or admin
    let owner_row = sqlx::query("SELECT owner_id FROM aliases WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let owner_id = owner_row.and_then(|row| row.get::<Option<String>, _>(0));
    let is_owner = owner_id.as_ref().map(|oid| oid == &user.id).unwrap_or(false);
    let is_admin = matches!(user.role, UserRole::Admin);
    
    if !is_owner && !is_admin {
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
    if !matches!(user.role, UserRole::Dev | UserRole::Admin) {
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
    
    // If HTML, wrap body in W9 Mail template (matching w9-tools design)
    let final_body = if is_html {
        crate::email::render_email_template(&body)
    } else {
        body.clone()
    };
    
    match email_service.send_email(
        &from_address,
        &resolved.auth_email,
        &resolved.auth_password,
        &to,
        &subject,
        &final_body,
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
    if !matches!(user.role, UserRole::Dev | UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }
    // TODO: Implement IMAP inbox retrieval
    Ok(Json(serde_json::json!([])))
}

// Get public accounts (for compose - visible to all authenticated users)
pub async fn get_public_accounts(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<EmailAccount>>, StatusCode> {
    user.ensure_password_updated()?;
    
    // Get public accounts + accounts owned by the user
    let rows = sqlx::query(
        "SELECT id, email, display_name, is_active, owner_id, is_public FROM accounts WHERE (is_public = 1 OR owner_id = ?) AND is_active = 1"
    )
    .bind(&user.id)
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
            owner_id: row.get::<Option<String>, _>(4),
            is_public: row.get::<bool, _>(5),
        })
        .collect();

    Ok(Json(accounts))
}

// Get public aliases (for compose - visible to all authenticated users)
pub async fn get_public_aliases(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<EmailAlias>>, StatusCode> {
    user.ensure_password_updated()?;
    
    // Get public aliases + aliases owned by the user
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
            accounts.is_active,
            aliases.owner_id,
            aliases.is_public
        FROM aliases
        JOIN accounts ON aliases.account_id = accounts.id
        WHERE (aliases.is_public = 1 OR aliases.owner_id = ?) AND aliases.is_active = 1 AND accounts.is_active = 1
        ORDER BY aliases.alias_email ASC
        "#
    )
    .bind(&user.id)
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
            owner_id: row.get::<Option<String>, _>(8),
            is_public: row.get::<bool, _>(9),
        })
        .collect();

    Ok(Json(aliases))
}

