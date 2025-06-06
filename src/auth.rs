use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use uuid::Uuid;
use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderValue, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
};
use std::env;
use crate::database::Database;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: Uuid,
    pub username: String,
    pub role: String,
    pub exp: usize,
}

pub fn create_jwt_token(claims: &Claims) -> anyhow::Result<String> {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "default_secret_key".to_string());
    let token = encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )?;
    Ok(token)
}

pub fn verify_jwt_token(token: &str) -> anyhow::Result<Claims> {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "default_secret_key".to_string());
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
    Ok(hashed)
}

pub fn verify_password(password: &str, hash: &str) -> anyhow::Result<bool> {
    let is_valid = bcrypt::verify(password, hash)?;
    Ok(is_valid)
}

// 身份验证中间件 - 用于API路由
pub async fn auth_middleware(
    State(_db): State<Database>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            match verify_jwt_token(token) {
                Ok(claims) => {
                    // 可以将claims添加到request extensions中供后续使用
                    request.extensions_mut().insert(claims);
                    return Ok(next.run(request).await);
                }
                Err(_) => return Err(StatusCode::UNAUTHORIZED),
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

// 检查Cookie中的JWT token
fn get_token_from_cookie(cookie_header: &str) -> Option<String> {
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(token) = cookie.strip_prefix("token=") {
            return Some(token.to_string());
        }
    }
    None
}

// Web页面身份验证中间件
pub async fn web_auth_middleware(
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path();
    
    // 允许访问登录和注册页面以及静态文件
    if path == "/login" || path == "/register" || path.starts_with("/static/") || path.starts_with("/api/auth/") {
        return Ok(next.run(request).await);
    }

    // 检查Cookie中的token
    let token = request
        .headers()
        .get("cookie")
        .and_then(|header| header.to_str().ok())
        .and_then(get_token_from_cookie);

    if let Some(token) = token {
        if verify_jwt_token(&token).is_ok() {
            return Ok(next.run(request).await);
        }
    }

    // 未认证，重定向到登录页面
    Ok(Redirect::to("/login").into_response())
} 