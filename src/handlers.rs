use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, Json},
    Json as RequestJson,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::{create_jwt_token, hash_password, verify_password, Claims},
    database::Database,
    models::*,
    utils::ApiResponse,
};

// API Health Check
pub async fn health() -> Json<ApiResponse<&'static str>> {
    Json(ApiResponse::success("VulnScope API is healthy"))
}

// Vulnerability endpoints
pub async fn get_vulnerabilities(
    State(db): State<Database>,
    Query(filter): Query<VulnerabilityFilter>,
) -> Result<Json<ApiResponse<Vec<Vulnerability>>>, StatusCode> {
    match db.get_vulnerabilities(&filter).await {
        Ok(vulnerabilities) => Ok(Json(ApiResponse::success(vulnerabilities))),
        Err(e) => {
            tracing::error!("Failed to get vulnerabilities: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn get_vulnerability(
    State(db): State<Database>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<Option<Vulnerability>>>, StatusCode> {
    match db.get_vulnerability_by_id(&id).await {
        Ok(vulnerability) => Ok(Json(ApiResponse::success(vulnerability))),
        Err(e) => {
            tracing::error!("Failed to get vulnerability {}: {}", id, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
pub struct SearchQuery {
    q: String,
    #[serde(flatten)]
    filter: VulnerabilityFilter,
}

pub async fn search_vulnerabilities(
    State(db): State<Database>,
    Query(search): Query<SearchQuery>,
) -> Result<Json<ApiResponse<Vec<Vulnerability>>>, StatusCode> {
    let mut filter = search.filter;
    filter.search = Some(search.q);
    
    match db.get_vulnerabilities(&filter).await {
        Ok(vulnerabilities) => Ok(Json(ApiResponse::success(vulnerabilities))),
        Err(e) => {
            tracing::error!("Failed to search vulnerabilities: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn get_statistics(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<VulnerabilityStats>>, StatusCode> {
    match db.get_statistics().await {
        Ok(stats) => Ok(Json(ApiResponse::success(stats))),
        Err(e) => {
            tracing::error!("Failed to get statistics: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Authentication endpoints
pub async fn login(
    State(db): State<Database>,
    RequestJson(login_req): RequestJson<LoginRequest>,
) -> Result<Json<ApiResponse<LoginResponse>>, StatusCode> {
    // Validate input
    if login_req.username.is_empty() || login_req.password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    match db.get_user_by_username(&login_req.username).await {
        Ok(Some(user)) => {
            if handle_anyhow_error(verify_password(&login_req.password, &user.password_hash))? {
                // Update last login
                if let Err(e) = db.update_last_login(&user.id).await {
                    tracing::warn!("Failed to update last login for user {}: {}", user.id, e);
                }

                let claims = Claims {
                    sub: user.id,
                    username: user.username.clone(),
                    role: user.role.to_string(),
                    exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
                };

                match create_jwt_token(&claims) {
                    Ok(token) => {
                        let response = LoginResponse {
                            token,
                            user: UserInfo {
                                id: user.id,
                                username: user.username,
                                email: user.email,
                                role: user.role,
                            },
                        };
                        Ok(Json(ApiResponse::success(response)))
                    }
                    Err(e) => {
                        tracing::error!("Failed to create JWT token: {}", e);
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        Ok(None) => Err(StatusCode::UNAUTHORIZED),
        Err(e) => {
            tracing::error!("Database error during login: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn register(
    State(db): State<Database>,
    RequestJson(registration): RequestJson<UserRegistration>,
) -> Result<Json<ApiResponse<UserInfo>>, StatusCode> {
    // Basic validation
    if registration.username.len() < 3 || registration.password.len() < 6 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let password_hash = handle_anyhow_error(hash_password(&registration.password))?;
    
    let user = User {
        id: Uuid::new_v4(),
        username: registration.username,
        email: registration.email,
        password_hash,
        role: registration.role,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_login: None,
        is_active: true,
    };

    match db.create_user(&user).await {
        Ok(_) => {
            let user_info = UserInfo {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
            };
            Ok(Json(ApiResponse::success(user_info)))
        }
        Err(e) => {
            tracing::error!("Failed to create user: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn get_profile(
    // In a real implementation, you would extract user from JWT token
) -> Result<Json<ApiResponse<&'static str>>, StatusCode> {
    Ok(Json(ApiResponse::success("User profile endpoint - requires authentication middleware")))
}

pub async fn logout() -> Result<Json<ApiResponse<&'static str>>, StatusCode> {
    // 对于JWT token，logout通常在客户端处理（删除token）
    // 但我们可以返回一个成功响应，客户端收到后清除本地token
    Ok(Json(ApiResponse::success("Successfully logged out")))
}

// Collector management endpoints
pub async fn start_collector(
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // 这里应该实现启动收集器的逻辑
    // 目前返回一个模拟响应
    Ok(Json(ApiResponse::success(format!("Collector {} started", name))))
}

pub async fn stop_collector(
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // 这里应该实现停止收集器的逻辑
    // 目前返回一个模拟响应
    Ok(Json(ApiResponse::success(format!("Collector {} stopped", name))))
}

pub async fn get_collector_logs(
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<Vec<String>>>, StatusCode> {
    // 这里应该实现获取收集器日志的逻辑
    // 目前返回一个模拟响应
    let logs = vec![
        format!("[INFO] {} collector started", name),
        format!("[INFO] {} collector collecting data...", name),
        format!("[INFO] {} collector finished", name),
    ];
    Ok(Json(ApiResponse::success(logs)))
}

// Web interface endpoints
pub async fn dashboard() -> Html<String> {
    let html = include_str!("../templates/dashboard.html");
    Html(html.to_string())
}

pub async fn vulnerabilities_page() -> Html<String> {
    let html = include_str!("../templates/vulnerabilities.html");
    Html(html.to_string())
}

pub async fn search_page() -> Html<String> {
    let html = include_str!("../templates/search.html");
    Html(html.to_string())
}

pub async fn analytics_page() -> Html<String> {
    let html = include_str!("../templates/analytics.html");
    Html(html.to_string())
}

pub async fn settings_page() -> Html<String> {
    let html = include_str!("../templates/settings.html");
    Html(html.to_string())
}

pub async fn login_page() -> Html<String> {
    let html = include_str!("../templates/login.html");
    Html(html.to_string())
}

pub async fn register_page() -> Html<String> {
    let html = include_str!("../templates/register.html");
    Html(html.to_string())
}

pub async fn vulnerability_detail_page() -> Html<String> {
    let html = include_str!("../templates/vulnerability_detail.html");
    Html(html.to_string())
}

// Helper functions for error conversion
fn handle_bcrypt_error<T>(result: Result<T, bcrypt::BcryptError>) -> Result<T, StatusCode> {
    result.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn handle_anyhow_error<T>(result: Result<T, anyhow::Error>) -> Result<T, StatusCode> {
    result.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

// Settings endpoints
pub async fn get_settings(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<SystemSettings>>, StatusCode> {
    match db.get_system_settings().await {
        Ok(settings) => Ok(Json(ApiResponse::success(settings))),
        Err(e) => {
            tracing::error!("Failed to get system settings: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn update_settings(
    State(db): State<Database>,
    RequestJson(settings_req): RequestJson<SettingsRequest>,
) -> Result<Json<ApiResponse<SystemSettings>>, StatusCode> {
    match db.update_system_settings(&settings_req).await {
        Ok(settings) => {
            tracing::info!("System settings updated successfully");
            Ok(Json(ApiResponse::success(settings)))
        }
        Err(e) => {
            tracing::error!("Failed to update system settings: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn get_system_status(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<SystemStatus>>, StatusCode> {
    match db.get_system_status().await {
        Ok(status) => Ok(Json(ApiResponse::success(status))),
        Err(e) => {
            tracing::error!("Failed to get system status: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn optimize_database(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<&'static str>>, StatusCode> {
    match db.optimize_database().await {
        Ok(_) => Ok(Json(ApiResponse::success("数据库优化完成"))),
        Err(e) => {
            tracing::error!("Failed to optimize database: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn cleanup_old_data(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // Get retention days from settings
    let settings = match db.get_system_settings().await {
        Ok(settings) => settings,
        Err(e) => {
            tracing::error!("Failed to get settings for cleanup: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    match db.cleanup_old_data(settings.data_retention_days).await {
        Ok(deleted_count) => {
            let message = format!("已清理 {} 条过期数据", deleted_count);
            Ok(Json(ApiResponse::success(message)))
        }
        Err(e) => {
            tracing::error!("Failed to cleanup old data: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// 数据清洗相关的API端点
pub async fn remove_duplicate_vulnerabilities(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    match db.remove_duplicate_vulnerabilities().await {
        Ok(removed_count) => {
            let message = format!("已移除 {} 条重复漏洞记录", removed_count);
            Ok(Json(ApiResponse::success(message)))
        }
        Err(e) => {
            tracing::error!("Failed to remove duplicate vulnerabilities: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn cleanup_empty_vulnerabilities(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    match db.cleanup_empty_vulnerabilities().await {
        Ok(cleaned_count) => {
            let message = format!("已清理 {} 条空记录", cleaned_count);
            Ok(Json(ApiResponse::success(message)))
        }
        Err(e) => {
            tracing::error!("Failed to cleanup empty vulnerabilities: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn cleanup_invalid_cvss_scores(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    match db.cleanup_invalid_cvss_scores().await {
        Ok(fixed_count) => {
            let message = format!("已修正 {} 条无效CVSS评分", fixed_count);
            Ok(Json(ApiResponse::success(message)))
        }
        Err(e) => {
            tracing::error!("Failed to cleanup invalid CVSS scores: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn standardize_severity_values(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    match db.standardize_severity_values().await {
        Ok(standardized_count) => {
            let message = format!("已标准化 {} 条严重程度值", standardized_count);
            Ok(Json(ApiResponse::success(message)))
        }
        Err(e) => {
            tracing::error!("Failed to standardize severity values: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn normalize_cve_ids(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    match db.normalize_cve_ids().await {
        Ok(normalized_count) => {
            let message = format!("已标准化 {} 条CVE ID", normalized_count);
            Ok(Json(ApiResponse::success(message)))
        }
        Err(e) => {
            tracing::error!("Failed to normalize CVE IDs: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn cleanup_malformed_urls(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    match db.cleanup_malformed_urls().await {
        Ok(cleaned_count) => {
            let message = format!("已清理 {} 条格式错误的URL", cleaned_count);
            Ok(Json(ApiResponse::success(message)))
        }
        Err(e) => {
            tracing::error!("Failed to cleanup malformed URLs: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn remove_test_data(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    match db.remove_test_data().await {
        Ok(removed_count) => {
            let message = format!("已移除 {} 条测试数据", removed_count);
            Ok(Json(ApiResponse::success(message)))
        }
        Err(e) => {
            tracing::error!("Failed to remove test data: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn comprehensive_data_cleaning(
    State(db): State<Database>,
) -> Result<Json<ApiResponse<DataCleaningResult>>, StatusCode> {
    match db.comprehensive_data_cleaning().await {
        Ok(mut result) => {
            result.cleaned_at = Some(chrono::Utc::now());
            tracing::info!("Comprehensive data cleaning completed: {} total records processed", result.total_processed);
            Ok(Json(ApiResponse::success(result)))
        }
        Err(e) => {
            tracing::error!("Failed to perform comprehensive data cleaning: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
} 