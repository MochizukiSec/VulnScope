use std::net::SocketAddr;
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod database;
mod models;
mod handlers;
mod collectors;
mod auth;
mod utils;
mod services;

use config::Config;
use database::Database;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vulnscope=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    
    // Initialize database
    let db = Database::new(&config.database_url).await?;
    db.run_migrations().await?;

    // Initialize collectors
    let collectors = collectors::init_collectors(&config).await?;
    
    // Start background collection tasks
    tokio::spawn(async move {
        collectors::start_collection(collectors).await;
    });

    // Public routes (no authentication required)
    let public_routes = Router::new()
        .route("/login", get(handlers::login_page))
        .route("/register", get(handlers::register_page))
        .route("/api/auth/login", post(handlers::login))
        .route("/api/auth/register", post(handlers::register))
        .route("/api/auth/logout", post(handlers::logout));

    // Protected API routes (require Bearer token)
    let protected_api_routes = Router::new()
        .route("/api/health", get(handlers::health))
        .route("/api/vulnerabilities", get(handlers::get_vulnerabilities))
        .route("/api/vulnerabilities/:id", get(handlers::get_vulnerability))
        .route("/api/search", get(handlers::search_vulnerabilities))
        .route("/api/stats", get(handlers::get_statistics))
        .route("/api/users/profile", get(handlers::get_profile))
        .route("/api/settings", get(handlers::get_settings))
        .route("/api/settings", post(handlers::update_settings))
        .route("/api/system/status", get(handlers::get_system_status))
        .route("/api/system/optimize", post(handlers::optimize_database))
        .route("/api/system/cleanup", post(handlers::cleanup_old_data))
        // 数据清洗相关路由
        .route("/api/system/clean/duplicates", post(handlers::remove_duplicate_vulnerabilities))
        .route("/api/system/clean/empty", post(handlers::cleanup_empty_vulnerabilities))
        .route("/api/system/clean/cvss", post(handlers::cleanup_invalid_cvss_scores))
        .route("/api/system/clean/severity", post(handlers::standardize_severity_values))
        .route("/api/system/clean/cve", post(handlers::normalize_cve_ids))
        .route("/api/system/clean/urls", post(handlers::cleanup_malformed_urls))
        .route("/api/system/clean/test", post(handlers::remove_test_data))
        .route("/api/system/clean/comprehensive", post(handlers::comprehensive_data_cleaning))
        // Collector management routes
        .route("/api/collectors/:name/start", post(handlers::start_collector))
        .route("/api/collectors/:name/stop", post(handlers::stop_collector))
        .route("/api/collectors/:name/logs", get(handlers::get_collector_logs))
        .route_layer(middleware::from_fn_with_state(db.clone(), auth::auth_middleware));

    // Protected web interface routes (require cookie authentication)
    let protected_web_routes = Router::new()
        .route("/", get(handlers::dashboard))
        .route("/vulnerabilities", get(handlers::vulnerabilities_page))
        .route("/vulnerabilities/:id", get(handlers::vulnerability_detail_page))
        .route("/search", get(handlers::search_page))
        .route("/analytics", get(handlers::analytics_page))
        .route("/settings", get(handlers::settings_page))
        .route_layer(middleware::from_fn(auth::web_auth_middleware));

    // Combine all routes
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_api_routes)
        .merge(protected_web_routes)
        // Static files (no authentication required)
        .nest_service("/static", ServeDir::new("static"))
        // Add CORS
        .layer(CorsLayer::permissive())
        // Add database layer
        .with_state(db);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    tracing::info!("🚀 VulnScope server starting on {}", addr);
    tracing::info!("📊 Dashboard: http://{}", addr);
    tracing::info!("🔍 API: http://{}/api", addr);
    
    axum::serve(listener, app).await?;
    
    Ok(())
} 