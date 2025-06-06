use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub jwt_secret: String,
    pub admin_username: String,
    pub admin_password: String,
    pub collectors: CollectorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorConfig {
    pub nvd_api_key: Option<String>,
    pub cve_feed_interval: u64, // minutes
    pub github_token: Option<String>,
    pub exploit_db_enabled: bool,
    pub vulndb_enabled: bool,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        
        let config = Config {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://vulnscope:password@localhost/vulnscope".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .unwrap_or(3000),
            jwt_secret: env::var("JWT_SECRET")
                .unwrap_or_else(|_| "your-super-secret-jwt-key-change-in-production".to_string()),
            admin_username: env::var("ADMIN_USERNAME")
                .unwrap_or_else(|_| "admin".to_string()),
            admin_password: env::var("ADMIN_PASSWORD")
                .unwrap_or_else(|_| "admin123".to_string()),
            collectors: CollectorConfig {
                nvd_api_key: env::var("NVD_API_KEY").ok(),
                cve_feed_interval: env::var("CVE_FEED_INTERVAL")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()
                    .unwrap_or(60),
                github_token: env::var("GITHUB_TOKEN").ok(),
                exploit_db_enabled: env::var("EXPLOIT_DB_ENABLED")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true),
                vulndb_enabled: env::var("VULNDB_ENABLED")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true),
            },
        };
        
        Ok(config)
    }
} 