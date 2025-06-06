use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Vulnerability {
    pub id: Uuid,
    pub cve_id: Option<String>,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub cwe_id: Option<String>,
    pub affected_products: Vec<String>,
    pub references: Vec<String>,
    pub exploits: Vec<String>,
    pub patches: Vec<String>,
    pub source: String,
    pub source_url: Option<String>,
    pub published_date: DateTime<Utc>,
    pub modified_date: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: Vec<String>,
    pub status: VulnStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "severity", rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
            Severity::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "vuln_status", rename_all = "lowercase")]
pub enum VulnStatus {
    New,
    Analyzed,
    InProgress,
    Patched,
    Ignored,
}

impl std::fmt::Display for VulnStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnStatus::New => write!(f, "new"),
            VulnStatus::Analyzed => write!(f, "analyzed"),
            VulnStatus::InProgress => write!(f, "inprogress"),
            VulnStatus::Patched => write!(f, "patched"),
            VulnStatus::Ignored => write!(f, "ignored"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    SecurityEngineer,
    SecurityAnalyst,
    Viewer,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Admin => write!(f, "admin"),
            UserRole::SecurityEngineer => write!(f, "securityengineer"),
            UserRole::SecurityAnalyst => write!(f, "securityanalyst"),
            UserRole::Viewer => write!(f, "viewer"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRegistration {
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: UserRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 3, max = 50))]
    pub username: String,
    #[validate(length(min = 6))]
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub role: UserRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFilter {
    pub severity: Option<Severity>,
    pub status: Option<VulnStatus>,
    pub source: Option<String>,
    pub search: Option<String>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityStats {
    pub total_vulnerabilities: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub new_count: i64,
    pub analyzed_count: i64,
    pub patched_count: i64,
    pub recent_vulnerabilities: Vec<Vulnerability>,
    pub top_affected_products: Vec<ProductStats>,
    pub severity_trend: Vec<SeverityTrend>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductStats {
    pub product: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityTrend {
    pub date: DateTime<Utc>,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CollectionLog {
    pub id: Uuid,
    pub source: String,
    pub status: CollectionStatus,
    pub vulnerabilities_collected: i32,
    pub errors: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "collection_status", rename_all = "lowercase")]
pub enum CollectionStatus {
    Running,
    Completed,
    Failed,
}

impl Default for VulnerabilityFilter {
    fn default() -> Self {
        Self {
            severity: None,
            status: None,
            source: None,
            search: None,
            tags: None,
            date_from: None,
            date_to: None,
            page: Some(1),
            limit: Some(20),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SystemSettings {
    pub id: Uuid,
    pub collection_interval: i32,           // 收集间隔（分钟）
    pub nvd_api_key: Option<String>,        // NVD API密钥
    pub github_token: Option<String>,       // GitHub Token
    pub enable_nvd: bool,                   // 启用NVD数据源
    pub enable_exploit_db: bool,            // 启用Exploit-DB数据源
    pub enable_github: bool,                // 启用GitHub数据源
    pub enable_cve_details: bool,           // 启用CVE Details数据源
    pub enable_aliyun_avd: bool,            // 启用阿里云漏洞库
    pub enable_chaitin_vuldb: bool,         // 启用长亭漏洞库
    pub enable_qianxin_ti: bool,            // 启用奇安信威胁情报
    pub enable_threatbook_x: bool,          // 启用微步在线威胁情报
    pub notify_critical: bool,              // 严重漏洞通知
    pub notify_high: bool,                  // 高危漏洞通知
    pub daily_report: bool,                 // 每日汇总报告
    pub email_server: Option<String>,       // 邮件服务器
    pub email_port: Option<i32>,            // 邮件端口
    pub slack_webhook: Option<String>,      // Slack Webhook URL
    pub data_retention_days: i32,           // 数据保留天数
    pub backup_frequency: String,           // 备份频率
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsRequest {
    pub collection_interval: Option<i32>,
    pub nvd_api_key: Option<String>,
    pub github_token: Option<String>,
    pub enable_nvd: Option<bool>,
    pub enable_exploit_db: Option<bool>,
    pub enable_github: Option<bool>,
    pub enable_cve_details: Option<bool>,
    pub enable_aliyun_avd: Option<bool>,
    pub enable_chaitin_vuldb: Option<bool>,
    pub enable_qianxin_ti: Option<bool>,
    pub enable_threatbook_x: Option<bool>,
    pub notify_critical: Option<bool>,
    pub notify_high: Option<bool>,
    pub daily_report: Option<bool>,
    pub email_server: Option<String>,
    pub email_port: Option<i32>,
    pub slack_webhook: Option<String>,
    pub data_retention_days: Option<i32>,
    pub backup_frequency: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub uptime: String,
    pub total_vulnerabilities: i64,
    pub today_new_vulnerabilities: i64,
    pub system_availability: f64,
    pub collectors_status: Vec<CollectorStatus>,
    pub database_size: String,
    pub last_backup: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorStatus {
    pub name: String,
    pub status: String,  // "active", "inactive", "syncing", "error"
    pub last_sync: Option<DateTime<Utc>>,
    pub next_sync: Option<DateTime<Utc>>,
    pub total_collected: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DataCleaningResult {
    pub duplicates_removed: i64,
    pub empty_records_cleaned: i64,
    pub invalid_cvss_fixed: i64,
    pub severity_standardized: i64,
    pub cve_ids_normalized: i64,
    pub malformed_urls_cleaned: i64,
    pub orphaned_logs_cleaned: i64,
    pub test_data_removed: i64,
    pub total_processed: i64,
    pub cleaned_at: Option<DateTime<Utc>>,
} 