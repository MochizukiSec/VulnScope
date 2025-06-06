use crate::{database::Database, models::*};
use chrono::Utc;

pub struct VulnerabilityService {
    db: Database,
}

impl VulnerabilityService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn get_vulnerability_trends(&self) -> anyhow::Result<Vec<SeverityTrend>> {
        // In a real implementation, this would aggregate data from the database
        let mut trends = Vec::new();
        
        for i in 0..7 {
            let date = Utc::now() - chrono::Duration::days(i);
            trends.push(SeverityTrend {
                date,
                critical: (i + 1) * 2,
                high: (i + 1) * 5,
                medium: (i + 1) * 8,
                low: (i + 1) * 12,
            });
        }
        
        trends.reverse();
        Ok(trends)
    }

    pub async fn get_top_affected_products(&self) -> anyhow::Result<Vec<ProductStats>> {
        // Mock data for demo
        Ok(vec![
            ProductStats { product: "Apache HTTP Server".to_string(), count: 45 },
            ProductStats { product: "WordPress".to_string(), count: 32 },
            ProductStats { product: "MySQL".to_string(), count: 28 },
            ProductStats { product: "OpenSSL".to_string(), count: 23 },
            ProductStats { product: "Nginx".to_string(), count: 19 },
        ])
    }

    pub async fn get_recent_critical_vulnerabilities(&self) -> anyhow::Result<Vec<Vulnerability>> {
        let mut filter = VulnerabilityFilter::default();
        filter.severity = Some(Severity::Critical);
        filter.limit = Some(10);
        
        self.db.get_vulnerabilities(&filter).await
    }
}

pub struct NotificationService;

impl NotificationService {
    pub fn new() -> Self {
        Self
    }

    pub async fn send_vulnerability_alert(&self, vulnerability: &Vulnerability) -> anyhow::Result<()> {
        tracing::info!(
            "🚨 VULNERABILITY ALERT: {} - {} ({})",
            vulnerability.cve_id.as_deref().unwrap_or("Unknown"),
            vulnerability.title,
            format!("{:?}", vulnerability.severity)
        );
        
        // In a real implementation, this would send emails, Slack messages, etc.
        Ok(())
    }

    pub async fn send_daily_report(&self, stats: &VulnerabilityStats) -> anyhow::Result<()> {
        tracing::info!(
            "📊 Daily Report: {} total vulnerabilities, {} critical, {} high",
            stats.total_vulnerabilities,
            stats.critical_count,
            stats.high_count
        );
        
        Ok(())
    }
} 