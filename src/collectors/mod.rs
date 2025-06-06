use crate::{config::Config, database::Database, models::*};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

pub mod nvd;
pub mod exploit_db;
pub mod github;
pub mod cve_details;
pub mod aliyun_avd;
pub mod chaitin_vuldb;
pub mod qianxin_ti;
pub mod threatbook_x;

pub struct CollectorManager {
    collectors: HashMap<String, Box<dyn VulnerabilityCollector + Send + Sync>>,
    database: Database,
    config: Config,
}

#[async_trait::async_trait]
pub trait VulnerabilityCollector {
    async fn collect(&self) -> anyhow::Result<Vec<Vulnerability>>;
    fn name(&self) -> &str;
    fn description(&self) -> &str;
}

impl CollectorManager {
    pub fn new(database: Database, config: Config) -> Self {
        Self {
            collectors: HashMap::new(),
            database,
            config,
        }
    }

    pub fn add_collector(&mut self, collector: Box<dyn VulnerabilityCollector + Send + Sync>) {
        let name = collector.name().to_string();
        self.collectors.insert(name, collector);
    }

    pub async fn run_collection_cycle(&self) -> anyhow::Result<()> {
        tracing::info!("Starting vulnerability collection cycle");

        for (name, collector) in &self.collectors {
            let log_id = Uuid::new_v4();
            let log = CollectionLog {
                id: log_id,
                source: name.clone(),
                status: CollectionStatus::Running,
                vulnerabilities_collected: 0,
                errors: None,
                started_at: chrono::Utc::now(),
                completed_at: None,
            };

            if let Err(e) = self.database.create_collection_log(&log).await {
                tracing::error!("Failed to create collection log for {}: {}", name, e);
                continue;
            }

            tracing::info!("Collecting vulnerabilities from {}", name);

            match collector.collect().await {
                Ok(vulnerabilities) => {
                    let mut collected_count = 0;
                    
                    for vuln in vulnerabilities {
                        match self.database.create_vulnerability(&vuln).await {
                            Ok(_) => collected_count += 1,
                            Err(e) => {
                                tracing::warn!("Failed to save vulnerability {}: {}", 
                                    vuln.cve_id.as_deref().unwrap_or("unknown"), e);
                            }
                        }
                    }

                    if let Err(e) = self.database.update_collection_log(
                        &log_id, 
                        CollectionStatus::Completed, 
                        collected_count, 
                        None
                    ).await {
                        tracing::error!("Failed to update collection log: {}", e);
                    }

                    tracing::info!("Successfully collected {} vulnerabilities from {}", 
                        collected_count, name);
                }
                Err(e) => {
                    let error_msg = format!("Collection failed: {}", e);
                    tracing::error!("Failed to collect from {}: {}", name, e);

                    if let Err(e) = self.database.update_collection_log(
                        &log_id, 
                        CollectionStatus::Failed, 
                        0, 
                        Some(error_msg)
                    ).await {
                        tracing::error!("Failed to update collection log: {}", e);
                    }
                }
            }

            // Small delay between collectors to avoid overwhelming sources
            sleep(Duration::from_secs(5)).await;
        }

        tracing::info!("Collection cycle completed");
        Ok(())
    }
}

pub async fn init_collectors(config: &Config) -> anyhow::Result<CollectorManager> {
    let database = Database::new(&config.database_url).await?;
    let mut manager = CollectorManager::new(database, config.clone());

    // Initialize NVD collector
    let nvd_collector = nvd::NvdCollector::new(config.collectors.nvd_api_key.clone());
    manager.add_collector(Box::new(nvd_collector));

    // Initialize Exploit-DB collector if enabled
    if config.collectors.exploit_db_enabled {
        let exploit_db_collector = exploit_db::ExploitDbCollector::new();
        manager.add_collector(Box::new(exploit_db_collector));
    }

    // Initialize GitHub collector if token is provided
    if let Some(token) = &config.collectors.github_token {
        let github_collector = github::GitHubCollector::new(token.clone());
        manager.add_collector(Box::new(github_collector));
    }

    // Initialize CVE Details collector
    let cve_details_collector = cve_details::CveDetailsCollector::new();
    manager.add_collector(Box::new(cve_details_collector));

    // Initialize Chinese vulnerability sources
    // 阿里云漏洞库
    let aliyun_avd_collector = aliyun_avd::AliyunAvdCollector::new();
    manager.add_collector(Box::new(aliyun_avd_collector));

    // 长亭漏洞库
    let chaitin_vuldb_collector = chaitin_vuldb::ChaitinVuldbCollector::new();
    manager.add_collector(Box::new(chaitin_vuldb_collector));

    // 奇安信威胁情报中心
    let qianxin_ti_collector = qianxin_ti::QianxinTiCollector::new();
    manager.add_collector(Box::new(qianxin_ti_collector));

    // 微步在线威胁情报
    let threatbook_x_collector = threatbook_x::ThreatbookXCollector::new();
    manager.add_collector(Box::new(threatbook_x_collector));

    tracing::info!("Initialized {} vulnerability collectors", manager.collectors.len());
    Ok(manager)
}

pub async fn start_collection(manager: CollectorManager) {
    let interval = Duration::from_secs(manager.config.collectors.cve_feed_interval * 60);
    
    loop {
        if let Err(e) = manager.run_collection_cycle().await {
            tracing::error!("Collection cycle failed: {}", e);
        }

        tracing::info!("Waiting {} minutes before next collection cycle", 
            manager.config.collectors.cve_feed_interval);
        sleep(interval).await;
    }
} 