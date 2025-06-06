use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::models::{Vulnerability, Severity, VulnStatus};
use crate::collectors::VulnerabilityCollector;
use anyhow::Result;
use uuid::Uuid;
use chrono::{DateTime, Utc, NaiveDateTime};

pub struct ChaitinVuldbCollector {
    client: Client,
}

#[derive(Debug, Deserialize)]
struct ChaitinResponse {
    msg: String,
    data: ChaitinData,
    code: i32,
}

#[derive(Debug, Deserialize)]
struct ChaitinData {
    count: i32,
    next: Option<String>,
    previous: Option<String>,
    list: Vec<ChaitinVulnItem>,
}

#[derive(Debug, Deserialize)]
struct ChaitinVulnItem {
    id: String,
    title: String,
    summary: String,
    severity: String,
    ct_id: String,
    cve_id: Option<String>,
    references: Option<String>,
    disclosure_date: Option<String>,
    created_at: String, // ISO 8601 format
    updated_at: String, // ISO 8601 format
}

impl ChaitinVuldbCollector {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }

    async fn fetch_vulnerabilities_page(&self, offset: i32) -> Result<Vec<ChaitinVulnItem>> {
        // 使用正确的长亭API端点，搜索CT-开头的漏洞
        let url = format!("https://stack.chaitin.com/api/v2/vuln/list/?limit=15&offset={}&search=CT-", offset);
        
        tracing::debug!("请求长亭API: {}", url);

        let response = self.client
            .get(&url)
            .header("Referer", "https://stack.chaitin.com/vuldb/index")
            .header("Origin", "https://stack.chaitin.com")
            .header("Accept", "application/json, text/plain, */*")
            .header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
            .send()
            .await?;

        if !response.status().is_success() {
            tracing::warn!("长亭API请求失败，状态码: {}", response.status());
            return Ok(vec![]);
        }

        let text = response.text().await?;
        tracing::debug!("长亭API响应: {}", text);

        match serde_json::from_str::<ChaitinResponse>(&text) {
            Ok(vuln_response) => {
                if vuln_response.code == 0 {  // 长亭API成功返回时 code 为 0
                    tracing::info!("成功获取长亭漏洞数据，数量: {}", vuln_response.data.list.len());
                    Ok(vuln_response.data.list)
                } else {
                    tracing::warn!("长亭API返回错误代码 {}: {}", vuln_response.code, vuln_response.msg);
                    Ok(vec![])
                }
            }
            Err(e) => {
                tracing::error!("解析长亭API响应失败: {}，响应内容: {}", e, text);
                Ok(vec![])
            }
        }
    }

    fn parse_severity(&self, severity: &str) -> Severity {
        match severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Unknown,
        }
    }

    fn parse_datetime(&self, time_str: &str) -> DateTime<Utc> {
        // 尝试解析ISO 8601格式
        if let Ok(dt) = DateTime::parse_from_rfc3339(time_str) {
            return dt.with_timezone(&Utc);
        }
        
        // 尝试解析其他格式
        if let Ok(dt) = NaiveDateTime::parse_from_str(time_str, "%Y-%m-%d %H:%M:%S") {
            return DateTime::from_naive_utc_and_offset(dt, Utc);
        }
        
        Utc::now()
    }

    fn contains_chinese(&self, text: &str) -> bool {
        text.chars().any(|c| {
            matches!(c, '\u{4e00}'..='\u{9fff}' | '\u{3400}'..='\u{4dbf}' | '\u{20000}'..='\u{2a6df}')
        })
    }

    fn is_valuable(&self, item: &ChaitinVulnItem) -> bool {
        // 按照参考代码的策略：等级为高危或严重并且标题含中文
        let severity = self.parse_severity(&item.severity);
        let has_high_severity = matches!(severity, Severity::High | Severity::Critical);
        let has_chinese = self.contains_chinese(&item.title);
        
        has_high_severity && has_chinese
    }

    fn convert_to_vulnerability(&self, item: ChaitinVulnItem) -> Vulnerability {
        let mut references = vec![];
        if let Some(refs) = item.references {
            references = refs.split('\n').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }

        let source_url = format!("https://stack.chaitin.com/vuldb/detail/{}", item.id);

        Vulnerability {
            id: Uuid::new_v4(),
            cve_id: item.cve_id,
            title: item.title,
            description: item.summary,
            severity: self.parse_severity(&item.severity),
            cvss_score: None,
            cvss_vector: None,
            cwe_id: None,
            affected_products: vec![],
            references,
            exploits: vec![],
            patches: vec![],
            source: "长亭漏洞库".to_string(),
            source_url: Some(source_url),
            published_date: self.parse_datetime(&item.created_at),
            modified_date: self.parse_datetime(&item.updated_at),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tags: vec!["长亭".to_string(), item.ct_id],
            status: VulnStatus::New,
        }
    }
}

#[async_trait::async_trait]
impl VulnerabilityCollector for ChaitinVuldbCollector {
    fn name(&self) -> &str {
        "长亭漏洞库"
    }

    fn description(&self) -> &str {
        "长亭科技漏洞数据库，提供高质量的漏洞分析和研究"
    }

    async fn collect(&self) -> Result<Vec<Vulnerability>> {
        tracing::info!("开始从长亭漏洞库收集漏洞数据");

        let mut all_vulnerabilities = Vec::new();
        let page_limit = 3; // 限制页数，每页15个

        for page in 0..page_limit {
            let offset = page * 15;
            
            tracing::info!("获取长亭漏洞数据第 {} 页 (offset: {})", page + 1, offset);
            
            match self.fetch_vulnerabilities_page(offset).await {
                Ok(items) => {
                    if items.is_empty() {
                        tracing::info!("第 {} 页无数据，停止获取", page + 1);
                        break;
                    }

                    let mut valuable_count = 0;
                    for item in items {
                        // 只收集有价值的漏洞（高危或严重级别且标题含中文）
                        if self.is_valuable(&item) {
                            let vulnerability = self.convert_to_vulnerability(item);
                            all_vulnerabilities.push(vulnerability);
                            valuable_count += 1;
                        }
                    }

                    tracing::info!("第 {} 页找到 {} 个有价值的漏洞", page + 1, valuable_count);

                    // 添加延迟避免请求过快
                    tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;
                }
                Err(e) => {
                    tracing::error!("获取长亭漏洞数据失败 (页面 {}): {}", page + 1, e);
                    break;
                }
            }
        }

        tracing::info!("从长亭漏洞库收集到 {} 个有价值的漏洞", all_vulnerabilities.len());
        Ok(all_vulnerabilities)
    }
} 