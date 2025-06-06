use crate::models::*;
use super::VulnerabilityCollector;
use reqwest::Client;
use serde::Deserialize;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub struct NvdCollector {
    client: Client,
    api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdResponse {
    vulnerabilities: Vec<VulnItem>,
}

#[derive(Debug, Deserialize)]
struct VulnItem {
    cve: CveData,
}

#[derive(Debug, Deserialize)]
struct CveData {
    id: String,
    #[serde(rename = "sourceIdentifier")]
    source_identifier: Option<String>,
    published: String,
    #[serde(rename = "lastModified")]
    last_modified: String,
    #[serde(rename = "vulnStatus")]
    vuln_status: Option<String>,
    descriptions: Vec<Description>,
    metrics: Option<Metrics>,
    references: Option<Vec<Reference>>,
    configurations: Option<Vec<Configuration>>,
}

#[derive(Debug, Deserialize)]
struct Description {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct Metrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_metric_v31: Option<Vec<CvssMetric>>,
    #[serde(rename = "cvssMetricV30")]
    cvss_metric_v30: Option<Vec<CvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    cvss_metric_v2: Option<Vec<CvssMetricV2>>,
}

#[derive(Debug, Deserialize)]
struct CvssMetric {
    source: String,
    #[serde(rename = "type")]
    metric_type: String,
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
struct CvssMetricV2 {
    source: String,
    #[serde(rename = "type")]
    metric_type: String,
    #[serde(rename = "cvssData")]
    cvss_data: CvssDataV2,
}

#[derive(Debug, Deserialize)]
struct CvssData {
    version: String,
    #[serde(rename = "vectorString")]
    vector_string: String,
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[serde(rename = "baseSeverity")]
    base_severity: String,
}

#[derive(Debug, Deserialize)]
struct CvssDataV2 {
    version: String,
    #[serde(rename = "vectorString")]
    vector_string: String,
    #[serde(rename = "baseScore")]
    base_score: f64,
}

#[derive(Debug, Deserialize)]
struct Reference {
    url: String,
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Configuration {
    nodes: Vec<ConfigNode>,
}

#[derive(Debug, Deserialize)]
struct ConfigNode {
    operator: Option<String>,
    #[serde(rename = "cpeMatch")]
    cpe_match: Option<Vec<CpeMatch>>,
}

#[derive(Debug, Deserialize)]
struct CpeMatch {
    vulnerable: bool,
    criteria: String,
}

impl NvdCollector {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }

    fn parse_severity(severity_str: Option<&str>, score: f64) -> Severity {
        if let Some(severity) = severity_str {
            match severity.to_uppercase().as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MEDIUM" => Severity::Medium,
                "LOW" => Severity::Low,
                _ => Self::score_to_severity(score),
            }
        } else {
            Self::score_to_severity(score)
        }
    }

    fn score_to_severity(score: f64) -> Severity {
        if score >= 9.0 { Severity::Critical }
        else if score >= 7.0 { Severity::High }
        else if score >= 4.0 { Severity::Medium }
        else if score > 0.0 { Severity::Low }
        else { Severity::Unknown }
    }

    fn extract_products(&self, configurations: &Option<Vec<Configuration>>) -> Vec<String> {
        let mut products = Vec::new();
        
        if let Some(configs) = configurations {
            for config in configs {
                for node in &config.nodes {
                    if let Some(cpe_matches) = &node.cpe_match {
                        for cpe in cpe_matches {
                            if cpe.vulnerable {
                                // Parse CPE to extract product info
                                let parts: Vec<&str> = cpe.criteria.split(':').collect();
                                if parts.len() >= 5 {
                                    let vendor = parts[3];
                                    let product = parts[4];
                                    products.push(format!("{}:{}", vendor, product));
                                }
                            }
                        }
                    }
                }
            }
        }
        
        products.into_iter().collect::<std::collections::HashSet<_>>().into_iter().collect()
    }
}

#[async_trait::async_trait]
impl VulnerabilityCollector for NvdCollector {
    async fn collect(&self) -> anyhow::Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Get recent CVEs (last 3 days to avoid API limits)
        let end_date = Utc::now();
        let start_date = end_date - chrono::Duration::days(3);
        
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={}&pubEndDate={}&resultsPerPage=100",
            start_date.format("%Y-%m-%dT%H:%M:%S.000"),
            end_date.format("%Y-%m-%dT%H:%M:%S.000")
        );

        let mut request = self.client.get(&url);
        
        if let Some(api_key) = &self.api_key {
            request = request.header("apikey", api_key);
        }

        tracing::info!("Fetching CVEs from NVD API");
        
        let response = request.send().await?;
        
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("NVD API request failed: {} - {}", status, error_text));
        }

        let nvd_response: NvdResponse = response.json().await?;
        
        tracing::info!("Received {} CVEs from NVD", nvd_response.vulnerabilities.len());

        for item in nvd_response.vulnerabilities {
            let cve_id = item.cve.id.clone();
            
            // Extract description
            let description = item.cve.descriptions
                .iter()
                .find(|d| d.lang == "en")
                .map(|d| d.value.clone())
                .unwrap_or_else(|| "No description available".to_string());

            // Extract references
            let references = item.cve.references
                .map(|refs| refs.into_iter().map(|r| r.url).collect())
                .unwrap_or_default();

            // Extract CVSS information
            let (cvss_score, cvss_vector, severity) = if let Some(metrics) = &item.cve.metrics {
                if let Some(v31_metrics) = &metrics.cvss_metric_v31 {
                    if let Some(metric) = v31_metrics.first() {
                        (
                            Some(metric.cvss_data.base_score),
                            Some(metric.cvss_data.vector_string.clone()),
                            Self::parse_severity(Some(&metric.cvss_data.base_severity), metric.cvss_data.base_score)
                        )
                    } else {
                        (None, None, Severity::Unknown)
                    }
                } else if let Some(v30_metrics) = &metrics.cvss_metric_v30 {
                    if let Some(metric) = v30_metrics.first() {
                        (
                            Some(metric.cvss_data.base_score),
                            Some(metric.cvss_data.vector_string.clone()),
                            Self::parse_severity(Some(&metric.cvss_data.base_severity), metric.cvss_data.base_score)
                        )
                    } else {
                        (None, None, Severity::Unknown)
                    }
                } else if let Some(v2_metrics) = &metrics.cvss_metric_v2 {
                    if let Some(metric) = v2_metrics.first() {
                        (
                            Some(metric.cvss_data.base_score),
                            Some(metric.cvss_data.vector_string.clone()),
                            Self::score_to_severity(metric.cvss_data.base_score)
                        )
                    } else {
                        (None, None, Severity::Unknown)
                    }
                } else {
                    (None, None, Severity::Unknown)
                }
            } else {
                (None, None, Severity::Unknown)
            };

            // Extract affected products
            let affected_products = self.extract_products(&item.cve.configurations);

            // Parse dates  
            let published_date = DateTime::parse_from_rfc3339(&item.cve.published)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            
            let modified_date = DateTime::parse_from_rfc3339(&item.cve.last_modified)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            let vulnerability = Vulnerability {
                id: Uuid::new_v4(),
                cve_id: Some(cve_id.clone()),
                title: format!("{} - {}", cve_id, 
                    description.chars().take(100).collect::<String>()),
                description,
                severity,
                cvss_score,
                cvss_vector,
                cwe_id: None, // Would need additional parsing
                affected_products,
                references,
                exploits: Vec::new(),
                patches: Vec::new(),
                source: "NVD".to_string(),
                source_url: Some(format!("https://nvd.nist.gov/vuln/detail/{}", cve_id)),
                published_date,
                modified_date,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                tags: vec!["nvd".to_string()],
                status: VulnStatus::New,
            };

            vulnerabilities.push(vulnerability);
        }

        Ok(vulnerabilities)
    }

    fn name(&self) -> &str {
        "NVD"
    }

    fn description(&self) -> &str {
        "National Vulnerability Database - Official US government vulnerability database"
    }
} 