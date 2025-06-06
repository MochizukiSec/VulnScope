use crate::models::*;
use super::VulnerabilityCollector;
use reqwest::Client;
use serde::Deserialize;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub struct GitHubCollector {
    client: Client,
    token: String,
}

#[derive(Debug, Deserialize)]
struct GitHubAdvisoryResponse {
    data: AdvisoryData,
}

#[derive(Debug, Deserialize)]
struct AdvisoryData {
    #[serde(rename = "securityAdvisories")]
    security_advisories: AdvisoryConnection,
}

#[derive(Debug, Deserialize)]
struct AdvisoryConnection {
    nodes: Vec<SecurityAdvisory>,
}

#[derive(Debug, Deserialize)]
struct SecurityAdvisory {
    id: String,
    #[serde(rename = "ghsaId")]
    ghsa_id: String,
    summary: String,
    description: String,
    severity: String,
    #[serde(rename = "publishedAt")]
    published_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    #[serde(rename = "withdrawnAt")]
    withdrawn_at: Option<String>,
    identifiers: Vec<Identifier>,
    references: Vec<Reference>,
    vulnerabilities: AdvisoryVulnerabilityConnection,
}

#[derive(Debug, Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    identifier_type: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct Reference {
    url: String,
}

#[derive(Debug, Deserialize)]
struct AdvisoryVulnerabilityConnection {
    nodes: Vec<AdvisoryVulnerability>,
}

#[derive(Debug, Deserialize)]
struct AdvisoryVulnerability {
    package: VulnerabilityPackage,
    #[serde(rename = "vulnerableVersionRange")]
    vulnerable_version_range: String,
}

#[derive(Debug, Deserialize)]
struct VulnerabilityPackage {
    name: String,
    ecosystem: String,
}

impl GitHubCollector {
    pub fn new(token: String) -> Self {
        Self {
            client: Client::new(),
            token,
        }
    }

    fn parse_severity(&self, severity: &str) -> Severity {
        match severity.to_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MODERATE" | "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Unknown,
        }
    }

    fn extract_cve_id(&self, identifiers: &[Identifier]) -> Option<String> {
        identifiers
            .iter()
            .find(|id| id.identifier_type == "CVE")
            .map(|id| id.value.clone())
    }

    fn extract_affected_products(&self, vulnerabilities: &[AdvisoryVulnerability]) -> Vec<String> {
        vulnerabilities
            .iter()
            .map(|vuln| format!("{}:{} ({})", 
                vuln.package.ecosystem, 
                vuln.package.name, 
                vuln.vulnerable_version_range))
            .collect()
    }
}

#[async_trait::async_trait]
impl VulnerabilityCollector for GitHubCollector {
    async fn collect(&self) -> anyhow::Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // GitHub GraphQL query for security advisories
        let query = r#"
        query {
            securityAdvisories(first: 50, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
                nodes {
                    id
                    ghsaId
                    summary
                    description
                    severity
                    publishedAt
                    updatedAt
                    withdrawnAt
                    identifiers {
                        type
                        value
                    }
                    references {
                        url
                    }
                    vulnerabilities(first: 10) {
                        nodes {
                            package {
                                name
                                ecosystem
                            }
                            vulnerableVersionRange
                        }
                    }
                }
            }
        }
        "#;

        let request_body = serde_json::json!({
            "query": query
        });

        tracing::info!("Fetching security advisories from GitHub");

        let response = self.client
            .post("https://api.github.com/graphql")
            .header("Authorization", format!("Bearer {}", self.token))
            .header("User-Agent", "VulnScope/1.0")
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("GitHub API request failed: {} - {}", status, error_text));
        }

        let github_response: GitHubAdvisoryResponse = response.json().await?;
        
        tracing::info!("Received {} advisories from GitHub", 
            github_response.data.security_advisories.nodes.len());

        for advisory in github_response.data.security_advisories.nodes {
            // Skip withdrawn advisories
            if advisory.withdrawn_at.is_some() {
                continue;
            }

            let cve_id = self.extract_cve_id(&advisory.identifiers);
            let severity = self.parse_severity(&advisory.severity);
            let affected_products = self.extract_affected_products(&advisory.vulnerabilities.nodes);
            let references: Vec<String> = advisory.references.into_iter().map(|r| r.url).collect();

            // Parse dates
            let published_date = DateTime::parse_from_rfc3339(&advisory.published_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            
            let modified_date = DateTime::parse_from_rfc3339(&advisory.updated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            let vulnerability = Vulnerability {
                id: Uuid::new_v4(),
                cve_id,
                title: format!("{} - {}", advisory.ghsa_id, advisory.summary),
                description: advisory.description,
                severity,
                cvss_score: None, // GitHub doesn't always provide CVSS scores
                cvss_vector: None,
                cwe_id: None,
                affected_products,
                references,
                exploits: Vec::new(),
                patches: Vec::new(),
                source: "GitHub".to_string(),
                source_url: Some(format!("https://github.com/advisories/{}", advisory.ghsa_id)),
                published_date,
                modified_date,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                tags: vec!["github".to_string(), "advisory".to_string(), advisory.ghsa_id],
                status: VulnStatus::New,
            };

            vulnerabilities.push(vulnerability);
        }

        Ok(vulnerabilities)
    }

    fn name(&self) -> &str {
        "GitHub"
    }

    fn description(&self) -> &str {
        "GitHub Security Advisories - Security vulnerabilities in open source projects"
    }
} 