use reqwest::Client;
use scraper::{Html, Selector};
use crate::models::{Vulnerability, Severity, VulnStatus};
use crate::collectors::VulnerabilityCollector;
use anyhow::{Result, anyhow};
use uuid::Uuid;
use chrono::{DateTime, Utc, NaiveDateTime};
use regex::Regex;
use std::time::Duration;
use tokio::time::sleep;

pub struct AliyunAvdCollector {
    client: Client,
    base_url: String,
}

impl AliyunAvdCollector {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::limited(3))
                .build()
                .unwrap(),
            base_url: "https://avd.aliyun.com".to_string(),
        }
    }

    /// 获取指定页面的漏洞详情链接
    async fn fetch_vulnerability_links(&self, page: i32) -> Result<Vec<String>> {
        let url = format!("{}/high-risk/list?page={}", self.base_url, page);
        
        tracing::info!("正在获取阿里云漏洞列表页面: {} (第{}页)", url, page);
        
        // 添加随机延时，模拟真实用户行为
        if page > 1 {
            let delay = fastrand::u64(1000..3000);
            sleep(Duration::from_millis(delay)).await;
        }

        let response = self.client
            .get(&url)
            .header("Referer", &self.base_url)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
            .header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("DNT", "1")
            .header("Connection", "keep-alive")
            .header("Upgrade-Insecure-Requests", "1")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow!("获取页面失败，状态码: {}，响应: {}", status, text.chars().take(200).collect::<String>()));
        }

        let html_content = response.text().await?;
        let document = Html::parse_document(&html_content);
        
        // 多种选择器兼容不同的页面结构
        let selectors = [
            "tbody > tr td > a",
            ".vuln-list tbody tr td a",
            "table tbody tr td a[href*='/detail']",
            "tr td a",
        ];
        
        let mut links = Vec::new();
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                for element in document.select(&selector) {
                    if let Some(href) = element.value().attr("href") {
                        let full_url = if href.starts_with("http") {
                            href.to_string()
                        } else if href.starts_with("/") {
                            format!("{}{}", self.base_url, href)
                        } else {
                            format!("{}/{}", self.base_url, href)
                        };
                        
                        // 验证是否为有效的详情页链接
                        if full_url.contains("/detail") && full_url.contains("id=") {
                            links.push(full_url);
                        }
                    }
                }
                
                if !links.is_empty() {
                    break; // 找到链接就停止尝试其他选择器
                }
            }
        }
        
        // 去重
        links.sort();
        links.dedup();
        
        if links.is_empty() {
            tracing::warn!("页面{}未找到漏洞链接，可能页面结构发生变化或遇到反爬虫限制", page);
        } else {
            tracing::info!("从页面{}成功获取到{}个漏洞链接", page, links.len());
        }
        
        Ok(links)
    }

    /// 解析单个漏洞详情页面
    async fn parse_vulnerability_detail(&self, vuln_url: &str) -> Result<Vulnerability> {
        tracing::debug!("正在解析漏洞详情: {}", vuln_url);
        
        // 添加随机延时，避免请求过于频繁
        let delay = fastrand::u64(800..2000);
        sleep(Duration::from_millis(delay)).await;
        
        let response = self.client
            .get(vuln_url)
            .header("Referer", &format!("{}/high-risk/list", self.base_url))
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("获取漏洞详情失败，状态码: {}", response.status()));
        }

        let html_content = response.text().await?;
        let document = Html::parse_document(&html_content);
        
        // 提取AVD ID
        let avd_id = self.extract_avd_id(vuln_url)?;
        
        // 解析基本信息
        let title = self.extract_title(&document).unwrap_or_else(|| format!("AVD-{}", avd_id));
        let severity = self.extract_severity(&document);
        let cve_id = self.extract_cve_id(&document);
        let disclosure_date = self.extract_disclosure_date(&document);
        let description = self.extract_description(&document);
        let solution = self.extract_solution(&document);
        let references = self.extract_references(&document);
        let tags = self.extract_tags(&document);
        
        // 验证必要字段
        if title.trim().is_empty() {
            return Err(anyhow!("漏洞标题为空，AVD ID: {}", avd_id));
        }
        
        // 只收集高危和严重级别的漏洞
        if !self.is_high_value_vulnerability(&severity, &cve_id) {
            return Err(anyhow!("跳过低价值漏洞: {} (等级: {:?})", title, severity));
        }

        // 解析时间
        let published_date = if let Some(date_str) = disclosure_date {
            self.parse_date(&date_str).unwrap_or_else(|| Utc::now())
        } else {
            Utc::now()
        };

        let vulnerability = Vulnerability {
            id: Uuid::new_v4(),
            cve_id,
            title,
            description: if description.is_empty() { 
                "暂无详细描述".to_string() 
            } else { 
                description 
            },
            severity,
            cvss_score: None, // AVD页面通常不提供CVSS评分
            cvss_vector: None,
            cwe_id: None,
            affected_products: vec![], // 需要进一步解析
            references,
            exploits: vec![],
            patches: if solution.is_empty() { vec![] } else { vec![solution] },
            source: "阿里云漏洞库".to_string(),
            source_url: Some(vuln_url.to_string()),
            published_date,
            modified_date: published_date,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tags,
            status: VulnStatus::New,
        };

        Ok(vulnerability)
    }

    /// 从URL中提取AVD ID
    fn extract_avd_id(&self, url: &str) -> Result<String> {
        if let Ok(parsed_url) = url::Url::parse(url) {
            for (key, value) in parsed_url.query_pairs() {
                if key == "id" {
                    return Ok(value.to_string());
                }
            }
        }
        
        // 尝试从URL路径中提取
        let id_regex = Regex::new(r"AVD-\d+-\d+").unwrap();
        if let Some(captures) = id_regex.find(url) {
            return Ok(captures.as_str().to_string());
        }
        
        Err(anyhow!("无法从URL中提取AVD ID: {}", url))
    }

    /// 提取漏洞标题
    fn extract_title(&self, document: &Html) -> Option<String> {
        let selectors = [
            "h5.header__title .header__title__text",
            ".header__title__text", 
            "h1",
            ".vuln-title",
            ".title",
        ];
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                if let Some(element) = document.select(&selector).next() {
                    let title = element.text().collect::<String>().trim().to_string();
                    if !title.is_empty() {
                        return Some(title);
                    }
                }
            }
        }
        None
    }

    /// 提取漏洞等级
    fn extract_severity(&self, document: &Html) -> Severity {
        let selectors = [
            ".badge",
            ".level",
            ".severity",
            ".risk-level",
        ];
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                for element in document.select(&selector) {
                    let text = element.text().collect::<String>().trim().to_string();
                    let severity = self.parse_severity(&text);
                    if !matches!(severity, Severity::Unknown) {
                        return severity;
                    }
                }
            }
        }
        
        Severity::Unknown
    }

    /// 提取CVE ID
    fn extract_cve_id(&self, document: &Html) -> Option<String> {
        let metric_selector = Selector::parse("div.metric").ok()?;
        let cve_regex = Regex::new(r"^CVE-\d+-\d+$").unwrap();
        
        for metric in document.select(&metric_selector) {
            let label_selector = Selector::parse(".metric-label").ok()?;
            let value_selector = Selector::parse(".metric-value").ok()?;
            
            if let (Some(label_elem), Some(value_elem)) = (
                metric.select(&label_selector).next(),
                metric.select(&value_selector).next()
            ) {
                let label = label_elem.text().collect::<String>().trim().to_string();
                let value = value_elem.text().collect::<String>().trim().to_string();
                
                if label.contains("CVE") && value != "暂无" && cve_regex.is_match(&value) {
                    return Some(value);
                }
            }
        }
        
        None
    }

    /// 提取披露时间
    fn extract_disclosure_date(&self, document: &Html) -> Option<String> {
        let metric_selector = Selector::parse("div.metric").ok()?;
        
        for metric in document.select(&metric_selector) {
            let label_selector = Selector::parse(".metric-label").ok()?;
            let value_selector = Selector::parse(".metric-value").ok()?;
            
            if let (Some(label_elem), Some(value_elem)) = (
                metric.select(&label_selector).next(),
                metric.select(&value_selector).next()
            ) {
                let label = label_elem.text().collect::<String>().trim().to_string();
                let value = value_elem.text().collect::<String>().trim().to_string();
                
                if label.contains("披露时间") && value != "暂无" {
                    return Some(value);
                }
            }
        }
        
        None
    }

    /// 提取漏洞描述
    fn extract_description(&self, document: &Html) -> String {
        let selectors = [
            "div.py-4.pl-4.pr-4.px-2.bg-white.rounded.shadow-sm",
            ".vuln-description",
            ".description",
        ];
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                if let Some(main_content) = document.select(&selector).next() {
                    let children_selector = Selector::parse("> *").unwrap();
                    let children: Vec<_> = main_content.select(&children_selector).collect();
                    
                    let mut i = 0;
                    while i < children.len() {
                        let text = children[i].text().collect::<String>().trim().to_string();
                        
                        if text == "漏洞描述" && i + 1 < children.len() {
                            let desc_elem = &children[i + 1];
                            if let Ok(div_selector) = Selector::parse("div") {
                                if let Some(desc_div) = desc_elem.select(&div_selector).next() {
                                    let description = desc_div.text().collect::<String>().trim().to_string();
                                    if !description.is_empty() {
                                        return description;
                                    }
                                }
                            }
                            let description = desc_elem.text().collect::<String>().trim().to_string();
                            if !description.is_empty() {
                                return description;
                            }
                        }
                        i += 1;
                    }
                }
            }
        }
        
        String::new()
    }

    /// 提取解决方案
    fn extract_solution(&self, document: &Html) -> String {
        let selectors = [
            "div.py-4.pl-4.pr-4.px-2.bg-white.rounded.shadow-sm",
            ".solution",
            ".fix",
        ];
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                if let Some(main_content) = document.select(&selector).next() {
                    let children_selector = Selector::parse("> *").unwrap();
                    let children: Vec<_> = main_content.select(&children_selector).collect();
                    
                    let mut i = 0;
                    while i < children.len() {
                        let text = children[i].text().collect::<String>().trim().to_string();
                        
                        if text == "解决建议" && i + 1 < children.len() {
                            let solution_elem = &children[i + 1];
                            let solution = solution_elem.text().collect::<String>().trim().to_string()
                                .replace("、", ". ");
                            if !solution.is_empty() {
                                return solution;
                            }
                        }
                        i += 1;
                    }
                }
            }
        }
        
        String::new()
    }

    /// 提取参考链接
    fn extract_references(&self, document: &Html) -> Vec<String> {
        let mut references = Vec::new();
        
        let selectors = [
            "div.reference tbody > tr a",
            ".references a",
            ".ref-link",
        ];
        
        for selector_str in &selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                for ref_link in document.select(&selector) {
                    if let Some(href) = ref_link.value().attr("href") {
                        let href = href.trim();
                        if href.starts_with("http") && !references.contains(&href.to_string()) {
                            references.push(href.to_string());
                        }
                    }
                }
            }
        }
        
        references
    }

    /// 提取标签
    fn extract_tags(&self, document: &Html) -> Vec<String> {
        let mut tags = Vec::new();
        let metric_selector = Selector::parse("div.metric").unwrap();
        
        for metric in document.select(&metric_selector) {
            let label_selector = Selector::parse(".metric-label").unwrap();
            let value_selector = Selector::parse(".metric-value").unwrap();
            
            if let (Some(label_elem), Some(value_elem)) = (
                metric.select(&label_selector).next(),
                metric.select(&value_selector).next()
            ) {
                let label = label_elem.text().collect::<String>().trim().to_string();
                let value = value_elem.text().collect::<String>().trim().to_string();
                
                if label.contains("利用情况") && value != "暂无" {
                    tags.push(value.replace(" ", ""));
                }
            }
        }
        
        tags
    }

    /// 解析严重程度
    fn parse_severity(&self, level: &str) -> Severity {
        match level.trim() {
            "严重" | "Critical" => Severity::Critical,
            "高危" | "High" => Severity::High,
            "中危" | "Medium" => Severity::Medium,
            "低危" | "Low" => Severity::Low,
            _ => Severity::Unknown,
        }
    }

    /// 解析日期
    fn parse_date(&self, date_str: &str) -> Option<DateTime<Utc>> {
        let formats = [
            "%Y-%m-%d",
            "%Y/%m/%d",
            "%Y年%m月%d日",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
        ];
        
        for format in &formats {
            if let Ok(naive_date) = NaiveDateTime::parse_from_str(&format!("{} 00:00:00", date_str), &format!("{} %H:%M:%S", format)) {
                return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive_date, Utc));
            }
            if let Ok(naive_date) = NaiveDateTime::parse_from_str(date_str, format) {
                return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive_date, Utc));
            }
        }
        
        None
    }

    /// 判断是否为高价值漏洞
    fn is_high_value_vulnerability(&self, severity: &Severity, cve_id: &Option<String>) -> bool {
        // 只收集高危和严重级别的漏洞
        match severity {
            Severity::High | Severity::Critical => true,
            _ => {
                // 如果有CVE ID，可能也值得关注
                if let Some(cve) = cve_id {
                    !cve.is_empty()
                } else {
                    false
                }
            }
        }
    }

    /// 检测是否遇到反爬虫或访问限制
    fn is_anti_crawling_response(&self, html: &str) -> bool {
        let indicators = [
            "验证码",
            "captcha",
            "blocked",
            "forbidden",
            "访问频率过快",
            "请稍后再试",
        ];
        
        let html_lower = html.to_lowercase();
        indicators.iter().any(|&indicator| html_lower.contains(indicator))
    }
}

#[async_trait::async_trait]
impl VulnerabilityCollector for AliyunAvdCollector {
    fn name(&self) -> &str {
        "阿里云漏洞库"
    }

    fn description(&self) -> &str {
        "阿里云安全漏洞库，专注收集高危和严重等级的安全漏洞信息"
    }

    async fn collect(&self) -> Result<Vec<Vulnerability>> {
        tracing::info!("开始从阿里云漏洞库收集高价值漏洞数据");

        let mut all_vulnerabilities = Vec::new();
        let max_pages = 5; // 增加到5页，获取更多最新漏洞
        let mut consecutive_empty_pages = 0;
        let max_empty_pages = 2; // 连续2页为空则停止

        for page in 1..=max_pages {
            tracing::info!("正在收集第 {} 页漏洞数据", page);
            
            match self.fetch_vulnerability_links(page).await {
                Ok(links) => {
                    if links.is_empty() {
                        consecutive_empty_pages += 1;
                        tracing::warn!("第 {} 页没有漏洞链接", page);
                        
                        if consecutive_empty_pages >= max_empty_pages {
                            tracing::info!("连续{}页为空，停止收集", max_empty_pages);
                            break;
                        }
                        continue;
                    }
                    
                    consecutive_empty_pages = 0; // 重置计数器
                    let mut page_vulns = 0;

                    for (index, link) in links.iter().enumerate() {
                        match self.parse_vulnerability_detail(link).await {
                            Ok(vuln) => {
                                tracing::info!("成功解析漏洞: {} (等级: {:?})", vuln.title, vuln.severity);
                                all_vulnerabilities.push(vuln);
                                page_vulns += 1;
                            }
                            Err(e) => {
                                tracing::debug!("解析漏洞详情失败 {}: {}", link, e);
                                // 不打印详细错误，避免日志噪音
                            }
                        }
                        
                        // 每处理5个漏洞后稍作休息
                        if (index + 1) % 5 == 0 {
                            sleep(Duration::from_millis(2000)).await;
                        }
                    }
                    
                    tracing::info!("第{}页成功收集{}个有效漏洞", page, page_vulns);
                }
                Err(e) => {
                    tracing::error!("获取第 {} 页漏洞链接失败: {}", page, e);
                    consecutive_empty_pages += 1;
                    
                    if consecutive_empty_pages >= max_empty_pages {
                        break;
                    }
                }
            }
            
            // 页面间添加延时，避免请求过于频繁
            if page < max_pages {
                let delay = fastrand::u64(2000..4000);
                sleep(Duration::from_millis(delay)).await;
            }
        }

        tracing::info!("从阿里云漏洞库总共收集到 {} 个高价值漏洞", all_vulnerabilities.len());
        Ok(all_vulnerabilities)
    }
} 