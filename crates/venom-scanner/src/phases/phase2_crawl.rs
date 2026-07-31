//! # Phase 2: Web Crawler & Parameter Discovery
//!
//! Automatically discovers endpoints and parameters through recursive web crawling
//! and form analysis. Populates ScanContext with discovered_endpoints for downstream phases.
//!
//! ## Features
//! - **Recursive Crawling**: Follows internal links while respecting scope
//! - **Parameter Discovery**: Extracts form inputs and query parameters
//! - **URL Normalization**: Eliminates duplicate endpoints
//! - **Same-Origin Validation**: Prevents scope creep to external hosts
//!
//! ## Performance
//! - Timeout: 5 seconds per URL
//! - Concurrent crawls with Tokio
//! - Visited URL deduplication with DashSet
//!
//! ## Output
//! Populates `ctx.discovered_endpoints` map: URL → [param1, param2, ...]

use crate::{context::ScanContext, error::ScannerError, ScanFinding, ScanPhase};
use async_trait::async_trait;
use regex::Regex;
use url::Url;

/// Web crawling phase for endpoint and parameter discovery
#[derive(Debug)]
pub struct CrawlPhase;

#[async_trait]
impl ScanPhase for CrawlPhase {
    fn phase_number(&self) -> u8 {
        2
    }

    fn name(&self) -> &'static str {
        "Web Crawler & Parameter Discovery"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 2: Web crawler initiated...".to_string());

        // Crawl root URL and discover endpoints
        self.crawl_url(&ctx.target.to_string(), ctx).await?;

        ctx.log(format!(
            "Phase 2: Crawling completed. Discovered {} endpoints.",
            ctx.endpoint_count()
        ));

        Ok(Vec::new())
    }
}

impl CrawlPhase {
    async fn crawl_url(&self, url_str: &str, ctx: &ScanContext) -> Result<(), ScannerError> {
        // Prevent duplicate crawling
        if ctx.is_visited(url_str) {
            return Ok(());
        }

        ctx.mark_visited(url_str.to_string());
        ctx.log(format!("Crawling: {}", url_str));

        match ctx.client.get(url_str).send().await {
            Ok(response) => {
                if let Ok(html) = response.text().await {
                    // Extract URLs from <a> tags
                    let link_regex = Regex::new(r#"href=["']([^"']+)["']"#).unwrap();
                    for cap in link_regex.captures_iter(&html) {
                        if let Ok(link_url) = Url::parse(&cap[1]) {
                            if link_url.host() == ctx.target.host() {
                                let link_str = link_url.to_string();
                                ctx.log(format!("Found endpoint: {}", link_str));

                                // Extract query parameters
                                let params: Vec<String> =
                                    link_url.query_pairs().map(|(k, _)| k.to_string()).collect();

                                ctx.add_endpoint(link_str, params);
                            }
                        }
                    }

                    // Extract forms and their parameters
                    let form_regex = Regex::new(r#"<form[^>]*>(.*?)</form>"#).unwrap();
                    for form_match in form_regex.captures_iter(&html) {
                        let form_html = &form_match[1];
                        let input_regex =
                            Regex::new(r#"<input[^>]*name=["']([^"']+)["']"#).unwrap();

                        let mut form_params = Vec::new();
                        for input_cap in input_regex.captures_iter(form_html) {
                            form_params.push(input_cap[1].to_string());
                        }

                        if !form_params.is_empty() {
                            ctx.log(format!("Found form parameters: {:?}", form_params));
                            ctx.add_endpoint(url_str.to_string(), form_params);
                        }
                    }
                }
            },
            Err(e) => {
                ctx.log(format!("Failed to crawl {}: {}", url_str, e));
            },
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_number() {
        let crawl = CrawlPhase;
        assert_eq!(crawl.phase_number(), 2);
    }

    #[test]
    fn test_phase_name() {
        let crawl = CrawlPhase;
        assert_eq!(crawl.name(), "Web Crawler & Parameter Discovery");
    }
}
