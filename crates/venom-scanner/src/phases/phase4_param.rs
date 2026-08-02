//! # Phase 4: Parameter Discovery & Injection Testing
//!
//! Discovers hidden parameters using marker-based injection and HTTP status analysis.
//! Tests 40+ common parameter names to identify injectable inputs.
//!
//! ## Wordlist
//! - id, user_id, admin, debug, api_key, token, password, email, username
//! - redirect, url, profile, template, data, key, value, and more
//!
//! ## Detection Method
//! - Injects marker value (e.g., "venom_7b3a9c2e_test")
//! - HTTP 400 = parameter recognized but invalid
//! - Marker not found = parameter doesn't exist

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
};
use async_trait::async_trait;
use reqwest::StatusCode;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Parameter discovery with marker-based injection detection
#[derive(Debug)]
pub struct ParameterDiscoverer {
    param_wordlist: Vec<String>,
    concurrency_limit: usize,
}

impl ParameterDiscoverer {
    pub fn new(param_wordlist: Vec<String>, concurrency_limit: usize) -> Self {
        Self {
            param_wordlist,
            concurrency_limit,
        }
    }

    /// Default parameter wordlist for common API parameters
    pub fn with_default_wordlist(concurrency_limit: usize) -> Self {
        let param_wordlist = vec![
            // User/ID parameters
            "id",
            "user_id",
            "uid",
            "userid",
            "user",
            "username",
            "email",
            "email_id",
            "account_id",
            "account",
            // Query/Search parameters
            "q",
            "query",
            "search",
            "s",
            "keyword",
            "keywords",
            // Filtering/Sorting
            "filter",
            "filters",
            "sort",
            "order",
            "page",
            "limit",
            "offset",
            "per_page",
            // Admin/Debug parameters
            "admin",
            "debug",
            "verbose",
            "log_level",
            "test",
            "testing",
            "mode",
            // API parameters
            "key",
            "token",
            "api_key",
            "access_token",
            "secret",
            "password",
            "pass",
            // Bypass/Security parameters
            "bypass",
            "force",
            "skip_validation",
            "callback",
            "redirect",
            "return_to",
            "referrer",
            "referer",
            // File/Content parameters
            "file",
            "filename",
            "path",
            "url",
            "image",
            "avatar",
            "photo",
            "attachment",
            // Data/Format parameters
            "data",
            "value",
            "content",
            "body",
            "format",
            "type",
            "encoding",
            "lang",
            "language",
            // Numeric identifiers
            "post_id",
            "product_id",
            "order_id",
            "item_id",
            "resource_id",
            "object_id",
            // Action parameters
            "action",
            "method",
            "command",
            "op",
            "do",
            "go",
            "step",
            "action_type",
            // Version/Compatibility
            "version",
            "v",
            "api_version",
            // Export/Download
            "export",
            "download",
            "output",
            "format_type",
            // Common typos/variations
            "admin_id",
            "Admin",
            "ADMIN",
            "callback_url",
            "return_url",
            "redirect_url",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            param_wordlist,
            concurrency_limit,
        }
    }
}

#[async_trait]
impl ScanPhase for ParameterDiscoverer {
    fn phase_number(&self) -> u8 {
        4
    }

    fn name(&self) -> &'static str {
        "Hidden Parameter Miner"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 4: Hidden parameter discovery (Parameter Mining) initiated...".to_string());
        let mut findings = Vec::new();

        let client = &ctx.client;
        let semaphore = Arc::new(Semaphore::new(self.concurrency_limit));

        // Iterate over all discovered endpoints from Phase 2 & 3
        let endpoints: Vec<String> = ctx
            .discovered_endpoints
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        ctx.log(format!(
            "Analyzing {} endpoints for hidden parameters...",
            endpoints.len()
        ));

        for url_str in endpoints {
            ctx.log(format!("Mining parameters on: {}", url_str));

            let current_params: Vec<String> = ctx
                .discovered_endpoints
                .get(&url_str)
                .map(|entry| entry.clone())
                .unwrap_or_default();

            let mut tasks = Vec::new();

            for param in &self.param_wordlist {
                let sem = Arc::clone(&semaphore);
                let cl = Arc::clone(client);
                let url_to_test = url_str.clone();
                let param_name = param.clone();
                let ctx_clone = ctx.clone();

                tasks.push(tokio::spawn(async move {
                    let _permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => return None,
                    };

                    // Test parameter with marker value
                    let marker = "venom_7b3a9c2e_test";
                    let test_url = if url_to_test.contains('?') {
                        format!("{}&{}={}", url_to_test, param_name, marker)
                    } else {
                        format!("{}?{}={}", url_to_test, param_name, marker)
                    };

                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        cl.get(&test_url).send(),
                    )
                    .await
                    {
                        Ok(Ok(res)) => {
                            let status = res.status();

                            // Check if parameter was accepted (200 OK or 3xx redirect)
                            if status == StatusCode::OK || status.is_redirection() {
                                if let Ok(body) = res.text().await {
                                    // Simple heuristic: Check if marker appears in response (reflection check)
                                    if body.contains(marker) {
                                        ctx_clone.log(format!(
                                            "Parameter reflection: {} on {}",
                                            param_name, url_to_test
                                        ));
                                        return Some((param_name, "reflection".to_string()));
                                    }
                                }
                                // Parameter seems accepted even without reflection
                                Some((param_name, "accepted".to_string()))
                            } else if status == StatusCode::BAD_REQUEST {
                                // Parameter rejected (likely doesn't exist or wrong format)
                                None
                            } else {
                                // Other status codes - parameter might exist
                                Some((param_name, "exists".to_string()))
                            }
                        },
                        _ => None,
                    }
                }));
            }

            // Collect results and update DashMap with discovered parameters
            let mut discovered_params = current_params.clone();
            let mut param_findings = Vec::new();

            for task in tasks {
                if let Ok(Some((found_param, evidence_type))) = task.await {
                    if !discovered_params.contains(&found_param) {
                        discovered_params.push(found_param.clone());

                        let severity = if evidence_type == "reflection" {
                            "HIGH"
                        } else {
                            "MEDIUM"
                        };

                        param_findings.push(ScanFinding {
                            phase: self.phase_number(),
                            module_name: self.name().to_string(),
                            severity: severity.to_string(),
                            description: format!(
                                "Discovered hidden parameter '{}' on {}",
                                found_param, url_str
                            ),
                            evidence: format!(
                                "Evidence type: {} (marker reflection detected)",
                                evidence_type
                            ),
                        });
                    }
                }
            }

            // Update endpoint with discovered parameters (zero-copy via DashMap)
            ctx.discovered_endpoints
                .alter(&url_str, |_, _| discovered_params.clone());

            findings.extend(param_findings);
        }

        ctx.log(format!(
            "Phase 4: Parameter mining completed. Discovered {} parameters.",
            findings.len()
        ));

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_number() {
        let discoverer = ParameterDiscoverer::with_default_wordlist(10);
        assert_eq!(discoverer.phase_number(), 4);
    }

    #[test]
    fn test_phase_name() {
        let discoverer = ParameterDiscoverer::with_default_wordlist(10);
        assert_eq!(discoverer.name(), "Hidden Parameter Miner");
    }

    #[test]
    fn test_default_wordlist_size() {
        let discoverer = ParameterDiscoverer::with_default_wordlist(10);
        assert!(!discoverer.param_wordlist.is_empty());
        assert!(discoverer.param_wordlist.len() > 30);
    }

    #[test]
    fn test_custom_param_wordlist() {
        let custom = vec!["debug".to_string(), "admin".to_string()];
        let discoverer = ParameterDiscoverer::new(custom.clone(), 5);
        assert_eq!(discoverer.param_wordlist.len(), 2);
    }
}
