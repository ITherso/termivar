//! # Phase 3: Directory Fuzzing & Discovery
//!
//! Brute-forces common directories and endpoints using wordlist fuzzing
//! with semaphore-based rate limiting to avoid WAF triggers.
//!
//! ## Wordlist
//! - `/admin`, `/api/v*`, `/swagger`, `/graphql`, `/.git`, `/.env`
//! - `/backup`, `/test`, `/config`, `/uploads`, and 40+ more
//!
//! ## Detection
//! - 200 (OK): Valid endpoint
//! - 3xx (Redirect): Follow with caution
//! - 401/403: Protected endpoint (still valuable intel)

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
};
use async_trait::async_trait;
use reqwest::StatusCode;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Directory fuzzer with concurrent requests and rate limiting
#[derive(Debug)]
pub struct DirectoryFuzzer {
    wordlist: Vec<String>,
    concurrency_limit: usize,
}

impl DirectoryFuzzer {
    pub fn new(wordlist: Vec<String>, concurrency_limit: usize) -> Self {
        Self {
            wordlist,
            concurrency_limit,
        }
    }

    /// Default wordlist for common hidden directories and endpoints
    pub fn with_default_wordlist(concurrency_limit: usize) -> Self {
        let wordlist = vec![
            // Admin panels
            "/admin",
            "/admin/",
            "/administrator",
            "/admin/login",
            // API endpoints
            "/api",
            "/api/",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/api/public",
            "/api/private",
            "/api/internal",
            // Version control
            "/.git",
            "/.git/",
            "/.gitconfig",
            "/.github",
            "/.github/workflows",
            "/.svn",
            "/.hg",
            // Configuration files
            "/config",
            "/config/",
            "/configuration",
            "/settings",
            "/.env",
            "/web.config",
            "/app.config",
            "/.htaccess",
            // Common directories
            "/uploads",
            "/upload",
            "/files",
            "/attachments",
            "/backup",
            "/backups",
            "/.backup",
            "/logs",
            "/log",
            "/.logs",
            "/data",
            "/database",
            "/db",
            "/tmp",
            "/temp",
            "/.tmp",
            // Testing/debugging endpoints
            "/test",
            "/tests",
            "/testing",
            "/debug",
            "/debugger",
            "/.debug",
            "/status",
            "/health",
            "/healthcheck",
            // Documentation
            "/docs",
            "/doc",
            "/documentation",
            "/swagger",
            "/swagger-ui",
            "/swagger.json",
            "/graphql",
            "/graphql-ui",
            // Backup extensions
            "/.bak",
            "/.backup",
            "/.old",
            "/.orig",
            // Hidden directories
            "/.well-known",
            "/.well-known/",
            "/.well-known/acme-challenge",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            wordlist,
            concurrency_limit,
        }
    }
}

#[async_trait]
impl ScanPhase for DirectoryFuzzer {
    fn phase_number(&self) -> u8 {
        3
    }

    fn name(&self) -> &'static str {
        "Directory & Endpoint Fuzzer"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 3: Async directory and endpoint brute-force initiated...".to_string());
        let mut findings = Vec::new();

        let base_url = ctx.target.to_string();
        let client = &ctx.client;

        let semaphore = Arc::new(Semaphore::new(self.concurrency_limit));
        let mut tasks = Vec::new();

        for word in &self.wordlist {
            let target_url = if base_url.ends_with('/') && word.starts_with('/') {
                format!("{}{}", base_url.trim_end_matches('/'), word)
            } else if !base_url.ends_with('/') && !word.starts_with('/') {
                format!("{}/{}", base_url, word)
            } else {
                format!("{}{}", base_url, word)
            };

            let sem = Arc::clone(&semaphore);
            let cl = Arc::clone(&client);
            let ctx_clone = ctx.clone();
            let url_clone = target_url.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(_) => return None,
                };

                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    cl.get(&url_clone).send(),
                )
                .await
                {
                    Ok(Ok(res)) => {
                        let status = res.status();

                        if status.is_success() || status.is_redirection() {
                            ctx_clone
                                .discovered_endpoints
                                .insert(url_clone.clone(), Vec::new());
                            ctx_clone.log(format!("Found: {} ({})", url_clone, status));
                            Some((url_clone, status))
                        } else if status == StatusCode::FORBIDDEN
                            || status == StatusCode::UNAUTHORIZED
                        {
                            // Protected endpoint (likely exists)
                            ctx_clone
                                .discovered_endpoints
                                .insert(url_clone.clone(), Vec::new());
                            ctx_clone.log(format!("Protected: {} ({})", url_clone, status));
                            Some((url_clone, status))
                        } else {
                            None
                        }
                    },
                    _ => None,
                }
            }));
        }

        for task in tasks {
            if let Ok(Some((url, status))) = task.await {
                findings.push(ScanFinding {
                    phase: self.phase_number(),
                    module_name: self.name().to_string(),
                    severity: if status.is_success() { "MEDIUM" } else { "LOW" }.to_string(),
                    description: format!("Discovered hidden directory/endpoint via brute-force"),
                    evidence: format!("URL: {} -> HTTP {}", url, status),
                });
            }
        }

        ctx.log(format!(
            "Phase 3: Directory fuzzing completed. Discovered {} endpoints.",
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
        let fuzzer = DirectoryFuzzer::with_default_wordlist(10);
        assert_eq!(fuzzer.phase_number(), 3);
    }

    #[test]
    fn test_phase_name() {
        let fuzzer = DirectoryFuzzer::with_default_wordlist(10);
        assert_eq!(fuzzer.name(), "Directory & Endpoint Fuzzer");
    }

    #[test]
    fn test_default_wordlist_not_empty() {
        let fuzzer = DirectoryFuzzer::with_default_wordlist(10);
        assert!(!fuzzer.wordlist.is_empty());
        assert!(fuzzer.wordlist.len() > 20);
    }

    #[test]
    fn test_custom_wordlist() {
        let custom = vec!["/custom".to_string(), "/test".to_string()];
        let fuzzer = DirectoryFuzzer::new(custom.clone(), 5);
        assert_eq!(fuzzer.wordlist.len(), 2);
        assert_eq!(fuzzer.concurrency_limit, 5);
    }
}
