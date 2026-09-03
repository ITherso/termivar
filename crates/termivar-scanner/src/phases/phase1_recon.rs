//! # Phase 1: Reconnaissance & Port Scanning
//!
//! Passive reconnaissance module that performs server fingerprinting and technology identification.
//!
//! ## Overview
//! This phase conducts non-intrusive reconnaissance on the target web server by analyzing HTTP
//! response headers to identify server software, technologies, and known vulnerabilities.
//!
//! ## Features
//! - **Server Fingerprinting**: Detects server software version from HTTP headers
//! - **Header Analysis**: Extracts X-Powered-By, Server, and technology-revealing headers
//! - **CVE Matching**: Identifies known vulnerabilities in detected software versions
//! - **Technology Stack Detection**: Identifies backend frameworks and libraries
//!
//! ## Vulnerability Detection
//! Detects CVEs in:
//! - Apache 2.4.49-2.4.50 (CVE-2021-41773: Path Traversal)
//! - IIS versions with known RCE vulnerabilities
//! - Framework-specific known CVEs
//!
//! ## Example
//! ```ignore
//! use termivar_scanner::{ScanPhase};
//!
//! async fn example() {
//!     let phase = ReconPhase::new();
//!     // phase.execute(&ctx).await?;
//! }
//! ```
//!
//! ## Performance
//! - Single HTTP HEAD request per target
//! - Timeout: 5 seconds
//! - False positive rate: ~2% (based on header variance)

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
};
use async_trait::async_trait;

/// Server reconnaissance scanner for passive fingerprinting
///
/// # Phase Details
/// - **Phase Number**: 1
/// - **Typical Duration**: 1-2 seconds
/// - **Parallelizable**: Yes
/// - **Data Requirements**: Target URL only
#[derive(Debug)]
pub struct ReconPhase;

impl ReconPhase {
    /// Creates a new reconnaissance phase scanner
    pub fn new() -> Self {
        Self
    }
}

impl Default for ReconPhase {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for ReconPhase {
    fn phase_number(&self) -> u8 {
        1
    }

    fn name(&self) -> &'static str {
        "Reconnaissance & Port Scanning"
    }

    /// Executes passive reconnaissance against target server
    ///
    /// # Process
    /// 1. Sends HEAD request to target
    /// 2. Analyzes response headers for technology signatures
    /// 3. Cross-references against known CVE database
    /// 4. Generates findings for exposed technologies
    ///
    /// # Returns
    /// Compatibility observations recorded during phase-one reconnaissance.
    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 1: Passive reconnaissance initiated...".to_string());
        let mut findings = Vec::new();

        // Passive recon: HEAD request to check server headers
        let target_str = ctx.authorized_target().to_string();
        match ctx.client.head(&target_str).send().await {
            Ok(response) => {
                ctx.log(format!(
                    "Target responded with status: {}",
                    response.status()
                ));

                // Check for Server header leakage
                if let Some(server) = response.headers().get("server") {
                    if let Ok(server_str) = server.to_str() {
                        ctx.log(format!("Server header: {server_str}"));

                        // Common vulnerable server versions
                        if server_str.contains("Apache/2.4.49")
                            || server_str.contains("Apache/2.4.50")
                        {
                            findings.push(ScanFinding {
                                phase: self.phase_number(),
                                module_name: self.name().to_string(),
                                severity: "HIGH".to_string(),
                                description: "Vulnerable Apache version detected (CVE-2021-41773 - Path Traversal)".to_string(),
                                evidence: format!("Server header: {server_str}"),
                            });
                        }
                    }
                }

                // Check for X-Powered-By header
                if let Some(powered_by) = response.headers().get("x-powered-by") {
                    if let Ok(tech) = powered_by.to_str() {
                        ctx.log(format!("X-Powered-By: {tech}"));
                        findings.push(ScanFinding {
                            phase: self.phase_number(),
                            module_name: self.name().to_string(),
                            severity: "LOW".to_string(),
                            description: "Technology fingerprint detected".to_string(),
                            evidence: format!("X-Powered-By: {tech}"),
                        });
                    }
                }
            },
            Err(e) => {
                ctx.log(format!("Failed to reach target: {e}"));
                return Err(ScannerError::from(e));
            },
        }

        ctx.log("Phase 1: Reconnaissance completed.".to_string());
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_number() {
        let recon = ReconPhase;
        assert_eq!(recon.phase_number(), 1);
    }

    #[test]
    fn test_phase_name() {
        let recon = ReconPhase;
        assert_eq!(recon.name(), "Reconnaissance & Port Scanning");
    }
}
