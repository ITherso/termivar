//! WAF (Web Application Firewall) Detection and Evasion
//!
//! Detects WAF presence, fingerprints specific WAF products, and implements
//! adaptive evasion techniques based on response patterns.

use std::collections::HashMap;

/// WAF fingerprint signatures
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WafProduct {
    ModSecurity,
    CloudFlare,
    AWSWaf,
    F5,
    Imperva,
    Akamai,
    Barracuda,
    Fortinet,
    PaloAlto,
    Checkmarx,
    Unknown,
}

impl WafProduct {
    /// Returns WAF product name
    pub fn name(&self) -> &str {
        match self {
            WafProduct::ModSecurity => "ModSecurity",
            WafProduct::CloudFlare => "Cloudflare",
            WafProduct::AWSWaf => "AWS WAF",
            WafProduct::F5 => "F5 ASM",
            WafProduct::Imperva => "Imperva",
            WafProduct::Akamai => "Akamai",
            WafProduct::Barracuda => "Barracuda",
            WafProduct::Fortinet => "Fortinet FortiWeb",
            WafProduct::PaloAlto => "Palo Alto Networks",
            WafProduct::Checkmarx => "Checkmarx",
            WafProduct::Unknown => "Unknown",
        }
    }
}

/// WAF detection engine
#[derive(Debug)]
pub struct WafDetector {
    signatures: HashMap<&'static str, WafProduct>,
}

impl WafDetector {
    /// Creates a new WAF detector
    pub fn new() -> Self {
        let mut signatures = HashMap::new();

        // Header-based signatures
        signatures.insert("Server: cloudflare", WafProduct::CloudFlare);
        signatures.insert("CF-RAY", WafProduct::CloudFlare);
        signatures.insert("Server: AmazonS3", WafProduct::AWSWaf);
        signatures.insert("X-Amzn-RequestId", WafProduct::AWSWaf);
        signatures.insert("Server: F5", WafProduct::F5);
        signatures.insert("X-Imperva-Ray-ID", WafProduct::Imperva);
        signatures.insert("Server: Barracuda", WafProduct::Barracuda);
        signatures.insert("X-Barracuda-Vs-Id", WafProduct::Barracuda);
        signatures.insert("Server: Akamai", WafProduct::Akamai);

        Self { signatures }
    }

    /// Detects WAF from response headers
    pub fn detect_from_headers(&self, headers: &[(&str, &str)]) -> Option<WafProduct> {
        for (header_name, header_value) in headers {
            let combined = format!("{}: {}", header_name, header_value);
            if let Some(waf) = self.signatures.get(combined.as_str()) {
                return Some(waf.clone());
            }
        }
        None
    }

    /// Detects WAF from response status patterns
    pub fn detect_from_status(&self, status: u16) -> Option<&'static str> {
        match status {
            403 => Some("Possible WAF blocking (403 Forbidden)"),
            406 => Some("Possible WAF blocking (406 Not Acceptable)"),
            418 => Some("Possible WAF blocking (418 I'm a teapot)"),
            429 => Some("Rate limited by WAF (429 Too Many Requests)"),
            _ => None,
        }
    }

    /// Checks for WAF patterns in response body
    pub fn detect_from_body(&self, body: &str) -> Option<WafProduct> {
        if body.contains("ModSecurity") {
            return Some(WafProduct::ModSecurity);
        }
        if body.contains("Cloudflare") || body.contains("error code:") {
            return Some(WafProduct::CloudFlare);
        }
        if body.contains("Imperva") || body.contains("Request blocked by security policy") {
            return Some(WafProduct::Imperva);
        }
        if body.contains("Barracuda") {
            return Some(WafProduct::Barracuda);
        }
        None
    }
}

impl Default for WafDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Evasion technique for bypassing WAF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvisionTechnique {
    /// Case variation: `SELECT` → `sElEcT`
    CaseVariation,
    /// Comment injection: `sel/**/ect`
    CommentInjection,
    /// Whitespace variation: `sel	ect`
    WhespaceVariation,
    /// Encoding: URL, Unicode, Hex encoding
    Encoding,
    /// Parameter pollution: duplicate parameters
    ParameterPollution,
    /// HTTP splitting: CRLF injection
    HttpSplitting,
}

/// Payload encoder for WAF evasion
pub struct PayloadEncoder;

impl PayloadEncoder {
    /// Encodes payload with case variation
    pub fn case_variation(payload: &str) -> String {
        payload
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().to_string()
                } else {
                    c.to_string()
                }
            })
            .collect()
    }

    /// Injects comments into SQL payload
    pub fn comment_injection_sql(payload: &str) -> String {
        payload
            .replace("select", "sel/**/ect")
            .replace("SELECT", "SEL/**/ECT")
            .replace("union", "un/**/ion")
            .replace("UNION", "UN/**/ION")
    }

    /// URL encodes payload
    pub fn url_encode(payload: &str) -> String {
        payload
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                    c.to_string()
                } else {
                    format!("%{:02X}", c as u8)
                }
            })
            .collect()
    }

    /// Double URL encodes payload
    pub fn double_url_encode(payload: &str) -> String {
        let first_pass = Self::url_encode(payload);
        Self::url_encode(&first_pass)
    }

    /// Hex encodes payload
    pub fn hex_encode(payload: &str) -> String {
        payload
            .bytes()
            .map(|b| format!("%{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    }

    /// Applies multiple evasion techniques
    pub fn apply_evasion(payload: &str, techniques: &[EvisionTechnique]) -> Vec<String> {
        techniques
            .iter()
            .map(|tech| match tech {
                EvisionTechnique::CaseVariation => Self::case_variation(payload),
                EvisionTechnique::CommentInjection => Self::comment_injection_sql(payload),
                EvisionTechnique::WhespaceVariation => payload.replace(' ', "\t"),
                EvisionTechnique::Encoding => Self::url_encode(payload),
                EvisionTechnique::ParameterPollution => format!("{}&id={}", payload, payload),
                EvisionTechnique::HttpSplitting => payload.replace('\n', "%0A"),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waf_product_names() {
        assert_eq!(WafProduct::CloudFlare.name(), "Cloudflare");
        assert_eq!(WafProduct::ModSecurity.name(), "ModSecurity");
        assert_eq!(WafProduct::AWSWaf.name(), "AWS WAF");
    }

    #[test]
    fn test_waf_detector_creation() {
        let detector = WafDetector::new();
        assert!(!detector.signatures.is_empty());
    }

    #[test]
    fn test_case_variation() {
        let original = "select";
        let varied = PayloadEncoder::case_variation(original);
        assert_ne!(original, varied);
        assert!(varied.to_lowercase().contains("select"));
    }

    #[test]
    fn test_comment_injection() {
        let original = "select * from users";
        let injected = PayloadEncoder::comment_injection_sql(original);
        assert!(injected.contains("/**/"));
    }

    #[test]
    fn test_url_encoding() {
        let payload = "' OR '1'='1";
        let encoded = PayloadEncoder::url_encode(payload);
        assert!(encoded.contains("%"));
        assert!(!encoded.contains("'"));
    }

    #[test]
    fn test_double_url_encoding() {
        let payload = "test";
        let double = PayloadEncoder::double_url_encode(payload);
        let single = PayloadEncoder::url_encode(payload);
        assert_eq!(double.len(), single.len()); // Same for alphanumeric
    }

    #[test]
    fn test_evasion_techniques() {
        let payload = "select";
        let techniques = vec![EvisionTechnique::CaseVariation, EvisionTechnique::Encoding];
        let variations = PayloadEncoder::apply_evasion(payload, &techniques);
        assert_eq!(variations.len(), 2);
        // One variation should be different from original (case variation)
        assert!(variations.iter().any(|v| v != "select"));
    }
}
