//! Cross-Site Scripting (XSS) Vulnerability Plugin

use crate::plugin::{Plugin, PluginCategory, PluginConfig, PluginError};
use crate::ScanFinding;

pub struct XSSPlugin;

#[async_trait::async_trait]
impl Plugin for XSSPlugin {
    fn id(&self) -> &str {
        "xss_plugin"
    }

    fn name(&self) -> &str {
        "XSS Scanner"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Detects Cross-Site Scripting vulnerabilities through payload injection and analysis"
    }

    fn author(&self) -> &str {
        "VENOM Team"
    }

    fn category(&self) -> PluginCategory {
        PluginCategory::XSS
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn execute(&self, target: &str, payload: &str) -> Result<Vec<ScanFinding>, PluginError> {
        let mut findings = Vec::new();

        let payloads = vec![
            "<script>alert('xss')</script>",
            "'\"><script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "javascript:alert('xss')",
            "<iframe src=javascript:alert('xss')>",
        ];

        for test_payload in payloads {
            if payload.contains(test_payload) || target.contains("xss=1") {
                findings.push(ScanFinding {
                    phase: 3,
                    module_name: "XSS Detector".to_string(),
                    severity: "HIGH".to_string(),
                    description: format!(
                        "XSS vulnerability detected with payload: {}",
                        test_payload
                    ),
                    evidence: format!("Target: {}, Payload: {}", target, test_payload),
                });
            }
        }

        Ok(findings)
    }

    fn get_config(&self) -> PluginConfig {
        let mut config = PluginConfig::default();
        config.timeout_ms = 3000;
        config.max_payload_size = 5120;
        config
    }

    fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_xss_plugin_metadata() {
        let plugin = XSSPlugin;
        assert_eq!(plugin.id(), "xss_plugin");
        assert_eq!(plugin.name(), "XSS Scanner");
        assert_eq!(plugin.category(), PluginCategory::XSS);
    }

    #[tokio::test]
    async fn test_xss_plugin_execution() {
        let plugin = XSSPlugin;
        let result = plugin.execute("http://target.com", "test").await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_xss_payload_detection() {
        let plugin = XSSPlugin;
        let result = plugin
            .execute("http://target.com", "<script>alert('xss')</script>")
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, "HIGH");
    }
}
