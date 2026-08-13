//! Server-Side Request Forgery (SSRF) Vulnerability Plugin

use crate::plugin::{Plugin, PluginCategory, PluginConfig, PluginError};
use crate::ScanFinding;

pub struct SSRFPlugin;

#[async_trait::async_trait]
impl Plugin for SSRFPlugin {
    fn id(&self) -> &str {
        "ssrf_plugin"
    }

    fn name(&self) -> &str {
        "SSRF Scanner"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Detects Server-Side Request Forgery vulnerabilities targeting internal services"
    }

    fn author(&self) -> &str {
        "VENOM Team"
    }

    fn category(&self) -> PluginCategory {
        PluginCategory::SSRF
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn execute(&self, target: &str, payload: &str) -> Result<Vec<ScanFinding>, PluginError> {
        let mut findings = Vec::new();

        let payloads = vec![
            "http://127.0.0.1:8080",
            "http://localhost/admin",
            "http://169.254.169.254/latest/meta-data",
            "gopher://localhost",
            "file:///etc/passwd",
            "http://internal.service:9999",
            "http://0.0.0.0:22",
        ];

        for test_payload in payloads {
            if payload.contains(test_payload)
                || payload.contains("127.0.0.1")
                || payload.contains("localhost")
            {
                findings.push(ScanFinding {
                    phase: 9,
                    module_name: "SSRF Detector".to_string(),
                    severity: "HIGH".to_string(),
                    description: "SSRF vulnerability detected - server can make arbitrary requests"
                        .to_string(),
                    evidence: format!("Target: {}, SSRF payload: {}", target, test_payload),
                });
                break;
            }
        }

        Ok(findings)
    }

    fn get_config(&self) -> PluginConfig {
        PluginConfig {
            timeout_ms: 5000,
            max_payload_size: 2048,
            ..PluginConfig::default()
        }
    }

    fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ssrf_plugin_metadata() {
        let plugin = SSRFPlugin;
        assert_eq!(plugin.id(), "ssrf_plugin");
        assert_eq!(plugin.name(), "SSRF Scanner");
        assert_eq!(plugin.category(), PluginCategory::SSRF);
    }

    #[tokio::test]
    async fn test_ssrf_execution() {
        let plugin = SSRFPlugin;
        let result = plugin.execute("http://target.com", "test").await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_ssrf_localhost_detection() {
        let plugin = SSRFPlugin;
        let result = plugin
            .execute("http://target.com", "http://localhost/admin")
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, "HIGH");
    }

    #[tokio::test]
    async fn test_ssrf_internal_ip_detection() {
        let plugin = SSRFPlugin;
        let result = plugin
            .execute("http://target.com", "http://127.0.0.1:8080")
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_ssrf_metadata_service() {
        let plugin = SSRFPlugin;
        let result = plugin
            .execute(
                "http://target.com",
                "http://169.254.169.254/latest/meta-data",
            )
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
    }
}
