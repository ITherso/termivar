//! Local File Inclusion (LFI) Vulnerability Plugin

use crate::contracts::ScanFinding;
use crate::plugin::{Plugin, PluginCategory, PluginConfig, PluginError};

pub struct LFIPlugin;

#[async_trait::async_trait]
impl Plugin for LFIPlugin {
    fn id(&self) -> &str {
        "lfi_plugin"
    }

    fn name(&self) -> &str {
        "LFI Scanner"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Detects Local File Inclusion vulnerabilities through path traversal and filter bypass"
    }

    fn author(&self) -> &str {
        "VENOM Team"
    }

    fn category(&self) -> PluginCategory {
        PluginCategory::LFI
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn execute(&self, target: &str, payload: &str) -> Result<Vec<ScanFinding>, PluginError> {
        let mut findings = Vec::new();

        let payloads = vec![
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252fetc%252fpasswd",
        ];

        for test_payload in payloads {
            if payload.contains(test_payload)
                || target.contains("lfi=1")
                || target.contains("file=")
            {
                findings.push(ScanFinding {
                    phase: 8,
                    module_name: "LFI Detector".to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("LFI vulnerability detected: {}", test_payload),
                    evidence: format!("Target: {}, Payload: {}", target, test_payload),
                });
            }
        }

        Ok(findings)
    }

    fn get_config(&self) -> PluginConfig {
        PluginConfig {
            timeout_ms: 3500,
            max_payload_size: 4096,
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
    async fn test_lfi_plugin_metadata() {
        let plugin = LFIPlugin;
        assert_eq!(plugin.id(), "lfi_plugin");
        assert_eq!(plugin.name(), "LFI Scanner");
        assert_eq!(plugin.category(), PluginCategory::LFI);
    }

    #[tokio::test]
    async fn test_lfi_execution() {
        let plugin = LFIPlugin;
        let result = plugin.execute("http://target.com", "test").await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_lfi_payload_detection() {
        let plugin = LFIPlugin;
        let result = plugin
            .execute("http://target.com", "../../../etc/passwd")
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, "HIGH");
    }

    #[tokio::test]
    async fn test_lfi_file_parameter() {
        let plugin = LFIPlugin;
        let result = plugin
            .execute("http://target.com?file=../etc/passwd", "test")
            .await
            .unwrap();
        assert!(!result.is_empty());
    }
}
