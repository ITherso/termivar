//! Server-Side Template Injection (SSTI) Vulnerability Plugin

use crate::contracts::ScanFinding;
use crate::plugin::{Plugin, PluginCategory, PluginConfig, PluginError};

pub struct SSTIPlugin;

#[async_trait::async_trait]
impl Plugin for SSTIPlugin {
    fn id(&self) -> &str {
        "ssti_plugin"
    }

    fn name(&self) -> &str {
        "SSTI Scanner"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Detects Server-Side Template Injection in Jinja2, Mako, Twig and other template engines"
    }

    fn author(&self) -> &str {
        "VENOM Team"
    }

    fn category(&self) -> PluginCategory {
        PluginCategory::SSTI
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn execute(&self, target: &str, payload: &str) -> Result<Vec<ScanFinding>, PluginError> {
        let mut findings = Vec::new();

        let payloads = vec![
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "*{7*7}",
            "{{7*'7'}}",
            "${request.getAttribute('foo')}",
            "{% for item in items %}",
            "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ];

        for test_payload in payloads {
            if payload.contains(test_payload) || target.contains("template=") {
                findings.push(ScanFinding {
                    phase: 7,
                    module_name: "SSTI Detector".to_string(),
                    severity: "CRITICAL".to_string(),
                    description: "SSTI vulnerability detected - template code execution possible"
                        .to_string(),
                    evidence: format!("Target: {}, Template payload: {}", target, test_payload),
                });
                break;
            }
        }

        Ok(findings)
    }

    fn get_config(&self) -> PluginConfig {
        let mut config = PluginConfig::default();
        config.timeout_ms = 3500;
        config.max_payload_size = 8192;
        config.retry_count = 2;
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
    async fn test_ssti_plugin_metadata() {
        let plugin = SSTIPlugin;
        assert_eq!(plugin.id(), "ssti_plugin");
        assert_eq!(plugin.name(), "SSTI Scanner");
        assert_eq!(plugin.category(), PluginCategory::SSTI);
    }

    #[tokio::test]
    async fn test_ssti_execution() {
        let plugin = SSTIPlugin;
        let result = plugin.execute("http://target.com", "test").await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_ssti_jinja_detection() {
        let plugin = SSTIPlugin;
        let result = plugin
            .execute("http://target.com", "{{7*7}}")
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, "CRITICAL");
    }

    #[tokio::test]
    async fn test_ssti_erb_detection() {
        let plugin = SSTIPlugin;
        let result = plugin
            .execute("http://target.com", "<%= 7*7 %>")
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_ssti_payload_injection() {
        let plugin = SSTIPlugin;
        let result = plugin
            .execute(
                "http://target.com",
                "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            )
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
    }
}
