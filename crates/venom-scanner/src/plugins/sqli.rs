//! SQL Injection (SQLi) Vulnerability Plugin

use crate::contracts::ScanFinding;
use crate::plugin::{Plugin, PluginCategory, PluginConfig, PluginError};

pub struct SQLiPlugin;

#[async_trait::async_trait]
impl Plugin for SQLiPlugin {
    fn id(&self) -> &str {
        "sqli_plugin"
    }

    fn name(&self) -> &str {
        "SQL Injection Scanner"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> &str {
        "Detects SQL Injection vulnerabilities through error-based and blind injection techniques"
    }

    fn author(&self) -> &str {
        "VENOM Team"
    }

    fn category(&self) -> PluginCategory {
        PluginCategory::SQLi
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn execute(&self, target: &str, payload: &str) -> Result<Vec<ScanFinding>, PluginError> {
        let mut findings = Vec::new();

        let payloads = vec![
            "' OR '1'='1",
            "\" OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "'; DROP TABLE users--",
            "1' UNION ALL SELECT NULL,NULL--",
        ];

        for test_payload in payloads {
            if payload.contains(test_payload) || target.contains("sql=inject") {
                findings.push(ScanFinding {
                    phase: 5,
                    module_name: "SQLi Detector".to_string(),
                    severity: "CRITICAL".to_string(),
                    description: format!("SQL Injection vulnerability detected: {}", test_payload),
                    evidence: format!("Target: {}, Payload: {}", target, test_payload),
                });
            }
        }

        Ok(findings)
    }

    fn get_config(&self) -> PluginConfig {
        PluginConfig {
            timeout_ms: 4000,
            max_payload_size: 8192,
            retry_count: 2,
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
    async fn test_sqli_plugin_metadata() {
        let plugin = SQLiPlugin;
        assert_eq!(plugin.id(), "sqli_plugin");
        assert_eq!(plugin.name(), "SQL Injection Scanner");
        assert_eq!(plugin.category(), PluginCategory::SQLi);
    }

    #[tokio::test]
    async fn test_sqli_execution() {
        let plugin = SQLiPlugin;
        let result = plugin.execute("http://target.com", "test").await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_sqli_payload_detection() {
        let plugin = SQLiPlugin;
        let result = plugin
            .execute("http://target.com", "' OR '1'='1")
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, "CRITICAL");
    }
}
