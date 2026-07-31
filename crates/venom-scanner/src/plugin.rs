//! Plugin System for Extensibility
//!
//! Comprehensive modular plugin architecture for vulnerability scanning.

use crate::contracts::ScanFinding;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

/// Plugin trait for custom vulnerability scanners
#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    /// Plugin identifier
    fn id(&self) -> &str;

    /// Plugin name
    fn name(&self) -> &str;

    /// Plugin version
    fn version(&self) -> &str;

    /// Plugin description
    fn description(&self) -> &str;

    /// Plugin author
    fn author(&self) -> &str;

    /// Plugin category (XSS, SQLi, LFI, etc.)
    fn category(&self) -> PluginCategory;

    /// Whether plugin is enabled
    fn enabled(&self) -> bool;

    /// Execute plugin logic
    async fn execute(&self, target: &str, payload: &str) -> Result<Vec<ScanFinding>, PluginError>;

    /// Get plugin configuration
    fn get_config(&self) -> PluginConfig {
        PluginConfig::default()
    }

    /// Validate plugin prerequisites
    fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Plugin vulnerability categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PluginCategory {
    #[serde(rename = "xss")]
    XSS,
    #[serde(rename = "sqli")]
    SQLi,
    #[serde(rename = "lfi")]
    LFI,
    #[serde(rename = "xxe")]
    XXE,
    #[serde(rename = "ssrf")]
    SSRF,
    #[serde(rename = "ssti")]
    SSTI,
    #[serde(rename = "rce")]
    RCE,
    #[serde(rename = "custom")]
    Custom,
}

impl PluginCategory {
    pub fn as_str(&self) -> &str {
        match self {
            PluginCategory::XSS => "xss",
            PluginCategory::SQLi => "sqli",
            PluginCategory::LFI => "lfi",
            PluginCategory::XXE => "xxe",
            PluginCategory::SSRF => "ssrf",
            PluginCategory::SSTI => "ssti",
            PluginCategory::RCE => "rce",
            PluginCategory::Custom => "custom",
        }
    }
}

/// Plugin errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginError {
    #[serde(rename = "execution_failed")]
    ExecutionFailed(String),
    #[serde(rename = "not_found")]
    NotFound(String),
    #[serde(rename = "invalid_config")]
    InvalidConfig(String),
    #[serde(rename = "timeout")]
    Timeout,
    #[serde(rename = "disabled")]
    Disabled,
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PluginError::ExecutionFailed(e) => write!(f, "Execution failed: {}", e),
            PluginError::NotFound(e) => write!(f, "Plugin not found: {}", e),
            PluginError::InvalidConfig(e) => write!(f, "Invalid config: {}", e),
            PluginError::Timeout => write!(f, "Plugin execution timeout"),
            PluginError::Disabled => write!(f, "Plugin is disabled"),
        }
    }
}

impl std::error::Error for PluginError {}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub timeout_ms: u64,
    pub max_payload_size: usize,
    pub retry_count: u32,
    pub enabled: bool,
    pub custom_options: std::collections::HashMap<String, String>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            max_payload_size: 10240,
            retry_count: 3,
            enabled: true,
            custom_options: std::collections::HashMap::new(),
        }
    }
}

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub category: String,
    pub enabled: bool,
    pub loaded_at: u64,
    pub execution_count: u64,
    pub success_count: u64,
    pub error_count: u64,
}

/// Plugin execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExecutionResult {
    pub plugin_id: String,
    pub success: bool,
    pub findings: Vec<ScanFinding>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
}

/// Plugin registry for managing plugins
pub struct PluginRegistry {
    plugins: Arc<DashMap<String, Arc<dyn Plugin>>>,
    metadata: Arc<DashMap<String, PluginMetadata>>,
    config: Arc<DashMap<String, PluginConfig>>,
}

impl PluginRegistry {
    /// Creates new registry
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(DashMap::new()),
            metadata: Arc::new(DashMap::new()),
            config: Arc::new(DashMap::new()),
        }
    }

    /// Registers plugin
    pub fn register(&self, plugin: Arc<dyn Plugin>) -> Result<(), PluginError> {
        plugin
            .validate()
            .map_err(|e| PluginError::InvalidConfig(e))?;

        let config = plugin.get_config();
        let metadata = PluginMetadata {
            id: plugin.id().to_string(),
            name: plugin.name().to_string(),
            version: plugin.version().to_string(),
            description: plugin.description().to_string(),
            author: plugin.author().to_string(),
            category: plugin.category().as_str().to_string(),
            enabled: plugin.enabled(),
            loaded_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            execution_count: 0,
            success_count: 0,
            error_count: 0,
        };

        self.plugins.insert(plugin.id().to_string(), plugin.clone());
        self.metadata.insert(plugin.id().to_string(), metadata);
        self.config.insert(plugin.id().to_string(), config);

        Ok(())
    }

    /// Unregisters plugin
    pub fn unregister(&self, plugin_id: &str) -> Result<(), PluginError> {
        self.plugins
            .remove(plugin_id)
            .ok_or_else(|| PluginError::NotFound(plugin_id.to_string()))?;
        self.metadata.remove(plugin_id);
        self.config.remove(plugin_id);
        Ok(())
    }

    /// Gets plugin by ID
    pub fn get(&self, plugin_id: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.get(plugin_id).map(|p| p.value().clone())
    }

    /// Gets plugin metadata
    pub fn get_metadata(&self, plugin_id: &str) -> Option<PluginMetadata> {
        self.metadata.get(plugin_id).map(|m| m.value().clone())
    }

    /// Executes plugin
    pub async fn execute(
        &self,
        plugin_id: &str,
        target: &str,
        payload: &str,
    ) -> Result<PluginExecutionResult, PluginError> {
        let plugin = self
            .get(plugin_id)
            .ok_or_else(|| PluginError::NotFound(plugin_id.to_string()))?;

        if !plugin.enabled() {
            return Err(PluginError::Disabled);
        }

        let start = Instant::now();

        match plugin.execute(target, payload).await {
            Ok(findings) => {
                let elapsed = start.elapsed().as_millis() as u64;
                self.update_metadata(plugin_id, true);

                Ok(PluginExecutionResult {
                    plugin_id: plugin_id.to_string(),
                    success: true,
                    findings,
                    error: None,
                    execution_time_ms: elapsed,
                })
            },
            Err(e) => {
                self.update_metadata(plugin_id, false);
                Ok(PluginExecutionResult {
                    plugin_id: plugin_id.to_string(),
                    success: false,
                    findings: vec![],
                    error: Some(e.to_string()),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                })
            },
        }
    }

    /// Lists all plugins
    pub fn list_all(&self) -> Vec<PluginMetadata> {
        self.metadata
            .iter()
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    /// Lists plugins by category
    pub fn list_by_category(&self, category: PluginCategory) -> Vec<PluginMetadata> {
        self.metadata
            .iter()
            .filter(|ref_multi| ref_multi.value().category == category.as_str())
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    /// Gets plugin count
    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    /// Updates plugin configuration
    pub fn update_config(&self, plugin_id: &str, config: PluginConfig) -> Result<(), PluginError> {
        if !self.plugins.contains_key(plugin_id) {
            return Err(PluginError::NotFound(plugin_id.to_string()));
        }
        self.config.insert(plugin_id.to_string(), config);
        Ok(())
    }

    /// Gets plugin configuration
    pub fn get_config(&self, plugin_id: &str) -> Option<PluginConfig> {
        self.config.get(plugin_id).map(|c| c.value().clone())
    }

    fn update_metadata(&self, plugin_id: &str, success: bool) {
        if let Some(mut meta) = self.metadata.get_mut(plugin_id) {
            meta.execution_count += 1;
            if success {
                meta.success_count += 1;
            } else {
                meta.error_count += 1;
            }
        }
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPlugin {
        id: String,
        category: PluginCategory,
    }

    #[async_trait::async_trait]
    impl Plugin for TestPlugin {
        fn id(&self) -> &str {
            &self.id
        }

        fn name(&self) -> &str {
            "Test Plugin"
        }

        fn version(&self) -> &str {
            "1.0.0"
        }

        fn description(&self) -> &str {
            "Test plugin"
        }

        fn author(&self) -> &str {
            "Test Author"
        }

        fn category(&self) -> PluginCategory {
            self.category
        }

        fn enabled(&self) -> bool {
            true
        }

        async fn execute(
            &self,
            _target: &str,
            _payload: &str,
        ) -> Result<Vec<ScanFinding>, PluginError> {
            Ok(vec![ScanFinding {
                phase: 1,
                module_name: "test".to_string(),
                severity: "LOW".to_string(),
                description: "Test finding".to_string(),
                evidence: "test".to_string(),
            }])
        }
    }

    #[test]
    fn test_plugin_category() {
        assert_eq!(PluginCategory::XSS.as_str(), "xss");
        assert_eq!(PluginCategory::SQLi.as_str(), "sqli");
        assert_eq!(PluginCategory::LFI.as_str(), "lfi");
    }

    #[test]
    fn test_plugin_config() {
        let config = PluginConfig::default();
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.max_payload_size, 10240);
    }

    #[test]
    fn test_registry_creation() {
        let registry = PluginRegistry::new();
        assert_eq!(registry.count(), 0);
    }

    #[tokio::test]
    async fn test_plugin_registration() {
        let registry = PluginRegistry::new();
        let plugin = Arc::new(TestPlugin {
            id: "test_1".to_string(),
            category: PluginCategory::XSS,
        });

        assert!(registry.register(plugin).is_ok());
        assert_eq!(registry.count(), 1);
    }

    #[tokio::test]
    async fn test_plugin_execution() {
        let registry = PluginRegistry::new();
        let plugin = Arc::new(TestPlugin {
            id: "test_1".to_string(),
            category: PluginCategory::XSS,
        });

        registry.register(plugin).unwrap();
        let result = registry
            .execute("test_1", "http://target.com", "<script>")
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.findings.len(), 1);
    }

    #[tokio::test]
    async fn test_plugin_retrieval() {
        let registry = PluginRegistry::new();
        let plugin = Arc::new(TestPlugin {
            id: "test_2".to_string(),
            category: PluginCategory::SQLi,
        });

        registry.register(plugin).is_ok();
        let retrieved = registry.get("test_2");
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_list_by_category() {
        let registry = PluginRegistry::new();

        for i in 0..3 {
            let plugin = Arc::new(TestPlugin {
                id: format!("xss_{}", i),
                category: PluginCategory::XSS,
            });
            registry.register(plugin).is_ok();
        }

        let xss_plugins = registry.list_by_category(PluginCategory::XSS);
        assert_eq!(xss_plugins.len(), 3);
    }

    #[tokio::test]
    async fn test_plugin_unregister() {
        let registry = PluginRegistry::new();
        let plugin = Arc::new(TestPlugin {
            id: "test_3".to_string(),
            category: PluginCategory::LFI,
        });

        registry.register(plugin).unwrap();
        assert_eq!(registry.count(), 1);

        registry.unregister("test_3").unwrap();
        assert_eq!(registry.count(), 0);
    }

    #[tokio::test]
    async fn test_plugin_metadata() {
        let registry = PluginRegistry::new();
        let plugin = Arc::new(TestPlugin {
            id: "test_4".to_string(),
            category: PluginCategory::SSRF,
        });

        registry.register(plugin).unwrap();
        let meta = registry.get_metadata("test_4");

        assert!(meta.is_some());
        assert_eq!(meta.unwrap().name, "Test Plugin");
    }

    #[tokio::test]
    async fn test_execution_metadata_tracking() {
        let registry = PluginRegistry::new();
        let plugin = Arc::new(TestPlugin {
            id: "test_5".to_string(),
            category: PluginCategory::XXE,
        });

        registry.register(plugin).unwrap();

        for _ in 0..3 {
            registry
                .execute("test_5", "target", "payload")
                .await
                .is_ok();
        }

        let meta = registry.get_metadata("test_5").unwrap();
        assert_eq!(meta.execution_count, 3);
        assert_eq!(meta.success_count, 3);
    }
}
