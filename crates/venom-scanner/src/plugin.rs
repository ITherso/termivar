//! Plugin System for Extensibility
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `plugins`.
//! - **Execution:** host/library only (source-level plugin trait boundary; see ADR 0002).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented (exercised by the Plugin Template).
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Comprehensive modular plugin architecture for vulnerability scanning.

use crate::contracts::ScanFinding;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Source-level plugin API version supported by this host.
///
/// During Preview, host and plugin versions must share the same major and
/// minor components. See `docs/plugin-api-policy.md` for the compatibility
/// policy.
pub const PLUGIN_API_VERSION: &str = "0.1.0";

/// Extension contract for custom scanner plugins.
///
/// The registry only knows this trait; it never inspects a plugin's concrete
/// type. Plugins return findings and must not reach into runner internals.
///
/// # Examples
///
/// ```
/// use async_trait::async_trait;
/// use venom_scanner::{Plugin, PluginCategory, PluginError, ScanFinding};
///
/// struct MarkerPlugin;
///
/// #[async_trait]
/// impl Plugin for MarkerPlugin {
///     fn id(&self) -> &str { "marker" }
///     fn name(&self) -> &str { "Marker Plugin" }
///     fn version(&self) -> &str { "0.1.0" }
///     fn description(&self) -> &str { "Finds an example response marker" }
///     fn author(&self) -> &str { "Example Author" }
///     fn category(&self) -> PluginCategory { PluginCategory::Custom }
///     fn enabled(&self) -> bool { true }
///
///     async fn execute(
///         &self,
///         target: &str,
///         payload: &str,
///     ) -> Result<Vec<ScanFinding>, PluginError> {
///         if !payload.contains("example-marker") {
///             return Ok(Vec::new());
///         }
///
///         Ok(vec![ScanFinding {
///             phase: 0,
///             module_name: self.id().into(),
///             severity: "INFO".into(),
///             description: "Example marker observed".into(),
///             evidence: target.into(),
///         }])
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    /// Plugin API line targeted by this implementation.
    ///
    /// The default tracks the API exposed by the dependency used to compile
    /// the plugin. Override this only for compatibility testing or an adapter.
    fn api_version(&self) -> &str {
        PLUGIN_API_VERSION
    }

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
#[non_exhaustive]
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
#[non_exhaustive]
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
    #[serde(rename = "payload_too_large")]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[serde(rename = "incompatible_api_version")]
    IncompatibleApiVersion { expected: String, actual: String },
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PluginError::ExecutionFailed(e) => write!(f, "Execution failed: {}", e),
            PluginError::NotFound(e) => write!(f, "Plugin not found: {}", e),
            PluginError::InvalidConfig(e) => write!(f, "Invalid config: {}", e),
            PluginError::Timeout => write!(f, "Plugin execution timeout"),
            PluginError::Disabled => write!(f, "Plugin is disabled"),
            PluginError::PayloadTooLarge { actual, maximum } => write!(
                f,
                "Plugin payload length {} exceeds configured maximum {}",
                actual, maximum
            ),
            PluginError::IncompatibleApiVersion { expected, actual } => write!(
                f,
                "Incompatible plugin API version: expected {}, received {}",
                expected, actual
            ),
        }
    }
}

impl std::error::Error for PluginError {}

/// Plugin configuration
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
        if !plugin_api_compatible(plugin.api_version()) {
            return Err(PluginError::IncompatibleApiVersion {
                expected: PLUGIN_API_VERSION.to_string(),
                actual: plugin.api_version().to_string(),
            });
        }

        plugin.validate().map_err(PluginError::InvalidConfig)?;

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
        let config = self
            .get_config(plugin_id)
            .ok_or_else(|| PluginError::NotFound(plugin_id.to_string()))?;

        if !plugin.enabled() || !config.enabled {
            return Err(PluginError::Disabled);
        }
        let payload_bytes = payload.len();
        if payload_bytes > config.max_payload_size {
            return Err(PluginError::PayloadTooLarge {
                actual: payload_bytes,
                maximum: config.max_payload_size,
            });
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(config.timeout_ms))
            .ok_or_else(|| {
                PluginError::InvalidConfig(
                    "plugin timeout exceeds the runtime clock range".to_owned(),
                )
            })?;

        let start = Instant::now();

        match tokio::time::timeout_at(deadline, plugin.execute(target, payload)).await {
            Ok(Ok(findings)) => {
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
            Ok(Err(error)) => {
                self.update_metadata(plugin_id, false);
                Ok(PluginExecutionResult {
                    plugin_id: plugin_id.to_string(),
                    success: false,
                    findings: vec![],
                    error: Some(error.to_string()),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                })
            },
            Err(_) => {
                self.update_metadata(plugin_id, false);
                Ok(PluginExecutionResult {
                    plugin_id: plugin_id.to_string(),
                    success: false,
                    findings: vec![],
                    error: Some(PluginError::Timeout.to_string()),
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

fn plugin_api_compatible(actual: &str) -> bool {
    fn api_line(version: &str) -> Option<(&str, &str)> {
        let mut components = version.split('.');
        Some((components.next()?, components.next()?))
    }

    api_line(actual) == api_line(PLUGIN_API_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestPlugin {
        id: String,
        category: PluginCategory,
    }

    struct PolicyProbePlugin {
        calls: Arc<AtomicUsize>,
        completions: Arc<AtomicUsize>,
        delay: Duration,
        config: PluginConfig,
        enabled: bool,
    }

    #[async_trait::async_trait]
    impl Plugin for PolicyProbePlugin {
        fn id(&self) -> &str {
            "policy-probe"
        }

        fn name(&self) -> &str {
            "Policy Probe"
        }

        fn version(&self) -> &str {
            "0.1.0"
        }

        fn description(&self) -> &str {
            "Exercises registry-owned execution policy"
        }

        fn author(&self) -> &str {
            "Venom"
        }

        fn category(&self) -> PluginCategory {
            PluginCategory::Custom
        }

        fn enabled(&self) -> bool {
            self.enabled
        }

        fn get_config(&self) -> PluginConfig {
            self.config.clone()
        }

        async fn execute(
            &self,
            _target: &str,
            _payload: &str,
        ) -> Result<Vec<ScanFinding>, PluginError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.completions.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    fn policy_probe(
        config: PluginConfig,
    ) -> (Arc<PolicyProbePlugin>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let completions = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(PolicyProbePlugin {
                calls: calls.clone(),
                completions: completions.clone(),
                delay: Duration::ZERO,
                config,
                enabled: true,
            }),
            calls,
            completions,
        )
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
    fn test_plugin_api_compatibility() {
        assert!(plugin_api_compatible("0.1.0"));
        assert!(plugin_api_compatible("0.1.9"));
        assert!(!plugin_api_compatible("0.2.0"));
        assert!(!plugin_api_compatible("1.0.0"));
        assert!(!plugin_api_compatible("invalid"));
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

        registry.register(plugin).unwrap();
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
            registry.register(plugin).unwrap();
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
            let _ = registry
                .execute("test_5", "target", "payload")
                .await
                .unwrap();
        }

        let meta = registry.get_metadata("test_5").unwrap();
        assert_eq!(meta.execution_count, 3);
        assert_eq!(meta.success_count, 3);
    }

    #[tokio::test]
    async fn host_configuration_disables_plugin_before_execution() {
        let config = PluginConfig {
            enabled: false,
            ..PluginConfig::default()
        };
        let (plugin, calls, _) = policy_probe(config);
        let registry = PluginRegistry::new();
        registry.register(plugin).unwrap();

        assert!(matches!(
            registry.execute("policy-probe", "target", "payload").await,
            Err(PluginError::Disabled)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            registry
                .get_metadata("policy-probe")
                .unwrap()
                .execution_count,
            0
        );
    }

    #[tokio::test]
    async fn oversized_payload_is_rejected_before_plugin_code_runs() {
        let config = PluginConfig {
            max_payload_size: 3,
            ..PluginConfig::default()
        };
        let (plugin, calls, _) = policy_probe(config);
        let registry = PluginRegistry::new();
        registry.register(plugin).unwrap();

        assert!(matches!(
            registry.execute("policy-probe", "target", "éé").await,
            Err(PluginError::PayloadTooLarge {
                actual: 4,
                maximum: 3
            })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            registry
                .get_metadata("policy-probe")
                .unwrap()
                .execution_count,
            0
        );
    }

    #[tokio::test]
    async fn registry_timeout_cancels_the_plugin_future_and_records_failure() {
        let config = PluginConfig {
            timeout_ms: 5,
            ..PluginConfig::default()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let completions = Arc::new(AtomicUsize::new(0));
        let plugin = Arc::new(PolicyProbePlugin {
            calls: calls.clone(),
            completions: completions.clone(),
            delay: Duration::from_secs(1),
            config,
            enabled: true,
        });
        let registry = PluginRegistry::new();
        registry.register(plugin).unwrap();

        let result = registry
            .execute("policy-probe", "target", "payload")
            .await
            .unwrap();

        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("Plugin execution timeout"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(completions.load(Ordering::SeqCst), 0);
        let metadata = registry.get_metadata("policy-probe").unwrap();
        assert_eq!(metadata.execution_count, 1);
        assert_eq!(metadata.success_count, 0);
        assert_eq!(metadata.error_count, 1);
    }

    #[tokio::test]
    async fn updated_host_policy_applies_to_the_next_execution() {
        let (plugin, calls, completions) = policy_probe(PluginConfig::default());
        let registry = PluginRegistry::new();
        registry.register(plugin).unwrap();
        registry
            .update_config(
                "policy-probe",
                PluginConfig {
                    enabled: false,
                    ..PluginConfig::default()
                },
            )
            .unwrap();

        assert!(matches!(
            registry.execute("policy-probe", "target", "payload").await,
            Err(PluginError::Disabled)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(completions.load(Ordering::SeqCst), 0);
    }
}
