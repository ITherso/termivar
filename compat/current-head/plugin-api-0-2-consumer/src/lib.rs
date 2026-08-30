//! Same-revision consumer of the evidence-only native plugin API 0.2 line.

#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use venom_core::{EvidenceKind, EvidenceValue, KnowledgePredicate};
use venom_scanner::{
    Plugin, PluginCategory, PluginConfig, PluginContext, PluginError, PluginObservation,
    PluginRegistry, PLUGIN_API_VERSION,
};

/// Minimal source-linked plugin that can stage only a host-owned observation.
///
/// The API has no return path for a finding, severity, or confirmed outcome.
pub struct HeaderPresenceObserver;

#[async_trait]
impl Plugin for HeaderPresenceObserver {
    fn api_version(&self) -> &str {
        PLUGIN_API_VERSION
    }

    fn id(&self) -> &str {
        "current-head.header-presence"
    }

    fn name(&self) -> &str {
        "Current-head header presence observer"
    }

    fn version(&self) -> &str {
        "0.0.0"
    }

    fn description(&self) -> &str {
        "Stages one boolean observation for host-owned evidence processing"
    }

    fn author(&self) -> &str {
        "Venom compatibility fixture"
    }

    fn category(&self) -> PluginCategory {
        PluginCategory::Custom
    }

    async fn execute(&self, context: &PluginContext) -> Result<(), PluginError> {
        let predicate = KnowledgePredicate::new("plugin.current-head", "header-present")
            .map_err(|_| PluginError::ExecutionFailed("static predicate rejected".to_owned()))?;
        let observation = PluginObservation::new(
            EvidenceKind::Custom("plugin.current-head.header".to_owned()),
            predicate,
            EvidenceValue::Boolean(true),
            "header-presence",
        )?;
        context.record(observation)
    }
}

/// Registers the fixture plugin without executing it or granting transport.
pub fn registry_with_observer() -> Result<PluginRegistry, PluginError> {
    let registry = PluginRegistry::new();
    registry.register(Arc::new(HeaderPresenceObserver), PluginConfig::default())?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_api_0_2_descriptor_and_registry_compile_without_execution() {
        assert!(PLUGIN_API_VERSION.starts_with("0.2."));
        let registry = registry_with_observer().unwrap();
        let metadata = registry
            .get_metadata("current-head.header-presence")
            .unwrap();
        assert_eq!(metadata.api_version(), PLUGIN_API_VERSION);
        assert_eq!(metadata.category(), PluginCategory::Custom);
        assert_eq!(metadata.execution_count(), 0);
        assert_eq!(metadata.success_count(), 0);
        assert_eq!(metadata.error_count(), 0);
    }
}
