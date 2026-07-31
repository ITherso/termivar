//! Register and execute a third-party-style plugin.
//!
//! Run with:
//! `cargo run -p venom-examples --bin custom_plugin`

use async_trait::async_trait;
use std::sync::Arc;
use venom_scanner::{
    Plugin, PluginCategory, PluginError, PluginRegistry, ScanFinding, PLUGIN_API_VERSION,
};

struct MarkerPlugin;

#[async_trait]
impl Plugin for MarkerPlugin {
    fn id(&self) -> &str {
        "example.marker"
    }

    fn name(&self) -> &str {
        "Marker Plugin"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    fn description(&self) -> &str {
        "Reports a harmless marker in supplied content"
    }

    fn author(&self) -> &str {
        "Venom contributors"
    }

    fn category(&self) -> PluginCategory {
        PluginCategory::Custom
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn execute(&self, target: &str, payload: &str) -> Result<Vec<ScanFinding>, PluginError> {
        if !payload.contains("venom-example-marker") {
            return Ok(Vec::new());
        }

        Ok(vec![ScanFinding {
            phase: 0,
            module_name: self.id().into(),
            severity: "INFO".into(),
            description: "Example marker observed".into(),
            evidence: target.into(),
        }])
    }
}

#[tokio::main]
async fn main() -> Result<(), PluginError> {
    let registry = PluginRegistry::new();
    registry.register(Arc::new(MarkerPlugin))?;

    let result = registry
        .execute(
            "example.marker",
            "https://example.test",
            "response contains venom-example-marker",
        )
        .await?;

    println!("plugin API: {PLUGIN_API_VERSION}");
    println!(
        "success={} findings={} elapsed={}ms",
        result.success,
        result.findings.len(),
        result.execution_time_ms
    );

    Ok(())
}
