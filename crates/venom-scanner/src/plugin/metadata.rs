use serde::Serialize;

use super::PluginCategory;

#[derive(Clone)]
pub(super) struct PluginDescriptor {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) description: String,
    pub(super) author: String,
    pub(super) category: PluginCategory,
    pub(super) api_version: String,
    pub(super) loaded_at: u64,
}

/// Consistent metadata snapshot from one registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginMetadata {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) description: String,
    pub(super) author: String,
    pub(super) category: PluginCategory,
    pub(super) api_version: String,
    pub(super) enabled: bool,
    pub(super) loaded_at: u64,
    pub(super) execution_count: u64,
    pub(super) success_count: u64,
    pub(super) error_count: u64,
}

impl PluginMetadata {
    /// Stable plugin identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Human-readable plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Plugin implementation version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Human-readable description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Human-readable author or owner.
    pub fn author(&self) -> &str {
        &self.author
    }

    /// Informational category.
    pub const fn category(&self) -> PluginCategory {
        self.category
    }

    /// Targeted plugin API line.
    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    /// Snapshotted host enable state.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Registration timestamp in Unix seconds.
    pub const fn loaded_at(&self) -> u64 {
        self.loaded_at
    }

    /// Invocation attempts that reached execution policy.
    pub const fn execution_count(&self) -> u64 {
        self.execution_count
    }

    /// Cleanly completed invocations.
    pub const fn success_count(&self) -> u64 {
        self.success_count
    }

    /// Failed, timed-out, cancelled, or panicked invocations.
    pub const fn error_count(&self) -> u64 {
        self.error_count
    }
}
