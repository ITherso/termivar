use dashmap::{mapref::entry::Entry, DashMap};
use std::{
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use super::{
    limits::{
        invalid_config, validate_identifier, validate_text, PluginConfig, MAX_PLUGIN_ID_BYTES,
    },
    metadata::{PluginDescriptor, PluginMetadata},
    Plugin, PluginCategory, PluginError, PLUGIN_API_VERSION,
};

pub(super) struct PluginStats {
    state: Mutex<PluginStatsState>,
}

#[derive(Default)]
struct PluginStatsState {
    execution_count: u64,
    success_count: u64,
    error_count: u64,
    active_invocations: u64,
}

impl PluginStats {
    pub(super) fn acquire_invocation(
        self: &Arc<Self>,
    ) -> Result<PluginInvocationLease, PluginError> {
        let mut state = lock_stats(&self.state);
        state.active_invocations = state
            .active_invocations
            .checked_add(1)
            .ok_or(PluginError::HostStateUnavailable)?;
        Ok(PluginInvocationLease {
            stats: self.clone(),
        })
    }

    fn release_invocation(&self) {
        let mut state = lock_stats(&self.state);
        state.active_invocations = state.active_invocations.saturating_sub(1);
    }

    fn has_active_invocation(&self) -> bool {
        lock_stats(&self.state).active_invocations != 0
    }

    pub(super) fn record_execution(&self) {
        let mut state = lock_stats(&self.state);
        state.execution_count = state.execution_count.saturating_add(1);
    }

    pub(super) fn record_success(&self) {
        let mut state = lock_stats(&self.state);
        state.success_count = state.success_count.saturating_add(1);
    }

    pub(super) fn record_error(&self) {
        let mut state = lock_stats(&self.state);
        state.error_count = state.error_count.saturating_add(1);
    }

    fn snapshot(&self) -> (u64, u64, u64) {
        let state = lock_stats(&self.state);
        (
            state.execution_count,
            state.success_count,
            state.error_count,
        )
    }
}

pub(super) struct PluginInvocationLease {
    stats: Arc<PluginStats>,
}

impl Drop for PluginInvocationLease {
    fn drop(&mut self) {
        self.stats.release_invocation();
    }
}

fn lock_stats(state: &Mutex<PluginStatsState>) -> MutexGuard<'_, PluginStatsState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(super) struct PluginEntry {
    pub(super) plugin: Arc<dyn Plugin>,
    pub(super) config: PluginConfig,
    descriptor: PluginDescriptor,
    pub(super) stats: Arc<PluginStats>,
}

#[derive(Default)]
pub struct PluginRegistry {
    pub(super) entries: DashMap<String, PluginEntry>,
}

impl PluginRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one plugin and host configuration without replacement.
    pub fn register(
        &self,
        plugin: Arc<dyn Plugin>,
        config: PluginConfig,
    ) -> Result<(), PluginError> {
        self.register_at(plugin, config, SystemTime::now())
    }

    pub(super) fn register_at(
        &self,
        plugin: Arc<dyn Plugin>,
        config: PluginConfig,
        now: SystemTime,
    ) -> Result<(), PluginError> {
        let descriptor = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let descriptor = plugin_descriptor(plugin.as_ref(), now)?;
            validate_plugin_descriptor(&descriptor)?;
            validate_api_version(&descriptor.api_version)?;
            plugin
                .validate()
                .map_err(|_| invalid_config("plugin validation failed"))?;
            Ok(descriptor)
        }))
        .map_err(|_| PluginError::Panicked)??;
        let id = descriptor.id.clone();
        let entry = PluginEntry {
            plugin,
            config,
            descriptor,
            stats: Arc::new(PluginStats {
                state: Mutex::new(PluginStatsState::default()),
            }),
        };
        match self.entries.entry(id) {
            Entry::Vacant(slot) => {
                slot.insert(entry);
                Ok(())
            },
            Entry::Occupied(_) => Err(PluginError::DuplicateId),
        }
    }

    /// Removes one plugin and its inseparable configuration/metadata entry.
    pub fn unregister(&self, plugin_id: &str) -> Result<(), PluginError> {
        if plugin_id.is_empty() || plugin_id.len() > MAX_PLUGIN_ID_BYTES {
            return Err(PluginError::NotFound);
        }
        match self.entries.entry(plugin_id.to_owned()) {
            Entry::Occupied(entry) if entry.get().stats.has_active_invocation() => {
                Err(PluginError::InUse)
            },
            Entry::Occupied(entry) => {
                entry.remove();
                Ok(())
            },
            Entry::Vacant(_) => Err(PluginError::NotFound),
        }
    }

    /// Returns the registered plugin trait object.
    pub fn get(&self, plugin_id: &str) -> Option<Arc<dyn Plugin>> {
        self.entries
            .get(plugin_id)
            .map(|entry| entry.plugin.clone())
    }

    /// Returns one consistent metadata snapshot.
    pub fn get_metadata(&self, plugin_id: &str) -> Option<PluginMetadata> {
        self.entries
            .get(plugin_id)
            .map(|entry| metadata_snapshot(&entry))
    }

    /// Returns one consistent host-configuration snapshot.
    pub fn get_config(&self, plugin_id: &str) -> Option<PluginConfig> {
        self.entries
            .get(plugin_id)
            .map(|entry| entry.config.clone())
    }

    /// Replaces host policy atomically for future invocations.
    pub fn update_config(&self, plugin_id: &str, config: PluginConfig) -> Result<(), PluginError> {
        let mut entry = self
            .entries
            .get_mut(plugin_id)
            .ok_or(PluginError::NotFound)?;
        entry.config = config;
        Ok(())
    }
}

impl PluginRegistry {
    /// Lists consistent metadata snapshots in plugin-ID order.
    pub fn list_all(&self) -> Vec<PluginMetadata> {
        let mut metadata: Vec<_> = self
            .entries
            .iter()
            .map(|entry| metadata_snapshot(&entry))
            .collect();
        metadata.sort_by(|left, right| left.id.cmp(&right.id));
        metadata
    }

    /// Lists consistent metadata snapshots for one category.
    pub fn list_by_category(&self, category: PluginCategory) -> Vec<PluginMetadata> {
        self.list_all()
            .into_iter()
            .filter(|metadata| metadata.category == category)
            .collect()
    }

    /// Registered plugin count.
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

fn metadata_snapshot(entry: &PluginEntry) -> PluginMetadata {
    let (execution_count, success_count, error_count) = entry.stats.snapshot();
    PluginMetadata {
        id: entry.descriptor.id.clone(),
        name: entry.descriptor.name.clone(),
        version: entry.descriptor.version.clone(),
        description: entry.descriptor.description.clone(),
        author: entry.descriptor.author.clone(),
        category: entry.descriptor.category,
        api_version: entry.descriptor.api_version.clone(),
        enabled: entry.config.enabled,
        loaded_at: entry.descriptor.loaded_at,
        execution_count,
        success_count,
        error_count,
    }
}

fn plugin_descriptor(
    plugin: &dyn Plugin,
    now: SystemTime,
) -> Result<PluginDescriptor, PluginError> {
    let loaded_at = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PluginError::ClockBeforeUnixEpoch)?
        .as_secs();
    Ok(PluginDescriptor {
        id: plugin.id().to_owned(),
        name: plugin.name().to_owned(),
        version: plugin.version().to_owned(),
        description: plugin.description().to_owned(),
        author: plugin.author().to_owned(),
        category: plugin.category(),
        api_version: plugin.api_version().to_owned(),
        loaded_at,
    })
}

fn validate_plugin_descriptor(descriptor: &PluginDescriptor) -> Result<(), PluginError> {
    validate_identifier(&descriptor.id, "plugin id", MAX_PLUGIN_ID_BYTES)?;
    validate_text(&descriptor.name, "plugin name")?;
    validate_identifier(&descriptor.version, "plugin version", MAX_PLUGIN_ID_BYTES)?;
    validate_text(&descriptor.description, "plugin description")?;
    validate_text(&descriptor.author, "plugin author")?;
    Ok(())
}

pub(super) fn validate_api_version(actual: &str) -> Result<(), PluginError> {
    fn line(version: &str) -> Option<(u64, u64)> {
        let mut parts = version.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let _patch: u64 = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some((major, minor))
    }
    let actual_line = line(actual);
    if actual_line.is_some() && actual_line == line(PLUGIN_API_VERSION) {
        Ok(())
    } else {
        Err(PluginError::IncompatibleApiVersion {
            expected: PLUGIN_API_VERSION.to_owned(),
            actual: if actual_line.is_some() && actual.len() <= 32 {
                actual.to_owned()
            } else {
                "[invalid]".to_owned()
            },
        })
    }
}
