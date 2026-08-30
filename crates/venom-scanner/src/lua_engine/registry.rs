use super::history::BoundedExecutionHistory;
use super::{
    LuaExecutionReceipt, LuaExecutionResult, LuaRegistryError, LuaScript, LuaScriptManifest,
    LuaScriptRegistry, ScriptCategory,
};
use crate::lua_config::LuaEngineConfig;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

pub(super) struct RegisteredScript {
    pub(super) script: LuaScript,
    pub(super) enabled: bool,
    pub(super) active_invocations: usize,
    pub(super) generation: u64,
}

pub(super) struct RegistryState {
    pub(super) scripts: BTreeMap<String, RegisteredScript>,
    names: BTreeMap<String, String>,
    histories: BTreeMap<String, BoundedExecutionHistory>,
    history_bytes: usize,
    pub(super) next_sequence: u64,
    next_generation: u64,
    total_source_bytes: usize,
}

impl RegistryState {
    fn new() -> Self {
        Self {
            scripts: BTreeMap::new(),
            names: BTreeMap::new(),
            histories: BTreeMap::new(),
            history_bytes: 0,
            next_sequence: 0,
            next_generation: 0,
            total_source_bytes: 0,
        }
    }

    fn allocate_sequence(&mut self) -> Result<u64, LuaRegistryError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(LuaRegistryError::HistorySequenceExhausted)?;
        Ok(sequence)
    }

    fn allocate_generation(&mut self) -> Result<u64, LuaRegistryError> {
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(LuaRegistryError::RegistrationGenerationExhausted)?;
        Ok(generation)
    }

    fn evict_global_oldest(&mut self) -> bool {
        let oldest = self
            .histories
            .iter()
            .filter_map(|(script_id, history)| {
                history
                    .entries
                    .front()
                    .map(|entry| (entry.sequence, script_id.clone()))
            })
            .min();
        let Some((_, script_id)) = oldest else {
            return false;
        };
        let Some(history) = self.histories.get_mut(&script_id) else {
            return false;
        };
        if let Some(entry) = history.pop_front() {
            self.history_bytes = self.history_bytes.saturating_sub(entry.retained_bytes);
        }
        if history.entries.is_empty() {
            self.histories.remove(&script_id);
        }
        true
    }
}

pub(super) struct InvocationLease {
    pub(super) state: Arc<Mutex<RegistryState>>,
    pub(super) script_id: String,
    pub(super) generation: u64,
}

impl Drop for InvocationLease {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(entry) = state.scripts.get_mut(&self.script_id) else {
            return;
        };
        if entry.generation == self.generation {
            entry.active_invocations = entry.active_invocations.saturating_sub(1);
        }
    }
}

impl LuaScriptRegistry {
    pub fn new() -> Result<Self, LuaRegistryError> {
        Self::from_config(&LuaEngineConfig::default())
    }

    pub fn from_config(config: &LuaEngineConfig) -> Result<Self, LuaRegistryError> {
        config.validate().map_err(LuaRegistryError::InvalidConfig)?;
        Ok(Self {
            state: Arc::new(Mutex::new(RegistryState::new())),
            config: config.clone(),
            execution_permits: Arc::new(Semaphore::new(config.max_concurrent_executions)),
        })
    }

    pub fn register(&self, script: LuaScript) -> Result<(), LuaRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        let id = script.id();
        if state.scripts.contains_key(&id) {
            return Err(LuaRegistryError::DuplicateId);
        }
        if state.names.contains_key(&script.name) {
            return Err(LuaRegistryError::DuplicateName);
        }
        if state.scripts.len() >= self.config.max_scripts {
            return Err(LuaRegistryError::ScriptCapacity);
        }
        if script.source.len() > self.config.max_source_bytes {
            return Err(LuaRegistryError::SourceLimit);
        }
        let total_source_bytes = state
            .total_source_bytes
            .checked_add(script.source.len())
            .ok_or(LuaRegistryError::TotalSourceCapacity)?;
        if total_source_bytes > self.config.max_total_source_bytes {
            return Err(LuaRegistryError::TotalSourceCapacity);
        }
        let generation = state.allocate_generation()?;
        state.names.insert(script.name.clone(), id.clone());
        state.scripts.insert(
            id,
            RegisteredScript {
                enabled: script.enabled,
                script,
                active_invocations: 0,
                generation,
            },
        );
        state.total_source_bytes = total_source_bytes;
        Ok(())
    }

    pub fn get(&self, script_id: &str) -> Result<Option<LuaScriptManifest>, LuaRegistryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        Ok(state
            .scripts
            .get(script_id)
            .map(|entry| entry.script.manifest_with_enabled(entry.enabled)))
    }

    pub fn list_all(&self) -> Result<Vec<LuaScriptManifest>, LuaRegistryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        let mut manifests: Vec<_> = state
            .scripts
            .values()
            .map(|entry| entry.script.manifest_with_enabled(entry.enabled))
            .collect();
        manifests.sort_by(|left, right| {
            (&left.name, &left.version, &left.id).cmp(&(&right.name, &right.version, &right.id))
        });
        Ok(manifests)
    }

    pub fn list_enabled(&self) -> Result<Vec<LuaScriptManifest>, LuaRegistryError> {
        Ok(self
            .list_all()?
            .into_iter()
            .filter(LuaScriptManifest::enabled)
            .collect())
    }

    pub fn list_by_category(
        &self,
        category: ScriptCategory,
    ) -> Result<Vec<LuaScriptManifest>, LuaRegistryError> {
        Ok(self
            .list_all()?
            .into_iter()
            .filter(|manifest| manifest.categories.contains(&category))
            .collect())
    }

    pub fn get_history(
        &self,
        script_id: &str,
    ) -> Result<Vec<LuaExecutionReceipt>, LuaRegistryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        Ok(state
            .histories
            .get(script_id)
            .map(|history| {
                history
                    .entries
                    .iter()
                    .map(|entry| entry.receipt.clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    pub fn get_recent_history(
        &self,
        script_id: &str,
        count: usize,
    ) -> Result<Vec<LuaExecutionReceipt>, LuaRegistryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        Ok(state
            .histories
            .get(script_id)
            .map(|history| {
                history
                    .entries
                    .iter()
                    .rev()
                    .take(count)
                    .map(|entry| entry.receipt.clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    pub fn count(&self) -> Result<usize, LuaRegistryError> {
        self.state
            .lock()
            .map(|state| state.scripts.len())
            .map_err(|_| LuaRegistryError::StateUnavailable)
    }

    pub fn enabled_count(&self) -> Result<usize, LuaRegistryError> {
        self.state
            .lock()
            .map(|state| state.scripts.values().filter(|entry| entry.enabled).count())
            .map_err(|_| LuaRegistryError::StateUnavailable)
    }

    pub fn set_enabled(&self, script_id: &str, enabled: bool) -> Result<(), LuaRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        let entry = state
            .scripts
            .get_mut(script_id)
            .ok_or(LuaRegistryError::ScriptNotFound)?;
        entry.enabled = enabled;
        Ok(())
    }

    pub fn unregister(&self, script_id: &str) -> Result<(), LuaRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        let entry = state
            .scripts
            .get(script_id)
            .ok_or(LuaRegistryError::ScriptNotFound)?;
        if entry.active_invocations != 0 {
            return Err(LuaRegistryError::ScriptInUse);
        }
        let total_source_bytes = state
            .total_source_bytes
            .checked_sub(entry.script.source.len())
            .ok_or(LuaRegistryError::StateUnavailable)?;
        let removed_history_bytes = state
            .histories
            .get(script_id)
            .map_or(0, |history| history.retained_bytes);
        let history_bytes = state
            .history_bytes
            .checked_sub(removed_history_bytes)
            .ok_or(LuaRegistryError::StateUnavailable)?;
        let entry = state
            .scripts
            .remove(script_id)
            .ok_or(LuaRegistryError::ScriptNotFound)?;
        state.names.remove(&entry.script.name);
        state.total_source_bytes = total_source_bytes;
        state.histories.remove(script_id);
        state.history_bytes = history_bytes;
        Ok(())
    }

    pub(super) fn record_result(
        &self,
        generation: u64,
        result: &LuaExecutionResult,
    ) -> Result<(), LuaRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        if state
            .scripts
            .get(result.script_id())
            .is_none_or(|entry| entry.generation != generation)
        {
            return Ok(());
        }
        let receipt = LuaExecutionReceipt::from_result(result);
        let receipt_bytes = receipt.retained_bytes();
        if receipt_bytes > self.config.max_history_bytes_per_script
            || receipt_bytes > self.config.max_history_bytes_total
        {
            return Ok(());
        }
        let sequence = state.allocate_sequence()?;
        while state.history_bytes.saturating_add(receipt_bytes)
            > self.config.max_history_bytes_total
        {
            if !state.evict_global_oldest() {
                return Ok(());
            }
        }
        let history = state
            .histories
            .entry(result.script_id().to_owned())
            .or_insert_with(BoundedExecutionHistory::new);
        let before = history.retained_bytes;
        let inserted = history.push(
            sequence,
            receipt,
            self.config.history_size,
            self.config.max_history_bytes_per_script,
        );
        let after = history.retained_bytes;
        if inserted {
            state.history_bytes = state
                .history_bytes
                .saturating_sub(before)
                .saturating_add(after);
        }
        Ok(())
    }
}
