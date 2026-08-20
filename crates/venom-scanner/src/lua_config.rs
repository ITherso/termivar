//! Resource limits shared by the opt-in Lua host and legacy platform profiles.

use serde::{Deserialize, Serialize};

/// Resource configuration for one Lua engine host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaEngineConfig {
    /// Maximum execution-history entries retained per script.
    pub history_size: usize,
    /// Maximum memory per Lua VM, in bytes.
    pub max_memory_bytes: usize,
    /// Default script deadline, in milliseconds.
    pub default_timeout_ms: u64,
}

impl LuaEngineConfig {
    /// Minimal limits for local tests and constrained hosts.
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            history_size: 10,
            max_memory_bytes: 10_000_000,
            default_timeout_ms: 1_000,
        }
    }

    /// Extended limits for an explicitly provisioned host.
    #[must_use]
    pub fn extended() -> Self {
        Self {
            history_size: 500,
            max_memory_bytes: 100_000_000,
            default_timeout_ms: 30_000,
        }
    }

    /// Validates that every resource limit is nonzero.
    pub fn validate(&self) -> Result<(), String> {
        if self.history_size == 0 {
            return Err("history_size must be > 0".to_owned());
        }
        if self.max_memory_bytes == 0 {
            return Err("max_memory_bytes must be > 0".to_owned());
        }
        if self.default_timeout_ms == 0 {
            return Err("default_timeout_ms must be > 0".to_owned());
        }
        Ok(())
    }
}

impl Default for LuaEngineConfig {
    fn default() -> Self {
        Self {
            history_size: 100,
            max_memory_bytes: 50_000_000,
            default_timeout_ms: 5_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_must_be_nonzero() {
        assert!(LuaEngineConfig::default().validate().is_ok());
        let mut invalid = LuaEngineConfig::minimal();
        invalid.max_memory_bytes = 0;
        assert_eq!(
            invalid.validate().unwrap_err(),
            "max_memory_bytes must be > 0"
        );
    }
}
