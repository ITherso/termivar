//! Host-owned limits for the opt-in Lua execution boundary.

use serde::{Deserialize, Serialize};
use std::fmt;

pub const HARD_MAX_HISTORY_ENTRIES: usize = 1_024;
pub const HARD_MAX_MEMORY_BYTES: usize = 256 * 1_024 * 1_024;
pub const HARD_MAX_TIMEOUT_MS: u64 = 60_000;
pub const HARD_MAX_SOURCE_BYTES: usize = 1_024 * 1_024;
pub const HARD_MAX_TOTAL_SOURCE_BYTES: usize = 64 * 1_024 * 1_024;
pub const HARD_MAX_CONTEXT_BYTES: usize = 1_024 * 1_024;
pub const HARD_MAX_TARGET_BYTES: usize = 256 * 1_024;
pub const HARD_MAX_PAYLOAD_BYTES: usize = 512 * 1_024;
pub const HARD_MAX_PARAMETERS: usize = 1_024;
pub const HARD_MAX_PARAMETER_KEY_BYTES: usize = 4 * 1_024;
pub const HARD_MAX_PARAMETER_VALUE_BYTES: usize = 64 * 1_024;
pub const HARD_MAX_OUTPUT_BYTES: usize = 1_024 * 1_024;
pub const HARD_MAX_RETURN_BYTES: usize = 1_024 * 1_024;
pub const HARD_MAX_INSTRUCTIONS: u64 = 100_000_000;
pub const HARD_MAX_HOOK_INTERVAL: u32 = 10_000;
pub const HARD_MAX_SCRIPTS: usize = 4_096;
pub const HARD_MAX_CONCURRENT_EXECUTIONS: usize = 64;
pub const HARD_MAX_HISTORY_BYTES_PER_SCRIPT: usize = 8 * 1_024 * 1_024;
pub const HARD_MAX_HISTORY_BYTES_TOTAL: usize = 64 * 1_024 * 1_024;

/// Resource configuration for one host-owned Lua registry.
///
/// Every value is validated against a nonzero hard ceiling before the registry
/// allocates storage or accepts executable source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuaEngineConfig {
    /// Maximum execution-history entries retained per script.
    pub history_size: usize,
    /// Maximum retained history bytes per script.
    pub max_history_bytes_per_script: usize,
    /// Maximum retained history bytes across the registry.
    pub max_history_bytes_total: usize,
    /// Maximum memory per fresh Lua VM, in bytes.
    pub max_memory_bytes: usize,
    /// Monotonic wall-clock deadline for one execution, in milliseconds.
    pub default_timeout_ms: u64,
    /// Deterministic VM instruction ceiling for one execution.
    pub instruction_limit: u64,
    /// Number of VM instructions between host budget checks.
    pub hook_interval: u32,
    /// Maximum registered source bytes.
    pub max_source_bytes: usize,
    /// Maximum source bytes retained across the registry.
    pub max_total_source_bytes: usize,
    /// Maximum aggregate context bytes.
    pub max_context_bytes: usize,
    /// Maximum target bytes inside a context.
    pub max_target_bytes: usize,
    /// Maximum payload bytes inside a context.
    pub max_payload_bytes: usize,
    /// Maximum parameter entries inside a context.
    pub max_parameters: usize,
    /// Maximum bytes in one parameter key.
    pub max_parameter_key_bytes: usize,
    /// Maximum bytes in one parameter value.
    pub max_parameter_value_bytes: usize,
    /// Maximum bytes emitted by one execution.
    pub max_output_bytes: usize,
    /// Maximum bytes in the supported scalar return value.
    pub max_return_bytes: usize,
    /// Maximum scripts registered at once.
    pub max_scripts: usize,
    /// Maximum Lua VMs executing concurrently in this registry.
    pub max_concurrent_executions: usize,
}

/// How one Lua configuration field violates its hard contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuaConfigViolation {
    Zero,
    AboveHardMaximum,
    Inconsistent,
}

/// Typed configuration validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LuaConfigError {
    field: &'static str,
    violation: LuaConfigViolation,
}

impl LuaConfigError {
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }

    #[must_use]
    pub fn violation(&self) -> LuaConfigViolation {
        self.violation
    }
}

impl fmt::Display for LuaConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self.violation {
            LuaConfigViolation::Zero => "must be nonzero",
            LuaConfigViolation::AboveHardMaximum => "exceeds its hard maximum",
            LuaConfigViolation::Inconsistent => "is inconsistent with another limit",
        };
        write!(formatter, "{} {reason}", self.field)
    }
}

impl std::error::Error for LuaConfigError {}

impl LuaEngineConfig {
    /// Minimal limits for local tests and constrained hosts.
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            history_size: 10,
            max_history_bytes_per_script: 128 * 1_024,
            max_history_bytes_total: 512 * 1_024,
            max_memory_bytes: 10 * 1_024 * 1_024,
            default_timeout_ms: 1_000,
            instruction_limit: 1_000_000,
            hook_interval: 1_000,
            max_source_bytes: 64 * 1_024,
            max_total_source_bytes: 256 * 1_024,
            max_context_bytes: 128 * 1_024,
            max_target_bytes: 16 * 1_024,
            max_payload_bytes: 64 * 1_024,
            max_parameters: 128,
            max_parameter_key_bytes: 1_024,
            max_parameter_value_bytes: 16 * 1_024,
            max_output_bytes: 64 * 1_024,
            max_return_bytes: 64 * 1_024,
            max_scripts: 64,
            max_concurrent_executions: 4,
        }
    }

    /// Extended limits for an explicitly provisioned host.
    #[must_use]
    pub fn extended() -> Self {
        Self {
            history_size: 500,
            max_history_bytes_per_script: 4 * 1_024 * 1_024,
            max_history_bytes_total: 32 * 1_024 * 1_024,
            max_memory_bytes: 100 * 1_024 * 1_024,
            default_timeout_ms: 30_000,
            instruction_limit: 50_000_000,
            hook_interval: 10_000,
            max_source_bytes: HARD_MAX_SOURCE_BYTES,
            max_total_source_bytes: HARD_MAX_TOTAL_SOURCE_BYTES,
            max_context_bytes: HARD_MAX_CONTEXT_BYTES,
            max_target_bytes: HARD_MAX_TARGET_BYTES,
            max_payload_bytes: HARD_MAX_PAYLOAD_BYTES,
            max_parameters: HARD_MAX_PARAMETERS,
            max_parameter_key_bytes: HARD_MAX_PARAMETER_KEY_BYTES,
            max_parameter_value_bytes: HARD_MAX_PARAMETER_VALUE_BYTES,
            max_output_bytes: HARD_MAX_OUTPUT_BYTES,
            max_return_bytes: HARD_MAX_RETURN_BYTES,
            max_scripts: 2_048,
            max_concurrent_executions: 32,
        }
    }

    /// Validates every configured limit before it can control allocation or execution.
    pub fn validate(&self) -> Result<(), LuaConfigError> {
        validate_usize("history_size", self.history_size, HARD_MAX_HISTORY_ENTRIES)?;
        validate_usize(
            "max_history_bytes_per_script",
            self.max_history_bytes_per_script,
            HARD_MAX_HISTORY_BYTES_PER_SCRIPT,
        )?;
        validate_usize(
            "max_history_bytes_total",
            self.max_history_bytes_total,
            HARD_MAX_HISTORY_BYTES_TOTAL,
        )?;
        validate_usize(
            "max_memory_bytes",
            self.max_memory_bytes,
            HARD_MAX_MEMORY_BYTES,
        )?;
        validate_u64(
            "default_timeout_ms",
            self.default_timeout_ms,
            HARD_MAX_TIMEOUT_MS,
        )?;
        validate_u64(
            "instruction_limit",
            self.instruction_limit,
            HARD_MAX_INSTRUCTIONS,
        )?;
        validate_u32("hook_interval", self.hook_interval, HARD_MAX_HOOK_INTERVAL)?;
        validate_usize(
            "max_source_bytes",
            self.max_source_bytes,
            HARD_MAX_SOURCE_BYTES,
        )?;
        validate_usize(
            "max_total_source_bytes",
            self.max_total_source_bytes,
            HARD_MAX_TOTAL_SOURCE_BYTES,
        )?;
        validate_usize(
            "max_context_bytes",
            self.max_context_bytes,
            HARD_MAX_CONTEXT_BYTES,
        )?;
        validate_usize(
            "max_target_bytes",
            self.max_target_bytes,
            HARD_MAX_TARGET_BYTES,
        )?;
        validate_usize(
            "max_payload_bytes",
            self.max_payload_bytes,
            HARD_MAX_PAYLOAD_BYTES,
        )?;
        validate_usize("max_parameters", self.max_parameters, HARD_MAX_PARAMETERS)?;
        validate_usize(
            "max_parameter_key_bytes",
            self.max_parameter_key_bytes,
            HARD_MAX_PARAMETER_KEY_BYTES,
        )?;
        validate_usize(
            "max_parameter_value_bytes",
            self.max_parameter_value_bytes,
            HARD_MAX_PARAMETER_VALUE_BYTES,
        )?;
        validate_usize(
            "max_output_bytes",
            self.max_output_bytes,
            HARD_MAX_OUTPUT_BYTES,
        )?;
        validate_usize(
            "max_return_bytes",
            self.max_return_bytes,
            HARD_MAX_RETURN_BYTES,
        )?;
        validate_usize("max_scripts", self.max_scripts, HARD_MAX_SCRIPTS)?;
        validate_usize(
            "max_concurrent_executions",
            self.max_concurrent_executions,
            HARD_MAX_CONCURRENT_EXECUTIONS,
        )?;

        if u64::from(self.hook_interval) > self.instruction_limit {
            return Err(LuaConfigError {
                field: "hook_interval",
                violation: LuaConfigViolation::Inconsistent,
            });
        }
        if self.max_history_bytes_per_script > self.max_history_bytes_total {
            return Err(LuaConfigError {
                field: "max_history_bytes_per_script",
                violation: LuaConfigViolation::Inconsistent,
            });
        }
        if self.max_source_bytes > self.max_total_source_bytes {
            return Err(LuaConfigError {
                field: "max_source_bytes",
                violation: LuaConfigViolation::Inconsistent,
            });
        }
        for (field, value) in [
            ("max_target_bytes", self.max_target_bytes),
            ("max_payload_bytes", self.max_payload_bytes),
            ("max_parameter_key_bytes", self.max_parameter_key_bytes),
            ("max_parameter_value_bytes", self.max_parameter_value_bytes),
        ] {
            if value > self.max_context_bytes {
                return Err(LuaConfigError {
                    field,
                    violation: LuaConfigViolation::Inconsistent,
                });
            }
        }
        Ok(())
    }
}

impl Default for LuaEngineConfig {
    fn default() -> Self {
        Self {
            history_size: 100,
            max_history_bytes_per_script: 1_024 * 1_024,
            max_history_bytes_total: 8 * 1_024 * 1_024,
            max_memory_bytes: 50 * 1_024 * 1_024,
            default_timeout_ms: 5_000,
            instruction_limit: 10_000_000,
            hook_interval: 5_000,
            max_source_bytes: 256 * 1_024,
            max_total_source_bytes: 16 * 1_024 * 1_024,
            max_context_bytes: 256 * 1_024,
            max_target_bytes: 32 * 1_024,
            max_payload_bytes: 128 * 1_024,
            max_parameters: 256,
            max_parameter_key_bytes: 1_024,
            max_parameter_value_bytes: 32 * 1_024,
            max_output_bytes: 128 * 1_024,
            max_return_bytes: 128 * 1_024,
            max_scripts: 256,
            max_concurrent_executions: 8,
        }
    }
}

fn validate_usize(field: &'static str, value: usize, maximum: usize) -> Result<(), LuaConfigError> {
    if value == 0 {
        return Err(LuaConfigError {
            field,
            violation: LuaConfigViolation::Zero,
        });
    }
    if value > maximum {
        return Err(LuaConfigError {
            field,
            violation: LuaConfigViolation::AboveHardMaximum,
        });
    }
    Ok(())
}

fn validate_u64(field: &'static str, value: u64, maximum: u64) -> Result<(), LuaConfigError> {
    if value == 0 {
        return Err(LuaConfigError {
            field,
            violation: LuaConfigViolation::Zero,
        });
    }
    if value > maximum {
        return Err(LuaConfigError {
            field,
            violation: LuaConfigViolation::AboveHardMaximum,
        });
    }
    Ok(())
}

fn validate_u32(field: &'static str, value: u32, maximum: u32) -> Result<(), LuaConfigError> {
    if value == 0 {
        return Err(LuaConfigError {
            field,
            violation: LuaConfigViolation::Zero,
        });
    }
    if value > maximum {
        return Err(LuaConfigError {
            field,
            violation: LuaConfigViolation::AboveHardMaximum,
        });
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct LuaEngineConfigWire {
    history_size: u64,
    max_history_bytes_per_script: u64,
    max_history_bytes_total: u64,
    max_memory_bytes: u64,
    default_timeout_ms: u64,
    instruction_limit: u64,
    hook_interval: u32,
    max_source_bytes: u64,
    max_total_source_bytes: u64,
    max_context_bytes: u64,
    max_target_bytes: u64,
    max_payload_bytes: u64,
    max_parameters: u64,
    max_parameter_key_bytes: u64,
    max_parameter_value_bytes: u64,
    max_output_bytes: u64,
    max_return_bytes: u64,
    max_scripts: u64,
    max_concurrent_executions: u64,
}

impl Serialize for LuaEngineConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let to_u64 = |value: usize| {
            u64::try_from(value)
                .map_err(|_| serde::ser::Error::custom("Lua limit does not fit u64"))
        };
        LuaEngineConfigWire {
            history_size: to_u64(self.history_size)?,
            max_history_bytes_per_script: to_u64(self.max_history_bytes_per_script)?,
            max_history_bytes_total: to_u64(self.max_history_bytes_total)?,
            max_memory_bytes: to_u64(self.max_memory_bytes)?,
            default_timeout_ms: self.default_timeout_ms,
            instruction_limit: self.instruction_limit,
            hook_interval: self.hook_interval,
            max_source_bytes: to_u64(self.max_source_bytes)?,
            max_total_source_bytes: to_u64(self.max_total_source_bytes)?,
            max_context_bytes: to_u64(self.max_context_bytes)?,
            max_target_bytes: to_u64(self.max_target_bytes)?,
            max_payload_bytes: to_u64(self.max_payload_bytes)?,
            max_parameters: to_u64(self.max_parameters)?,
            max_parameter_key_bytes: to_u64(self.max_parameter_key_bytes)?,
            max_parameter_value_bytes: to_u64(self.max_parameter_value_bytes)?,
            max_output_bytes: to_u64(self.max_output_bytes)?,
            max_return_bytes: to_u64(self.max_return_bytes)?,
            max_scripts: to_u64(self.max_scripts)?,
            max_concurrent_executions: to_u64(self.max_concurrent_executions)?,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LuaEngineConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = LuaEngineConfigWire::deserialize(deserializer)?;
        let to_usize = |field: &'static str, value: u64| {
            usize::try_from(value)
                .map_err(|_| serde::de::Error::custom(format!("{field} does not fit usize")))
        };
        let config = Self {
            history_size: to_usize("history_size", wire.history_size)?,
            max_history_bytes_per_script: to_usize(
                "max_history_bytes_per_script",
                wire.max_history_bytes_per_script,
            )?,
            max_history_bytes_total: to_usize(
                "max_history_bytes_total",
                wire.max_history_bytes_total,
            )?,
            max_memory_bytes: to_usize("max_memory_bytes", wire.max_memory_bytes)?,
            default_timeout_ms: wire.default_timeout_ms,
            instruction_limit: wire.instruction_limit,
            hook_interval: wire.hook_interval,
            max_source_bytes: to_usize("max_source_bytes", wire.max_source_bytes)?,
            max_total_source_bytes: to_usize(
                "max_total_source_bytes",
                wire.max_total_source_bytes,
            )?,
            max_context_bytes: to_usize("max_context_bytes", wire.max_context_bytes)?,
            max_target_bytes: to_usize("max_target_bytes", wire.max_target_bytes)?,
            max_payload_bytes: to_usize("max_payload_bytes", wire.max_payload_bytes)?,
            max_parameters: to_usize("max_parameters", wire.max_parameters)?,
            max_parameter_key_bytes: to_usize(
                "max_parameter_key_bytes",
                wire.max_parameter_key_bytes,
            )?,
            max_parameter_value_bytes: to_usize(
                "max_parameter_value_bytes",
                wire.max_parameter_value_bytes,
            )?,
            max_output_bytes: to_usize("max_output_bytes", wire.max_output_bytes)?,
            max_return_bytes: to_usize("max_return_bytes", wire.max_return_bytes)?,
            max_scripts: to_usize("max_scripts", wire.max_scripts)?,
            max_concurrent_executions: to_usize(
                "max_concurrent_executions",
                wire.max_concurrent_executions,
            )?,
        };
        config.validate().map_err(serde::de::Error::custom)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_profiles_validate() {
        for config in [
            LuaEngineConfig::minimal(),
            LuaEngineConfig::default(),
            LuaEngineConfig::extended(),
        ] {
            assert_eq!(config.validate(), Ok(()));
        }
    }

    #[test]
    fn zero_and_huge_values_fail_before_allocation() {
        let mut zero = LuaEngineConfig::minimal();
        zero.max_memory_bytes = 0;
        assert_eq!(
            zero.validate(),
            Err(LuaConfigError {
                field: "max_memory_bytes",
                violation: LuaConfigViolation::Zero,
            })
        );

        let mut huge = LuaEngineConfig::minimal();
        huge.history_size = HARD_MAX_HISTORY_ENTRIES + 1;
        assert_eq!(
            huge.validate(),
            Err(LuaConfigError {
                field: "history_size",
                violation: LuaConfigViolation::AboveHardMaximum,
            })
        );
    }

    #[test]
    fn inconsistent_limits_fail_closed() {
        let mut config = LuaEngineConfig::minimal();
        config.hook_interval = 1_001;
        config.instruction_limit = 1_000;
        assert_eq!(
            config.validate(),
            Err(LuaConfigError {
                field: "hook_interval",
                violation: LuaConfigViolation::Inconsistent,
            })
        );

        let mut config = LuaEngineConfig::minimal();
        config.max_context_bytes = 1;
        assert_eq!(
            config.validate(),
            Err(LuaConfigError {
                field: "max_target_bytes",
                violation: LuaConfigViolation::Inconsistent,
            })
        );

        let mut config = LuaEngineConfig::minimal();
        config.max_total_source_bytes = config.max_source_bytes - 1;
        assert_eq!(
            config.validate(),
            Err(LuaConfigError {
                field: "max_source_bytes",
                violation: LuaConfigViolation::Inconsistent,
            })
        );
    }

    #[test]
    fn serde_uses_fixed_width_wire_values_and_revalidates() {
        let config = LuaEngineConfig::default();
        let wire = serde_json::to_string(&config).expect("serialize config");
        let round_trip: LuaEngineConfig = serde_json::from_str(&wire).expect("deserialize config");
        assert_eq!(round_trip, config);

        let invalid = wire.replace(
            &format!("\"max_memory_bytes\":{}", config.max_memory_bytes),
            "\"max_memory_bytes\":0",
        );
        let error = serde_json::from_str::<LuaEngineConfig>(&invalid).unwrap_err();
        assert!(error.to_string().contains("max_memory_bytes"));
    }
}
