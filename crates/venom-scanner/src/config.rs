//! Caller-supplied scan-configuration records.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `platform-models`.
//! - **Execution:** host/library data model only; no repository runtime caller.
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! The repository does not provide behavior presets and does not apply these
//! values to either scanner runtime. An integrating host must define and enforce
//! the meaning of every field. See `docs/internals/runtime-map.md`.

use serde::{Deserialize, Serialize};

use crate::lua_config::LuaEngineConfig;

/// Caller-assigned intensity label; it grants no scanner behavior by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanIntensity {
    Light,
    Normal,
    Aggressive,
    Stealth,
}

impl ScanIntensity {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Light => "light",
            Self::Normal => "normal",
            Self::Aggressive => "aggressive",
            Self::Stealth => "stealth",
        }
    }
}

/// Uninterpreted host configuration record with basic value validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub intensity: ScanIntensity,
    pub timeout_secs: u64,
    pub max_concurrency: u32,
    #[serde(with = "positive_f32")]
    pub rate_limit: f32,
    pub max_payload_size: u64,
    /// Historical phase identifiers supplied by a host; this module does not run them.
    pub phases: Vec<u8>,
    pub lua_engine: LuaEngineConfig,
}

mod positive_f32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &f32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if value.is_finite() && *value > 0.0 {
            serializer.serialize_f32(*value)
        } else {
            Err(serde::ser::Error::custom(
                "rate limit must be finite and greater than zero",
            ))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        if value.is_finite() && value > 0.0 {
            Ok(value)
        } else {
            Err(serde::de::Error::custom(
                "rate limit must be finite and greater than zero",
            ))
        }
    }
}

impl ScanConfig {
    /// Validates the record envelope without authorizing or executing a scan.
    pub fn validate(&self) -> Result<(), String> {
        if self.timeout_secs == 0 {
            return Err("Timeout must be > 0".to_string());
        }
        if self.max_concurrency == 0 {
            return Err("Max concurrency must be > 0".to_string());
        }
        if !self.rate_limit.is_finite() || self.rate_limit <= 0.0 {
            return Err("Rate limit must be finite and > 0".to_string());
        }
        if self.max_payload_size == 0 {
            return Err("Max payload size must be > 0".to_string());
        }
        if self.phases.is_empty() {
            return Err("At least one phase identifier must be supplied".to_string());
        }
        for phase in &self.phases {
            if !(1..=9).contains(phase) {
                return Err(format!("Invalid phase number: {phase}"));
            }
        }
        self.lua_engine
            .validate()
            .map_err(|error| format!("Invalid Lua engine configuration: {error}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_record() -> ScanConfig {
        ScanConfig {
            intensity: ScanIntensity::Normal,
            timeout_secs: 5,
            max_concurrency: 4,
            rate_limit: 10.0,
            max_payload_size: 1024,
            phases: vec![1, 2],
            lua_engine: LuaEngineConfig::minimal(),
        }
    }

    #[test]
    fn intensity_is_only_a_stable_label() {
        assert_eq!(ScanIntensity::Light.as_str(), "light");
        assert_eq!(ScanIntensity::Stealth.as_str(), "stealth");
    }

    #[test]
    fn valid_host_record_passes_envelope_validation() {
        assert!(valid_record().validate().is_ok());
    }

    #[test]
    fn invalid_limits_and_phase_ids_fail_closed() {
        let mut config = valid_record();
        config.timeout_secs = 0;
        assert!(config.validate().is_err());

        let mut config = valid_record();
        config.phases = vec![0];
        assert!(config.validate().is_err());

        for invalid_rate in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 0.0, -1.0] {
            let mut config = valid_record();
            config.rate_limit = invalid_rate;
            assert_eq!(
                config.validate().unwrap_err(),
                "Rate limit must be finite and > 0"
            );
        }
    }

    #[test]
    fn nested_lua_limits_are_validated() {
        let mut config = valid_record();
        config.lua_engine.default_timeout_ms = 0;
        assert_eq!(
            config.validate().unwrap_err(),
            "Invalid Lua engine configuration: default_timeout_ms must be nonzero"
        );
    }

    #[test]
    fn wire_rejects_invalid_rate_and_uses_fixed_width_limits() {
        let mut invalid = valid_record();
        invalid.rate_limit = f32::NAN;
        assert!(serde_json::to_string(&invalid).is_err());

        let record = valid_record();
        let encoded = serde_json::to_string(&record).expect("valid record serializes");
        let decoded: ScanConfig = serde_json::from_str(&encoded).expect("record round-trips");
        assert_eq!(decoded.max_concurrency, 4_u32);
        assert_eq!(decoded.max_payload_size, 1_024_u64);
    }
}
