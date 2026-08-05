//! Scan Configuration Profiles
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** shared support (library configuration types).
//! - **Default `venom scan`:** no (support type, not an execution stage).
//! - **Support:** implemented.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Predefined and custom scan configurations for different scenarios.

use serde::{Deserialize, Serialize};

/// Lua Engine Configuration (P0 - configurable from config file)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaEngineConfig {
    /// Maximum execution history per script (prevents unbounded memory)
    /// Example: adaptive: history_size = 50
    pub history_size: usize,
    /// Maximum memory per Lua VM (bytes)
    pub max_memory_bytes: usize,
    /// Default script timeout (milliseconds)
    pub default_timeout_ms: u64,
}

impl LuaEngineConfig {
    /// Default config: reasonable limits for production
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        <Self as Default>::default()
    }

    /// Minimal config: for CI/tests
    pub fn minimal() -> Self {
        Self {
            history_size: 10,
            max_memory_bytes: 10_000_000,
            default_timeout_ms: 1000,
        }
    }

    /// Extended config: for dashboards/analysis
    pub fn extended() -> Self {
        Self {
            history_size: 500,             // Keep more history
            max_memory_bytes: 100_000_000, // 100MB per script
            default_timeout_ms: 30000,     // 30 second limit
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.history_size == 0 {
            return Err("history_size must be > 0".to_string());
        }
        if self.max_memory_bytes == 0 {
            return Err("max_memory_bytes must be > 0".to_string());
        }
        if self.default_timeout_ms == 0 {
            return Err("default_timeout_ms must be > 0".to_string());
        }
        Ok(())
    }
}

impl Default for LuaEngineConfig {
    fn default() -> Self {
        Self {
            history_size: 100,            // Keep last 100 executions
            max_memory_bytes: 50_000_000, // 50MB per script
            default_timeout_ms: 5000,     // 5 second default
        }
    }
}

/// Scan intensity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanIntensity {
    /// Light: Fast, low resource usage
    Light,
    /// Normal: Balanced performance and thoroughness
    Normal,
    /// Aggressive: Thorough, high resource usage
    Aggressive,
    /// Stealth: Slow, evasive, WAF-aware
    Stealth,
}

impl ScanIntensity {
    pub fn as_str(&self) -> &str {
        match self {
            ScanIntensity::Light => "light",
            ScanIntensity::Normal => "normal",
            ScanIntensity::Aggressive => "aggressive",
            ScanIntensity::Stealth => "stealth",
        }
    }
}

/// Scan configuration profile
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Scan intensity level
    pub intensity: ScanIntensity,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Maximum concurrent connections
    pub max_concurrency: usize,
    /// Rate limit (requests per second)
    pub rate_limit: f32,
    /// Enable WAF evasion
    pub enable_waf_evasion: bool,
    /// Enable adaptive payloads
    pub enable_adaptive_payloads: bool,
    /// Enable anomaly detection
    pub enable_anomaly_detection: bool,
    /// Maximum payload size
    pub max_payload_size: usize,
    /// Phases to execute (1-9)
    pub phases: Vec<u8>,
    /// Custom headers
    pub headers: Vec<(String, String)>,
    /// Lua Engine configuration (P0 - configurable from file)
    pub lua_engine: LuaEngineConfig,
}

impl ScanConfig {
    /// Creates a new config with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a light scan profile
    pub fn light() -> Self {
        Self {
            intensity: ScanIntensity::Light,
            timeout_secs: 3,
            max_concurrency: 10,
            rate_limit: 50.0,
            enable_waf_evasion: false,
            enable_adaptive_payloads: false,
            enable_anomaly_detection: false,
            max_payload_size: 1000,
            phases: vec![1, 2, 3],
            headers: Vec::new(),
            lua_engine: LuaEngineConfig::minimal(),
        }
    }

    /// Returns a normal scan profile
    pub fn normal() -> Self {
        Self {
            intensity: ScanIntensity::Normal,
            timeout_secs: 5,
            max_concurrency: 25,
            rate_limit: 20.0,
            enable_waf_evasion: true,
            enable_adaptive_payloads: true,
            enable_anomaly_detection: true,
            max_payload_size: 5000,
            phases: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            headers: Vec::new(),
            lua_engine: LuaEngineConfig::default(),
        }
    }

    /// Returns an aggressive scan profile
    pub fn aggressive() -> Self {
        Self {
            intensity: ScanIntensity::Aggressive,
            timeout_secs: 10,
            max_concurrency: 100,
            rate_limit: 100.0,
            enable_waf_evasion: true,
            enable_adaptive_payloads: true,
            enable_anomaly_detection: true,
            max_payload_size: 10000,
            phases: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            headers: Vec::new(),
            lua_engine: LuaEngineConfig::default(),
        }
    }

    /// Returns a stealth scan profile
    pub fn stealth() -> Self {
        Self {
            intensity: ScanIntensity::Stealth,
            timeout_secs: 15,
            max_concurrency: 5,
            rate_limit: 2.0,
            enable_waf_evasion: true,
            enable_adaptive_payloads: true,
            enable_anomaly_detection: true,
            max_payload_size: 2000,
            phases: vec![1, 2, 3, 5, 6, 7, 8],
            headers: vec![(
                "User-Agent".to_string(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            )],
            lua_engine: LuaEngineConfig::extended(), // Extended history for stealth
        }
    }

    /// Validates configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.timeout_secs == 0 {
            return Err("Timeout must be > 0".to_string());
        }
        if self.max_concurrency == 0 {
            return Err("Max concurrency must be > 0".to_string());
        }
        if self.rate_limit <= 0.0 {
            return Err("Rate limit must be > 0".to_string());
        }
        if self.max_payload_size == 0 {
            return Err("Max payload size must be > 0".to_string());
        }
        if self.phases.is_empty() {
            return Err("At least one phase must be enabled".to_string());
        }
        for phase in &self.phases {
            if *phase < 1 || *phase > 9 {
                return Err(format!("Invalid phase number: {}", phase));
            }
        }
        Ok(())
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self::normal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_intensity_str() {
        assert_eq!(ScanIntensity::Light.as_str(), "light");
        assert_eq!(ScanIntensity::Stealth.as_str(), "stealth");
    }

    #[test]
    fn test_light_config() {
        let cfg = ScanConfig::light();
        assert_eq!(cfg.intensity, ScanIntensity::Light);
        assert_eq!(cfg.timeout_secs, 3);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_normal_config() {
        let cfg = ScanConfig::normal();
        assert_eq!(cfg.intensity, ScanIntensity::Normal);
        assert_eq!(cfg.phases.len(), 9);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_aggressive_config() {
        let cfg = ScanConfig::aggressive();
        assert_eq!(cfg.intensity, ScanIntensity::Aggressive);
        assert_eq!(cfg.max_concurrency, 100);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_stealth_config() {
        let cfg = ScanConfig::stealth();
        assert_eq!(cfg.intensity, ScanIntensity::Stealth);
        assert_eq!(cfg.rate_limit, 2.0);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = ScanConfig::normal();
        assert!(cfg.validate().is_ok());

        cfg.timeout_secs = 0;
        assert!(cfg.validate().is_err());

        cfg.timeout_secs = 5;
        cfg.phases.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_custom_headers() {
        let mut cfg = ScanConfig::normal();
        cfg.headers
            .push(("X-Custom".to_string(), "value".to_string()));
        assert_eq!(cfg.headers.len(), 1);
    }
}
