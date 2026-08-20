//! Historical configuration compatibility facade.
//!
//! This module is available only with the non-default `legacy-contracts`
//! feature. No repository runtime consumes this configuration or its
//! environment overrides; scanner hosts use their feature-specific contracts.
//!
//! ## Deprecated compatibility surface
//!
//! These types remain solely for the pinned pre-1.0 patch-compatibility
//! baseline. New integrations should not adopt them.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::Path;

/// Historical scan configuration retained for compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Target URL/IP to scan
    pub target: String,

    /// Scan intensity (light, normal, aggressive, stealth)
    pub intensity: ScanIntensity,

    /// Scan timeout in seconds (must be > 0)
    pub timeout_secs: u64,

    /// Maximum concurrent workers (must be > 0)
    pub num_threads: u32,

    /// Requests per second rate limit (>= 0)
    pub rate_limit_rps: u32,

    /// Enable aggressive scanning
    pub aggressive: bool,

    /// Maximum payload size in bytes
    pub max_payload_size: usize,

    /// Custom options
    pub options: HashMap<String, String>,

    /// Enable SSL verification
    pub verify_ssl: bool,

    /// Connection timeout in seconds
    pub connect_timeout_secs: u64,
}

/// Scan intensity levels
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanIntensity {
    #[serde(rename = "light")]
    Light,
    #[serde(rename = "normal")]
    #[default]
    Normal,
    #[serde(rename = "aggressive")]
    Aggressive,
    #[serde(rename = "stealth")]
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

/// Validation errors
#[derive(Debug, Clone)]
pub enum ConfigError {
    TargetEmpty,
    TimeoutZero,
    NumThreadsZero,
    RateLimitNegative,
    MaxPayloadSizeZero,
    ConnectTimeoutZero,
    InvalidTarget(String),
    ParseError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConfigError::TargetEmpty => write!(f, "Target cannot be empty"),
            ConfigError::TimeoutZero => write!(f, "Timeout must be greater than 0"),
            ConfigError::NumThreadsZero => write!(f, "Number of threads must be greater than 0"),
            ConfigError::RateLimitNegative => write!(f, "Rate limit cannot be negative"),
            ConfigError::MaxPayloadSizeZero => write!(f, "Max payload size must be greater than 0"),
            ConfigError::ConnectTimeoutZero => write!(f, "Connect timeout must be greater than 0"),
            ConfigError::InvalidTarget(msg) => write!(f, "Invalid target: {}", msg),
            ConfigError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Validates configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Target validation
        if self.target.is_empty() {
            return Err(ConfigError::TargetEmpty);
        }

        // Basic URL validation (should start with http:// or https://)
        if !self.target.starts_with("http://")
            && !self.target.starts_with("https://")
            && !self.target.contains(':')
            && !self.target.contains('.')
        {
            return Err(ConfigError::InvalidTarget(
                "Must be valid URL or IP address".to_string(),
            ));
        }

        // Timeout validation
        if self.timeout_secs == 0 {
            return Err(ConfigError::TimeoutZero);
        }

        // Thread validation
        if self.num_threads == 0 {
            return Err(ConfigError::NumThreadsZero);
        }

        // Rate limit validation
        if self.rate_limit_rps > 1_000_000 {
            return Err(ConfigError::RateLimitNegative);
        }

        // Payload size validation
        if self.max_payload_size == 0 {
            return Err(ConfigError::MaxPayloadSizeZero);
        }

        // Connect timeout validation
        if self.connect_timeout_secs == 0 {
            return Err(ConfigError::ConnectTimeoutZero);
        }

        Ok(())
    }

    /// Creates a builder for fluent configuration
    pub fn builder(target: impl Into<String>) -> ConfigBuilder {
        ConfigBuilder::new(target)
    }

    /// Loads configuration from TOML file with environment overrides
    pub fn from_toml(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::ParseError(format!("Failed to read file: {}", e)))?;

        let mut config: Config = toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(format!("Failed to parse TOML: {}", e)))?;

        // Apply environment overrides
        config.apply_env_overrides()?;
        config.validate()?;

        Ok(config)
    }

    /// Applies environment variable overrides
    pub fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
        // Override target
        if let Ok(target) = env::var("VENOM_TARGET") {
            self.target = target;
        }

        // Override timeout
        if let Ok(timeout) = env::var("VENOM_TIMEOUT_SECS") {
            self.timeout_secs = timeout
                .parse()
                .map_err(|_| ConfigError::ParseError("Invalid VENOM_TIMEOUT_SECS".to_string()))?;
        }

        // Override num_threads
        if let Ok(threads) = env::var("VENOM_NUM_THREADS") {
            self.num_threads = threads
                .parse()
                .map_err(|_| ConfigError::ParseError("Invalid VENOM_NUM_THREADS".to_string()))?;
        }

        // Override rate_limit_rps
        if let Ok(rate_limit) = env::var("VENOM_RATE_LIMIT_RPS") {
            self.rate_limit_rps = rate_limit
                .parse()
                .map_err(|_| ConfigError::ParseError("Invalid VENOM_RATE_LIMIT_RPS".to_string()))?;
        }

        // Override intensity
        if let Ok(intensity) = env::var("VENOM_INTENSITY") {
            self.intensity = match intensity.as_str() {
                "light" => ScanIntensity::Light,
                "aggressive" => ScanIntensity::Aggressive,
                "stealth" => ScanIntensity::Stealth,
                _ => ScanIntensity::Normal,
            };
        }

        // Override aggressive flag
        if let Ok(aggressive) = env::var("VENOM_AGGRESSIVE") {
            self.aggressive = aggressive.to_lowercase() == "true" || aggressive == "1";
        }

        // Override verify_ssl
        if let Ok(verify) = env::var("VENOM_VERIFY_SSL") {
            self.verify_ssl = verify.to_lowercase() == "true" || verify == "1";
        }

        Ok(())
    }

    /// Exports configuration as TOML string
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self)
            .map_err(|e| ConfigError::ParseError(format!("Failed to serialize to TOML: {}", e)))
    }

    /// Exports configuration as JSON string
    pub fn to_json(&self) -> Result<String, ConfigError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| ConfigError::ParseError(format!("Failed to serialize to JSON: {}", e)))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target: String::new(),
            intensity: ScanIntensity::Normal,
            timeout_secs: 300,
            num_threads: 4,
            rate_limit_rps: 50,
            aggressive: false,
            max_payload_size: 10240,
            options: HashMap::new(),
            verify_ssl: true,
            connect_timeout_secs: 30,
        }
    }
}

/// Builder for creating Config with validation
pub struct ConfigBuilder {
    target: String,
    intensity: ScanIntensity,
    timeout_secs: u64,
    num_threads: u32,
    rate_limit_rps: u32,
    aggressive: bool,
    max_payload_size: usize,
    options: HashMap<String, String>,
    verify_ssl: bool,
    connect_timeout_secs: u64,
}

impl ConfigBuilder {
    /// Creates new builder with required target
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            intensity: ScanIntensity::Normal,
            timeout_secs: 300,
            num_threads: 4,
            rate_limit_rps: 50,
            aggressive: false,
            max_payload_size: 10240,
            options: HashMap::new(),
            verify_ssl: true,
            connect_timeout_secs: 30,
        }
    }

    /// Sets scan intensity
    pub fn intensity(mut self, intensity: ScanIntensity) -> Self {
        self.intensity = intensity;
        self
    }

    /// Sets timeout in seconds
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Sets number of threads
    pub fn threads(mut self, count: u32) -> Self {
        self.num_threads = count;
        self
    }

    /// Sets rate limit (requests per second)
    pub fn rate_limit(mut self, rps: u32) -> Self {
        self.rate_limit_rps = rps;
        self
    }

    /// Enables aggressive scanning
    pub fn aggressive(mut self, enabled: bool) -> Self {
        self.aggressive = enabled;
        self
    }

    /// Sets maximum payload size
    pub fn max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
    }

    /// Adds custom option
    pub fn option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.insert(key.into(), value.into());
        self
    }

    /// Sets SSL verification
    pub fn verify_ssl(mut self, verify: bool) -> Self {
        self.verify_ssl = verify;
        self
    }

    /// Sets connection timeout
    pub fn connect_timeout(mut self, secs: u64) -> Self {
        self.connect_timeout_secs = secs;
        self
    }

    /// Builds and validates configuration
    pub fn build(self) -> Result<Config, ConfigError> {
        let config = Config {
            target: self.target,
            intensity: self.intensity,
            timeout_secs: self.timeout_secs,
            num_threads: self.num_threads,
            rate_limit_rps: self.rate_limit_rps,
            aggressive: self.aggressive,
            max_payload_size: self.max_payload_size,
            options: self.options,
            verify_ssl: self.verify_ssl,
            connect_timeout_secs: self.connect_timeout_secs,
        };

        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation_empty_target() {
        let config = Config {
            target: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_zero_timeout() {
        let config = Config {
            target: "http://localhost".to_string(),
            timeout_secs: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_zero_threads() {
        let config = Config {
            target: "http://localhost".to_string(),
            num_threads: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_valid() {
        let config = Config {
            target: "http://localhost:8080".to_string(),
            timeout_secs: 300,
            num_threads: 4,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_builder_basic() {
        let config = Config::builder("http://localhost")
            .timeout(600)
            .threads(8)
            .build()
            .unwrap();

        assert_eq!(config.target, "http://localhost");
        assert_eq!(config.timeout_secs, 600);
        assert_eq!(config.num_threads, 8);
    }

    #[test]
    fn test_builder_with_options() {
        let config = Config::builder("http://target.com")
            .intensity(ScanIntensity::Aggressive)
            .aggressive(true)
            .option("custom_key", "custom_value")
            .build()
            .unwrap();

        assert_eq!(config.intensity, ScanIntensity::Aggressive);
        assert!(config.aggressive);
        assert_eq!(
            config.options.get("custom_key"),
            Some(&"custom_value".to_string())
        );
    }

    #[test]
    fn test_builder_validation_fails() {
        let result = Config::builder("http://localhost").timeout(0).build();

        assert!(result.is_err());
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.timeout_secs, 300);
        assert_eq!(config.num_threads, 4);
        assert_eq!(config.rate_limit_rps, 50);
        assert_eq!(config.intensity, ScanIntensity::Normal);
    }

    #[test]
    fn test_scan_intensity() {
        assert_eq!(ScanIntensity::Light.as_str(), "light");
        assert_eq!(ScanIntensity::Aggressive.as_str(), "aggressive");
        assert_eq!(ScanIntensity::Stealth.as_str(), "stealth");
    }

    #[test]
    fn test_config_to_toml() {
        let config = Config::builder("http://localhost")
            .timeout(300)
            .threads(4)
            .build()
            .unwrap();

        let toml = config.to_toml();
        assert!(toml.is_ok());
        let toml_str = toml.unwrap();
        assert!(toml_str.contains("http://localhost"));
    }

    #[test]
    fn test_config_to_json() {
        let config = Config::builder("http://localhost")
            .timeout(300)
            .threads(4)
            .build()
            .unwrap();

        let json = config.to_json();
        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("http://localhost"));
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::TargetEmpty;
        assert_eq!(err.to_string(), "Target cannot be empty");
    }
}
