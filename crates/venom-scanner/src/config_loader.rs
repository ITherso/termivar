//! Configuration Management - TOML-based Config Profiles
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** host/library only; no repository runtime caller.
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Load and manage scanning profiles (enterprise, cloud, aggressive, etc.)

use crate::config::ScanIntensity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Scan profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    pub name: String,
    pub description: String,
    pub scan_intensity: ScanIntensity,
    pub timeout_secs: u32,
    pub rate_limit_rps: u32,
    pub concurrent_workers: u32,
    pub plugins_enabled: Vec<String>,
    pub lua_scripts_enabled: Vec<String>,
    pub event_subscriptions: Vec<String>,
    pub options: HashMap<String, String>,
}

/// Enterprise profile - Compliance-focused
impl Default for ScanProfile {
    fn default() -> Self {
        Self::enterprise()
    }
}

impl ScanProfile {
    /// Creates enterprise profile
    pub fn enterprise() -> Self {
        Self {
            name: "enterprise".to_string(),
            description: "Compliance-focused scanning with detailed reporting".to_string(),
            scan_intensity: ScanIntensity::Normal,
            timeout_secs: 300,
            rate_limit_rps: 10,
            concurrent_workers: 4,
            plugins_enabled: vec![],
            lua_scripts_enabled: vec![
                "compliance_check".to_string(),
                "risk_assessment".to_string(),
            ],
            event_subscriptions: vec!["finding_found".to_string(), "scan_completed".to_string()],
            options: {
                let mut opts = HashMap::new();
                opts.insert("report_format".to_string(), "pdf".to_string());
                opts.insert("include_compliance".to_string(), "true".to_string());
                opts
            },
        }
    }

    /// Creates cloud scanning profile
    pub fn cloud() -> Self {
        Self {
            name: "cloud".to_string(),
            description: "Optimized for cloud infrastructure scanning".to_string(),
            scan_intensity: ScanIntensity::Aggressive,
            timeout_secs: 600,
            rate_limit_rps: 50,
            concurrent_workers: 16,
            plugins_enabled: vec![],
            lua_scripts_enabled: vec!["cloud_config_check".to_string(), "api_security".to_string()],
            event_subscriptions: vec!["finding_found".to_string(), "worker_finished".to_string()],
            options: {
                let mut opts = HashMap::new();
                opts.insert("aws_detection".to_string(), "true".to_string());
                opts.insert("gcp_detection".to_string(), "true".to_string());
                opts.insert("azure_detection".to_string(), "true".to_string());
                opts
            },
        }
    }

    /// Creates aggressive scanning profile
    pub fn aggressive() -> Self {
        Self {
            name: "aggressive".to_string(),
            description: "Fast, comprehensive scanning".to_string(),
            scan_intensity: ScanIntensity::Aggressive,
            timeout_secs: 180,
            rate_limit_rps: 100,
            concurrent_workers: 32,
            plugins_enabled: vec![],
            lua_scripts_enabled: vec!["aggressive_scan".to_string(), "waf_bypass".to_string()],
            event_subscriptions: vec![
                "finding_found".to_string(),
                "worker_finished".to_string(),
                "plugin_executed".to_string(),
            ],
            options: {
                let mut opts = HashMap::new();
                opts.insert("waf_detection".to_string(), "true".to_string());
                opts.insert("fuzzing_level".to_string(), "high".to_string());
                opts
            },
        }
    }

    /// Creates passive scanning profile
    pub fn passive() -> Self {
        Self {
            name: "passive".to_string(),
            description: "Non-invasive passive scanning only".to_string(),
            scan_intensity: ScanIntensity::Stealth,
            timeout_secs: 60,
            rate_limit_rps: 5,
            concurrent_workers: 2,
            plugins_enabled: vec![],
            lua_scripts_enabled: vec!["passive_recon".to_string(), "header_analysis".to_string()],
            event_subscriptions: vec!["finding_found".to_string()],
            options: {
                let mut opts = HashMap::new();
                opts.insert("no_payloads".to_string(), "true".to_string());
                opts
            },
        }
    }

    /// Creates custom profile
    pub fn custom(name: impl Into<String>, intensity: ScanIntensity) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            scan_intensity: intensity,
            timeout_secs: 300,
            rate_limit_rps: 20,
            concurrent_workers: 8,
            plugins_enabled: vec![],
            lua_scripts_enabled: vec![],
            event_subscriptions: vec![],
            options: HashMap::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_timeout(mut self, secs: u32) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_rate_limit(mut self, rps: u32) -> Self {
        self.rate_limit_rps = rps;
        self
    }

    pub fn with_workers(mut self, count: u32) -> Self {
        self.concurrent_workers = count;
        self
    }

    pub fn add_plugin(mut self, plugin_id: impl Into<String>) -> Self {
        self.plugins_enabled.push(plugin_id.into());
        self
    }

    pub fn add_script(mut self, script_id: impl Into<String>) -> Self {
        self.lua_scripts_enabled.push(script_id.into());
        self
    }

    pub fn add_subscription(mut self, event: impl Into<String>) -> Self {
        self.event_subscriptions.push(event.into());
        self
    }

    pub fn add_option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.insert(key.into(), value.into());
        self
    }
}

/// Configuration loader
pub struct ConfigLoader {
    profiles: dashmap::DashMap<String, ScanProfile>,
    active_profile: std::sync::Mutex<String>,
}

impl ConfigLoader {
    /// Creates new config loader
    pub fn new() -> Self {
        let profiles = dashmap::DashMap::new();

        // Load built-in profiles
        profiles.insert("enterprise".to_string(), ScanProfile::enterprise());
        profiles.insert("cloud".to_string(), ScanProfile::cloud());
        profiles.insert("aggressive".to_string(), ScanProfile::aggressive());
        profiles.insert("passive".to_string(), ScanProfile::passive());

        Self {
            profiles,
            active_profile: std::sync::Mutex::new("enterprise".to_string()),
        }
    }

    /// Registers a profile
    pub fn register_profile(&self, profile: ScanProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// Gets profile by name
    pub fn get_profile(&self, name: &str) -> Option<ScanProfile> {
        self.profiles.get(name).map(|p| p.clone())
    }

    /// Lists all available profiles
    pub fn list_profiles(&self) -> Vec<String> {
        self.profiles
            .iter()
            .map(|ref_multi| ref_multi.key().clone())
            .collect()
    }

    /// Gets currently active profile
    pub fn get_active_profile(&self) -> ScanProfile {
        let name = self.active_profile.lock().unwrap().clone();
        self.get_profile(&name)
            .unwrap_or_else(ScanProfile::enterprise)
    }

    /// Sets active profile
    pub fn set_active_profile(&self, name: &str) -> Result<(), String> {
        if self.profiles.contains_key(name) {
            *self.active_profile.lock().unwrap() = name.to_string();
            Ok(())
        } else {
            Err(format!("Profile '{}' not found", name))
        }
    }

    /// Gets profile count
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Merges profiles (overlay custom on base)
    pub fn merge_profiles(&self, base: &str, overlay: &str) -> Result<ScanProfile, String> {
        let base_profile = self
            .get_profile(base)
            .ok_or_else(|| format!("Base profile '{}' not found", base))?;
        let overlay_profile = self
            .get_profile(overlay)
            .ok_or_else(|| format!("Overlay profile '{}' not found", overlay))?;

        let mut merged = base_profile;
        merged.name = format!("{}_merged_with_{}", base, overlay);
        merged.timeout_secs = overlay_profile.timeout_secs;
        merged.rate_limit_rps = overlay_profile.rate_limit_rps;
        merged.concurrent_workers = overlay_profile.concurrent_workers;
        merged
            .plugins_enabled
            .extend(overlay_profile.plugins_enabled);
        merged
            .lua_scripts_enabled
            .extend(overlay_profile.lua_scripts_enabled);
        merged.options.extend(overlay_profile.options);

        Ok(merged)
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_intensity() {
        assert_eq!(ScanIntensity::Light.as_str(), "light");
        assert_eq!(ScanIntensity::Stealth.as_str(), "stealth");
    }

    #[test]
    fn test_enterprise_profile() {
        let profile = ScanProfile::enterprise();
        assert_eq!(profile.name, "enterprise");
        assert_eq!(profile.scan_intensity, ScanIntensity::Normal);
        assert_eq!(profile.concurrent_workers, 4);
    }

    #[test]
    fn test_cloud_profile() {
        let profile = ScanProfile::cloud();
        assert_eq!(profile.name, "cloud");
        assert_eq!(profile.scan_intensity, ScanIntensity::Aggressive);
        assert_eq!(profile.concurrent_workers, 16);
    }

    #[test]
    fn test_aggressive_profile() {
        let profile = ScanProfile::aggressive();
        assert_eq!(profile.name, "aggressive");
        assert_eq!(profile.scan_intensity, ScanIntensity::Aggressive);
        assert!(profile.plugins_enabled.is_empty());
    }

    #[test]
    fn test_passive_profile() {
        let profile = ScanProfile::passive();
        assert_eq!(profile.name, "passive");
        assert_eq!(profile.scan_intensity, ScanIntensity::Stealth);
        assert_eq!(profile.plugins_enabled.len(), 0);
    }

    #[test]
    fn test_custom_profile() {
        let profile = ScanProfile::custom("test", ScanIntensity::Normal)
            .with_description("Test Profile")
            .with_timeout(120)
            .with_rate_limit(50)
            .with_workers(8);

        assert_eq!(profile.name, "test");
        assert_eq!(profile.description, "Test Profile");
        assert_eq!(profile.timeout_secs, 120);
        assert_eq!(profile.rate_limit_rps, 50);
        assert_eq!(profile.concurrent_workers, 8);
    }

    #[test]
    fn test_profile_with_plugins() {
        let profile = ScanProfile::custom("test", ScanIntensity::Normal)
            .add_plugin("example.marker.one")
            .add_plugin("example.marker.two");

        assert_eq!(profile.plugins_enabled.len(), 2);
    }

    #[test]
    fn test_profile_with_scripts() {
        let profile = ScanProfile::custom("test", ScanIntensity::Normal)
            .add_script("script1")
            .add_script("script2");

        assert_eq!(profile.lua_scripts_enabled.len(), 2);
    }

    #[test]
    fn test_profile_with_options() {
        let profile = ScanProfile::custom("test", ScanIntensity::Normal)
            .add_option("key1", "value1")
            .add_option("key2", "value2");

        assert_eq!(profile.options.get("key1"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_config_loader_creation() {
        let loader = ConfigLoader::new();
        assert!(loader.profile_count() >= 4);
    }

    #[test]
    fn test_config_loader_get_profile() {
        let loader = ConfigLoader::new();
        let enterprise = loader.get_profile("enterprise");

        assert!(enterprise.is_some());
        assert_eq!(enterprise.unwrap().name, "enterprise");
    }

    #[test]
    fn test_config_loader_list_profiles() {
        let loader = ConfigLoader::new();
        let profiles = loader.list_profiles();

        assert!(profiles.contains(&"enterprise".to_string()));
        assert!(profiles.contains(&"cloud".to_string()));
        assert!(profiles.contains(&"aggressive".to_string()));
        assert!(profiles.contains(&"passive".to_string()));
    }

    #[test]
    fn test_config_loader_active_profile() {
        let loader = ConfigLoader::new();
        let active = loader.get_active_profile();

        assert_eq!(active.name, "enterprise");
    }

    #[test]
    fn test_config_loader_set_active() {
        let loader = ConfigLoader::new();
        loader.set_active_profile("cloud").unwrap();

        let active = loader.get_active_profile();
        assert_eq!(active.name, "cloud");
    }

    #[test]
    fn test_config_loader_register_profile() {
        let loader = ConfigLoader::new();
        let initial_count = loader.profile_count();

        let custom = ScanProfile::custom("custom", ScanIntensity::Normal);
        loader.register_profile(custom);

        assert_eq!(loader.profile_count(), initial_count + 1);
        assert!(loader.get_profile("custom").is_some());
    }

    #[test]
    fn test_config_loader_merge_profiles() {
        let loader = ConfigLoader::new();

        let custom = ScanProfile::custom("custom", ScanIntensity::Normal).add_plugin("test_plugin");
        loader.register_profile(custom);

        let merged = loader.merge_profiles("enterprise", "custom");
        assert!(merged.is_ok());

        let merged_profile = merged.unwrap();
        assert!(merged_profile
            .plugins_enabled
            .contains(&"test_plugin".to_string()));
    }
}
