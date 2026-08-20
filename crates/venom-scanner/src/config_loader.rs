//! In-memory profile models and registry.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `platform-models`.
//! - **Execution:** host/library only; no repository runtime caller.
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! This module does not parse TOML, load files, or drive a scanner. Hosts may
//! use it to store descriptive profile values for an experimental integration.

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
            description: "Descriptive enterprise policy model; not runtime-wired".to_string(),
            scan_intensity: ScanIntensity::Normal,
            timeout_secs: 300,
            rate_limit_rps: 10,
            concurrent_workers: 4,
            plugins_enabled: vec![],
            lua_scripts_enabled: vec![],
            event_subscriptions: vec![],
            options: HashMap::new(),
        }
    }

    /// Creates cloud scanning profile
    pub fn cloud() -> Self {
        Self {
            name: "cloud".to_string(),
            description: "Descriptive cloud policy model; not runtime-wired".to_string(),
            scan_intensity: ScanIntensity::Aggressive,
            timeout_secs: 600,
            rate_limit_rps: 50,
            concurrent_workers: 16,
            plugins_enabled: vec![],
            lua_scripts_enabled: vec![],
            event_subscriptions: vec![],
            options: HashMap::new(),
        }
    }

    /// Creates aggressive scanning profile
    pub fn aggressive() -> Self {
        Self {
            name: "aggressive".to_string(),
            description: "Descriptive high-intensity policy model; not runtime-wired".to_string(),
            scan_intensity: ScanIntensity::Aggressive,
            timeout_secs: 180,
            rate_limit_rps: 100,
            concurrent_workers: 32,
            plugins_enabled: vec![],
            lua_scripts_enabled: vec![],
            event_subscriptions: vec![],
            options: HashMap::new(),
        }
    }

    /// Creates passive scanning profile
    pub fn passive() -> Self {
        Self {
            name: "passive".to_string(),
            description: "Descriptive low-activity policy model; not runtime-wired".to_string(),
            scan_intensity: ScanIntensity::Stealth,
            timeout_secs: 60,
            rate_limit_rps: 5,
            concurrent_workers: 2,
            plugins_enabled: vec![],
            lua_scripts_enabled: vec![],
            event_subscriptions: vec![],
            options: HashMap::new(),
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

/// In-memory profile registry; it performs no file or environment loading.
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
        let mut profiles = self
            .profiles
            .iter()
            .map(|ref_multi| ref_multi.key().clone())
            .collect::<Vec<_>>();
        profiles.sort();
        profiles
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

    /// Overlays every profile field using deterministic collection semantics.
    ///
    /// Scalar fields come from `overlay`. List fields retain the base order,
    /// append overlay-only values in overlay order, and remove duplicates.
    /// Overlay option values replace base values with the same key.
    pub fn merge_profiles(&self, base: &str, overlay: &str) -> Result<ScanProfile, String> {
        let base_profile = self
            .get_profile(base)
            .ok_or_else(|| format!("Base profile '{}' not found", base))?;
        let overlay_profile = self
            .get_profile(overlay)
            .ok_or_else(|| format!("Overlay profile '{}' not found", overlay))?;

        let mut merged = base_profile;
        merged.name = format!("{}_merged_with_{}", base, overlay);
        merged.description = overlay_profile.description;
        merged.scan_intensity = overlay_profile.scan_intensity;
        merged.timeout_secs = overlay_profile.timeout_secs;
        merged.rate_limit_rps = overlay_profile.rate_limit_rps;
        merged.concurrent_workers = overlay_profile.concurrent_workers;
        extend_unique(&mut merged.plugins_enabled, overlay_profile.plugins_enabled);
        extend_unique(
            &mut merged.lua_scripts_enabled,
            overlay_profile.lua_scripts_enabled,
        );
        extend_unique(
            &mut merged.event_subscriptions,
            overlay_profile.event_subscriptions,
        );
        merged.options.extend(overlay_profile.options);

        Ok(merged)
    }
}

fn extend_unique(values: &mut Vec<String>, additions: Vec<String>) {
    for addition in additions {
        if !values.contains(&addition) {
            values.push(addition);
        }
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
    fn built_in_profiles_do_not_claim_unwired_capabilities() {
        for profile in [
            ScanProfile::enterprise(),
            ScanProfile::cloud(),
            ScanProfile::aggressive(),
            ScanProfile::passive(),
        ] {
            assert!(profile.plugins_enabled.is_empty());
            assert!(profile.lua_scripts_enabled.is_empty());
            assert!(profile.event_subscriptions.is_empty());
            assert!(profile.options.is_empty());
            assert!(profile.description.contains("not runtime-wired"));
        }
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
    fn profile_merge_overlays_every_field_deterministically() {
        let loader = ConfigLoader::new();

        let mut base = ScanProfile::custom("base", ScanIntensity::Light)
            .with_description("base description")
            .with_timeout(10)
            .with_rate_limit(2)
            .with_workers(1)
            .add_plugin("base-plugin")
            .add_plugin("shared-plugin")
            .add_script("base-script")
            .add_subscription("base-event")
            .add_option("base-only", "base")
            .add_option("shared-option", "base");
        base.options
            .insert("stable-option".to_owned(), "stable".to_owned());

        let overlay = ScanProfile::custom("overlay", ScanIntensity::Aggressive)
            .with_description("overlay description")
            .with_timeout(99)
            .with_rate_limit(42)
            .with_workers(8)
            .add_plugin("shared-plugin")
            .add_plugin("overlay-plugin")
            .add_script("overlay-script")
            .add_subscription("overlay-event")
            .add_option("shared-option", "overlay")
            .add_option("overlay-only", "overlay");
        loader.register_profile(base);
        loader.register_profile(overlay);

        let merged = loader.merge_profiles("base", "overlay").unwrap();

        assert_eq!(merged.name, "base_merged_with_overlay");
        assert_eq!(merged.description, "overlay description");
        assert_eq!(merged.scan_intensity, ScanIntensity::Aggressive);
        assert_eq!(merged.timeout_secs, 99);
        assert_eq!(merged.rate_limit_rps, 42);
        assert_eq!(merged.concurrent_workers, 8);
        assert_eq!(
            merged.plugins_enabled,
            vec![
                "base-plugin".to_owned(),
                "shared-plugin".to_owned(),
                "overlay-plugin".to_owned(),
            ]
        );
        assert_eq!(
            merged.lua_scripts_enabled,
            vec!["base-script".to_owned(), "overlay-script".to_owned()]
        );
        assert_eq!(
            merged.event_subscriptions,
            vec!["base-event".to_owned(), "overlay-event".to_owned()]
        );
        assert_eq!(merged.options["base-only"], "base");
        assert_eq!(merged.options["stable-option"], "stable");
        assert_eq!(merged.options["shared-option"], "overlay");
        assert_eq!(merged.options["overlay-only"], "overlay");
    }
}
