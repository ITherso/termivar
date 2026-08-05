//! Threat Intelligence & Security Alerts
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `threat-intel`.
//! - **Execution:** no repository runtime caller (not on any default path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! CVE correlation, threat feeds, automated responses.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Threat intelligence feed source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatFeedSource {
    #[serde(rename = "nvd")]
    NVD,
    #[serde(rename = "cisa")]
    CISA,
    #[serde(rename = "exploit_db")]
    ExploitDB,
    #[serde(rename = "mitre_att&ck")]
    MitreAttack,
    #[serde(rename = "custom")]
    Custom,
}

impl ThreatFeedSource {
    pub fn as_str(&self) -> &str {
        match self {
            ThreatFeedSource::NVD => "nvd",
            ThreatFeedSource::CISA => "cisa",
            ThreatFeedSource::ExploitDB => "exploit_db",
            ThreatFeedSource::MitreAttack => "mitre_att&ck",
            ThreatFeedSource::Custom => "custom",
        }
    }
}

/// CVE record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVERecord {
    pub cve_id: String,
    pub title: String,
    pub description: String,
    pub cvss_score: f32,
    pub published_date: u64,
    pub updated_date: u64,
    pub affected_products: Vec<String>,
    pub exploit_available: bool,
    pub active_exploitation: bool,
}

/// Threat feed entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedEntry {
    pub entry_id: String,
    pub source: ThreatFeedSource,
    pub threat_type: String,
    pub severity: ThreatSeverity,
    pub description: String,
    pub indicators: Vec<String>,
    pub last_updated: u64,
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatSeverity {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

impl ThreatSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            ThreatSeverity::Low => "low",
            ThreatSeverity::Medium => "medium",
            ThreatSeverity::High => "high",
            ThreatSeverity::Critical => "critical",
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            ThreatSeverity::Low => 1,
            ThreatSeverity::Medium => 2,
            ThreatSeverity::High => 3,
            ThreatSeverity::Critical => 4,
        }
    }
}

/// CVE correlator for matching vulnerabilities
pub struct CVECorrelator {
    cves: HashMap<String, CVERecord>,
}

impl CVECorrelator {
    pub fn new() -> Self {
        Self {
            cves: HashMap::new(),
        }
    }

    /// Registers a CVE record
    pub fn register_cve(&mut self, cve: CVERecord) {
        self.cves.insert(cve.cve_id.clone(), cve);
    }

    /// Gets CVE by ID
    pub fn get_cve(&self, cve_id: &str) -> Option<&CVERecord> {
        self.cves.get(cve_id)
    }

    /// Finds CVEs by severity
    pub fn get_cves_by_severity(&self, min_cvss: f32) -> Vec<&CVERecord> {
        self.cves
            .values()
            .filter(|cve| cve.cvss_score >= min_cvss)
            .collect()
    }

    /// Finds exploitable CVEs
    pub fn get_exploitable_cves(&self) -> Vec<&CVERecord> {
        self.cves
            .values()
            .filter(|cve| cve.exploit_available || cve.active_exploitation)
            .collect()
    }

    pub fn cve_count(&self) -> usize {
        self.cves.len()
    }
}

impl Default for CVECorrelator {
    fn default() -> Self {
        Self::new()
    }
}

/// Threat feed manager
pub struct ThreatFeedManager {
    feeds: HashMap<String, ThreatFeedEntry>,
}

impl ThreatFeedManager {
    pub fn new() -> Self {
        Self {
            feeds: HashMap::new(),
        }
    }

    /// Ingests a threat feed entry
    pub fn ingest_entry(&mut self, entry: ThreatFeedEntry) {
        self.feeds.insert(entry.entry_id.clone(), entry);
    }

    /// Gets entries by source
    pub fn get_by_source(&self, source: ThreatFeedSource) -> Vec<&ThreatFeedEntry> {
        self.feeds.values().filter(|e| e.source == source).collect()
    }

    /// Gets critical threats
    pub fn get_critical_threats(&self) -> Vec<&ThreatFeedEntry> {
        self.feeds
            .values()
            .filter(|e| e.severity == ThreatSeverity::Critical)
            .collect()
    }

    /// Gets recent threats
    pub fn get_recent_threats(&self, since: u64) -> Vec<&ThreatFeedEntry> {
        self.feeds
            .values()
            .filter(|e| e.last_updated >= since)
            .collect()
    }

    pub fn entry_count(&self) -> usize {
        self.feeds.len()
    }
}

impl Default for ThreatFeedManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Alert rule for automated responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub rule_id: String,
    pub name: String,
    pub condition: String,
    pub severity_threshold: ThreatSeverity,
    pub enabled: bool,
    pub actions: Vec<AlertAction>,
}

/// Alert actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertAction {
    #[serde(rename = "notify")]
    Notify,
    #[serde(rename = "isolate")]
    Isolate,
    #[serde(rename = "block")]
    Block,
    #[serde(rename = "escalate")]
    Escalate,
    #[serde(rename = "report")]
    Report,
}

impl AlertAction {
    pub fn as_str(&self) -> &str {
        match self {
            AlertAction::Notify => "notify",
            AlertAction::Isolate => "isolate",
            AlertAction::Block => "block",
            AlertAction::Escalate => "escalate",
            AlertAction::Report => "report",
        }
    }
}

/// Alert engine for rule processing
pub struct AlertEngine {
    rules: HashMap<String, AlertRule>,
    alerts: Vec<SecurityAlert>,
}

/// Security alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub alert_id: String,
    pub rule_id: String,
    pub severity: ThreatSeverity,
    pub message: String,
    pub timestamp: u64,
    pub triggered: bool,
}

impl AlertEngine {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    /// Registers an alert rule
    pub fn register_rule(&mut self, rule: AlertRule) {
        self.rules.insert(rule.rule_id.clone(), rule);
    }

    /// Processes an alert
    pub fn process_alert(&mut self, alert: SecurityAlert) {
        self.alerts.push(alert);
    }

    /// Gets active alerts
    pub fn get_active_alerts(&self) -> Vec<&SecurityAlert> {
        self.alerts.iter().filter(|a| a.triggered).collect()
    }

    /// Gets alerts by severity
    pub fn get_alerts_by_severity(&self, severity: ThreatSeverity) -> Vec<&SecurityAlert> {
        self.alerts
            .iter()
            .filter(|a| a.severity == severity)
            .collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }
}

impl Default for AlertEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Threat actor profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorProfile {
    pub actor_id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub techniques: Vec<String>,
    pub infrastructure: Vec<String>,
    pub last_seen: u64,
    pub threat_level: ThreatSeverity,
}

/// Threat intelligence repository
pub struct ThreatIntelligenceRepo {
    actors: HashMap<String, ThreatActorProfile>,
}

impl ThreatIntelligenceRepo {
    pub fn new() -> Self {
        Self {
            actors: HashMap::new(),
        }
    }

    /// Registers a threat actor
    pub fn register_actor(&mut self, actor: ThreatActorProfile) {
        self.actors.insert(actor.actor_id.clone(), actor);
    }

    /// Gets actor by ID
    pub fn get_actor(&self, actor_id: &str) -> Option<&ThreatActorProfile> {
        self.actors.get(actor_id)
    }

    /// Gets critical threat actors
    pub fn get_critical_actors(&self) -> Vec<&ThreatActorProfile> {
        self.actors
            .values()
            .filter(|a| a.threat_level == ThreatSeverity::Critical)
            .collect()
    }

    pub fn actor_count(&self) -> usize {
        self.actors.len()
    }
}

impl Default for ThreatIntelligenceRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_feed_source() {
        assert_eq!(ThreatFeedSource::NVD.as_str(), "nvd");
        assert_eq!(ThreatFeedSource::CISA.as_str(), "cisa");
    }

    #[test]
    fn test_cve_record() {
        let cve = CVERecord {
            cve_id: "CVE-2024-1234".to_string(),
            title: "Critical RCE".to_string(),
            description: "Remote code execution".to_string(),
            cvss_score: 9.8,
            published_date: 1000,
            updated_date: 2000,
            affected_products: vec!["product1".to_string()],
            exploit_available: true,
            active_exploitation: true,
        };

        assert_eq!(cve.cvss_score, 9.8);
        assert!(cve.exploit_available);
    }

    #[test]
    fn test_threat_severity() {
        assert_eq!(ThreatSeverity::Low.score(), 1);
        assert_eq!(ThreatSeverity::Critical.score(), 4);
        assert!(ThreatSeverity::Critical > ThreatSeverity::High);
    }

    #[test]
    fn test_cve_correlator() {
        let mut correlator = CVECorrelator::new();
        let cve = CVERecord {
            cve_id: "CVE-2024-0001".to_string(),
            title: "Test".to_string(),
            description: "Test CVE".to_string(),
            cvss_score: 9.0,
            published_date: 1000,
            updated_date: 2000,
            affected_products: vec![],
            exploit_available: true,
            active_exploitation: false,
        };

        correlator.register_cve(cve);
        assert_eq!(correlator.cve_count(), 1);
    }

    #[test]
    fn test_threat_feed_manager() {
        let mut manager = ThreatFeedManager::new();
        let entry = ThreatFeedEntry {
            entry_id: "threat1".to_string(),
            source: ThreatFeedSource::CISA,
            threat_type: "Malware".to_string(),
            severity: ThreatSeverity::High,
            description: "Active threat".to_string(),
            indicators: vec!["ip1".to_string()],
            last_updated: 1000,
        };

        manager.ingest_entry(entry);
        assert_eq!(manager.entry_count(), 1);
    }

    #[test]
    fn test_alert_action() {
        assert_eq!(AlertAction::Notify.as_str(), "notify");
        assert_eq!(AlertAction::Block.as_str(), "block");
    }

    #[test]
    fn test_alert_engine() {
        let mut engine = AlertEngine::new();
        let rule = AlertRule {
            rule_id: "rule1".to_string(),
            name: "Critical Alert".to_string(),
            condition: "severity >= critical".to_string(),
            severity_threshold: ThreatSeverity::Critical,
            enabled: true,
            actions: vec![AlertAction::Escalate],
        };

        engine.register_rule(rule);
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn test_threat_actor_profile() {
        let actor = ThreatActorProfile {
            actor_id: "actor1".to_string(),
            name: "APT28".to_string(),
            aliases: vec!["Fancy Bear".to_string()],
            techniques: vec!["Spear Phishing".to_string()],
            infrastructure: vec!["server1".to_string()],
            last_seen: 1000,
            threat_level: ThreatSeverity::Critical,
        };

        assert_eq!(actor.name, "APT28");
        assert_eq!(actor.threat_level, ThreatSeverity::Critical);
    }
}
