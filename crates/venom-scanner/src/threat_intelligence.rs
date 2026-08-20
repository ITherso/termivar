//! Offline threat-intelligence records, catalogs, and rule predicates.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `threat-intel`.
//! - **Execution:** no repository runtime caller (not on any default path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental data models.
//!
//! This module does not fetch a feed, correlate observations, emit an alert,
//! execute an alert action, or persist data. Catalog queries inspect only
//! caller-supplied records. Alert rules evaluate one explicit severity
//! predicate and return a pure evaluation record.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

mod cvss_score {
    use super::*;

    fn is_valid(value: f32) -> bool {
        value.is_finite() && (0.0..=10.0).contains(&value)
    }

    pub fn serialize<S>(value: &f32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !is_valid(*value) {
            return Err(serde::ser::Error::custom(
                "CVSS score must be finite and in 0..=10",
            ));
        }
        serializer.serialize_f32(*value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        if !is_valid(value) {
            return Err(serde::de::Error::custom(
                "CVSS score must be finite and in 0..=10",
            ));
        }
        Ok(value)
    }
}

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
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NVD => "nvd",
            Self::CISA => "cisa",
            Self::ExploitDB => "exploit_db",
            Self::MitreAttack => "mitre_att&ck",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CVERecord {
    pub cve_id: String,
    pub title: String,
    pub description: String,
    #[serde(with = "cvss_score")]
    pub cvss_score: f32,
    pub published_date: u64,
    pub updated_date: u64,
    pub affected_products: Vec<String>,
    pub exploit_available: bool,
    pub active_exploitation: bool,
}

/// A CVE record carried a non-finite score or a score outside `0..=10`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCvssScore;

impl CVERecord {
    pub fn has_valid_cvss_score(&self) -> bool {
        self.cvss_score.is_finite() && (0.0..=10.0).contains(&self.cvss_score)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatFeedEntry {
    pub entry_id: String,
    pub source: ThreatFeedSource,
    pub threat_type: String,
    pub severity: ThreatSeverity,
    pub description: String,
    pub indicators: Vec<String>,
    pub last_updated: u64,
}

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
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn score(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

/// In-memory catalog of caller-supplied CVE records.
#[derive(Debug, Clone, Default)]
pub struct CveCatalog {
    records: BTreeMap<String, CVERecord>,
}

impl CveCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, record: CVERecord) -> Result<Option<CVERecord>, InvalidCvssScore> {
        if !record.has_valid_cvss_score() {
            return Err(InvalidCvssScore);
        }
        Ok(self.records.insert(record.cve_id.clone(), record))
    }

    pub fn get(&self, cve_id: &str) -> Option<&CVERecord> {
        self.records.get(cve_id)
    }

    /// Filters valid caller-supplied scores using an explicit valid threshold.
    pub fn records_at_or_above_cvss(&self, minimum: f32) -> Option<Vec<&CVERecord>> {
        if !minimum.is_finite() || !(0.0..=10.0).contains(&minimum) {
            return None;
        }
        Some(
            self.records
                .values()
                .filter(|record| record.cvss_score >= minimum)
                .collect(),
        )
    }

    /// Returns records whose caller-supplied exploit flags contain evidence.
    pub fn records_with_reported_exploit_evidence(&self) -> Vec<&CVERecord> {
        self.records
            .values()
            .filter(|record| record.exploit_available || record.active_exploitation)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// In-memory catalog of caller-supplied feed-entry records.
#[derive(Debug, Clone, Default)]
pub struct ThreatFeedCatalog {
    entries: BTreeMap<String, ThreatFeedEntry>,
}

impl ThreatFeedCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, entry: ThreatFeedEntry) -> Option<ThreatFeedEntry> {
        self.entries.insert(entry.entry_id.clone(), entry)
    }

    pub fn entries_from(&self, source: ThreatFeedSource) -> Vec<&ThreatFeedEntry> {
        self.entries
            .values()
            .filter(|entry| entry.source == source)
            .collect()
    }

    pub fn entries_at_or_above(&self, minimum: ThreatSeverity) -> Vec<&ThreatFeedEntry> {
        self.entries
            .values()
            .filter(|entry| entry.severity >= minimum)
            .collect()
    }

    pub fn entries_updated_at_or_after(&self, timestamp: u64) -> Vec<&ThreatFeedEntry> {
        self.entries
            .values()
            .filter(|entry| entry.last_updated >= timestamp)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Action requested by a matching rule. Evaluation does not execute it.
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
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Notify => "notify",
            Self::Isolate => "isolate",
            Self::Block => "block",
            Self::Escalate => "escalate",
            Self::Report => "report",
        }
    }
}

/// A single implemented predicate: enabled and severity at or above threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRule {
    pub rule_id: String,
    pub name: String,
    pub severity_threshold: ThreatSeverity,
    pub enabled: bool,
    pub requested_actions: Vec<AlertAction>,
}

impl AlertRule {
    pub fn evaluate(&self, observed_severity: ThreatSeverity) -> AlertEvaluation {
        let matched = self.enabled && observed_severity >= self.severity_threshold;
        AlertEvaluation {
            rule_id: self.rule_id.clone(),
            observed_severity,
            matched,
            requested_actions: if matched {
                self.requested_actions.clone()
            } else {
                Vec::new()
            },
        }
    }
}

/// Pure rule-evaluation result. No alert was delivered and no action was run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertEvaluation {
    pub rule_id: String,
    pub observed_severity: ThreatSeverity,
    pub matched: bool,
    pub requested_actions: Vec<AlertAction>,
}

/// In-memory rule catalog. It stores rules, not emitted alerts.
#[derive(Debug, Clone, Default)]
pub struct AlertRuleCatalog {
    rules: BTreeMap<String, AlertRule>,
}

impl AlertRuleCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_rule(&mut self, rule: AlertRule) -> Option<AlertRule> {
        self.rules.insert(rule.rule_id.clone(), rule)
    }

    pub fn evaluate_all(&self, observed_severity: ThreatSeverity) -> Vec<AlertEvaluation> {
        self.rules
            .values()
            .map(|rule| rule.evaluate(observed_severity))
            .collect()
    }

    pub fn matching_rules(&self, observed_severity: ThreatSeverity) -> Vec<&AlertRule> {
        self.rules
            .values()
            .filter(|rule| rule.enabled && observed_severity >= rule.severity_threshold)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatActorProfile {
    pub actor_id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub techniques: Vec<String>,
    pub infrastructure: Vec<String>,
    pub last_seen: u64,
    pub threat_level: ThreatSeverity,
}

/// In-memory catalog of caller-supplied actor profiles.
#[derive(Debug, Clone, Default)]
pub struct ThreatActorCatalog {
    actors: BTreeMap<String, ThreatActorProfile>,
}

impl ThreatActorCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, actor: ThreatActorProfile) -> Option<ThreatActorProfile> {
        self.actors.insert(actor.actor_id.clone(), actor)
    }

    pub fn get(&self, actor_id: &str) -> Option<&ThreatActorProfile> {
        self.actors.get(actor_id)
    }

    pub fn actors_at_or_above(&self, minimum: ThreatSeverity) -> Vec<&ThreatActorProfile> {
        self.actors
            .values()
            .filter(|actor| actor.threat_level >= minimum)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.actors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.actors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cve(id: &str, score: f32) -> CVERecord {
        CVERecord {
            cve_id: id.into(),
            title: "fixture".into(),
            description: "fixture".into(),
            cvss_score: score,
            published_date: 1,
            updated_date: 2,
            affected_products: Vec::new(),
            exploit_available: false,
            active_exploitation: false,
        }
    }

    #[test]
    fn cve_catalog_queries_records_without_claiming_correlation() {
        let mut catalog = CveCatalog::new();
        catalog.record(cve("valid", 9.0)).unwrap();
        assert_eq!(catalog.record(cve("invalid", 11.0)), Err(InvalidCvssScore));

        let records = catalog.records_at_or_above_cvss(8.0).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].cve_id, "valid");
        assert_eq!(catalog.records_at_or_above_cvss(f32::NAN), None);
    }

    #[test]
    fn cvss_score_round_trips_and_rejects_invalid_wire_values() {
        let valid = cve("CVE-1", 7.5);
        let json = serde_json::to_string(&valid).unwrap();
        assert_eq!(serde_json::from_str::<CVERecord>(&json).unwrap(), valid);

        assert!(serde_json::to_string(&cve("CVE-2", f32::NAN)).is_err());
        let invalid = r#"{"cve_id":"CVE-3","title":"fixture","description":"fixture","cvss_score":10.1,"published_date":1,"updated_date":2,"affected_products":[],"exploit_available":false,"active_exploitation":false}"#;
        assert!(serde_json::from_str::<CVERecord>(invalid).is_err());
    }

    #[test]
    fn catalog_queries_are_ordered_by_record_id() {
        let mut cves = CveCatalog::new();
        cves.record(cve("CVE-Z", 9.0)).unwrap();
        cves.record(cve("CVE-A", 9.0)).unwrap();
        let ids: Vec<_> = cves
            .records_at_or_above_cvss(0.0)
            .unwrap()
            .into_iter()
            .map(|record| record.cve_id.as_str())
            .collect();
        assert_eq!(ids, vec!["CVE-A", "CVE-Z"]);

        let mut rules = AlertRuleCatalog::new();
        for id in ["z-rule", "a-rule"] {
            rules.record_rule(AlertRule {
                rule_id: id.into(),
                name: id.into(),
                severity_threshold: ThreatSeverity::Low,
                enabled: true,
                requested_actions: Vec::new(),
            });
        }
        let rule_ids: Vec<_> = rules
            .evaluate_all(ThreatSeverity::Low)
            .into_iter()
            .map(|evaluation| evaluation.rule_id)
            .collect();
        assert_eq!(rule_ids, vec!["a-rule", "z-rule"]);

        let mut feeds = ThreatFeedCatalog::new();
        for id in ["z-entry", "a-entry"] {
            feeds.record(ThreatFeedEntry {
                entry_id: id.into(),
                source: ThreatFeedSource::CISA,
                threat_type: "fixture".into(),
                severity: ThreatSeverity::High,
                description: "fixture".into(),
                indicators: Vec::new(),
                last_updated: 1,
            });
        }
        let entry_ids: Vec<_> = feeds
            .entries_at_or_above(ThreatSeverity::Low)
            .into_iter()
            .map(|entry| entry.entry_id.as_str())
            .collect();
        assert_eq!(entry_ids, vec!["a-entry", "z-entry"]);

        let mut actors = ThreatActorCatalog::new();
        for id in ["z-actor", "a-actor"] {
            actors.record(ThreatActorProfile {
                actor_id: id.into(),
                name: id.into(),
                aliases: Vec::new(),
                techniques: Vec::new(),
                infrastructure: Vec::new(),
                last_seen: 1,
                threat_level: ThreatSeverity::High,
            });
        }
        let actor_ids: Vec<_> = actors
            .actors_at_or_above(ThreatSeverity::Low)
            .into_iter()
            .map(|actor| actor.actor_id.as_str())
            .collect();
        assert_eq!(actor_ids, vec!["a-actor", "z-actor"]);
    }

    #[test]
    fn disabled_and_below_threshold_rules_do_not_match() {
        let disabled = AlertRule {
            rule_id: "disabled".into(),
            name: "disabled".into(),
            severity_threshold: ThreatSeverity::Low,
            enabled: false,
            requested_actions: vec![AlertAction::Block],
        };
        let enabled = AlertRule {
            rule_id: "enabled".into(),
            name: "enabled".into(),
            severity_threshold: ThreatSeverity::Critical,
            enabled: true,
            requested_actions: vec![AlertAction::Notify],
        };

        assert!(!disabled.evaluate(ThreatSeverity::Critical).matched);
        assert!(disabled
            .evaluate(ThreatSeverity::Critical)
            .requested_actions
            .is_empty());
        assert!(!enabled.evaluate(ThreatSeverity::High).matched);
        assert!(enabled
            .evaluate(ThreatSeverity::High)
            .requested_actions
            .is_empty());
    }

    #[test]
    fn matching_rule_returns_requested_actions_without_execution_claim() {
        let rule = AlertRule {
            rule_id: "rule".into(),
            name: "fixture".into(),
            severity_threshold: ThreatSeverity::High,
            enabled: true,
            requested_actions: vec![AlertAction::Escalate],
        };
        let evaluation = rule.evaluate(ThreatSeverity::Critical);
        assert!(evaluation.matched);
        assert_eq!(evaluation.requested_actions, vec![AlertAction::Escalate]);
    }
}
