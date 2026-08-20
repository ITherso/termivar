#![cfg(feature = "threat-intel")]

use venom_scanner::{
    AlertAction, AlertRule, AlertRuleCatalog, CVERecord, CveCatalog, ThreatActorCatalog,
    ThreatActorProfile, ThreatFeedCatalog, ThreatFeedEntry, ThreatFeedSource, ThreatSeverity,
};

fn cve(id: &str, score: f32, exploit_available: bool) -> CVERecord {
    CVERecord {
        cve_id: id.into(),
        title: "fixture".into(),
        description: "caller supplied".into(),
        cvss_score: score,
        published_date: 1_000,
        updated_date: 2_000,
        affected_products: vec!["fixture-product".into()],
        exploit_available,
        active_exploitation: false,
    }
}

#[test]
fn cve_catalog_performs_only_explicit_record_queries() {
    let mut catalog = CveCatalog::new();
    catalog.record(cve("CVE-valid-low", 4.0, false)).unwrap();
    catalog.record(cve("CVE-valid-high", 9.0, true)).unwrap();
    assert!(catalog.record(cve("CVE-invalid", 20.0, true)).is_err());

    let high = catalog.records_at_or_above_cvss(8.0).unwrap();
    assert_eq!(high.len(), 1);
    assert_eq!(high[0].cve_id, "CVE-valid-high");
    assert!(catalog.records_at_or_above_cvss(-1.0).is_none());
    assert!(catalog.get("not-recorded").is_none());

    let reported = catalog.records_with_reported_exploit_evidence();
    assert_eq!(reported.len(), 1);
}

#[test]
fn cve_wire_validation_and_order_are_deterministic() {
    let valid = cve("CVE-roundtrip", 5.5, false);
    let json = serde_json::to_string(&valid).unwrap();
    assert_eq!(serde_json::from_str::<CVERecord>(&json).unwrap(), valid);
    assert!(serde_json::to_string(&cve("CVE-nonfinite", f32::INFINITY, false)).is_err());

    let mut catalog = CveCatalog::new();
    catalog.record(cve("CVE-Z", 8.0, false)).unwrap();
    catalog.record(cve("CVE-A", 8.0, false)).unwrap();
    let ids: Vec<_> = catalog
        .records_at_or_above_cvss(8.0)
        .unwrap()
        .into_iter()
        .map(|record| record.cve_id.as_str())
        .collect();
    assert_eq!(ids, vec!["CVE-A", "CVE-Z"]);
}

#[test]
fn feed_catalog_does_not_fetch_or_invent_entries() {
    let mut catalog = ThreatFeedCatalog::new();
    assert!(catalog.is_empty());
    let _ = catalog.record(ThreatFeedEntry {
        entry_id: "entry".into(),
        source: ThreatFeedSource::CISA,
        threat_type: "fixture".into(),
        severity: ThreatSeverity::High,
        description: "caller supplied".into(),
        indicators: vec!["indicator".into()],
        last_updated: 1_000,
    });

    assert_eq!(catalog.entries_from(ThreatFeedSource::CISA).len(), 1);
    assert!(catalog.entries_from(ThreatFeedSource::NVD).is_empty());
    assert!(catalog
        .entries_at_or_above(ThreatSeverity::Critical)
        .is_empty());
}

#[test]
fn rule_predicate_respects_enabled_and_threshold() {
    let mut catalog = AlertRuleCatalog::new();
    let _ = catalog.record_rule(AlertRule {
        rule_id: "enabled".into(),
        name: "enabled high".into(),
        severity_threshold: ThreatSeverity::High,
        enabled: true,
        requested_actions: vec![AlertAction::Notify],
    });
    let _ = catalog.record_rule(AlertRule {
        rule_id: "disabled".into(),
        name: "disabled low".into(),
        severity_threshold: ThreatSeverity::Low,
        enabled: false,
        requested_actions: vec![AlertAction::Block],
    });

    assert!(catalog.matching_rules(ThreatSeverity::Medium).is_empty());
    let evaluations = catalog.evaluate_all(ThreatSeverity::High);
    assert_eq!(
        evaluations.iter().filter(|result| result.matched).count(),
        1
    );
    assert!(evaluations
        .iter()
        .find(|result| result.rule_id == "disabled")
        .unwrap()
        .requested_actions
        .is_empty());
}

#[test]
fn actor_catalog_applies_only_explicit_severity_filter() {
    let mut catalog = ThreatActorCatalog::new();
    for (id, severity) in [
        ("medium", ThreatSeverity::Medium),
        ("critical", ThreatSeverity::Critical),
    ] {
        let _ = catalog.record(ThreatActorProfile {
            actor_id: id.into(),
            name: id.into(),
            aliases: Vec::new(),
            techniques: Vec::new(),
            infrastructure: Vec::new(),
            last_seen: 1_000,
            threat_level: severity,
        });
    }

    let critical = catalog.actors_at_or_above(ThreatSeverity::Critical);
    assert_eq!(critical.len(), 1);
    assert_eq!(critical[0].actor_id, "critical");
}

#[test]
fn labels_do_not_imply_external_activity() {
    assert_eq!(ThreatFeedSource::MitreAttack.as_str(), "mitre_att&ck");
    assert_eq!(ThreatSeverity::Critical.score(), 4);
    assert_eq!(AlertAction::Isolate.as_str(), "isolate");
}
