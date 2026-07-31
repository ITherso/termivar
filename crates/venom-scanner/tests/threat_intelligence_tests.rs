use venom_scanner::{
    AlertAction, AlertEngine, AlertRule, CVECorrelator, CVERecord, SecurityAlert,
    ThreatActorProfile, ThreatFeedEntry, ThreatFeedManager, ThreatFeedSource,
    ThreatIntelligenceRepo, ThreatSeverity,
};

#[test]
fn test_threat_feed_source_variants() {
    assert_eq!(ThreatFeedSource::NVD.as_str(), "nvd");
    assert_eq!(ThreatFeedSource::CISA.as_str(), "cisa");
    assert_eq!(ThreatFeedSource::ExploitDB.as_str(), "exploit_db");
    assert_eq!(ThreatFeedSource::MitreAttack.as_str(), "mitre_att&ck");
}

#[test]
fn test_cve_record_creation() {
    let cve = CVERecord {
        cve_id: "CVE-2024-12345".to_string(),
        title: "Critical SQL Injection".to_string(),
        description: "SQL injection in authentication module".to_string(),
        cvss_score: 9.8,
        published_date: 1000,
        updated_date: 2000,
        affected_products: vec!["Product A".to_string(), "Product B".to_string()],
        exploit_available: true,
        active_exploitation: true,
    };

    assert_eq!(cve.cve_id, "CVE-2024-12345");
    assert_eq!(cve.cvss_score, 9.8);
    assert!(cve.exploit_available);
}

#[test]
fn test_threat_severity_scoring() {
    assert_eq!(ThreatSeverity::Low.score(), 1);
    assert_eq!(ThreatSeverity::Medium.score(), 2);
    assert_eq!(ThreatSeverity::High.score(), 3);
    assert_eq!(ThreatSeverity::Critical.score(), 4);
}

#[test]
fn test_threat_severity_ordering() {
    assert!(ThreatSeverity::Critical > ThreatSeverity::High);
    assert!(ThreatSeverity::High > ThreatSeverity::Medium);
    assert!(ThreatSeverity::Medium > ThreatSeverity::Low);
}

#[test]
fn test_cve_correlator_registration() {
    let mut correlator = CVECorrelator::new();

    for i in 0..5 {
        let cve = CVERecord {
            cve_id: format!("CVE-2024-{:05}", 1000 + i),
            title: format!("Vulnerability {}", i),
            description: "Test CVE".to_string(),
            cvss_score: 5.0 + i as f32,
            published_date: 1000,
            updated_date: 2000,
            affected_products: vec![],
            exploit_available: i % 2 == 0,
            active_exploitation: false,
        };
        correlator.register_cve(cve);
    }

    assert_eq!(correlator.cve_count(), 5);
}

#[test]
fn test_cve_correlator_retrieval() {
    let mut correlator = CVECorrelator::new();

    let cve = CVERecord {
        cve_id: "CVE-2024-0001".to_string(),
        title: "Test CVE".to_string(),
        description: "Test".to_string(),
        cvss_score: 7.5,
        published_date: 1000,
        updated_date: 2000,
        affected_products: vec![],
        exploit_available: true,
        active_exploitation: false,
    };

    correlator.register_cve(cve);

    let retrieved = correlator.get_cve("CVE-2024-0001");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().title, "Test CVE");
}

#[test]
fn test_cve_correlator_severity_filtering() {
    let mut correlator = CVECorrelator::new();

    for i in 0..10 {
        let cve = CVERecord {
            cve_id: format!("CVE-2024-{:05}", i),
            title: "Test".to_string(),
            description: "Test".to_string(),
            cvss_score: 3.0 + i as f32,
            published_date: 1000,
            updated_date: 2000,
            affected_products: vec![],
            exploit_available: false,
            active_exploitation: false,
        };
        correlator.register_cve(cve);
    }

    let critical_cves = correlator.get_cves_by_severity(8.0);
    assert_eq!(critical_cves.len(), 5);
}

#[test]
fn test_cve_correlator_exploitable() {
    let mut correlator = CVECorrelator::new();

    let exploitable = CVERecord {
        cve_id: "CVE-2024-0001".to_string(),
        title: "Exploitable".to_string(),
        description: "Test".to_string(),
        cvss_score: 9.0,
        published_date: 1000,
        updated_date: 2000,
        affected_products: vec![],
        exploit_available: true,
        active_exploitation: false,
    };

    let non_exploitable = CVERecord {
        cve_id: "CVE-2024-0002".to_string(),
        title: "Non-exploitable".to_string(),
        description: "Test".to_string(),
        cvss_score: 7.0,
        published_date: 1000,
        updated_date: 2000,
        affected_products: vec![],
        exploit_available: false,
        active_exploitation: false,
    };

    correlator.register_cve(exploitable);
    correlator.register_cve(non_exploitable);

    let exploitable_cves = correlator.get_exploitable_cves();
    assert_eq!(exploitable_cves.len(), 1);
}

#[test]
fn test_threat_feed_manager_ingestion() {
    let mut manager = ThreatFeedManager::new();

    for i in 0..3 {
        let entry = ThreatFeedEntry {
            entry_id: format!("threat_{}", i),
            source: ThreatFeedSource::NVD,
            threat_type: "Vulnerability".to_string(),
            severity: if i == 0 {
                ThreatSeverity::Critical
            } else {
                ThreatSeverity::High
            },
            description: "Test threat".to_string(),
            indicators: vec![format!("indicator_{}", i)],
            last_updated: 1000 + i as u64,
        };
        manager.ingest_entry(entry);
    }

    assert_eq!(manager.entry_count(), 3);
}

#[test]
fn test_threat_feed_manager_source_filtering() {
    let mut manager = ThreatFeedManager::new();

    let nvd_entry = ThreatFeedEntry {
        entry_id: "nvd_1".to_string(),
        source: ThreatFeedSource::NVD,
        threat_type: "CVE".to_string(),
        severity: ThreatSeverity::High,
        description: "NVD threat".to_string(),
        indicators: vec![],
        last_updated: 1000,
    };

    let cisa_entry = ThreatFeedEntry {
        entry_id: "cisa_1".to_string(),
        source: ThreatFeedSource::CISA,
        threat_type: "Alert".to_string(),
        severity: ThreatSeverity::Critical,
        description: "CISA alert".to_string(),
        indicators: vec![],
        last_updated: 1000,
    };

    manager.ingest_entry(nvd_entry);
    manager.ingest_entry(cisa_entry);

    let nvd_threats = manager.get_by_source(ThreatFeedSource::NVD);
    let cisa_threats = manager.get_by_source(ThreatFeedSource::CISA);

    assert_eq!(nvd_threats.len(), 1);
    assert_eq!(cisa_threats.len(), 1);
}

#[test]
fn test_threat_feed_manager_critical_threats() {
    let mut manager = ThreatFeedManager::new();

    for i in 0..5 {
        let severity = match i {
            0 => ThreatSeverity::Critical,
            1 => ThreatSeverity::Critical,
            _ => ThreatSeverity::High,
        };

        let entry = ThreatFeedEntry {
            entry_id: format!("threat_{}", i),
            source: ThreatFeedSource::CISA,
            threat_type: "Malware".to_string(),
            severity,
            description: "Test".to_string(),
            indicators: vec![],
            last_updated: 1000,
        };
        manager.ingest_entry(entry);
    }

    let critical = manager.get_critical_threats();
    assert_eq!(critical.len(), 2);
}

#[test]
fn test_alert_action_variants() {
    assert_eq!(AlertAction::Notify.as_str(), "notify");
    assert_eq!(AlertAction::Isolate.as_str(), "isolate");
    assert_eq!(AlertAction::Block.as_str(), "block");
    assert_eq!(AlertAction::Escalate.as_str(), "escalate");
    assert_eq!(AlertAction::Report.as_str(), "report");
}

#[test]
fn test_alert_engine_rule_registration() {
    let mut engine = AlertEngine::new();

    for i in 0..3 {
        let rule = AlertRule {
            rule_id: format!("rule_{}", i),
            name: format!("Alert Rule {}", i),
            condition: "severity >= high".to_string(),
            severity_threshold: ThreatSeverity::High,
            enabled: true,
            actions: vec![AlertAction::Notify],
        };
        engine.register_rule(rule);
    }

    assert_eq!(engine.rule_count(), 3);
}

#[test]
fn test_alert_engine_alert_processing() {
    let mut engine = AlertEngine::new();

    for i in 0..5 {
        let alert = SecurityAlert {
            alert_id: format!("alert_{}", i),
            rule_id: format!("rule_{}", i % 3),
            severity: if i % 2 == 0 {
                ThreatSeverity::Critical
            } else {
                ThreatSeverity::High
            },
            message: "Security alert triggered".to_string(),
            timestamp: 1000 + i as u64,
            triggered: i % 3 != 2,
        };
        engine.process_alert(alert);
    }

    assert_eq!(engine.alert_count(), 5);

    let active_alerts = engine.get_active_alerts();
    assert_eq!(active_alerts.len(), 4);
}

#[test]
fn test_alert_engine_severity_filtering() {
    let mut engine = AlertEngine::new();

    let critical_alert = SecurityAlert {
        alert_id: "alert_1".to_string(),
        rule_id: "rule_1".to_string(),
        severity: ThreatSeverity::Critical,
        message: "Critical alert".to_string(),
        timestamp: 1000,
        triggered: true,
    };

    let high_alert = SecurityAlert {
        alert_id: "alert_2".to_string(),
        rule_id: "rule_2".to_string(),
        severity: ThreatSeverity::High,
        message: "High alert".to_string(),
        timestamp: 2000,
        triggered: true,
    };

    engine.process_alert(critical_alert);
    engine.process_alert(high_alert);

    let critical_alerts = engine.get_alerts_by_severity(ThreatSeverity::Critical);
    assert_eq!(critical_alerts.len(), 1);
}

#[test]
fn test_threat_actor_profile() {
    let actor = ThreatActorProfile {
        actor_id: "apt_001".to_string(),
        name: "APT28".to_string(),
        aliases: vec!["Fancy Bear".to_string(), "Sofacy".to_string()],
        techniques: vec!["Spear Phishing".to_string(), "Lateral Movement".to_string()],
        infrastructure: vec!["server1.example.com".to_string()],
        last_seen: 1000,
        threat_level: ThreatSeverity::Critical,
    };

    assert_eq!(actor.name, "APT28");
    assert_eq!(actor.aliases.len(), 2);
    assert_eq!(actor.threat_level, ThreatSeverity::Critical);
}

#[test]
fn test_threat_intelligence_repo() {
    let mut repo = ThreatIntelligenceRepo::new();

    for i in 0..3 {
        let actor = ThreatActorProfile {
            actor_id: format!("actor_{}", i),
            name: format!("APT{}", i),
            aliases: vec![],
            techniques: vec![],
            infrastructure: vec![],
            last_seen: 1000,
            threat_level: if i == 0 {
                ThreatSeverity::Critical
            } else {
                ThreatSeverity::High
            },
        };
        repo.register_actor(actor);
    }

    assert_eq!(repo.actor_count(), 3);
}

#[test]
fn test_threat_intelligence_repo_critical_actors() {
    let mut repo = ThreatIntelligenceRepo::new();

    let critical_actor = ThreatActorProfile {
        actor_id: "apt_critical".to_string(),
        name: "Critical APT".to_string(),
        aliases: vec![],
        techniques: vec![],
        infrastructure: vec![],
        last_seen: 1000,
        threat_level: ThreatSeverity::Critical,
    };

    let high_actor = ThreatActorProfile {
        actor_id: "apt_high".to_string(),
        name: "High APT".to_string(),
        aliases: vec![],
        techniques: vec![],
        infrastructure: vec![],
        last_seen: 1000,
        threat_level: ThreatSeverity::High,
    };

    repo.register_actor(critical_actor);
    repo.register_actor(high_actor);

    let critical = repo.get_critical_actors();
    assert_eq!(critical.len(), 1);
}

#[test]
fn test_comprehensive_threat_intelligence_scenario() {
    let mut correlator = CVECorrelator::new();
    let mut feed_manager = ThreatFeedManager::new();
    let mut alert_engine = AlertEngine::new();
    let mut repo = ThreatIntelligenceRepo::new();

    // Register CVEs
    let cve = CVERecord {
        cve_id: "CVE-2024-9999".to_string(),
        title: "Critical RCE".to_string(),
        description: "Remote code execution".to_string(),
        cvss_score: 9.8,
        published_date: 1000,
        updated_date: 2000,
        affected_products: vec!["Product X".to_string()],
        exploit_available: true,
        active_exploitation: true,
    };
    correlator.register_cve(cve);

    // Ingest threat feed
    let threat = ThreatFeedEntry {
        entry_id: "threat_001".to_string(),
        source: ThreatFeedSource::CISA,
        threat_type: "Active Exploitation".to_string(),
        severity: ThreatSeverity::Critical,
        description: "CVE-2024-9999 actively exploited".to_string(),
        indicators: vec!["malware_hash_1".to_string()],
        last_updated: 1500,
    };
    feed_manager.ingest_entry(threat);

    // Register alert rule
    let rule = AlertRule {
        rule_id: "rule_cve_critical".to_string(),
        name: "Critical CVE Alert".to_string(),
        condition: "cvss_score >= 9.0".to_string(),
        severity_threshold: ThreatSeverity::Critical,
        enabled: true,
        actions: vec![AlertAction::Escalate, AlertAction::Report],
    };
    alert_engine.register_rule(rule);

    // Register threat actor
    let actor = ThreatActorProfile {
        actor_id: "apt_exploiting".to_string(),
        name: "Exploitation Group".to_string(),
        aliases: vec!["EvilCorp".to_string()],
        techniques: vec!["Zero Day Exploitation".to_string()],
        infrastructure: vec!["c2.example.com".to_string()],
        last_seen: 1500,
        threat_level: ThreatSeverity::Critical,
    };
    repo.register_actor(actor);

    assert_eq!(correlator.cve_count(), 1);
    assert_eq!(feed_manager.entry_count(), 1);
    assert_eq!(alert_engine.rule_count(), 1);
    assert_eq!(repo.actor_count(), 1);
}

#[test]
fn test_threat_feed_recency() {
    let mut manager = ThreatFeedManager::new();

    for i in 0..5 {
        let entry = ThreatFeedEntry {
            entry_id: format!("threat_{}", i),
            source: ThreatFeedSource::NVD,
            threat_type: "Vulnerability".to_string(),
            severity: ThreatSeverity::High,
            description: "Test".to_string(),
            indicators: vec![],
            last_updated: 1000 + i as u64 * 200,
        };
        manager.ingest_entry(entry);
    }

    let recent = manager.get_recent_threats(1300);
    assert_eq!(recent.len(), 3);
}
