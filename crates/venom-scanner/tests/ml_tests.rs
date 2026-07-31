use venom_scanner::{
    AnomalyClassifier, AnomalyPattern, AnomalyType, ExploitBuilder, ExploitStage, PatternLearner,
    VulnerabilityPattern,
};

#[test]
fn test_pattern_learning_with_multiple_patterns() {
    let mut learner = PatternLearner::new();

    // Register multiple patterns
    for i in 0..10 {
        let pattern = VulnerabilityPattern {
            pattern_id: format!("sqli_{}", i),
            pattern_name: "SQLi".to_string(),
            signature: vec![0.1 * i as f32, 0.2 * i as f32, 0.3 * i as f32],
            confidence: 0.95,
            occurrences: 10 + i as u32,
            severity: "CRITICAL".to_string(),
            exploit_chain: vec![format!("stage_{}", i)],
        };
        learner.register_pattern(pattern);
    }

    assert_eq!(learner.pattern_count(), 10);
}

#[test]
fn test_pattern_clustering_with_different_k() {
    let mut learner = PatternLearner::new();

    // Register patterns
    for i in 0..6 {
        let pattern = VulnerabilityPattern {
            pattern_id: format!("p_{}", i),
            pattern_name: match i % 3 {
                0 => "SQLi".to_string(),
                1 => "XSS".to_string(),
                _ => "SSTI".to_string(),
            },
            signature: vec![0.1 * (i % 3) as f32, 0.2 * i as f32, 0.3 * i as f32],
            confidence: 0.9,
            occurrences: 5 + i as u32,
            severity: "HIGH".to_string(),
            exploit_chain: vec![format!("chain_{}", i)],
        };
        learner.register_pattern(pattern);
    }

    let clusters = learner.cluster_patterns(2);
    assert!(!clusters.is_empty());
    assert!(clusters.len() <= 2);
}

#[test]
fn test_pattern_retrieval_by_id() {
    let mut learner = PatternLearner::new();

    let pattern = VulnerabilityPattern {
        pattern_id: "xss_1".to_string(),
        pattern_name: "XSS".to_string(),
        signature: vec![0.5, 0.6, 0.7],
        confidence: 0.85,
        occurrences: 15,
        severity: "HIGH".to_string(),
        exploit_chain: vec!["stage1".to_string(), "stage2".to_string()],
    };

    learner.register_pattern(pattern);
    let retrieved = learner.get_pattern("xss_1");

    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().pattern_name, "XSS");
}

#[test]
fn test_exploit_chain_building() {
    let mut builder = ExploitBuilder::new();

    // Create a multi-stage exploitation chain
    builder.create_chain("rce_chain".to_string());

    // Stage 1: SQLi for data exfiltration
    builder.add_stage(
        "rce_chain",
        ExploitStage {
            stage_id: 1,
            name: "SQLi".to_string(),
            technique: "Union-based".to_string(),
            payload: "UNION SELECT version()".to_string(),
            expected_response: "MySQL version".to_string(),
            fallback: Some("Error-based SQLi".to_string()),
        },
    );

    // Stage 2: File write via LOAD_FILE
    builder.add_stage(
        "rce_chain",
        ExploitStage {
            stage_id: 2,
            name: "File Write".to_string(),
            technique: "INTO OUTFILE".to_string(),
            payload: "SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE...".to_string(),
            expected_response: "File written".to_string(),
            fallback: None,
        },
    );

    // Stage 3: RCE through uploaded shell
    builder.add_stage(
        "rce_chain",
        ExploitStage {
            stage_id: 3,
            name: "RCE".to_string(),
            technique: "Web Shell".to_string(),
            payload: "curl http://target/shell.php?cmd=id".to_string(),
            expected_response: "uid=".to_string(),
            fallback: None,
        },
    );

    let chain = builder.get_chain("rce_chain").unwrap();
    assert_eq!(chain.stages.len(), 3);
    assert_eq!(chain.stages[0].stage_id, 1);
    assert_eq!(chain.stages[2].name, "RCE");
}

#[test]
fn test_exploit_success_rate_calculation() {
    let mut builder = ExploitBuilder::new();

    builder.create_chain("chain1".to_string());

    for i in 1..=4 {
        let stage = ExploitStage {
            stage_id: i as u32,
            name: format!("Stage {}", i),
            technique: "Technique".to_string(),
            payload: "payload".to_string(),
            expected_response: "response".to_string(),
            fallback: None,
        };
        builder.add_stage("chain1", stage);
    }

    let success_rate = builder.estimate_success_rate("chain1");

    // With 4 stages at 0.8 each: 0.8^4 ≈ 0.4096
    assert!(success_rate > 0.4 && success_rate < 0.5);
}

#[test]
fn test_anomaly_pattern_classification() {
    let mut classifier = AnomalyClassifier::new();

    // Add timing anomaly patterns
    classifier.add_pattern(AnomalyPattern {
        pattern_id: "timing_1".to_string(),
        feature_vector: vec![0.1, 0.2, 0.3],
        anomaly_score: 0.9,
        pattern_type: AnomalyType::Timing,
    });

    classifier.add_pattern(AnomalyPattern {
        pattern_id: "timing_2".to_string(),
        feature_vector: vec![0.11, 0.21, 0.31],
        anomaly_score: 0.85,
        pattern_type: AnomalyType::Timing,
    });

    assert_eq!(classifier.pattern_count(), 2);
}

#[test]
fn test_anomaly_detection_score() {
    let mut classifier = AnomalyClassifier::new();

    // Normal pattern
    classifier.add_pattern(AnomalyPattern {
        pattern_id: "normal".to_string(),
        feature_vector: vec![0.5, 0.5, 0.5],
        anomaly_score: 0.1,
        pattern_type: AnomalyType::Behavior,
    });

    // Test point close to normal
    let (_is_anomalous, score) = classifier.classify(&[0.5, 0.5, 0.5]);
    assert!(score >= 0.0 && score <= 1.0);
}

#[test]
fn test_multiple_vulnerability_types() {
    let mut learner = PatternLearner::new();

    let vuln_types = vec!["SQLi", "XSS", "SSTI", "XXE", "SSRF"];

    for (i, vuln_type) in vuln_types.iter().enumerate() {
        let pattern = VulnerabilityPattern {
            pattern_id: format!("{}_{}", vuln_type, i),
            pattern_name: vuln_type.to_string(),
            signature: vec![0.1 * i as f32, 0.2 * i as f32, 0.3 * i as f32],
            confidence: 0.9,
            occurrences: 5 + i as u32,
            severity: "HIGH".to_string(),
            exploit_chain: vec![format!("{}_chain", vuln_type)],
        };
        learner.register_pattern(pattern);
    }

    assert_eq!(learner.pattern_count(), 5);

    let patterns = learner.get_patterns();
    assert_eq!(patterns.len(), 5);
}

#[test]
fn test_exploit_chain_with_fallbacks() {
    let mut builder = ExploitBuilder::new();

    builder.create_chain("sqli_chain".to_string());

    builder.add_stage(
        "sqli_chain",
        ExploitStage {
            stage_id: 1,
            name: "SQLi Detection".to_string(),
            technique: "Boolean-based".to_string(),
            payload: "' AND 1=1".to_string(),
            expected_response: "true condition".to_string(),
            fallback: Some("' AND 1=2".to_string()),
        },
    );

    builder.add_stage(
        "sqli_chain",
        ExploitStage {
            stage_id: 2,
            name: "Data Extraction".to_string(),
            technique: "Union-based".to_string(),
            payload: "UNION SELECT username, password".to_string(),
            expected_response: "credentials".to_string(),
            fallback: Some("Time-based blind SQL".to_string()),
        },
    );

    let chain = builder.get_chain("sqli_chain").unwrap();
    assert_eq!(chain.stages[0].fallback, Some("' AND 1=2".to_string()));
    assert_eq!(
        chain.stages[1].fallback,
        Some("Time-based blind SQL".to_string())
    );
}

#[test]
fn test_pattern_confidence_scoring() {
    let mut learner = PatternLearner::new();

    // High confidence pattern
    let high_conf = VulnerabilityPattern {
        pattern_id: "high_conf".to_string(),
        pattern_name: "SQLi".to_string(),
        signature: vec![0.9, 0.9, 0.9],
        confidence: 0.99,
        occurrences: 100,
        severity: "CRITICAL".to_string(),
        exploit_chain: vec!["stage1".to_string()],
    };

    // Low confidence pattern
    let low_conf = VulnerabilityPattern {
        pattern_id: "low_conf".to_string(),
        pattern_name: "Potential SQLi".to_string(),
        signature: vec![0.1, 0.1, 0.1],
        confidence: 0.45,
        occurrences: 2,
        severity: "LOW".to_string(),
        exploit_chain: vec![],
    };

    learner.register_pattern(high_conf);
    learner.register_pattern(low_conf);

    let patterns = learner.get_patterns();
    let high_pattern = patterns
        .iter()
        .find(|p| p.pattern_id == "high_conf")
        .unwrap();
    let low_pattern = patterns
        .iter()
        .find(|p| p.pattern_id == "low_conf")
        .unwrap();

    assert!(high_pattern.confidence > low_pattern.confidence);
}

#[test]
fn test_anomaly_type_variants() {
    let timing = AnomalyType::Timing;
    let size = AnomalyType::Size;
    let error = AnomalyType::Error;
    let behavior = AnomalyType::Behavior;

    assert_eq!(timing, AnomalyType::Timing);
    assert_eq!(size, AnomalyType::Size);
    assert_eq!(error, AnomalyType::Error);
    assert_eq!(behavior, AnomalyType::Behavior);

    assert_ne!(timing, size);
    assert_ne!(error, behavior);
}

#[test]
fn test_complex_exploitation_scenario() {
    let mut learner = PatternLearner::new();
    let mut builder = ExploitBuilder::new();

    // Learn patterns for a complex scenario
    for i in 0..3 {
        let pattern = VulnerabilityPattern {
            pattern_id: format!("cve_2024_{:04}", 1000 + i),
            pattern_name: "Critical RCE".to_string(),
            signature: vec![0.8, 0.9, 0.85],
            confidence: 0.99,
            occurrences: 50 + i as u32,
            severity: "CRITICAL".to_string(),
            exploit_chain: vec!["rce_chain".to_string()],
        };
        learner.register_pattern(pattern);
    }

    // Build exploitation chain
    builder.create_chain("rce_chain".to_string());

    builder.add_stage(
        "rce_chain",
        ExploitStage {
            stage_id: 1,
            name: "Initial Access".to_string(),
            technique: "0-day".to_string(),
            payload: "exploit".to_string(),
            expected_response: "shell".to_string(),
            fallback: Some("cve-2024-1000".to_string()),
        },
    );

    assert_eq!(learner.pattern_count(), 3);
    assert!(builder.get_chain("rce_chain").is_some());
}
