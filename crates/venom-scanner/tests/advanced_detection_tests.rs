use venom_scanner::{
    BehaviorIndicator, BehavioralAnalysisData, BehavioralAnalyzer, BehavioralSignature,
    BypassCategory, ComparisonOperator, EversionRule, EversionType, IndicatorType,
    SignatureEvasionEngine, WafBypassSelector, WafBypassTechnique,
};

#[test]
fn test_behavioral_signature_registration() {
    let mut analyzer = BehavioralAnalyzer::new();

    let signature = BehavioralSignature {
        signature_id: "sig_sqli_timing".to_string(),
        vulnerability_type: "SQLi".to_string(),
        indicators: vec![BehaviorIndicator {
            indicator_type: IndicatorType::Timing,
            metric: "response_time".to_string(),
            operator: ComparisonOperator::GreaterThan,
            value: 5000.0,
            weight: 0.8,
        }],
        threshold: 1.0,
        confidence: 0.95,
    };

    analyzer.register_signature(signature);
    assert_eq!(analyzer.signature_count(), 1);
}

#[test]
fn test_behavioral_analysis_detection() {
    let mut analyzer = BehavioralAnalyzer::new();

    let signature = BehavioralSignature {
        signature_id: "sig_sqli_1".to_string(),
        vulnerability_type: "SQLi".to_string(),
        indicators: vec![BehaviorIndicator {
            indicator_type: IndicatorType::Timing,
            metric: "response_time".to_string(),
            operator: ComparisonOperator::GreaterThan,
            value: 100.0,
            weight: 1.0,
        }],
        threshold: 1.0,
        confidence: 0.9,
    };

    analyzer.register_signature(signature);

    let data = BehavioralAnalysisData {
        response_time_ms: 150.0,
        response_size_bytes: 1024,
        error_keywords_count: 0,
        unique_patterns: 1,
        consistency_score: 0.95,
    };

    let results = analyzer.analyze(&data);
    assert!(!results.is_empty());
}

#[test]
fn test_multiple_behavior_indicators() {
    let mut analyzer = BehavioralAnalyzer::new();

    let indicators = vec![
        BehaviorIndicator {
            indicator_type: IndicatorType::Timing,
            metric: "response_time".to_string(),
            operator: ComparisonOperator::GreaterThan,
            value: 100.0,
            weight: 0.6,
        },
        BehaviorIndicator {
            indicator_type: IndicatorType::Size,
            metric: "response_size".to_string(),
            operator: ComparisonOperator::LessThan,
            value: 500.0,
            weight: 0.4,
        },
    ];

    let signature = BehavioralSignature {
        signature_id: "sig_complex".to_string(),
        vulnerability_type: "SQLi".to_string(),
        indicators,
        threshold: 1.5,
        confidence: 0.85,
    };

    analyzer.register_signature(signature);
    assert_eq!(analyzer.signature_count(), 1);
}

#[test]
fn test_waf_bypass_technique_registration() {
    let mut selector = WafBypassSelector::new();

    let technique = WafBypassTechnique {
        technique_id: "waf_bypass_url_encoding".to_string(),
        technique_name: "URL Encoding Bypass".to_string(),
        category: BypassCategory::Encoding,
        description: "Double URL encoding to bypass WAF filters".to_string(),
        effectiveness_score: 0.88,
        false_positive_rate: 0.05,
        evasion_methods: vec!["double_url_encode".to_string(), "hex_encode".to_string()],
    };

    selector.register_technique(technique);
    assert_eq!(selector.technique_count(), 1);
}

#[test]
fn test_select_best_waf_bypass_technique() {
    let mut selector = WafBypassSelector::new();

    let technique1 = WafBypassTechnique {
        technique_id: "waf_1".to_string(),
        technique_name: "Encoding 1".to_string(),
        category: BypassCategory::Encoding,
        description: "Test 1".to_string(),
        effectiveness_score: 0.75,
        false_positive_rate: 0.1,
        evasion_methods: vec![],
    };

    let technique2 = WafBypassTechnique {
        technique_id: "waf_2".to_string(),
        technique_name: "Encoding 2".to_string(),
        category: BypassCategory::Encoding,
        description: "Test 2".to_string(),
        effectiveness_score: 0.95,
        false_positive_rate: 0.02,
        evasion_methods: vec![],
    };

    selector.register_technique(technique1);
    selector.register_technique(technique2);

    let best = selector.select_best(BypassCategory::Encoding);
    assert!(best.is_some());
    assert_eq!(best.unwrap().technique_id, "waf_2");
}

#[test]
fn test_waf_bypass_ranking() {
    let mut selector = WafBypassSelector::new();

    for i in 0..3 {
        let technique = WafBypassTechnique {
            technique_id: format!("waf_{}", i),
            technique_name: format!("Technique {}", i),
            category: BypassCategory::Encoding,
            description: "Test".to_string(),
            effectiveness_score: 0.6 + i as f32 * 0.15,
            false_positive_rate: 0.05,
            evasion_methods: vec![],
        };
        selector.register_technique(technique);
    }

    let ranked = selector.rank_by_effectiveness();
    assert_eq!(ranked.len(), 3);
    assert!(ranked[0].effectiveness_score >= ranked[1].effectiveness_score);
}

#[test]
fn test_signature_evasion_engine() {
    let mut engine = SignatureEvasionEngine::new();

    let rule = EversionRule {
        rule_id: "evasion_mod_security_1".to_string(),
        target_signature: "mod_security_sqli_1".to_string(),
        mutation_strategy: "hex_encode_payload".to_string(),
        mutation_type: EversionType::Encoding,
        effectiveness: 0.92,
    };

    engine.add_rule(rule);
    assert_eq!(engine.rule_count(), 1);
}

#[test]
fn test_evasion_rule_lookup() {
    let mut engine = SignatureEvasionEngine::new();

    let rule1 = EversionRule {
        rule_id: "evasion_1".to_string(),
        target_signature: "mod_security_1".to_string(),
        mutation_strategy: "hex".to_string(),
        mutation_type: EversionType::Encoding,
        effectiveness: 0.85,
    };

    let rule2 = EversionRule {
        rule_id: "evasion_2".to_string(),
        target_signature: "mod_security_1".to_string(),
        mutation_strategy: "double_url".to_string(),
        mutation_type: EversionType::Encoding,
        effectiveness: 0.95,
    };

    engine.add_rule(rule1);
    engine.add_rule(rule2);

    let rules = engine.get_rules_for_signature("mod_security_1");
    assert_eq!(rules.len(), 2);

    let best = engine.get_best_rule("mod_security_1");
    assert!(best.is_some());
    assert_eq!(best.unwrap().rule_id, "evasion_2");
}

#[test]
fn test_behavioral_analysis_with_error_keywords() {
    let mut analyzer = BehavioralAnalyzer::new();

    let signature = BehavioralSignature {
        signature_id: "sig_error_based_sqli".to_string(),
        vulnerability_type: "SQLi".to_string(),
        indicators: vec![BehaviorIndicator {
            indicator_type: IndicatorType::Error,
            metric: "error_keywords".to_string(),
            operator: ComparisonOperator::GreaterThan,
            value: 2.0,
            weight: 1.0,
        }],
        threshold: 1.0,
        confidence: 0.88,
    };

    analyzer.register_signature(signature);

    let data = BehavioralAnalysisData {
        response_time_ms: 100.0,
        response_size_bytes: 512,
        error_keywords_count: 5,
        unique_patterns: 2,
        consistency_score: 0.90,
    };

    let results = analyzer.analyze(&data);
    assert!(!results.is_empty());
}

#[test]
fn test_waf_bypass_category_filtering() {
    let mut selector = WafBypassSelector::new();

    let encoding_tech = WafBypassTechnique {
        technique_id: "encoding".to_string(),
        technique_name: "Encoding".to_string(),
        category: BypassCategory::Encoding,
        description: "Test".to_string(),
        effectiveness_score: 0.8,
        false_positive_rate: 0.05,
        evasion_methods: vec![],
    };

    let timing_tech = WafBypassTechnique {
        technique_id: "timing".to_string(),
        technique_name: "Timing".to_string(),
        category: BypassCategory::Timing,
        description: "Test".to_string(),
        effectiveness_score: 0.7,
        false_positive_rate: 0.1,
        evasion_methods: vec![],
    };

    selector.register_technique(encoding_tech);
    selector.register_technique(timing_tech);

    let encoding_techs = selector.get_by_category(BypassCategory::Encoding);
    let timing_techs = selector.get_by_category(BypassCategory::Timing);

    assert_eq!(encoding_techs.len(), 1);
    assert_eq!(timing_techs.len(), 1);
}

#[test]
fn test_indicator_type_variants() {
    assert_eq!(IndicatorType::Timing.as_str(), "timing");
    assert_eq!(IndicatorType::Size.as_str(), "size");
    assert_eq!(IndicatorType::Pattern.as_str(), "pattern");
    assert_eq!(IndicatorType::Error.as_str(), "error");
    assert_eq!(IndicatorType::Consistency.as_str(), "consistency");
}

#[test]
fn test_evasion_type_variants() {
    assert_eq!(EversionType::Encoding.as_str(), "encoding");
    assert_eq!(EversionType::Manipulation.as_str(), "manipulation");
    assert_eq!(EversionType::Noise.as_str(), "noise");
    assert_eq!(EversionType::Bypass.as_str(), "bypass");
}

#[test]
fn test_comparison_operator_variants() {
    assert_eq!(ComparisonOperator::GreaterThan.as_str(), "greater_than");
    assert_eq!(ComparisonOperator::LessThan.as_str(), "less_than");
    assert_eq!(ComparisonOperator::Equals.as_str(), "equals");
    assert_eq!(ComparisonOperator::Contains.as_str(), "contains");
}

#[test]
fn test_bypass_category_variants() {
    assert_eq!(BypassCategory::Encoding.as_str(), "encoding");
    assert_eq!(BypassCategory::Obfuscation.as_str(), "obfuscation");
    assert_eq!(BypassCategory::Fragmentation.as_str(), "fragmentation");
    assert_eq!(BypassCategory::Normalization.as_str(), "normalization");
    assert_eq!(BypassCategory::Timing.as_str(), "timing");
}

#[test]
fn test_complex_evasion_scenario() {
    let mut engine = SignatureEvasionEngine::new();

    // Multiple evasion rules for same signature
    for i in 0..5 {
        let rule = EversionRule {
            rule_id: format!("evasion_{}", i),
            target_signature: "cloudflare_waf".to_string(),
            mutation_strategy: format!("technique_{}", i),
            mutation_type: if i % 2 == 0 {
                EversionType::Encoding
            } else {
                EversionType::Manipulation
            },
            effectiveness: 0.7 + i as f32 * 0.04,
        };
        engine.add_rule(rule);
    }

    let rules = engine.get_rules_for_signature("cloudflare_waf");
    assert_eq!(rules.len(), 5);

    let best = engine.get_best_rule("cloudflare_waf").unwrap();
    assert_eq!(best.rule_id, "evasion_4"); // Highest effectiveness
}
