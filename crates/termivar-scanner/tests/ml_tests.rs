#![cfg(feature = "ml")]

use termivar_scanner::{
    AnomalyPattern, AnomalyType, ClusterResult, ExploitStage, ExploitationChain,
    MlRecordValidationError, VulnerabilityPattern,
};

#[test]
fn external_model_records_preserve_caller_values() {
    let pattern = VulnerabilityPattern {
        pattern_id: "pattern-1".to_string(),
        pattern_name: "external-model-label".to_string(),
        signature: vec![0.25, 0.5],
        confidence: 0.6,
        occurrences: 3,
        severity: "external-label".to_string(),
        exploit_chain: Vec::new(),
    };
    let cluster = ClusterResult {
        cluster_id: 1,
        centroid: vec![0.25, 0.5],
        members: vec![pattern.pattern_id.clone()],
        similarity_score: 0.7,
    };
    let anomaly = AnomalyPattern {
        pattern_id: "anomaly-1".to_string(),
        feature_vector: vec![0.1, 0.9],
        anomaly_score: 0.8,
        pattern_type: AnomalyType::Behavior,
    };

    assert_eq!(pattern.validate(), Ok(()));
    assert_eq!(cluster.validate(), Ok(()));
    assert_eq!(anomaly.validate(), Ok(()));
    assert_eq!(cluster.members, vec!["pattern-1"]);
    assert_eq!(anomaly.pattern_type, AnomalyType::Behavior);
}

#[test]
fn research_chain_is_serializable_but_not_executable() {
    let chain = ExploitationChain {
        chain_id: "research-chain".to_string(),
        stages: vec![ExploitStage {
            stage_id: 1,
            name: "fixture-stage".to_string(),
            technique: "inert-marker".to_string(),
            payload: "inert-input".to_string(),
            expected_response: "inert-output".to_string(),
            fallback: Some("inert-fallback".to_string()),
        }],
        success_rate: 0.0,
        time_to_exploit_secs: 0,
    };

    let encoded = serde_json::to_string(&chain).expect("record serializes");
    let decoded: ExploitationChain = serde_json::from_str(&encoded).expect("record deserializes");
    assert_eq!(decoded.validate(), Ok(()));
    assert_eq!(decoded, chain);
}

#[test]
fn invalid_external_scores_fail_closed() {
    let invalid = ClusterResult {
        cluster_id: 1,
        centroid: vec![0.0],
        members: vec![],
        similarity_score: f32::INFINITY,
    };
    assert_eq!(
        invalid.validate(),
        Err(MlRecordValidationError::InvalidScore)
    );
}
