#![cfg(feature = "detection")]

use termivar_scanner::{
    BehaviorIndicator, BehavioralSignature, BehavioralSignatureValidationError, CatalogRecordError,
    ComparisonOperator, IndicatorType, TechniqueCatalog, TechniqueCategory, TechniqueRecord,
};

#[test]
fn signal_records_validate_without_classifying() {
    let signature = BehavioralSignature {
        signature_id: "shape-1".to_string(),
        signal_type: "response-shape".to_string(),
        indicators: vec![BehaviorIndicator {
            indicator_type: IndicatorType::Size,
            metric: "response_size".to_string(),
            operator: ComparisonOperator::GreaterThan,
            value: 1024.0,
            weight: 1.0,
        }],
        threshold: 0.5,
        confidence: 0.6,
    };
    assert_eq!(signature.validate(), Ok(()));

    let mut invalid = signature;
    invalid.indicators[0].value = f32::INFINITY;
    assert_eq!(
        invalid.validate(),
        Err(BehavioralSignatureValidationError::InvalidIndicator { index: 0 })
    );
}

#[test]
fn technique_catalog_is_validated_and_deterministic() {
    let mut catalog = TechniqueCatalog::new();
    let record = |id: &str, score: f32| TechniqueRecord {
        technique_id: id.to_string(),
        technique_name: "fixture".to_string(),
        category: TechniqueCategory::Normalization,
        description: "caller-supplied record".to_string(),
        reported_effectiveness: score,
        reported_false_positive_rate: 0.2,
        method_labels: vec!["inert-marker".to_string()],
    };
    catalog.insert(record("z", 0.7)).expect("valid record");
    catalog.insert(record("a", 0.7)).expect("valid record");
    assert_eq!(
        catalog
            .ranked(TechniqueCategory::Normalization)
            .into_iter()
            .map(|item| item.technique_id.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "z"]
    );
    assert_eq!(
        catalog.insert(record("bad", f32::NAN)),
        Err(CatalogRecordError::InvalidReportedScore)
    );
}
