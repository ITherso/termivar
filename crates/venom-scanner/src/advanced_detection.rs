//! Experimental signal definitions and caller-scored technique catalogs.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `detection`.
//! - **Execution:** no repository runtime caller.
//! - **Default `venom scan`:** no.
//! - **Support:** experimental record/catalog scaffold.
//!
//! This module validates and stores caller-supplied records. It does not inspect
//! responses, execute transformations, classify vulnerabilities, or emit findings.
//! See `docs/internals/runtime-map.md`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use thiserror::Error;

/// Caller-supplied behavioral signal definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralSignature {
    pub signature_id: String,
    pub signal_type: String,
    pub indicators: Vec<BehaviorIndicator>,
    /// Caller-supplied normalized threshold.
    #[serde(with = "positive_unit_interval_f32")]
    pub threshold: f32,
    /// Caller-supplied normalized confidence label.
    #[serde(with = "unit_interval_f32")]
    pub confidence: f32,
}

impl BehavioralSignature {
    /// Validates the record envelope without evaluating the signal.
    pub fn validate(&self) -> Result<(), BehavioralSignatureValidationError> {
        if self.signature_id.trim().is_empty() {
            return Err(BehavioralSignatureValidationError::BlankSignatureId);
        }
        if self.signal_type.trim().is_empty() {
            return Err(BehavioralSignatureValidationError::BlankSignalType);
        }
        if self.indicators.is_empty() {
            return Err(BehavioralSignatureValidationError::NoIndicators);
        }
        if !normalized(self.threshold) || self.threshold == 0.0 {
            return Err(BehavioralSignatureValidationError::InvalidThreshold);
        }
        if !normalized(self.confidence) {
            return Err(BehavioralSignatureValidationError::InvalidConfidence);
        }
        for (index, indicator) in self.indicators.iter().enumerate() {
            if !indicator.is_valid() {
                return Err(BehavioralSignatureValidationError::InvalidIndicator { index });
            }
        }
        Ok(())
    }
}

/// Validation failures for caller-supplied signal records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BehavioralSignatureValidationError {
    #[error("behavioral signature ID must not be blank")]
    BlankSignatureId,
    #[error("behavioral signal type must not be blank")]
    BlankSignalType,
    #[error("behavioral signature must contain at least one indicator")]
    NoIndicators,
    #[error("behavioral signature threshold must be finite and within (0, 1]")]
    InvalidThreshold,
    #[error("behavioral signature confidence must be finite and within 0..=1")]
    InvalidConfidence,
    #[error("behavioral signature indicator {index} is contradictory or invalid")]
    InvalidIndicator { index: usize },
}

/// Caller-supplied signal indicator.
#[derive(Debug, Clone, PartialEq)]
pub struct BehaviorIndicator {
    pub indicator_type: IndicatorType,
    pub metric: String,
    pub operator: ComparisonOperator,
    pub value: f32,
    pub weight: f32,
}

impl BehaviorIndicator {
    fn has_wire_safe_numbers(&self) -> bool {
        let value_is_valid = self.value.is_finite()
            && self.value >= 0.0
            && (self.indicator_type != IndicatorType::Consistency || normalized(self.value));
        value_is_valid && normalized(self.weight) && self.weight > 0.0
    }

    fn is_valid(&self) -> bool {
        let metric_matches_type = matches!(
            (self.indicator_type, self.metric.as_str()),
            (IndicatorType::Timing, "response_time")
                | (IndicatorType::Size, "response_size")
                | (IndicatorType::Pattern, "unique_patterns")
                | (IndicatorType::Error, "error_keywords")
                | (IndicatorType::Consistency, "consistency")
        );
        metric_matches_type && self.has_wire_safe_numbers()
    }
}

const BEHAVIOR_INDICATOR_WIRE_ERROR: &str =
    "behavior indicator values must be finite and within their documented ranges";

#[derive(Serialize)]
struct BehaviorIndicatorRef<'a> {
    indicator_type: IndicatorType,
    metric: &'a str,
    operator: ComparisonOperator,
    value: f32,
    weight: f32,
}

#[derive(Deserialize)]
struct BehaviorIndicatorWire {
    indicator_type: IndicatorType,
    metric: String,
    operator: ComparisonOperator,
    value: f32,
    weight: f32,
}

impl Serialize for BehaviorIndicator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !self.has_wire_safe_numbers() {
            return Err(serde::ser::Error::custom(BEHAVIOR_INDICATOR_WIRE_ERROR));
        }
        BehaviorIndicatorRef {
            indicator_type: self.indicator_type,
            metric: &self.metric,
            operator: self.operator,
            value: self.value,
            weight: self.weight,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BehaviorIndicator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = BehaviorIndicatorWire::deserialize(deserializer)?;
        let indicator = Self {
            indicator_type: wire.indicator_type,
            metric: wire.metric,
            operator: wire.operator,
            value: wire.value,
            weight: wire.weight,
        };
        if indicator.has_wire_safe_numbers() {
            Ok(indicator)
        } else {
            Err(serde::de::Error::custom(BEHAVIOR_INDICATOR_WIRE_ERROR))
        }
    }
}

/// Supported dimensions for a caller-supplied indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorType {
    #[serde(rename = "timing")]
    Timing,
    #[serde(rename = "size")]
    Size,
    #[serde(rename = "pattern")]
    Pattern,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "consistency")]
    Consistency,
}

/// Numeric comparison recorded by a host. This module does not apply it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOperator {
    #[serde(rename = "greater_than")]
    GreaterThan,
    #[serde(rename = "less_than")]
    LessThan,
    #[serde(rename = "equals")]
    Equals,
}

/// Caller-supplied observation record. No signal is evaluated from it here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralAnalysisData {
    #[serde(with = "nonnegative_f32")]
    pub response_time_ms: f32,
    pub response_size_bytes: u32,
    pub error_keywords_count: u32,
    pub unique_patterns: u32,
    #[serde(with = "unit_interval_f32")]
    pub consistency_score: f32,
}

/// Neutral technique category used by caller-supplied records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TechniqueCategory {
    Encoding,
    Transformation,
    Fragmentation,
    Normalization,
    Timing,
}

/// Caller-supplied technique record; the scanner never executes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TechniqueRecord {
    pub technique_id: String,
    pub technique_name: String,
    pub category: TechniqueCategory,
    pub description: String,
    #[serde(with = "unit_interval_f32")]
    pub reported_effectiveness: f32,
    #[serde(with = "unit_interval_f32")]
    pub reported_false_positive_rate: f32,
    pub method_labels: Vec<String>,
}

impl TechniqueRecord {
    pub fn validate(&self) -> Result<(), CatalogRecordError> {
        if self.technique_id.trim().is_empty() {
            return Err(CatalogRecordError::BlankId);
        }
        if self.technique_name.trim().is_empty() {
            return Err(CatalogRecordError::BlankName);
        }
        if !normalized(self.reported_effectiveness)
            || !normalized(self.reported_false_positive_rate)
        {
            return Err(CatalogRecordError::InvalidReportedScore);
        }
        Ok(())
    }
}

/// Deterministic in-memory catalog for validated technique records.
#[derive(Debug, Default)]
pub struct TechniqueCatalog {
    records: BTreeMap<String, TechniqueRecord>,
}

impl TechniqueCatalog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, record: TechniqueRecord) -> Result<(), CatalogRecordError> {
        record.validate()?;
        if self.records.contains_key(&record.technique_id) {
            return Err(CatalogRecordError::DuplicateId);
        }
        self.records.insert(record.technique_id.clone(), record);
        Ok(())
    }

    /// Returns records ordered by reported score descending, then ID ascending.
    #[must_use]
    pub fn ranked(&self, category: TechniqueCategory) -> Vec<&TechniqueRecord> {
        let mut records: Vec<_> = self
            .records
            .values()
            .filter(|record| record.category == category)
            .collect();
        records.sort_by(|left, right| {
            right
                .reported_effectiveness
                .total_cmp(&left.reported_effectiveness)
                .then_with(|| left.technique_id.cmp(&right.technique_id))
        });
        records
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Neutral transformation category for a caller-supplied rule record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformationType {
    Encoding,
    Manipulation,
    Noise,
    Other,
}

/// Caller-supplied transformation-rule record; the scanner never applies it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransformationRule {
    pub rule_id: String,
    pub target_label: String,
    pub transformation_label: String,
    pub transformation_type: TransformationType,
    #[serde(with = "unit_interval_f32")]
    pub reported_effectiveness: f32,
}

impl TransformationRule {
    pub fn validate(&self) -> Result<(), CatalogRecordError> {
        if self.rule_id.trim().is_empty() {
            return Err(CatalogRecordError::BlankId);
        }
        if self.target_label.trim().is_empty() || self.transformation_label.trim().is_empty() {
            return Err(CatalogRecordError::BlankName);
        }
        if !normalized(self.reported_effectiveness) {
            return Err(CatalogRecordError::InvalidReportedScore);
        }
        Ok(())
    }
}

/// Deterministic in-memory catalog for validated transformation-rule records.
#[derive(Debug, Default)]
pub struct TransformationRuleCatalog {
    records: BTreeMap<String, TransformationRule>,
}

impl TransformationRuleCatalog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, record: TransformationRule) -> Result<(), CatalogRecordError> {
        record.validate()?;
        if self.records.contains_key(&record.rule_id) {
            return Err(CatalogRecordError::DuplicateId);
        }
        self.records.insert(record.rule_id.clone(), record);
        Ok(())
    }

    #[must_use]
    pub fn for_target(&self, target: &str) -> Vec<&TransformationRule> {
        self.records
            .values()
            .filter(|record| record.target_label == target)
            .collect()
    }
}

/// Validation failure for a caller-supplied catalog record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CatalogRecordError {
    #[error("catalog record ID must not be blank")]
    BlankId,
    #[error("catalog record name/label must not be blank")]
    BlankName,
    #[error("reported scores must be finite and within 0..=1")]
    InvalidReportedScore,
    #[error("catalog record ID already exists")]
    DuplicateId,
}

fn normalized(value: f32) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

mod unit_interval_f32 {
    use serde::{Deserialize, Deserializer, Serializer};

    const ERROR: &str = "score must be finite and within 0..=1";

    pub fn serialize<S>(value: &f32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if super::normalized(*value) {
            serializer.serialize_f32(*value)
        } else {
            Err(serde::ser::Error::custom(ERROR))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        if super::normalized(value) {
            Ok(value)
        } else {
            Err(serde::de::Error::custom(ERROR))
        }
    }
}

mod positive_unit_interval_f32 {
    use serde::{Deserialize, Deserializer, Serializer};

    const ERROR: &str = "score must be finite and within (0, 1]";

    pub fn serialize<S>(value: &f32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if super::normalized(*value) && *value > 0.0 {
            serializer.serialize_f32(*value)
        } else {
            Err(serde::ser::Error::custom(ERROR))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        if super::normalized(value) && value > 0.0 {
            Ok(value)
        } else {
            Err(serde::de::Error::custom(ERROR))
        }
    }
}

mod nonnegative_f32 {
    use serde::{Deserialize, Deserializer, Serializer};

    const ERROR: &str = "value must be finite and non-negative";

    pub fn serialize<S>(value: &f32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if value.is_finite() && *value >= 0.0 {
            serializer.serialize_f32(*value)
        } else {
            Err(serde::ser::Error::custom(ERROR))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        if value.is_finite() && value >= 0.0 {
            Ok(value)
        } else {
            Err(serde::de::Error::custom(ERROR))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_signature() -> BehavioralSignature {
        BehavioralSignature {
            signature_id: "signal-1".to_string(),
            signal_type: "timing-deviation".to_string(),
            indicators: vec![BehaviorIndicator {
                indicator_type: IndicatorType::Timing,
                metric: "response_time".to_string(),
                operator: ComparisonOperator::GreaterThan,
                value: 500.0,
                weight: 1.0,
            }],
            threshold: 0.5,
            confidence: 0.8,
        }
    }

    #[test]
    fn signal_validation_rejects_type_metric_mismatch() {
        assert_eq!(valid_signature().validate(), Ok(()));
        let mut invalid = valid_signature();
        invalid.indicators[0].metric = "response_size".to_string();
        assert_eq!(
            invalid.validate(),
            Err(BehavioralSignatureValidationError::InvalidIndicator { index: 0 })
        );
    }

    #[test]
    fn catalogs_reject_invalid_scores_duplicates_and_sort_ties_by_id() {
        let record = |id: &str, score: f32| TechniqueRecord {
            technique_id: id.to_string(),
            technique_name: "fixture".to_string(),
            category: TechniqueCategory::Encoding,
            description: "caller record".to_string(),
            reported_effectiveness: score,
            reported_false_positive_rate: 0.1,
            method_labels: vec!["inert-marker".to_string()],
        };
        let mut catalog = TechniqueCatalog::new();
        assert_eq!(catalog.insert(record("b", 0.5)), Ok(()));
        assert_eq!(catalog.insert(record("a", 0.5)), Ok(()));
        assert_eq!(
            catalog.insert(record("c", f32::NAN)),
            Err(CatalogRecordError::InvalidReportedScore)
        );
        assert_eq!(
            catalog.insert(record("a", 0.4)),
            Err(CatalogRecordError::DuplicateId)
        );
        assert_eq!(
            catalog
                .ranked(TechniqueCategory::Encoding)
                .into_iter()
                .map(|item| item.technique_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn transformation_catalog_stores_only_valid_records() {
        let mut catalog = TransformationRuleCatalog::new();
        assert_eq!(
            catalog.insert(TransformationRule {
                rule_id: "rule-1".to_string(),
                target_label: "host-marker".to_string(),
                transformation_label: "inert-marker".to_string(),
                transformation_type: TransformationType::Encoding,
                reported_effectiveness: 0.4,
            }),
            Ok(())
        );
        assert_eq!(catalog.for_target("host-marker").len(), 1);
    }

    #[test]
    fn advanced_detection_wire_rejects_unsafe_numeric_values() {
        let mut invalid_signature = valid_signature();
        invalid_signature.threshold = f32::NAN;
        assert!(serde_json::to_string(&invalid_signature).is_err());

        let mut signature_json =
            serde_json::to_value(valid_signature()).expect("valid signature serializes");
        signature_json["confidence"] = serde_json::json!(1.01);
        assert!(serde_json::from_value::<BehavioralSignature>(signature_json).is_err());

        let invalid_indicator = BehaviorIndicator {
            indicator_type: IndicatorType::Timing,
            metric: "response_time".to_string(),
            operator: ComparisonOperator::GreaterThan,
            value: -1.0,
            weight: 0.5,
        };
        assert!(serde_json::to_string(&invalid_indicator).is_err());

        let invalid_consistency_indicator = serde_json::json!({
            "indicator_type": "consistency",
            "metric": "consistency",
            "operator": "equals",
            "value": 1.01,
            "weight": 0.5
        });
        assert!(
            serde_json::from_value::<BehaviorIndicator>(invalid_consistency_indicator).is_err()
        );

        let invalid_analysis = BehavioralAnalysisData {
            response_time_ms: 1.0,
            response_size_bytes: 0,
            error_keywords_count: 0,
            unique_patterns: 0,
            consistency_score: f32::INFINITY,
        };
        assert!(serde_json::to_string(&invalid_analysis).is_err());

        let invalid_technique = TechniqueRecord {
            technique_id: "technique-1".to_string(),
            technique_name: "fixture".to_string(),
            category: TechniqueCategory::Encoding,
            description: "caller record".to_string(),
            reported_effectiveness: 0.5,
            reported_false_positive_rate: -0.01,
            method_labels: Vec::new(),
        };
        assert!(serde_json::to_string(&invalid_technique).is_err());

        let invalid_rule = serde_json::json!({
            "rule_id": "rule-1",
            "target_label": "host-marker",
            "transformation_label": "inert-marker",
            "transformation_type": "Other",
            "reported_effectiveness": 1.01
        });
        assert!(serde_json::from_value::<TransformationRule>(invalid_rule).is_err());
    }

    #[test]
    fn advanced_detection_records_round_trip_without_execution() {
        let signature = valid_signature();
        let encoded = serde_json::to_string(&signature).expect("signature serializes");
        let decoded: BehavioralSignature =
            serde_json::from_str(&encoded).expect("signature deserializes");
        assert_eq!(decoded, signature);

        let analysis = BehavioralAnalysisData {
            response_time_ms: 12.5,
            response_size_bytes: u32::MAX,
            error_keywords_count: 2,
            unique_patterns: 3,
            consistency_score: 0.75,
        };
        let encoded = serde_json::to_string(&analysis).expect("analysis record serializes");
        let decoded: BehavioralAnalysisData =
            serde_json::from_str(&encoded).expect("analysis record deserializes");
        assert_eq!(decoded, analysis);

        let rule = TransformationRule {
            rule_id: "rule-1".to_string(),
            target_label: "host-marker".to_string(),
            transformation_label: "inert-marker".to_string(),
            transformation_type: TransformationType::Other,
            reported_effectiveness: 0.25,
        };
        let encoded = serde_json::to_string(&rule).expect("rule record serializes");
        let decoded: TransformationRule =
            serde_json::from_str(&encoded).expect("rule record deserializes");
        assert_eq!(decoded, rule);
    }
}
