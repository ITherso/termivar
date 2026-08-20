//! Experimental research records for externally computed model output.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `ml`.
//! - **Execution:** no repository runtime caller (not on any default path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental data-model scaffold only.
//!
//! The repository does not train models, cluster observations, classify anomalies,
//! estimate exploitation success, or execute a recorded stage. Hosts may use these
//! serializable records to carry results computed by their own reviewed systems.
//! See `docs/internals/runtime-map.md`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Caller-supplied pattern record. No claim is inferred from this record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnerabilityPattern {
    pub pattern_id: String,
    pub pattern_name: String,
    #[serde(with = "finite_f32_vector")]
    pub signature: Vec<f32>,
    #[serde(with = "unit_interval_f32")]
    pub confidence: f32,
    pub occurrences: u32,
    pub severity: String,
    pub exploit_chain: Vec<String>,
}

impl VulnerabilityPattern {
    pub fn validate(&self) -> Result<(), MlRecordValidationError> {
        if self.pattern_id.trim().is_empty() || self.pattern_name.trim().is_empty() {
            return Err(MlRecordValidationError::BlankIdentity);
        }
        if self.signature.is_empty() || self.signature.iter().any(|value| !value.is_finite()) {
            return Err(MlRecordValidationError::InvalidVector);
        }
        if !normalized(self.confidence) {
            return Err(MlRecordValidationError::InvalidScore);
        }
        if self.severity.trim().is_empty()
            || self
                .exploit_chain
                .iter()
                .any(|identifier| identifier.trim().is_empty())
        {
            return Err(MlRecordValidationError::BlankLabel);
        }
        Ok(())
    }
}

/// Caller-supplied clustering record from an external model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClusterResult {
    pub cluster_id: u32,
    #[serde(with = "finite_f32_vector")]
    pub centroid: Vec<f32>,
    pub members: Vec<String>,
    #[serde(with = "unit_interval_f32")]
    pub similarity_score: f32,
}

impl ClusterResult {
    pub fn validate(&self) -> Result<(), MlRecordValidationError> {
        if self.centroid.is_empty() || self.centroid.iter().any(|value| !value.is_finite()) {
            return Err(MlRecordValidationError::InvalidVector);
        }
        if self.members.iter().any(|member| member.trim().is_empty()) {
            return Err(MlRecordValidationError::InvalidMembers);
        }
        if !normalized(self.similarity_score) {
            return Err(MlRecordValidationError::InvalidScore);
        }
        Ok(())
    }

    /// Returns the derived member count in a target-independent wire width.
    #[must_use]
    pub fn member_count(&self) -> u64 {
        u64::try_from(self.members.len()).unwrap_or(u64::MAX)
    }
}

/// Caller-supplied research-chain record. The scanner never executes its stages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExploitationChain {
    pub chain_id: String,
    pub stages: Vec<ExploitStage>,
    #[serde(with = "unit_interval_f32")]
    pub success_rate: f32,
    pub time_to_exploit_secs: u32,
}

impl ExploitationChain {
    pub fn validate(&self) -> Result<(), MlRecordValidationError> {
        if self.chain_id.trim().is_empty() {
            return Err(MlRecordValidationError::BlankIdentity);
        }
        if !normalized(self.success_rate) {
            return Err(MlRecordValidationError::InvalidScore);
        }
        let mut stage_ids = BTreeSet::new();
        for stage in &self.stages {
            stage.validate()?;
            if !stage_ids.insert(stage.stage_id) {
                return Err(MlRecordValidationError::DuplicateStageId);
            }
        }
        Ok(())
    }
}

/// Caller-supplied stage record containing inert host data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExploitStage {
    pub stage_id: u32,
    pub name: String,
    pub technique: String,
    pub payload: String,
    pub expected_response: String,
    pub fallback: Option<String>,
}

impl ExploitStage {
    pub fn validate(&self) -> Result<(), MlRecordValidationError> {
        if self.name.trim().is_empty()
            || self.technique.trim().is_empty()
            || self.payload.trim().is_empty()
            || self.expected_response.trim().is_empty()
            || self
                .fallback
                .as_ref()
                .is_some_and(|fallback| fallback.trim().is_empty())
        {
            return Err(MlRecordValidationError::BlankLabel);
        }
        Ok(())
    }
}

/// Caller-supplied anomaly-pattern record from an external model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyPattern {
    pub pattern_id: String,
    #[serde(with = "finite_f32_vector")]
    pub feature_vector: Vec<f32>,
    #[serde(with = "unit_interval_f32")]
    pub anomaly_score: f32,
    pub pattern_type: AnomalyType,
}

impl AnomalyPattern {
    pub fn validate(&self) -> Result<(), MlRecordValidationError> {
        if self.pattern_id.trim().is_empty() {
            return Err(MlRecordValidationError::BlankIdentity);
        }
        if self.feature_vector.is_empty()
            || self.feature_vector.iter().any(|value| !value.is_finite())
        {
            return Err(MlRecordValidationError::InvalidVector);
        }
        if !normalized(self.anomaly_score) {
            return Err(MlRecordValidationError::InvalidScore);
        }
        Ok(())
    }
}

/// Caller-assigned anomaly dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    #[serde(rename = "timing")]
    Timing,
    #[serde(rename = "size")]
    Size,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "behavior")]
    Behavior,
}

/// Validation failure for externally computed research records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MlRecordValidationError {
    #[error("record identity fields must not be blank")]
    BlankIdentity,
    #[error("record labels and markers must not be blank")]
    BlankLabel,
    #[error("vectors must be nonempty and contain only finite values")]
    InvalidVector,
    #[error("reported scores must be finite and within 0..=1")]
    InvalidScore,
    #[error("cluster members must not contain blank identifiers")]
    InvalidMembers,
    #[error("research-chain stage IDs must be unique")]
    DuplicateStageId,
}

fn normalized(value: f32) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

mod finite_f32_vector {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    const ERROR: &str = "vector values must be finite";

    pub fn serialize<S>(values: &[f32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if values.iter().all(|value| value.is_finite()) {
            values.serialize(serializer)
        } else {
            Err(serde::ser::Error::custom(ERROR))
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<f32>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<f32>::deserialize(deserializer)?;
        if values.iter().all(|value| value.is_finite()) {
            Ok(values)
        } else {
            Err(serde::de::Error::custom(ERROR))
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_without_computation() {
        let pattern = VulnerabilityPattern {
            pattern_id: "pattern-1".to_string(),
            pattern_name: "host-label".to_string(),
            signature: vec![0.1, 0.2],
            confidence: 0.4,
            occurrences: 2,
            severity: "host-label".to_string(),
            exploit_chain: vec!["chain-1".to_string()],
        };

        assert_eq!(pattern.validate(), Ok(()));
        let encoded = serde_json::to_string(&pattern).expect("record serializes");
        let decoded: VulnerabilityPattern =
            serde_json::from_str(&encoded).expect("record deserializes");
        assert_eq!(decoded, pattern);
    }

    #[test]
    fn stage_content_remains_inert_caller_data() {
        let chain = ExploitationChain {
            chain_id: "chain-1".to_string(),
            stages: vec![ExploitStage {
                stage_id: 1,
                name: "fixture-stage".to_string(),
                technique: "fixture-marker".to_string(),
                payload: "inert-input-marker".to_string(),
                expected_response: "inert-output-marker".to_string(),
                fallback: None,
            }],
            success_rate: 0.25,
            time_to_exploit_secs: 0,
        };

        assert_eq!(chain.validate(), Ok(()));
        let encoded = serde_json::to_string(&chain).expect("record serializes");
        let decoded: ExploitationChain =
            serde_json::from_str(&encoded).expect("record deserializes");
        assert_eq!(decoded, chain);
    }

    #[test]
    fn every_record_type_rejects_nonfinite_or_inconsistent_values() {
        let cluster = ClusterResult {
            cluster_id: 1,
            centroid: vec![0.2],
            members: vec![" ".to_string()],
            similarity_score: 0.5,
        };
        assert_eq!(
            cluster.validate(),
            Err(MlRecordValidationError::InvalidMembers)
        );

        let anomaly = AnomalyPattern {
            pattern_id: "anomaly".to_string(),
            feature_vector: vec![f32::NAN],
            anomaly_score: 0.5,
            pattern_type: AnomalyType::Behavior,
        };
        assert_eq!(
            anomaly.validate(),
            Err(MlRecordValidationError::InvalidVector)
        );
    }

    #[test]
    fn ml_wire_rejects_nonfinite_vectors_and_out_of_range_scores() {
        let invalid_pattern = VulnerabilityPattern {
            pattern_id: "pattern-1".to_string(),
            pattern_name: "host-label".to_string(),
            signature: vec![f32::NAN],
            confidence: 0.5,
            occurrences: 1,
            severity: "host-label".to_string(),
            exploit_chain: Vec::new(),
        };
        assert!(serde_json::to_string(&invalid_pattern).is_err());

        let mut pattern_json = serde_json::json!({
            "pattern_id": "pattern-1",
            "pattern_name": "host-label",
            "signature": [0.25],
            "confidence": 1.01,
            "occurrences": 1,
            "severity": "host-label",
            "exploit_chain": []
        });
        assert!(serde_json::from_value::<VulnerabilityPattern>(pattern_json.clone()).is_err());
        pattern_json["confidence"] = serde_json::json!(0.5);
        assert!(serde_json::from_value::<VulnerabilityPattern>(pattern_json).is_ok());

        let invalid_chain = ExploitationChain {
            chain_id: "chain-1".to_string(),
            stages: Vec::new(),
            success_rate: f32::INFINITY,
            time_to_exploit_secs: 0,
        };
        assert!(serde_json::to_string(&invalid_chain).is_err());

        let invalid_anomaly = serde_json::json!({
            "pattern_id": "anomaly-1",
            "feature_vector": [0.25],
            "anomaly_score": -0.01,
            "pattern_type": "behavior"
        });
        assert!(serde_json::from_value::<AnomalyPattern>(invalid_anomaly).is_err());
    }

    #[test]
    fn cluster_member_count_is_derived_and_wire_has_no_redundant_size() {
        let cluster = ClusterResult {
            cluster_id: 7,
            centroid: vec![0.25, -0.5],
            members: vec!["member-a".to_string(), "member-b".to_string()],
            similarity_score: 0.75,
        };

        let encoded = serde_json::to_string(&cluster).expect("finite cluster serializes");
        assert!(!encoded.contains("\"size\""));
        let decoded: ClusterResult =
            serde_json::from_str(&encoded).expect("finite cluster deserializes");
        assert_eq!(decoded, cluster);
        assert_eq!(decoded.member_count(), 2);
    }
}
