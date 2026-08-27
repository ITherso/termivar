//! Assessment-owned semantic composition over exact committed evidence.

use std::collections::{BTreeMap, BTreeSet};

use venom_core::{Evidence, EvidenceId};

use super::{WebAssessmentLimits, WebAssessmentSubject};
use crate::{
    web_runtime::{BOOTSTRAP_ACTION_ID, BOOTSTRAP_CASE_ID, BOOTSTRAP_HYPOTHESIS_ID},
    DecisionEvidenceReceipt, DecisionExecutionStage, EntityExtractor, KnowledgeBase, LimitsError,
    SemanticExtractionLimits, SemanticExtractionResult, HTTP_EVIDENCE_EXECUTOR_ID,
};

/// Exact evidence records admitted from assessment-owned bootstrap receipts.
///
/// This accumulator is intentionally neither serializable nor debuggable. It
/// never scans the knowledge base: every retained record is named by one
/// committed receipt and compared structurally with the record at that exact
/// identity before it can enter the semantic input set.
#[derive(Default)]
pub(super) struct AssessmentSemanticEvidence {
    records: BTreeMap<EvidenceId, Evidence>,
}

impl AssessmentSemanticEvidence {
    pub(super) fn commit_bootstrap(
        &mut self,
        receipt: Option<&DecisionEvidenceReceipt>,
        knowledge: &KnowledgeBase,
        subject: &WebAssessmentSubject,
    ) -> Result<(), ()> {
        let Some(receipt) = receipt else {
            return Ok(());
        };
        if receipt.case().id() != BOOTSTRAP_CASE_ID
            || receipt.case().action_id() != BOOTSTRAP_ACTION_ID
            || receipt.case().hypothesis_id() != BOOTSTRAP_HYPOTHESIS_ID
            || receipt.case().subject().as_str() != format!("endpoint:{}", subject.url())
            || receipt.case().payload_strategy().is_some()
            || !receipt.case().applies_hypothesis_transition()
            || receipt.executor_id() != HTTP_EVIDENCE_EXECUTOR_ID
            || receipt.stage() != DecisionExecutionStage::Passive
            || receipt.evidence().len() != receipt.writes().len()
        {
            return Err(());
        }
        let unique_ids = receipt
            .evidence()
            .iter()
            .map(|evidence| evidence.id())
            .collect::<BTreeSet<_>>();
        if unique_ids.len() != receipt.evidence().len() {
            return Err(());
        }

        for evidence in receipt.evidence() {
            if knowledge.evidence(evidence.id()).as_ref() != Some(evidence)
                || self
                    .records
                    .get(evidence.id())
                    .is_some_and(|existing| existing != evidence)
            {
                return Err(());
            }
        }
        for evidence in receipt.evidence() {
            self.records
                .entry(evidence.id().clone())
                .or_insert_with(|| evidence.clone());
        }
        Ok(())
    }

    pub(super) fn extract(&self, limits: &SemanticExtractionLimits) -> SemanticExtractionResult {
        let evidence = self.records.values().cloned().collect::<Vec<_>>();
        EntityExtractor::with_limits(limits.clone()).extract_from_web_assessment_evidence(&evidence)
    }

    #[cfg(test)]
    pub(super) fn record_count(&self) -> usize {
        self.records.len()
    }
}

pub(super) fn assessment_semantic_limits(
    assessment: WebAssessmentLimits,
) -> Result<SemanticExtractionLimits, LimitsError> {
    let defaults = SemanticExtractionLimits::default();
    SemanticExtractionLimits::new(
        defaults.max_entities(),
        defaults.max_attribute_keys(),
        defaults
            .max_values_per_attribute()
            .max(SemanticExtractionLimits::HARD_MAX_ASSESSMENT_PARAMETER_NAMES_PER_REFERENCE),
        defaults
            .max_value_bytes()
            .max(assessment.max_canonical_url_bytes()),
        defaults.max_source_evidence_ids(),
        assessment.max_canonical_url_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assessment_limits_are_checked_and_cover_discovery_names_and_urls() {
        let assessment = WebAssessmentLimits::default();
        let semantic = assessment_semantic_limits(assessment).unwrap();
        semantic.validate().unwrap();
        assert!(
            semantic.max_values_per_attribute()
                >= SemanticExtractionLimits::HARD_MAX_ASSESSMENT_PARAMETER_NAMES_PER_REFERENCE
        );
        assert_eq!(
            semantic.max_url_bytes(),
            assessment.max_canonical_url_bytes()
        );
        assert!(semantic.max_value_bytes() >= assessment.max_canonical_url_bytes());
    }
}
