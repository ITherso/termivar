//! Opt-in decision policy for native low-risk web review.
//!
//! This profile composes only reasoning, planning, and verification. It owns no
//! executor route and performs no I/O. A host must explicitly install the
//! profile and separately provide executors under its existing broker, scope,
//! and runtime-budget authority.
//!
//! `Success` from these verifier rules means only that the passive-control and
//! active-candidate workflow obtained fresh case-correlated HTTP status
//! evidence. Every action is knowledge-only, so that workflow truth can never
//! confirm the generic hypothesis that made the action eligible.

use std::collections::BTreeSet;

use thiserror::Error;
use venom_core::{
    EvidenceValue, HttpEvidencePredicate, HypothesisState, HypothesisStrength, KnowledgePredicate,
    OutcomeStatus, Probability, VerificationStage,
};

use crate::{
    payload_strategies::{
        CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION, EXTERNAL_URL_QUERY_PAIR_ID,
        EXTERNAL_URL_QUERY_PAIR_REVISION,
    },
    payload_strategy::{PayloadStrategyError, PayloadStrategyRef},
    planner::{
        ActionCost, AttackAction, BenefitScore, HypothesisSelector, PlannerError, PlannerWrite,
        RequiredStrength,
    },
    rules::{
        EvidenceAggregation, EvidenceCalibration, EvidenceSelector, Expression,
        HypothesisConclusion, KnowledgeLayer, ReasoningRule, RuleEngineError, RuleWrite,
    },
    verification::{VerificationError, VerificationRule, VerifierWrite},
    web_review_actions::native_web_review_response_marker_predicate,
    DecisionLoop, NativeWebReviewActionKind, NATIVE_WEB_REVIEW_ACTION_COUNT,
};

#[cfg(test)]
pub(crate) const NATIVE_WEB_REVIEW_REASONING_RULE_COUNT: usize = 1;
pub(crate) const NATIVE_WEB_REVIEW_ACTIVE_RULE_COUNT: usize = NATIVE_WEB_REVIEW_ACTION_COUNT;
#[cfg(test)]
pub(crate) const WEB_REVIEW_ELIGIBLE_PREDICATE: &str = "web.review.eligible";

const WEB_REVIEW_ELIGIBLE_RULE_ID: &str = "web.review.reason.eligible-from-response-status@1";

/// Construction or atomic-installation failure for the opt-in profile.
#[derive(Debug, Error)]
pub(crate) enum NativeWebReviewDecisionError {
    #[error(transparent)]
    Reasoning(#[from] RuleEngineError),

    #[error(transparent)]
    Planning(#[from] PlannerError),

    #[error(transparent)]
    Payload(#[from] PayloadStrategyError),

    #[error(transparent)]
    Verification(#[from] VerificationError),
}

/// Writes made by one idempotent profile installation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct NativeWebReviewDecisionInstallReport {
    pub(crate) reasoning_rules_inserted: usize,
    pub(crate) actions_inserted: usize,
    pub(crate) active_rules_inserted: usize,
}

/// Validated, executor-free native web-review decision profile.
#[derive(Debug, Clone)]
pub(crate) struct NativeWebReviewDecisionProfile {
    reasoning_rule: ReasoningRule,
    actions: Vec<AttackAction>,
    active_rules: Vec<VerificationRule>,
}

impl NativeWebReviewDecisionProfile {
    /// Builds every definition without modifying host state.
    pub(crate) fn new() -> Result<Self, NativeWebReviewDecisionError> {
        let actions = NativeWebReviewActionKind::all()
            .into_iter()
            .map(build_action)
            .collect::<Result<Vec<_>, _>>()?;
        let active_rules = NativeWebReviewActionKind::all()
            .into_iter()
            .map(build_active_rule)
            .collect::<Result<Vec<_>, _>>()?;
        debug_assert_eq!(actions.len(), NATIVE_WEB_REVIEW_ACTION_COUNT);
        debug_assert_eq!(active_rules.len(), NATIVE_WEB_REVIEW_ACTIVE_RULE_COUNT);
        Ok(Self {
            reasoning_rule: build_eligibility_rule()?,
            actions,
            active_rules,
        })
    }

    /// Installs reasoning, actions, and active verifier rules atomically.
    ///
    /// No executor registry is accepted or modified by this operation.
    pub(crate) fn install(
        &self,
        decision_loop: &mut DecisionLoop,
    ) -> Result<NativeWebReviewDecisionInstallReport, NativeWebReviewDecisionError> {
        let mut prospective = decision_loop.clone();
        let reasoning_rules_inserted = usize::from(matches!(
            prospective
                .rules_mut()
                .register(self.reasoning_rule.clone())?,
            RuleWrite::Inserted
        ));

        let mut actions_inserted = 0;
        for action in &self.actions {
            actions_inserted += usize::from(matches!(
                prospective.planner_mut().register(action.clone())?,
                PlannerWrite::Inserted
            ));
        }

        let mut active_rules_inserted = 0;
        for rule in &self.active_rules {
            active_rules_inserted += usize::from(matches!(
                prospective
                    .verification_mut()
                    .active_mut()
                    .register(rule.clone())?,
                VerifierWrite::Inserted
            ));
        }

        *decision_loop = prospective;
        Ok(NativeWebReviewDecisionInstallReport {
            reasoning_rules_inserted,
            actions_inserted,
            active_rules_inserted,
        })
    }
}

fn eligible_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("web.review", "eligible")
        .expect("web.review.eligible is a valid static predicate")
}

fn build_eligibility_rule() -> Result<ReasoningRule, RuleEngineError> {
    let status = HttpEvidencePredicate::RESPONSE_STATUS.into_knowledge();
    let calibration = EvidenceCalibration::new(
        EvidenceSelector::exists(status.clone()),
        Probability::from_percent(99).map_err(RuleEngineError::from)?,
        Probability::from_percent(1)?,
        "A case-correlated HTTP response status makes bounded web review eligible",
    )?
    .with_aggregation(EvidenceAggregation::max_contributions(1)?);
    ReasoningRule::new(
        WEB_REVIEW_ELIGIBLE_RULE_ID,
        Expression::exists(KnowledgeLayer::Evidence, status),
        HypothesisConclusion::new(
            eligible_predicate(),
            EvidenceValue::Boolean(true),
            Probability::from_percent(50)?,
            HypothesisStrength::Weak,
            HypothesisState::Supported,
            vec![calibration],
        )?,
    )
}

fn build_action(
    kind: NativeWebReviewActionKind,
) -> Result<AttackAction, NativeWebReviewDecisionError> {
    let predicate = eligible_predicate();
    let value = EvidenceValue::Boolean(true);
    Ok(AttackAction::new(
        kind.action_id(),
        kind.executor_id(),
        Expression::equals(KnowledgeLayer::Hypothesis, predicate.clone(), value.clone()),
        HypothesisSelector::new(
            predicate,
            value,
            Probability::from_percent(90).map_err(RuleEngineError::from)?,
            RequiredStrength::Any,
        ),
        BenefitScore::from_percent(20)?,
        ActionCost::new(2)?,
        kind.risk(),
        BTreeSet::new(),
    )?
    .with_payload_strategy(payload_strategy_ref(kind)?)
    .with_verification_target(kind.verification_target()))
}

fn payload_strategy_ref(
    kind: NativeWebReviewActionKind,
) -> Result<PayloadStrategyRef, PayloadStrategyError> {
    let (id, revision) = match kind {
        NativeWebReviewActionKind::CorsPolicyPair => {
            (CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION)
        },
        NativeWebReviewActionKind::RedirectReflectionQueryPair => {
            (EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION)
        },
    };
    PayloadStrategyRef::new(id, revision)
}

fn build_active_rule(
    kind: NativeWebReviewActionKind,
) -> Result<VerificationRule, VerificationError> {
    VerificationRule::new(
        format!("web.review.verify.active.{}.pair-complete@1", kind.slug()),
        VerificationStage::Active,
        500,
        Expression::exists(
            KnowledgeLayer::Evidence,
            native_web_review_response_marker_predicate(),
        ),
        OutcomeStatus::Success,
        Probability::from_percent(99).map_err(RuleEngineError::from)?,
        "The active candidate returned fresh case-correlated status evidence; this records pair completion only",
    )?
    .scoped_to_action(kind.action_id())?
    .with_case_correlated_evidence()
}

#[cfg(test)]
#[path = "web_review_decision_tests.rs"]
mod tests;
