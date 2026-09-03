//! Runtime-local opt-in decision policy for native low-risk web review.
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

use termivar_core::{
    EvidenceValue, HttpEvidencePredicate, HypothesisState, HypothesisStrength, KnowledgePredicate,
    OutcomeStatus, Probability, VerificationStage,
};
use thiserror::Error;

#[cfg(test)]
use crate::web_actions::NATIVE_WEB_REVIEW_ACTION_COUNT;
use crate::{
    payload_strategies::{
        CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION, EXTERNAL_URL_QUERY_PAIR_ID,
        EXTERNAL_URL_QUERY_PAIR_REVISION, REFLECTION_MARKER_QUERY_PAIR_ID,
        REFLECTION_MARKER_QUERY_PAIR_REVISION, SQL_QUOTE_BALANCE_QUERY_PAIR_ID,
        SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION, SSTI_ARITHMETIC_EXPRESSION_PAIR_ID,
        SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION, XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID,
        XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION, XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_ID,
        XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_REVISION, XSS_STRUCTURAL_QUERY_PAIR_ID,
        XSS_STRUCTURAL_QUERY_PAIR_REVISION,
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
    web_actions::{native_web_review_response_marker_predicate, NativeWebReviewActionKind},
    DecisionLoop,
};

#[cfg(feature = "normalization-resilience")]
use crate::payload_strategies::normalization_resilience_query_pair::{
    NORMALIZATION_RESILIENCE_QUERY_PAIR_ID, NORMALIZATION_RESILIENCE_QUERY_PAIR_REVISION,
};

#[cfg(test)]
pub(crate) const NATIVE_WEB_REVIEW_REASONING_RULE_COUNT: usize =
    1 + cfg!(feature = "rest-review") as usize;
#[cfg(test)]
pub(crate) const NATIVE_WEB_REVIEW_PASSIVE_RULE_COUNT: usize =
    if cfg!(feature = "authorization-review") {
        1
    } else {
        0
    } + if cfg!(feature = "openapi-review") {
        2
    } else {
        0
    } + if cfg!(feature = "rest-review") { 2 } else { 0 };
#[cfg(test)]
pub(crate) const NATIVE_WEB_REVIEW_ACTIVE_RULE_COUNT: usize = NATIVE_WEB_REVIEW_ACTION_COUNT
    + if cfg!(feature = "authorization-review") {
        1
    } else {
        0
    }
    + if cfg!(feature = "openapi-review") {
        1
    } else {
        0
    }
    + if cfg!(feature = "rest-review") { 1 } else { 0 };
#[cfg(test)]
pub(crate) const WEB_REVIEW_ELIGIBLE_PREDICATE: &str = "web.review.eligible";

const WEB_REVIEW_ELIGIBLE_RULE_ID: &str = "web.review.reason.eligible-from-response-status@1";
#[cfg(feature = "rest-review")]
const REST_REVIEW_ELIGIBLE_RULE_ID: &str =
    "web.review.reason.rest-eligible-from-stable-openapi-catalog@1";

/// Construction or atomic-installation failure for the opt-in profile.
#[derive(Debug, Error)]
pub(crate) enum NativeWebReviewDecisionError {
    #[error("duplicate native web-review action `{action_id}`")]
    DuplicateAction { action_id: &'static str },

    #[error("native web-review action `{action_id}` is outside the closed catalog")]
    ActionOutsideCatalog { action_id: &'static str },

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
    pub(crate) passive_rules_inserted: usize,
    pub(crate) active_rules_inserted: usize,
}

/// Validated, executor-free native web-review decision profile.
#[derive(Debug, Clone)]
pub(crate) struct NativeWebReviewDecisionProfile {
    reasoning_rules: Vec<ReasoningRule>,
    enabled_actions: Vec<NativeWebReviewActionKind>,
    actions: Vec<AttackAction>,
    passive_rules: Vec<VerificationRule>,
    active_rules: Vec<VerificationRule>,
}

impl NativeWebReviewDecisionProfile {
    /// Builds every definition without modifying host state.
    #[cfg(test)]
    pub(crate) fn new() -> Result<Self, NativeWebReviewDecisionError> {
        Self::for_actions(NativeWebReviewActionKind::all())
    }

    /// Builds the exact subject-specific executable subset in catalog order.
    ///
    /// The enum remains the closed universe. Duplicate inputs and values not
    /// represented by [`NativeWebReviewActionKind::all`] fail closed, while an
    /// empty set intentionally installs no eligibility rule or action.
    pub(crate) fn for_actions(
        actions: impl IntoIterator<Item = NativeWebReviewActionKind>,
    ) -> Result<Self, NativeWebReviewDecisionError> {
        let catalog = NativeWebReviewActionKind::all();
        let mut requested = BTreeSet::new();
        for kind in actions {
            if !catalog.contains(&kind) {
                return Err(NativeWebReviewDecisionError::ActionOutsideCatalog {
                    action_id: kind.action_id(),
                });
            }
            if !requested.insert(kind) {
                return Err(NativeWebReviewDecisionError::DuplicateAction {
                    action_id: kind.action_id(),
                });
            }
        }
        let enabled_actions = catalog
            .into_iter()
            .filter(|kind| requested.contains(kind))
            .collect::<Vec<_>>();
        let actions = enabled_actions
            .iter()
            .copied()
            .map(build_action)
            .collect::<Result<Vec<_>, _>>()?;
        let mut active_rules = Vec::new();
        for kind in enabled_actions.iter().copied() {
            #[cfg(feature = "authorization-review")]
            if kind == NativeWebReviewActionKind::ResourceAuthorizationDifferential {
                active_rules.push(build_authorization_terminal_rule(
                    kind,
                    VerificationStage::Active,
                )?);
            }
            #[cfg(feature = "openapi-review")]
            if kind == NativeWebReviewActionKind::OpenApiDocumentReplay {
                active_rules.push(build_openapi_terminal_rule(
                    kind,
                    VerificationStage::Active,
                )?);
            }
            #[cfg(feature = "rest-review")]
            if kind == NativeWebReviewActionKind::RestReadOnlyReplay {
                active_rules.push(build_rest_terminal_rule(kind, VerificationStage::Active)?);
            }
            active_rules.push(build_active_rule(kind)?);
        }
        #[cfg(feature = "authorization-review")]
        let passive_rules = enabled_actions
            .iter()
            .copied()
            .filter(|kind| *kind == NativeWebReviewActionKind::ResourceAuthorizationDifferential)
            .map(|kind| build_authorization_terminal_rule(kind, VerificationStage::Passive))
            .collect::<Result<Vec<_>, _>>()?;
        #[cfg(not(feature = "authorization-review"))]
        let passive_rules = Vec::new();
        #[cfg(feature = "openapi-review")]
        let mut passive_rules = passive_rules;
        #[cfg(feature = "openapi-review")]
        if enabled_actions.contains(&NativeWebReviewActionKind::OpenApiDocumentReplay) {
            passive_rules.push(build_openapi_terminal_rule(
                NativeWebReviewActionKind::OpenApiDocumentReplay,
                VerificationStage::Passive,
            )?);
            passive_rules.push(build_openapi_passive_progress_rule(
                NativeWebReviewActionKind::OpenApiDocumentReplay,
            )?);
        }
        #[cfg(feature = "rest-review")]
        if enabled_actions.contains(&NativeWebReviewActionKind::RestReadOnlyReplay) {
            passive_rules.push(build_rest_terminal_rule(
                NativeWebReviewActionKind::RestReadOnlyReplay,
                VerificationStage::Passive,
            )?);
            passive_rules.push(build_rest_passive_progress_rule(
                NativeWebReviewActionKind::RestReadOnlyReplay,
            )?);
        }
        debug_assert_eq!(actions.len(), enabled_actions.len());
        #[cfg(feature = "authorization-review")]
        let authorization_count = usize::from(
            enabled_actions.contains(&NativeWebReviewActionKind::ResourceAuthorizationDifferential),
        );
        #[cfg(not(feature = "authorization-review"))]
        let authorization_count = 0;
        #[cfg(feature = "openapi-review")]
        let openapi_count = usize::from(
            enabled_actions.contains(&NativeWebReviewActionKind::OpenApiDocumentReplay),
        );
        #[cfg(not(feature = "openapi-review"))]
        let openapi_count = 0;
        #[cfg(feature = "rest-review")]
        let rest_count =
            usize::from(enabled_actions.contains(&NativeWebReviewActionKind::RestReadOnlyReplay));
        #[cfg(not(feature = "rest-review"))]
        let rest_count = 0;
        debug_assert_eq!(
            passive_rules.len(),
            authorization_count + (2 * openapi_count) + (2 * rest_count)
        );
        debug_assert_eq!(
            active_rules.len(),
            enabled_actions.len() + authorization_count + openapi_count + rest_count
        );
        let mut reasoning_rules = Vec::new();
        if enabled_actions.iter().any(|kind| {
            #[cfg(feature = "rest-review")]
            {
                *kind != NativeWebReviewActionKind::RestReadOnlyReplay
            }
            #[cfg(not(feature = "rest-review"))]
            {
                let _ = kind;
                true
            }
        }) {
            reasoning_rules.push(build_eligibility_rule()?);
        }
        #[cfg(feature = "rest-review")]
        if rest_count == 1 {
            reasoning_rules.push(build_rest_eligibility_rule()?);
        }
        Ok(Self {
            reasoning_rules,
            enabled_actions,
            actions,
            passive_rules,
            active_rules,
        })
    }

    pub(crate) fn actions(&self) -> impl ExactSizeIterator<Item = NativeWebReviewActionKind> + '_ {
        self.enabled_actions.iter().copied()
    }

    /// Installs reasoning, actions, and active verifier rules atomically.
    ///
    /// No executor registry is accepted or modified by this operation.
    pub(crate) fn install(
        &self,
        decision_loop: &mut DecisionLoop,
    ) -> Result<NativeWebReviewDecisionInstallReport, NativeWebReviewDecisionError> {
        let mut prospective = decision_loop.clone();
        let mut reasoning_rules_inserted = 0;
        for rule in &self.reasoning_rules {
            reasoning_rules_inserted += usize::from(matches!(
                prospective.rules_mut().register(rule.clone())?,
                RuleWrite::Inserted
            ));
        }

        let mut actions_inserted = 0;
        for action in &self.actions {
            actions_inserted += usize::from(matches!(
                prospective.planner_mut().register(action.clone())?,
                PlannerWrite::Inserted
            ));
        }

        let mut active_rules_inserted = 0;
        let mut passive_rules_inserted = 0;
        for rule in &self.passive_rules {
            passive_rules_inserted += usize::from(matches!(
                prospective
                    .verification_mut()
                    .passive_mut()
                    .register(rule.clone())?,
                VerifierWrite::Inserted
            ));
        }
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
            passive_rules_inserted,
            active_rules_inserted,
        })
    }
}

fn eligible_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("web.review", "eligible")
        .expect("web.review.eligible is a valid static predicate")
}

#[cfg(feature = "rest-review")]
fn rest_eligible_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("web.rest-review", "eligible")
        .expect("web.rest-review.eligible is a valid static predicate")
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

#[cfg(feature = "rest-review")]
fn build_rest_eligibility_rule() -> Result<ReasoningRule, RuleEngineError> {
    let ready = crate::web_actions::rest_review_catalog_ready_predicate();
    let calibration = EvidenceCalibration::new(
        EvidenceSelector::equals(ready.clone(), EvidenceValue::Boolean(true)),
        Probability::from_percent(99).map_err(RuleEngineError::from)?,
        Probability::from_percent(1)?,
        "A replay-stable OpenAPI catalog completed bounded REST eligibility selection",
    )?
    .with_aggregation(EvidenceAggregation::max_contributions(1)?);
    ReasoningRule::new(
        REST_REVIEW_ELIGIBLE_RULE_ID,
        Expression::equals(
            KnowledgeLayer::Evidence,
            ready,
            EvidenceValue::Boolean(true),
        ),
        HypothesisConclusion::new(
            rest_eligible_predicate(),
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
    #[cfg(feature = "rest-review")]
    let predicate = if kind == NativeWebReviewActionKind::RestReadOnlyReplay {
        rest_eligible_predicate()
    } else {
        eligible_predicate()
    };
    #[cfg(not(feature = "rest-review"))]
    let predicate = eligible_predicate();
    let value = EvidenceValue::Boolean(true);
    let action = AttackAction::new(
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
        ActionCost::new(
            u32::try_from(kind.maximum_requests_per_case())
                .expect("native request counts fit the planner cost domain"),
        )?,
        kind.risk(),
        BTreeSet::new(),
    )?
    .with_verification_target(kind.verification_target());
    #[cfg(feature = "authorization-review")]
    if kind == NativeWebReviewActionKind::ResourceAuthorizationDifferential {
        return Ok(action);
    }
    #[cfg(feature = "openapi-review")]
    if kind == NativeWebReviewActionKind::OpenApiDocumentReplay {
        return Ok(action);
    }
    #[cfg(feature = "rest-review")]
    if kind == NativeWebReviewActionKind::RestReadOnlyReplay {
        return Ok(action);
    }
    Ok(action.with_payload_strategy(payload_strategy_ref(kind)?))
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
        NativeWebReviewActionKind::ReflectionContextQueryPair => (
            REFLECTION_MARKER_QUERY_PAIR_ID,
            REFLECTION_MARKER_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::SqlStructuralQueryPair
        | NativeWebReviewActionKind::SqlStructuralQueryReplayPair => (
            SQL_QUOTE_BALANCE_QUERY_PAIR_ID,
            SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::SstiStructuralQueryPair
        | NativeWebReviewActionKind::SstiStructuralQueryReplayPair => (
            SSTI_ARITHMETIC_EXPRESSION_PAIR_ID,
            SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssStructuralQueryPair => (
            XSS_STRUCTURAL_QUERY_PAIR_ID,
            XSS_STRUCTURAL_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssAttributeBoundaryQueryPair => (
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID,
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION,
        ),
        NativeWebReviewActionKind::XssScriptLexicalBoundaryQueryPair => (
            XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_ID,
            XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_REVISION,
        ),
        #[cfg(feature = "normalization-resilience")]
        NativeWebReviewActionKind::NormalizationResilienceQueryPair => (
            NORMALIZATION_RESILIENCE_QUERY_PAIR_ID,
            NORMALIZATION_RESILIENCE_QUERY_PAIR_REVISION,
        ),
        #[cfg(feature = "authorization-review")]
        NativeWebReviewActionKind::ResourceAuthorizationDifferential => {
            return Err(PayloadStrategyError::DerivationFailed);
        },
        #[cfg(feature = "openapi-review")]
        NativeWebReviewActionKind::OpenApiDocumentReplay => {
            return Err(PayloadStrategyError::DerivationFailed);
        },
        #[cfg(feature = "rest-review")]
        NativeWebReviewActionKind::RestReadOnlyReplay => {
            return Err(PayloadStrategyError::DerivationFailed);
        },
    };
    PayloadStrategyRef::new(id, revision)
}

#[cfg(feature = "authorization-review")]
fn build_authorization_terminal_rule(
    kind: NativeWebReviewActionKind,
    stage: VerificationStage,
) -> Result<VerificationRule, VerificationError> {
    debug_assert_eq!(
        kind,
        NativeWebReviewActionKind::ResourceAuthorizationDifferential
    );
    let stage_slug = match stage {
        VerificationStage::Passive => "passive",
        VerificationStage::Active => "active",
        _ => {
            return Err(VerificationError::EmptyValue {
                field: "authorization review verification stage",
            });
        },
    };
    VerificationRule::new(
        format!("web.review.verify.{stage_slug}.authorization-resource-terminal@1"),
        stage,
        1_000,
        Expression::equals(
            KnowledgeLayer::Evidence,
            crate::web_actions::authorization_review_phase_terminal_predicate(),
            EvidenceValue::Boolean(true),
        ),
        OutcomeStatus::Blocked,
        Probability::from_percent(99).map_err(RuleEngineError::from)?,
        "Authorization review stopped before replay after defensive, rate-limit, or incomplete transport evidence",
    )?
    .scoped_to_action(kind.action_id())?
    .with_case_correlated_evidence()
}

#[cfg(feature = "openapi-review")]
fn build_openapi_terminal_rule(
    kind: NativeWebReviewActionKind,
    stage: VerificationStage,
) -> Result<VerificationRule, VerificationError> {
    let stage_slug = match stage {
        VerificationStage::Passive => "passive",
        VerificationStage::Active => "active",
        _ => {
            return Err(VerificationError::EmptyValue {
                field: "OpenAPI review verification stage",
            })
        },
    };
    VerificationRule::new(
        format!("web.review.verify.{stage_slug}.openapi-terminal@1"),
        stage,
        1_000,
        Expression::equals(
            KnowledgeLayer::Evidence,
            crate::web_actions::openapi_review_phase_terminal_predicate(),
            EvidenceValue::Boolean(true),
        ),
        OutcomeStatus::Blocked,
        Probability::from_percent(99).map_err(RuleEngineError::from)?,
        "OpenAPI review stopped after a terminal bounded transport or document outcome",
    )?
    .scoped_to_action(kind.action_id())?
    .with_case_correlated_evidence()
}

#[cfg(feature = "openapi-review")]
fn build_openapi_passive_progress_rule(
    kind: NativeWebReviewActionKind,
) -> Result<VerificationRule, VerificationError> {
    VerificationRule::new(
        "web.review.verify.passive.openapi-candidate-observed@1",
        VerificationStage::Passive,
        500,
        Expression::exists(
            KnowledgeLayer::Evidence,
            native_web_review_response_marker_predicate(),
        ),
        OutcomeStatus::NeedsReview,
        Probability::from_percent(99).map_err(RuleEngineError::from)?,
        "The bounded OpenAPI candidate was observed and requires an independent active replay",
    )?
    .scoped_to_action(kind.action_id())?
    .with_case_correlated_evidence()
}

#[cfg(feature = "rest-review")]
fn build_rest_terminal_rule(
    kind: NativeWebReviewActionKind,
    stage: VerificationStage,
) -> Result<VerificationRule, VerificationError> {
    let stage_slug = match stage {
        VerificationStage::Passive => "passive",
        VerificationStage::Active => "active",
        _ => {
            return Err(VerificationError::EmptyValue {
                field: "REST review verification stage",
            });
        },
    };
    VerificationRule::new(
        format!("web.review.verify.{stage_slug}.rest-readonly-terminal@1"),
        stage,
        1_000,
        Expression::equals(
            KnowledgeLayer::Evidence,
            crate::web_actions::rest_review_phase_terminal_predicate(),
            EvidenceValue::Boolean(true),
        ),
        OutcomeStatus::Blocked,
        Probability::from_percent(99).map_err(RuleEngineError::from)?,
        "REST review stopped after a terminal bounded transport or response outcome",
    )?
    .scoped_to_action(kind.action_id())?
    .with_case_correlated_evidence()
}

#[cfg(feature = "rest-review")]
fn build_rest_passive_progress_rule(
    kind: NativeWebReviewActionKind,
) -> Result<VerificationRule, VerificationError> {
    VerificationRule::new(
        "web.review.verify.passive.rest-readonly-candidate-observed@1",
        VerificationStage::Passive,
        500,
        Expression::exists(
            KnowledgeLayer::Evidence,
            native_web_review_response_marker_predicate(),
        ),
        OutcomeStatus::NeedsReview,
        Probability::from_percent(99).map_err(RuleEngineError::from)?,
        "The bounded REST candidate was observed and requires an independent active replay",
    )?
    .scoped_to_action(kind.action_id())?
    .with_case_correlated_evidence()
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
