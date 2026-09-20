//! Bounded six-leg JWT target-acceptance orchestration.
//!
//! The runtime consumes the local S06 signature proof and one exact-resource
//! operator policy. Every leg uses a fresh ambient-proxy-free pool while
//! retaining the assessment's single request-accounting, cancellation,
//! deadline, exact-origin, and evidence authorities. Response bodies and token
//! bytes are reduced before any value enters the shared knowledge store.

use std::{collections::BTreeSet, fmt, time::Duration};

use serde::{
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserializer,
};
use sha2::{Digest, Sha256};
use termivar_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    KnowledgePredicate,
};
use thiserror::Error;

use super::authority::SharedWebRuntimeAuthority;
use crate::{
    http_evidence::{CollectedHttpResponse, JwtTargetAcceptanceRequestDescriptor},
    jwt_policy_review::{JwtTargetAcceptanceCredentials, JwtTargetAcceptanceRuntimeInput},
    jwt_target_acceptance::{
        JwtTargetAcceptanceAudit, JwtTargetAcceptanceAuditError, JwtTargetAcceptanceBinding,
        JwtTargetAcceptanceCommitStatus, JwtTargetAcceptanceDispatchStatus,
        JwtTargetAcceptanceLegFact, JwtTargetAcceptanceLegFactError, JwtTargetAcceptanceLegRole,
        JwtTargetAcceptanceMarkerStatus, JwtTargetAcceptanceNotEligibleReason,
        JwtTargetAcceptancePolicy, JwtTargetAcceptanceResponseStatus,
        MAX_JWT_TARGET_ACCEPTANCE_RESPONSE_BYTES, MAX_JWT_TARGET_ACCEPTANCE_TOTAL_RESPONSE_BYTES,
    },
    DecisionActionOrigin, DecisionExecutionLimits, DecisionExecutionStage, KnowledgeBase,
};

const JWT_TARGET_ACCEPTANCE_LOCAL_DEADLINE: Duration = Duration::from_secs(30);
const JWT_TARGET_ACCEPTANCE_EVIDENCE_NAMESPACE: &str = "web.jwt-target-acceptance.transport";
const JWT_TARGET_ACCEPTANCE_EVIDENCE_COMPONENT: &str = "jwt-target-acceptance-runtime";
const JWT_TARGET_ACCEPTANCE_EVIDENCE_METHOD: &str = "exact-resource-json-marker";
const JWT_TARGET_ACCEPTANCE_EVIDENCE_DOMAIN: &[u8] =
    b"security.jwt-target-acceptance.evidence.v1\0";
const JSON_MAX_DEPTH: usize = 16;
const JSON_MAX_NODES: usize = 512;
const JSON_MAX_KEY_BYTES: usize = 256;

/// Move-only target selection consumed by the sole assessment runtime.
pub(super) struct JwtTargetAcceptanceRuntimeConfig {
    policy: JwtTargetAcceptancePolicy,
    credentials: Option<JwtTargetAcceptanceCredentials>,
    not_eligible_reason: Option<JwtTargetAcceptanceNotEligibleReason>,
    preparation_binding: JwtTargetAcceptanceBinding,
    #[cfg(test)]
    failure_point: Option<JwtTargetAcceptanceTestFailurePoint>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JwtTargetAcceptanceTestFailurePoint {
    BeforeDispatch(JwtTargetAcceptanceLegRole),
    AfterResponseBeforeCommit(JwtTargetAcceptanceLegRole),
}

pub(super) struct JwtTargetAcceptanceRuntimeFailure {
    partial_audit: Option<JwtTargetAcceptanceAudit>,
    _source: JwtTargetAcceptanceRuntimeError,
}

impl JwtTargetAcceptanceRuntimeFailure {
    pub(super) fn into_partial_audit(self) -> Option<JwtTargetAcceptanceAudit> {
        self.partial_audit
    }
}

impl JwtTargetAcceptanceRuntimeConfig {
    pub(super) fn new(
        policy: JwtTargetAcceptancePolicy,
        runtime_input: JwtTargetAcceptanceRuntimeInput,
    ) -> Result<Self, JwtTargetAcceptanceRuntimeError> {
        let (credentials, not_eligible_reason, preparation_binding) = runtime_input.into_parts();
        if credentials.is_some() == not_eligible_reason.is_some() {
            return Err(JwtTargetAcceptanceRuntimeError::InvalidConfiguration);
        }
        if credentials
            .as_ref()
            .is_some_and(|credentials| credentials.preparation_binding() != &preparation_binding)
        {
            return Err(JwtTargetAcceptanceRuntimeError::InvalidConfiguration);
        }
        Ok(Self {
            policy,
            credentials,
            not_eligible_reason,
            preparation_binding,
            #[cfg(test)]
            failure_point: None,
        })
    }

    #[cfg(test)]
    pub(super) fn inject_failure_for_test(
        &mut self,
        failure_point: JwtTargetAcceptanceTestFailurePoint,
    ) {
        self.failure_point = Some(failure_point);
    }

    pub(super) async fn execute(
        self,
        authority: &SharedWebRuntimeAuthority,
    ) -> Result<JwtTargetAcceptanceAudit, JwtTargetAcceptanceRuntimeFailure> {
        let Self {
            policy,
            credentials,
            not_eligible_reason,
            preparation_binding,
            #[cfg(test)]
            failure_point,
        } = self;
        let Some(credentials) = credentials else {
            return Ok(JwtTargetAcceptanceAudit::not_eligible(
                &policy,
                not_eligible_reason.ok_or_else(|| {
                    runtime_failure(
                        &policy,
                        &preparation_binding,
                        &[],
                        None,
                        JwtTargetAcceptanceRuntimeError::InvalidConfiguration,
                    )
                })?,
            )
            .bind_to_preparation(preparation_binding));
        };

        let timing = authority.start();
        let local_deadline = tokio::time::Instant::now()
            .checked_add(JWT_TARGET_ACCEPTANCE_LOCAL_DEADLINE)
            .ok_or_else(|| {
                runtime_failure(
                    &policy,
                    &preparation_binding,
                    &[],
                    None,
                    JwtTargetAcceptanceRuntimeError::Clock,
                )
            })?;
        let deadline = timing
            .deadline()
            .map_or(local_deadline, |parent| parent.min(local_deadline));
        let mut facts = Vec::with_capacity(JwtTargetAcceptanceLegRole::ORDERED.len());
        let mut local_retained_response_bytes = 0_u64;
        let mut stopped = false;

        for role in JwtTargetAcceptanceLegRole::ORDERED {
            #[cfg(test)]
            if failure_point == Some(JwtTargetAcceptanceTestFailurePoint::BeforeDispatch(role)) {
                return Err(runtime_failure(
                    &policy,
                    &preparation_binding,
                    &facts,
                    None,
                    JwtTargetAcceptanceRuntimeError::InjectedTestFailure,
                ));
            }
            if stopped
                || authority.cancellation().is_cancelled()
                || tokio::time::Instant::now() >= deadline
                || local_retained_response_bytes >= MAX_JWT_TARGET_ACCEPTANCE_TOTAL_RESPONSE_BYTES
            {
                stopped = true;
                facts.push(JwtTargetAcceptanceLegFact::not_dispatched(role));
                continue;
            }
            if role.is_active() && !active_prerequisite_is_established(role, &facts) {
                facts.push(JwtTargetAcceptanceLegFact::not_dispatched(role));
                continue;
            }

            #[cfg(test)]
            let fail_after_response_before_commit = failure_point
                == Some(JwtTargetAcceptanceTestFailurePoint::AfterResponseBeforeCommit(role));
            #[cfg(not(test))]
            let fail_after_response_before_commit = false;
            let execution = execute_leg(
                authority,
                &policy,
                &credentials,
                role,
                deadline,
                MAX_JWT_TARGET_ACCEPTANCE_TOTAL_RESPONSE_BYTES
                    .saturating_sub(local_retained_response_bytes),
                fail_after_response_before_commit,
            )
            .await
            .map_err(|failure| {
                runtime_failure(
                    &policy,
                    &preparation_binding,
                    &facts,
                    failure.partial_fact,
                    failure.source,
                )
            })?;
            let fact = match execution {
                JwtTargetAcceptanceLegExecution::Fact(fact) => fact,
                JwtTargetAcceptanceLegExecution::NotEligible(reason) if facts.is_empty() => {
                    return Ok(JwtTargetAcceptanceAudit::not_eligible(&policy, reason)
                        .bind_to_preparation(preparation_binding));
                },
                JwtTargetAcceptanceLegExecution::NotEligible(_) => {
                    stopped = true;
                    JwtTargetAcceptanceLegFact::not_dispatched(role)
                },
            };
            local_retained_response_bytes = local_retained_response_bytes
                .checked_add(fact.retained_response_bytes())
                .ok_or_else(|| {
                    runtime_failure(
                        &policy,
                        &preparation_binding,
                        &facts,
                        Some(fact.clone()),
                        JwtTargetAcceptanceRuntimeError::ResponseAccounting,
                    )
                })?;
            if local_retained_response_bytes > MAX_JWT_TARGET_ACCEPTANCE_TOTAL_RESPONSE_BYTES {
                return Err(runtime_failure(
                    &policy,
                    &preparation_binding,
                    &facts,
                    Some(fact),
                    JwtTargetAcceptanceRuntimeError::ResponseAccounting,
                ));
            }
            if !fact.was_committed() {
                stopped = true;
            }
            facts.push(fact);
        }

        let failed_facts = facts.clone();
        JwtTargetAcceptanceAudit::from_legs(&policy, facts)
            .map(|audit| audit.bind_to_preparation(preparation_binding.clone()))
            .map_err(|source| {
                runtime_failure(
                    &policy,
                    &preparation_binding,
                    &failed_facts,
                    None,
                    JwtTargetAcceptanceRuntimeError::from(source),
                )
            })
    }
}

fn runtime_failure(
    policy: &JwtTargetAcceptancePolicy,
    preparation_binding: &JwtTargetAcceptanceBinding,
    completed_facts: &[JwtTargetAcceptanceLegFact],
    partial_fact: Option<JwtTargetAcceptanceLegFact>,
    source: JwtTargetAcceptanceRuntimeError,
) -> JwtTargetAcceptanceRuntimeFailure {
    let mut facts = completed_facts.to_vec();
    if let Some(fact) = partial_fact {
        if JwtTargetAcceptanceLegRole::ORDERED.get(facts.len()) == Some(&fact.role()) {
            facts.push(fact);
        }
    }
    facts.truncate(JwtTargetAcceptanceLegRole::ORDERED.len());
    let partial_audit = (0..=facts.len()).rev().find_map(|prefix_len| {
        let mut candidate = facts[..prefix_len].to_vec();
        candidate.extend(
            JwtTargetAcceptanceLegRole::ORDERED
                .iter()
                .copied()
                .skip(prefix_len)
                .map(JwtTargetAcceptanceLegFact::not_dispatched),
        );
        JwtTargetAcceptanceAudit::from_legs(policy, candidate)
            .ok()
            .map(|audit| audit.bind_to_preparation(preparation_binding.clone()))
    });
    JwtTargetAcceptanceRuntimeFailure {
        partial_audit,
        _source: source,
    }
}

impl fmt::Debug for JwtTargetAcceptanceRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtTargetAcceptanceRuntimeConfig")
            .field("policy", &self.policy)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|_| "<redacted>"),
            )
            .field("not_eligible_reason", &self.not_eligible_reason)
            .field("preparation_binding", &"<opaque-per-preparation>")
            .finish()
    }
}

fn active_prerequisite_is_established(
    role: JwtTargetAcceptanceLegRole,
    facts: &[JwtTargetAcceptanceLegFact],
) -> bool {
    let (valid, anonymous) = match role {
        JwtTargetAcceptanceLegRole::InvalidCandidate => (0, 1),
        JwtTargetAcceptanceLegRole::InvalidReplay => (3, 4),
        _ => return true,
    };
    facts.get(valid).is_some_and(|fact| {
        fact.was_committed()
            && fact.response_status() == JwtTargetAcceptanceResponseStatus::CompleteAndClassified
            && fact.marker_status() == JwtTargetAcceptanceMarkerStatus::Observed
    }) && facts.get(anonymous).is_some_and(|fact| {
        fact.was_committed()
            && fact.response_status() == JwtTargetAcceptanceResponseStatus::CompleteAndClassified
            && fact.marker_status() == JwtTargetAcceptanceMarkerStatus::NotObserved
    })
}

async fn execute_leg(
    authority: &SharedWebRuntimeAuthority,
    policy: &JwtTargetAcceptancePolicy,
    credentials: &JwtTargetAcceptanceCredentials,
    role: JwtTargetAcceptanceLegRole,
    deadline: tokio::time::Instant,
    remaining_retained_response_bytes: u64,
    fail_after_response_before_commit: bool,
) -> Result<JwtTargetAcceptanceLegExecution, JwtTargetAcceptanceLegFailure> {
    #[cfg(not(test))]
    let _ = fail_after_response_before_commit;
    let before = authority.request_accounting().snapshot();
    let broker = match authority.requests().isolated_jwt_target_acceptance() {
        Ok(broker) => broker,
        Err(_) => {
            return Ok(JwtTargetAcceptanceLegExecution::NotEligible(
                JwtTargetAcceptanceNotEligibleReason::RuntimeAuthorityUnavailable,
            ));
        },
    };
    let descriptor = JwtTargetAcceptanceRequestDescriptor::from_policy(policy, role);
    let stage = if role.is_active() {
        DecisionExecutionStage::Active
    } else {
        DecisionExecutionStage::Passive
    };
    let origin = (!role.is_active()).then_some(DecisionActionOrigin::Planned);
    let response_limit =
        MAX_JWT_TARGET_ACCEPTANCE_RESPONSE_BYTES.min(remaining_retained_response_bytes);
    let limits = DecisionExecutionLimits::new().with_max_response_body_bytes(response_limit);
    let request = broker.collect_jwt_target_acceptance_get_for_runtime(
        stage,
        origin,
        limits,
        &descriptor,
        policy,
        credentials,
    );
    let cancellation = authority.cancellation_token();
    let result = tokio::select! {
        biased;
        () = cancellation.cancelled() => None,
        result = tokio::time::timeout_at(deadline, request) => result.ok(),
    };
    let after = authority.request_accounting().snapshot();
    let request_delta = after
        .total_requests()
        .saturating_sub(before.total_requests());
    let response_bytes = after
        .response_bytes()
        .saturating_sub(before.response_bytes());
    if request_delta > 1 {
        return Err(JwtTargetAcceptanceLegFailure::new(
            JwtTargetAcceptanceRuntimeError::ResponseAccounting,
            None,
        ));
    }
    let Some(result) = result else {
        return dispatched_without_commit(role, request_delta, response_bytes)
            .map(JwtTargetAcceptanceLegExecution::Fact)
            .map_err(|source| {
                JwtTargetAcceptanceLegFailure::new(
                    source,
                    fallback_fact(role, request_delta, response_bytes, 0),
                )
            });
    };
    let response = match result {
        Ok(response) => response,
        Err(crate::http_evidence::JwtTargetAcceptanceRequestError::RuntimeLimit)
            if request_delta == 0 =>
        {
            return Ok(JwtTargetAcceptanceLegExecution::NotEligible(
                JwtTargetAcceptanceNotEligibleReason::RequestBudgetUnavailable,
            ));
        },
        Err(crate::http_evidence::JwtTargetAcceptanceRequestError::InvalidDescriptor) => {
            return Err(JwtTargetAcceptanceLegFailure::new(
                JwtTargetAcceptanceRuntimeError::InvalidDescriptor,
                fallback_fact(role, request_delta, response_bytes, 0),
            ));
        },
        Err(crate::http_evidence::JwtTargetAcceptanceRequestError::Http)
        | Err(crate::http_evidence::JwtTargetAcceptanceRequestError::RuntimeLimit) => {
            return dispatched_without_commit(role, request_delta, response_bytes)
                .map(JwtTargetAcceptanceLegExecution::Fact)
                .map_err(|source| {
                    JwtTargetAcceptanceLegFailure::new(
                        source,
                        fallback_fact(role, request_delta, response_bytes, 0),
                    )
                });
        },
    };
    if request_delta != 1 {
        return Err(JwtTargetAcceptanceLegFailure::new(
            JwtTargetAcceptanceRuntimeError::ResponseAccounting,
            None,
        ));
    }
    let retained_response_bytes = u64::try_from(response.body().len()).map_err(|_| {
        JwtTargetAcceptanceLegFailure::new(
            JwtTargetAcceptanceRuntimeError::ResponseAccounting,
            fallback_fact(role, request_delta, response_bytes, 0),
        )
    })?;
    #[cfg(test)]
    if fail_after_response_before_commit {
        return Err(JwtTargetAcceptanceLegFailure::new(
            JwtTargetAcceptanceRuntimeError::InjectedTestFailure,
            fallback_fact(role, request_delta, response_bytes, retained_response_bytes),
        ));
    }
    reduce_and_commit_response(
        policy,
        &descriptor,
        role,
        response_bytes,
        response,
        authority.knowledge(),
    )
    .map(JwtTargetAcceptanceLegExecution::Fact)
    .map_err(|source| {
        JwtTargetAcceptanceLegFailure::new(
            source,
            fallback_fact(role, request_delta, response_bytes, retained_response_bytes),
        )
    })
}

struct JwtTargetAcceptanceLegFailure {
    source: JwtTargetAcceptanceRuntimeError,
    partial_fact: Option<JwtTargetAcceptanceLegFact>,
}

impl JwtTargetAcceptanceLegFailure {
    fn new(
        source: JwtTargetAcceptanceRuntimeError,
        partial_fact: Option<JwtTargetAcceptanceLegFact>,
    ) -> Self {
        Self {
            source,
            partial_fact,
        }
    }
}

fn fallback_fact(
    role: JwtTargetAcceptanceLegRole,
    request_delta: u32,
    accounted_response_bytes: u64,
    retained_response_bytes: u64,
) -> Option<JwtTargetAcceptanceLegFact> {
    (request_delta == 1)
        .then(|| {
            JwtTargetAcceptanceLegFact::new_with_transport_accounting(
                role,
                JwtTargetAcceptanceDispatchStatus::Dispatched,
                JwtTargetAcceptanceCommitStatus::NotCommitted,
                JwtTargetAcceptanceResponseStatus::NotClassified,
                JwtTargetAcceptanceMarkerStatus::NotEvaluated,
                retained_response_bytes,
                accounted_response_bytes,
                None,
            )
            .ok()
        })
        .flatten()
}

enum JwtTargetAcceptanceLegExecution {
    Fact(JwtTargetAcceptanceLegFact),
    NotEligible(JwtTargetAcceptanceNotEligibleReason),
}

fn dispatched_without_commit(
    role: JwtTargetAcceptanceLegRole,
    request_delta: u32,
    response_bytes: u64,
) -> Result<JwtTargetAcceptanceLegFact, JwtTargetAcceptanceRuntimeError> {
    if request_delta == 0 {
        return Ok(JwtTargetAcceptanceLegFact::not_dispatched(role));
    }
    if request_delta != 1 {
        return Err(JwtTargetAcceptanceRuntimeError::ResponseAccounting);
    }
    JwtTargetAcceptanceLegFact::new_with_transport_accounting(
        role,
        JwtTargetAcceptanceDispatchStatus::Dispatched,
        JwtTargetAcceptanceCommitStatus::NotCommitted,
        JwtTargetAcceptanceResponseStatus::NotClassified,
        JwtTargetAcceptanceMarkerStatus::NotEvaluated,
        0,
        response_bytes,
        None,
    )
    .map_err(Into::into)
}

fn reduce_and_commit_response(
    policy: &JwtTargetAcceptancePolicy,
    descriptor: &JwtTargetAcceptanceRequestDescriptor,
    role: JwtTargetAcceptanceLegRole,
    accounted_response_bytes: u64,
    response: CollectedHttpResponse,
    knowledge: &KnowledgeBase,
) -> Result<JwtTargetAcceptanceLegFact, JwtTargetAcceptanceRuntimeError> {
    let retained_response_bytes = u64::try_from(response.body().len())
        .map_err(|_| JwtTargetAcceptanceRuntimeError::ResponseAccounting)?;
    if !descriptor.validate_against(policy)
        || descriptor.role() != role
        || response.final_url() != policy.resource()
    {
        return JwtTargetAcceptanceLegFact::new_with_transport_accounting(
            role,
            JwtTargetAcceptanceDispatchStatus::Dispatched,
            JwtTargetAcceptanceCommitStatus::NotCommitted,
            JwtTargetAcceptanceResponseStatus::NotClassified,
            JwtTargetAcceptanceMarkerStatus::NotEvaluated,
            retained_response_bytes,
            accounted_response_bytes,
            None,
        )
        .map_err(Into::into);
    }

    let status = response.status();
    let (response_status, marker_status) = classify_response(policy, &response);
    let observation = JwtTargetAcceptanceEvidenceObservation {
        status,
        response_status,
        marker_status,
        retained_response_bytes,
        accounted_response_bytes,
    };
    let Some(evidence_reference) =
        commit_value_safe_evidence(policy, descriptor, role, observation, knowledge)
    else {
        return JwtTargetAcceptanceLegFact::new_with_transport_accounting(
            role,
            JwtTargetAcceptanceDispatchStatus::Dispatched,
            JwtTargetAcceptanceCommitStatus::NotCommitted,
            JwtTargetAcceptanceResponseStatus::NotClassified,
            JwtTargetAcceptanceMarkerStatus::NotEvaluated,
            retained_response_bytes,
            accounted_response_bytes,
            None,
        )
        .map_err(Into::into);
    };
    JwtTargetAcceptanceLegFact::new_with_transport_accounting(
        role,
        JwtTargetAcceptanceDispatchStatus::Dispatched,
        JwtTargetAcceptanceCommitStatus::Committed,
        response_status,
        marker_status,
        retained_response_bytes,
        accounted_response_bytes,
        Some(evidence_reference),
    )
    .map_err(Into::into)
}

fn classify_response(
    policy: &JwtTargetAcceptancePolicy,
    response: &CollectedHttpResponse,
) -> (
    JwtTargetAcceptanceResponseStatus,
    JwtTargetAcceptanceMarkerStatus,
) {
    if !response.body_complete() {
        return (
            JwtTargetAcceptanceResponseStatus::Incomplete,
            JwtTargetAcceptanceMarkerStatus::NotEvaluated,
        );
    }
    if !response.has_json_compatible_media_type() || !matches!(response.status(), 200 | 401 | 403) {
        return (
            JwtTargetAcceptanceResponseStatus::NotClassified,
            JwtTargetAcceptanceMarkerStatus::NotEvaluated,
        );
    }
    let Some(marker) = strict_top_level_boolean(response.body(), policy.success_json_field())
    else {
        return (
            JwtTargetAcceptanceResponseStatus::NotClassified,
            JwtTargetAcceptanceMarkerStatus::NotEvaluated,
        );
    };
    let observed = response.status() == 200 && marker;
    (
        JwtTargetAcceptanceResponseStatus::CompleteAndClassified,
        if observed {
            JwtTargetAcceptanceMarkerStatus::Observed
        } else {
            JwtTargetAcceptanceMarkerStatus::NotObserved
        },
    )
}

#[derive(Clone, Copy)]
struct JwtTargetAcceptanceEvidenceObservation {
    status: u16,
    response_status: JwtTargetAcceptanceResponseStatus,
    marker_status: JwtTargetAcceptanceMarkerStatus,
    retained_response_bytes: u64,
    accounted_response_bytes: u64,
}

fn commit_value_safe_evidence(
    policy: &JwtTargetAcceptancePolicy,
    descriptor: &JwtTargetAcceptanceRequestDescriptor,
    role: JwtTargetAcceptanceLegRole,
    observation: JwtTargetAcceptanceEvidenceObservation,
    knowledge: &KnowledgeBase,
) -> Option<String> {
    if !descriptor.validate_against(policy) || descriptor.role() != role {
        return None;
    }
    let JwtTargetAcceptanceEvidenceObservation {
        status,
        response_status,
        marker_status,
        retained_response_bytes,
        accounted_response_bytes,
    } = observation;
    let binding = format!(
        "policy={};policy_reference={};policy_revision={};resource_reference={};role={};status={status};response_status={};marker_status={};retained_response_bytes={retained_response_bytes};accounted_response_bytes={accounted_response_bytes}",
        policy.policy_id(),
        policy.operator_policy_reference(),
        policy.operator_policy_revision(),
        policy.resource_reference(),
        role_token(role),
        response_status_token(response_status),
        marker_status_token(marker_status),
    );
    let mut digest = Sha256::new();
    digest.update(JWT_TARGET_ACCEPTANCE_EVIDENCE_DOMAIN);
    digest.update(binding.as_bytes());
    let evidence_reference = format!("jwt-target-leg:{:x}", digest.finalize());
    let evidence_id = EvidenceId::parse(evidence_reference.clone()).ok()?;
    let subject = EntityId::new(format!(
        "jwt-target-acceptance:{}",
        policy.resource_reference()
    ))
    .ok()?;
    let predicate =
        KnowledgePredicate::new(JWT_TARGET_ACCEPTANCE_EVIDENCE_NAMESPACE, "leg").ok()?;
    let source = EvidenceSource::new(
        JWT_TARGET_ACCEPTANCE_EVIDENCE_COMPONENT,
        JWT_TARGET_ACCEPTANCE_EVIDENCE_METHOD,
    )
    .and_then(|source| source.with_correlation_id(policy.operator_policy_reference().to_owned()))
    .ok()?;
    let evidence = Evidence::with_id(
        evidence_id.clone(),
        subject,
        EvidenceKind::Authentication,
        predicate,
        EvidenceValue::Text(binding),
        source,
        ConfidenceScore::MAX,
    );
    knowledge.insert_evidence(evidence.clone()).ok()?;
    (knowledge.inspect_evidence(&evidence_id, |stored| stored == &evidence) == Some(true))
        .then_some(evidence_reference)
}

const fn role_token(role: JwtTargetAcceptanceLegRole) -> &'static str {
    match role {
        JwtTargetAcceptanceLegRole::ValidCandidate => "valid_candidate",
        JwtTargetAcceptanceLegRole::AnonymousCandidate => "anonymous_candidate",
        JwtTargetAcceptanceLegRole::InvalidCandidate => "invalid_candidate",
        JwtTargetAcceptanceLegRole::ValidReplay => "valid_replay",
        JwtTargetAcceptanceLegRole::AnonymousReplay => "anonymous_replay",
        JwtTargetAcceptanceLegRole::InvalidReplay => "invalid_replay",
    }
}

const fn response_status_token(status: JwtTargetAcceptanceResponseStatus) -> &'static str {
    match status {
        JwtTargetAcceptanceResponseStatus::NotClassified => "not_classified",
        JwtTargetAcceptanceResponseStatus::CompleteAndClassified => "complete_and_classified",
        JwtTargetAcceptanceResponseStatus::Incomplete => "incomplete",
    }
}

const fn marker_status_token(status: JwtTargetAcceptanceMarkerStatus) -> &'static str {
    match status {
        JwtTargetAcceptanceMarkerStatus::Observed => "observed",
        JwtTargetAcceptanceMarkerStatus::NotObserved => "not_observed",
        JwtTargetAcceptanceMarkerStatus::NotEvaluated => "not_evaluated",
    }
}

#[derive(Clone, Copy)]
enum StrictJsonValue {
    Bool(bool),
    Other,
}

struct StrictJsonSeed<'a> {
    depth: usize,
    nodes: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed<'_> {
    type Value = StrictJsonValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > JSON_MAX_DEPTH || *self.nodes >= JSON_MAX_NODES {
            return Err(serde::de::Error::custom("bounded JWT target JSON limit"));
        }
        *self.nodes += 1;
        deserializer.deserialize_any(StrictJsonVisitor {
            depth: self.depth,
            nodes: self.nodes,
        })
    }
}

struct StrictJsonVisitor<'a> {
    depth: usize,
    nodes: &'a mut usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor<'_> {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Bool(value))
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Other)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Other)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Other)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Other)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > JSON_MAX_KEY_BYTES {
            return Err(E::custom("bounded JWT target JSON string"));
        }
        Ok(StrictJsonValue::Other)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(StrictJsonSeed {
                depth: self.depth + 1,
                nodes: self.nodes,
            })?
            .is_some()
        {}
        Ok(StrictJsonValue::Other)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > JSON_MAX_KEY_BYTES || !seen.insert(key) {
                return Err(serde::de::Error::custom(
                    "duplicate or oversized JWT target JSON key",
                ));
            }
            let _ = map.next_value_seed(StrictJsonSeed {
                depth: self.depth + 1,
                nodes: self.nodes,
            })?;
        }
        Ok(StrictJsonValue::Other)
    }
}

fn strict_top_level_boolean(bytes: &[u8], field: &str) -> Option<bool> {
    struct RootSeed<'a> {
        field: &'a str,
        nodes: &'a mut usize,
    }

    impl<'de> DeserializeSeed<'de> for RootSeed<'_> {
        type Value = Option<bool>;

        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct RootVisitor<'a> {
                field: &'a str,
                nodes: &'a mut usize,
            }

            impl<'de> Visitor<'de> for RootVisitor<'_> {
                type Value = Option<bool>;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a bounded JWT target JSON object")
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut seen = BTreeSet::new();
                    let mut selected = None;
                    while let Some(key) = map.next_key::<String>()? {
                        if key.len() > JSON_MAX_KEY_BYTES || !seen.insert(key.clone()) {
                            return Err(serde::de::Error::custom(
                                "duplicate or oversized JWT target JSON key",
                            ));
                        }
                        let value = map.next_value_seed(StrictJsonSeed {
                            depth: 1,
                            nodes: self.nodes,
                        })?;
                        if key == self.field {
                            selected = match value {
                                StrictJsonValue::Bool(value) => Some(value),
                                StrictJsonValue::Other => return Ok(None),
                            };
                        }
                    }
                    Ok(selected)
                }
            }

            deserializer.deserialize_map(RootVisitor {
                field: self.field,
                nodes: self.nodes,
            })
        }
    }

    let mut nodes = 0;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let parsed = RootSeed {
        field,
        nodes: &mut nodes,
    }
    .deserialize(&mut decoder)
    .ok()??;
    decoder.end().ok()?;
    Some(parsed)
}

/// Static, redaction-safe runtime wiring or accounting failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub(super) enum JwtTargetAcceptanceRuntimeError {
    #[error("JWT target-acceptance runtime configuration is inconsistent")]
    InvalidConfiguration,
    #[error("JWT target-acceptance runtime clock could not establish its deadline")]
    Clock,
    #[error("JWT target-acceptance response accounting is inconsistent")]
    ResponseAccounting,
    #[error("JWT target-acceptance request descriptor is inconsistent")]
    InvalidDescriptor,
    #[cfg(test)]
    #[error("injected JWT target-acceptance test failure")]
    InjectedTestFailure,
    #[error(transparent)]
    Leg(#[from] JwtTargetAcceptanceLegFactError),
    #[error(transparent)]
    Audit(#[from] JwtTargetAcceptanceAuditError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> JwtTargetAcceptancePolicy {
        policy_with(
            ("operator-policy", "revision-1"),
            "protected-marker",
            "accepted",
        )
    }

    fn policy_with(
        operator_policy_identity: (&str, &str),
        resource_reference: &str,
        success_json_field: &str,
    ) -> JwtTargetAcceptancePolicy {
        JwtTargetAcceptancePolicy::new(
            operator_policy_identity,
            url::Url::parse("https://example.test/app/").unwrap(),
            url::Url::parse("https://example.test/app/private/marker").unwrap(),
            resource_reference,
            success_json_field,
        )
        .unwrap()
    }

    #[test]
    fn strict_marker_rejects_duplicates_wrong_types_and_excessive_nesting() {
        assert_eq!(
            strict_top_level_boolean(br#"{"ok":true}"#, "ok"),
            Some(true)
        );
        assert_eq!(strict_top_level_boolean(br#"{"other":1}"#, "ok"), None);
        assert_eq!(
            strict_top_level_boolean(br#"{"ok":false}"#, "ok"),
            Some(false)
        );
        assert_eq!(strict_top_level_boolean(br#"{"ok":"true"}"#, "ok"), None);
        assert_eq!(
            strict_top_level_boolean(br#"{"ok":true,"ok":false}"#, "ok"),
            None
        );
        assert_eq!(strict_top_level_boolean(br#"[true]"#, "ok"), None);
        let deeply_nested = format!(
            "{}0{}",
            "[".repeat(JSON_MAX_DEPTH + 2),
            "]".repeat(JSON_MAX_DEPTH + 2)
        );
        assert_eq!(
            strict_top_level_boolean(deeply_nested.as_bytes(), "ok"),
            None
        );
    }

    #[test]
    fn active_controls_require_the_corresponding_passive_pair() {
        let complete = |role, marker| {
            JwtTargetAcceptanceLegFact::new(
                role,
                JwtTargetAcceptanceDispatchStatus::Dispatched,
                JwtTargetAcceptanceCommitStatus::Committed,
                JwtTargetAcceptanceResponseStatus::CompleteAndClassified,
                marker,
                1,
                Some(format!("evidence-{}", role_token(role))),
            )
            .unwrap()
        };
        let candidate = vec![
            complete(
                JwtTargetAcceptanceLegRole::ValidCandidate,
                JwtTargetAcceptanceMarkerStatus::Observed,
            ),
            complete(
                JwtTargetAcceptanceLegRole::AnonymousCandidate,
                JwtTargetAcceptanceMarkerStatus::NotObserved,
            ),
        ];
        assert!(active_prerequisite_is_established(
            JwtTargetAcceptanceLegRole::InvalidCandidate,
            &candidate,
        ));
        assert!(!active_prerequisite_is_established(
            JwtTargetAcceptanceLegRole::InvalidReplay,
            &candidate,
        ));
    }

    #[test]
    fn evidence_commit_revalidates_descriptor_role_binding() {
        let policy = policy();
        let descriptor = JwtTargetAcceptanceRequestDescriptor::from_policy(
            &policy,
            JwtTargetAcceptanceLegRole::AnonymousCandidate,
        );
        let knowledge = KnowledgeBase::new();
        let observation = JwtTargetAcceptanceEvidenceObservation {
            status: 401,
            response_status: JwtTargetAcceptanceResponseStatus::CompleteAndClassified,
            marker_status: JwtTargetAcceptanceMarkerStatus::NotObserved,
            retained_response_bytes: 17,
            accounted_response_bytes: 17,
        };

        assert!(commit_value_safe_evidence(
            &policy,
            &descriptor,
            JwtTargetAcceptanceLegRole::ValidCandidate,
            JwtTargetAcceptanceEvidenceObservation {
                status: 200,
                response_status: JwtTargetAcceptanceResponseStatus::CompleteAndClassified,
                marker_status: JwtTargetAcceptanceMarkerStatus::Observed,
                retained_response_bytes: 17,
                accounted_response_bytes: 17,
            },
            &knowledge,
        )
        .is_none());

        for changed_policy in [
            policy_with(
                ("different-policy", "revision-1"),
                "protected-marker",
                "accepted",
            ),
            policy_with(
                ("operator-policy", "revision-2"),
                "protected-marker",
                "accepted",
            ),
            policy_with(
                ("operator-policy", "revision-1"),
                "different-resource",
                "accepted",
            ),
            policy_with(
                ("operator-policy", "revision-1"),
                "protected-marker",
                "authorized",
            ),
        ] {
            assert!(commit_value_safe_evidence(
                &changed_policy,
                &descriptor,
                JwtTargetAcceptanceLegRole::AnonymousCandidate,
                observation,
                &knowledge,
            )
            .is_none());
        }

        assert!(commit_value_safe_evidence(
            &policy,
            &descriptor,
            JwtTargetAcceptanceLegRole::AnonymousCandidate,
            observation,
            &knowledge,
        )
        .is_some());
    }
}
