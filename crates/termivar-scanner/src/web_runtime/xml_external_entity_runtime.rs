//! Controlled XML external-entity interaction review.
//!
//! This child owns no independent authority. It consumes one validated policy,
//! uses the assessment's exact-origin broker for three fixed XML documents, and
//! mints the existing one-shot native OAST provider under the same parent
//! request/byte/deadline/cancellation accounting. Callback targets and XML
//! bodies never enter evidence, diagnostics, or saved reports.

use std::{collections::BTreeSet, fmt, time::Duration};

use sha2::{Digest, Sha256};
use termivar_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    KnowledgePredicate,
};
use termivar_oast::PublicOrigin;
use thiserror::Error;

use super::{
    assessment_item::{
        AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentItemTarget,
        AssessmentProjectionContext,
    },
    SharedWebRuntimeAuthority,
};
use crate::{
    http_evidence::{
        CollectedHttpResponse, HttpRequestBrokerError, XmlExternalEntityRequestBroker,
        XmlExternalEntityRequestDescriptor,
    },
    native_oast_provider::{
        NativeOastProviderAdapter, NativeOastProviderConfiguration, NativeOastProviderErrorKind,
        NativeOastProviderLimits, NativeOastProviderOperation,
    },
    oast::{OastCorrelationId, OastCorrelationToken, OastEventDisposition, OastEventKey},
    xml_external_entity_review::{
        XmlExternalEntityAdminToken, XmlExternalEntityAuditFacts, XmlExternalEntityDocumentPlan,
        XmlExternalEntityDocumentRole, XmlExternalEntityExecutionMode,
        XmlExternalEntityReviewAudit, XmlExternalEntityReviewOutcome,
        MAX_XML_EXTERNAL_ENTITY_DOCUMENT_BYTES, MAX_XML_EXTERNAL_ENTITY_PROVIDER_REQUESTS,
        MAX_XML_EXTERNAL_ENTITY_TARGET_RESPONSE_BYTES, XML_EXTERNAL_ENTITY_REVIEW_ACTION_ID,
        XML_EXTERNAL_ENTITY_REVIEW_CAPABILITY_ID, XML_EXTERNAL_ENTITY_TARGET_REQUESTS,
    },
    DecisionActionOrigin, DecisionExecutionLimits, DecisionExecutionStage, KnowledgeBase,
    TransportDispatchOutcome, VerificationCase,
};

const XML_EXTERNAL_ENTITY_EVIDENCE_NAMESPACE: &str = "web.xml-external-entity-review.transport";
const XML_EXTERNAL_ENTITY_EVIDENCE_COMPONENT: &str = "xml-external-entity-review-runtime";
const XML_EXTERNAL_ENTITY_EVIDENCE_CATEGORY: &str = "xml-external-entity-lifecycle";
const PROVIDER_REQUEST_BYTES: u64 = 64 * 1024;
const PROVIDER_RESPONSE_BYTES: u64 = 1024 * 1024;
const PREFLIGHT_CLEAN: &str = "preflight-clean";
const CONTROL_CALLBACK_ABSENT: &str = "control-callback-absent";
const TARGET_ACCOUNTING_COMPLETE: &str = "target-accounting-complete";
const CANDIDATE_CALLBACK_CORRELATED: &str = "candidate-callback-correlated";
const REPLAY_CALLBACK_CORRELATED: &str = "replay-callback-correlated";
const EVENT_IDENTITIES_DISTINCT: &str = "event-identities-distinct";
const CLEANUP_VERIFIED: &str = "cleanup-verified";
const PROVIDER_ACCOUNTING_COMPLETE: &str = "provider-accounting-complete";

const XML_EXTERNAL_ENTITY_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        XML_EXTERNAL_ENTITY_REVIEW_CAPABILITY_ID,
        "Repeated correlated outbound interactions after XML inputs",
        "XML external resource resolution",
        "Two independently allocated callback targets received distinct correlated HTTP interactions after fixed candidate and replay XML documents; parser identity, semantic effect, exploitability, and impact remain unestablished.",
        None,
        900_000,
        Some("CWE-611"),
        "web.remediation.xml-external-entity-policy@1",
        "Disable unneeded external entity resolution and independently review the exact server-side XML parser policy before treating this observation as a vulnerability.",
    );

/// Move-only configuration consumed once by one assessment.
pub(super) struct XmlExternalEntityRuntimeConfig {
    policy: crate::xml_external_entity_review::XmlExternalEntityReviewPolicy,
    administrator: XmlExternalEntityAdminToken,
}

impl XmlExternalEntityRuntimeConfig {
    pub(super) const fn new(
        policy: crate::xml_external_entity_review::XmlExternalEntityReviewPolicy,
        administrator: XmlExternalEntityAdminToken,
    ) -> Self {
        Self {
            policy,
            administrator,
        }
    }

    pub(super) async fn execute(
        self,
        authority: &SharedWebRuntimeAuthority,
        subject: EntityId,
        application: &url::Url,
    ) -> Result<XmlExternalEntityRuntimeResult, XmlExternalEntityRuntimeError> {
        execute_review(self, authority, subject, application).await
    }
}

impl fmt::Debug for XmlExternalEntityRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XmlExternalEntityRuntimeConfig")
            .field("policy", &self.policy)
            .field("administrator", &"<redacted>")
            .finish()
    }
}

pub(super) enum XmlExternalEntityRuntimeResult {
    Complete {
        audit: XmlExternalEntityReviewAudit,
        committed: Option<CommittedXmlExternalEntityReview>,
    },
    Stopped {
        audit: XmlExternalEntityReviewAudit,
    },
}

pub(super) struct CommittedXmlExternalEntityReview {
    subject: EntityId,
    control_evidence_ids: Vec<EvidenceId>,
    candidate_evidence_ids: Vec<EvidenceId>,
    audit: XmlExternalEntityReviewAudit,
}

#[derive(Debug, Error)]
pub(super) enum XmlExternalEntityRuntimeError {
    #[error("controlled XML runtime invariant failed")]
    Invariant,
}

#[derive(Default)]
struct RuntimeFacts {
    target_request_body_bytes: u64,
    target_response_bytes: u64,
    target_complete: bool,
    preflight_clean: bool,
    control_events: BTreeSet<OastEventKey>,
    candidate_events: BTreeSet<OastEventKey>,
    replay_events: BTreeSet<OastEventKey>,
    callback_targets_distinct: bool,
    phase_contaminated: bool,
    cleanup_verified: bool,
    target_accounting_complete: bool,
    provider_accounting_complete: bool,
    stop_reason: Option<RuntimeStopReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeStopReason {
    Cancelled,
    BudgetExhausted,
    Incomplete,
}

struct CallbackBindings {
    control: OastCorrelationId,
    candidate: OastCorrelationId,
    replay: OastCorrelationId,
}

async fn execute_review(
    config: XmlExternalEntityRuntimeConfig,
    authority: &SharedWebRuntimeAuthority,
    subject: EntityId,
    application: &url::Url,
) -> Result<XmlExternalEntityRuntimeResult, XmlExternalEntityRuntimeError> {
    let XmlExternalEntityRuntimeConfig {
        policy,
        administrator,
    } = config;
    let initial_target_receipt_count = authority
        .request_accounting()
        .dispatch_audit()
        .receipts()
        .iter()
        .filter(|receipt| receipt.action_id() == XML_EXTERNAL_ENTITY_REVIEW_ACTION_ID)
        .count();
    if initial_target_receipt_count != 0 {
        return Err(XmlExternalEntityRuntimeError::Invariant);
    }

    let limits = NativeOastProviderLimits::new(
        1,
        3,
        u16::try_from(MAX_XML_EXTERNAL_ENTITY_PROVIDER_REQUESTS)
            .map_err(|_| XmlExternalEntityRuntimeError::Invariant)?,
        1_u16.saturating_add(policy.polls_per_leg().saturating_mul(3)),
        PROVIDER_REQUEST_BYTES,
        PROVIDER_RESPONSE_BYTES,
        policy.lifetime_ms(),
    )
    .map_err(|_| XmlExternalEntityRuntimeError::Invariant)?;
    let mut facts = RuntimeFacts::default();
    let configuration = provider_configuration(
        policy.provider_origin(),
        &assessment_identity(&subject, policy.policy_id().as_bytes()),
        random_entropy()?,
        administrator.into_bytes(),
        limits,
        policy.execution_mode(),
    );
    let mut provider = match configuration
        .and_then(|configuration| authority.mint_native_oast_provider(configuration))
    {
        Ok(provider) => provider,
        Err(error) => {
            return terminal_result(
                &policy,
                authority,
                facts,
                None,
                outcome_for_provider_error(error.kind()),
                None,
            )
        },
    };

    if let Err(error) = provider.register().await {
        return terminal_with_provider(
            &policy,
            authority,
            facts,
            provider,
            outcome_for_provider_error(error.kind()),
            None,
        )
        .await;
    }

    let control = match allocate_callback(&mut provider, &subject, "control").await {
        Ok(callback) => callback,
        Err(error) => {
            return terminal_with_provider(
                &policy,
                authority,
                facts,
                provider,
                outcome_for_provider_error(error),
                None,
            )
            .await
        },
    };
    let candidate = match allocate_callback(&mut provider, &subject, "candidate").await {
        Ok(callback) => callback,
        Err(error) => {
            return terminal_with_provider(
                &policy,
                authority,
                facts,
                provider,
                outcome_for_provider_error(error),
                None,
            )
            .await
        },
    };
    let replay = match allocate_callback(&mut provider, &subject, "replay").await {
        Ok(callback) => callback,
        Err(error) => {
            return terminal_with_provider(
                &policy,
                authority,
                facts,
                provider,
                outcome_for_provider_error(error),
                None,
            )
            .await
        },
    };

    let bindings = CallbackBindings {
        control: control.correlation_receipt().correlation_id().clone(),
        candidate: candidate.correlation_receipt().correlation_id().clone(),
        replay: replay.correlation_receipt().correlation_id().clone(),
    };
    let plan = match XmlExternalEntityDocumentPlan::new(
        &policy,
        control.target(),
        candidate.target(),
        replay.target(),
    ) {
        Ok(plan) => plan,
        Err(_) => {
            return cleanup_then_error(provider, XmlExternalEntityRuntimeError::Invariant).await
        },
    };
    facts.callback_targets_distinct = true;

    match provider.poll().await {
        Ok(poll) => {
            absorb_poll(&mut facts, &bindings, &poll);
            facts.preflight_clean = facts.control_events.is_empty()
                && facts.candidate_events.is_empty()
                && facts.replay_events.is_empty();
        },
        Err(error) => {
            return terminal_with_provider(
                &policy,
                authority,
                facts,
                provider,
                outcome_for_provider_error(error.kind()),
                None,
            )
            .await
        },
    }
    if !facts.preflight_clean {
        return terminal_with_provider(
            &policy,
            authority,
            facts,
            provider,
            XmlExternalEntityReviewOutcome::PreflightContaminated,
            None,
        )
        .await;
    }

    let broker = match authority
        .requests()
        .isolated_xml_external_entity_review(application, &policy)
    {
        Ok(broker) => broker,
        Err(_) => {
            return cleanup_then_error(provider, XmlExternalEntityRuntimeError::Invariant).await
        },
    };
    let mut expected_body_lengths = Vec::with_capacity(XML_EXTERNAL_ENTITY_TARGET_REQUESTS);
    let mut target_complete = true;
    for role in [
        XmlExternalEntityDocumentRole::Control,
        XmlExternalEntityDocumentRole::Candidate,
        XmlExternalEntityDocumentRole::Replay,
    ] {
        if authority.cancellation().is_cancelled() {
            target_complete = false;
            facts.stop_reason = Some(RuntimeStopReason::Cancelled);
            break;
        }
        if role != XmlExternalEntityDocumentRole::Control && !facts.control_events.is_empty() {
            target_complete = false;
            break;
        }
        let body = plan.document(role).as_bytes();
        let body_len = match u64::try_from(body.len()) {
            Ok(body_len) => body_len,
            Err(_) => {
                return cleanup_then_error(provider, XmlExternalEntityRuntimeError::Invariant).await
            },
        };
        if body.len() > MAX_XML_EXTERNAL_ENTITY_DOCUMENT_BYTES {
            return cleanup_then_error(provider, XmlExternalEntityRuntimeError::Invariant).await;
        }
        expected_body_lengths.push(body_len);
        facts.target_request_body_bytes = facts.target_request_body_bytes.saturating_add(body_len);
        let descriptor =
            match XmlExternalEntityRequestDescriptor::from_document(&policy, plan.document(role)) {
                Ok(descriptor) => descriptor,
                Err(_) => {
                    return cleanup_then_error(provider, XmlExternalEntityRuntimeError::Invariant)
                        .await
                },
            };
        let dispatch = dispatch_shape(role);
        let response = collect_target_with_runtime_bounds(
            &broker,
            authority,
            dispatch,
            DecisionExecutionLimits::new()
                .with_max_response_body_bytes(MAX_XML_EXTERNAL_ENTITY_TARGET_RESPONSE_BYTES),
            &descriptor,
            &policy,
            plan.document(role),
        )
        .await;
        match response {
            Ok(response) => {
                facts.target_response_bytes = facts
                    .target_response_bytes
                    .saturating_add(u64::try_from(response.body().len()).unwrap_or(u64::MAX));
                if response.final_url() != policy.endpoint() || !response.body_complete() {
                    target_complete = false;
                    facts.stop_reason = Some(RuntimeStopReason::Incomplete);
                }
            },
            Err(reason) => {
                facts.stop_reason = Some(reason);
                target_complete = false;
                break;
            },
        }
        if !target_complete {
            break;
        }

        for _ in 0..policy.polls_per_leg() {
            if let Err(reason) = wait_for_poll(authority, policy.poll_interval_ms()).await {
                facts.stop_reason = Some(reason);
                target_complete = false;
                break;
            }
            match provider.poll().await {
                Ok(poll) => {
                    absorb_poll(&mut facts, &bindings, &poll);
                    mark_phase_contamination(&mut facts, role);
                },
                Err(error) => {
                    facts.stop_reason = Some(stop_reason_for_provider_error(error.kind()));
                    target_complete = false;
                    break;
                },
            }
            if role == XmlExternalEntityDocumentRole::Candidate
                && !facts.candidate_events.is_empty()
            {
                break;
            }
            if role == XmlExternalEntityDocumentRole::Replay && !facts.replay_events.is_empty() {
                break;
            }
        }
        if !target_complete {
            break;
        }
        if facts.phase_contaminated {
            target_complete = false;
            break;
        }
    }
    facts.target_complete =
        target_complete && expected_body_lengths.len() == XML_EXTERNAL_ENTITY_TARGET_REQUESTS;
    facts.cleanup_verified = provider
        .cleanup()
        .await
        .as_ref()
        .is_ok_and(|receipt| receipt.cleanup_verified());
    facts.provider_accounting_complete = provider_accounting_is_complete(&provider);
    let target_accounting =
        target_accounting(authority, &expected_body_lengths, facts.target_complete);
    facts.target_request_body_bytes = target_accounting.request_body_bytes;
    facts.target_response_bytes = target_accounting.response_bytes;
    facts.target_accounting_complete = target_accounting.complete;

    let outcome = classify_outcome(authority, &facts);
    let positive =
        outcome == XmlExternalEntityReviewOutcome::RepeatedExternalEntityResolutionObserved;
    let (control_evidence_ids, candidate_evidence_ids) = if positive {
        commit_positive_evidence(authority.knowledge(), &subject, &policy)?
    } else {
        (Vec::new(), Vec::new())
    };
    let audit = audit(
        &policy,
        &facts,
        target_accounting.request_count,
        provider.admitted_provider_requests(),
        positive,
        outcome,
    )?;
    if positive {
        Ok(XmlExternalEntityRuntimeResult::Complete {
            audit: audit.clone(),
            committed: Some(CommittedXmlExternalEntityReview {
                subject,
                control_evidence_ids,
                candidate_evidence_ids,
                audit,
            }),
        })
    } else if facts.phase_contaminated || is_stopped_outcome(outcome) {
        Ok(XmlExternalEntityRuntimeResult::Stopped { audit })
    } else {
        Ok(XmlExternalEntityRuntimeResult::Complete {
            audit,
            committed: None,
        })
    }
}

async fn allocate_callback(
    provider: &mut NativeOastProviderAdapter,
    subject: &EntityId,
    role: &'static str,
) -> Result<crate::native_oast_provider::NativeOastAllocatedCallback, NativeOastProviderErrorKind> {
    let case = VerificationCase::new(
        format!("xml-external-entity:{role}"),
        subject.clone(),
        XML_EXTERNAL_ENTITY_REVIEW_ACTION_ID,
        "xml-external-entity-resolution-review",
    )
    .map(VerificationCase::without_hypothesis_transition)
    .map_err(|_| NativeOastProviderErrorKind::InternalInvariant)?;
    let token = OastCorrelationToken::new(
        random_entropy().map_err(|_| NativeOastProviderErrorKind::InternalInvariant)?,
    )
    .map_err(|_| NativeOastProviderErrorKind::InternalInvariant)?;
    provider
        .allocate_callback(case, token)
        .await
        .map_err(|error| error.kind())
}

fn absorb_poll(
    facts: &mut RuntimeFacts,
    bindings: &CallbackBindings,
    poll: &crate::native_oast_provider::NativeOastPollOutcome,
) {
    for receipt in poll.correlation_receipts() {
        let target = if receipt.correlation_id() == &bindings.control {
            &mut facts.control_events
        } else if receipt.correlation_id() == &bindings.candidate {
            &mut facts.candidate_events
        } else if receipt.correlation_id() == &bindings.replay {
            &mut facts.replay_events
        } else {
            continue;
        };
        for event in receipt.event_receipts() {
            if event.disposition() == OastEventDisposition::Accepted {
                target.insert(event.event_key().clone());
            }
        }
    }
}

fn mark_phase_contamination(
    facts: &mut RuntimeFacts,
    dispatched_role: XmlExternalEntityDocumentRole,
) {
    facts.phase_contaminated |= match dispatched_role {
        XmlExternalEntityDocumentRole::Control => {
            !facts.candidate_events.is_empty() || !facts.replay_events.is_empty()
        },
        XmlExternalEntityDocumentRole::Candidate => !facts.replay_events.is_empty(),
        XmlExternalEntityDocumentRole::Replay => false,
    };
}

async fn wait_for_poll(
    authority: &SharedWebRuntimeAuthority,
    interval_ms: u64,
) -> Result<(), RuntimeStopReason> {
    let deadline = authority.start().deadline();
    if authority.cancellation().is_cancelled() {
        return Err(RuntimeStopReason::Cancelled);
    }
    let now = tokio::time::Instant::now();
    if deadline.is_some_and(|deadline| now >= deadline) {
        return Err(RuntimeStopReason::BudgetExhausted);
    }
    let interval_deadline = now + Duration::from_millis(interval_ms);
    if let Some(parent_deadline) = deadline {
        if interval_deadline >= parent_deadline {
            return tokio::select! {
                biased;
                () = authority.cancellation().cancelled() => Err(RuntimeStopReason::Cancelled),
                () = tokio::time::sleep_until(parent_deadline) => Err(RuntimeStopReason::BudgetExhausted),
            };
        }
    }
    tokio::select! {
        biased;
        () = authority.cancellation().cancelled() => Err(RuntimeStopReason::Cancelled),
        () = tokio::time::sleep_until(interval_deadline) => Ok(()),
    }
}

async fn collect_target_with_runtime_bounds(
    broker: &XmlExternalEntityRequestBroker,
    authority: &SharedWebRuntimeAuthority,
    dispatch: XmlExternalEntityDispatchShape,
    limits: DecisionExecutionLimits,
    descriptor: &XmlExternalEntityRequestDescriptor,
    policy: &crate::xml_external_entity_review::XmlExternalEntityReviewPolicy,
    document: &crate::xml_external_entity_review::XmlExternalEntityDocument,
) -> Result<CollectedHttpResponse, RuntimeStopReason> {
    if authority.cancellation().is_cancelled() {
        return Err(RuntimeStopReason::Cancelled);
    }
    let deadline = authority.start().deadline();
    if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
        return Err(RuntimeStopReason::BudgetExhausted);
    }
    let request = broker.collect_post(
        dispatch.stage,
        dispatch.origin,
        limits,
        descriptor,
        policy,
        document,
    );
    tokio::pin!(request);
    if let Some(deadline) = deadline {
        tokio::select! {
            biased;
            () = authority.cancellation().cancelled() => Err(RuntimeStopReason::Cancelled),
            () = tokio::time::sleep_until(deadline) => Err(RuntimeStopReason::BudgetExhausted),
            result = &mut request => result.map_err(stop_reason_for_target_error),
        }
    } else {
        tokio::select! {
            biased;
            () = authority.cancellation().cancelled() => Err(RuntimeStopReason::Cancelled),
            result = &mut request => result.map_err(stop_reason_for_target_error),
        }
    }
}

fn stop_reason_for_target_error(error: HttpRequestBrokerError) -> RuntimeStopReason {
    match error {
        HttpRequestBrokerError::RuntimeLimit(_) => RuntimeStopReason::BudgetExhausted,
        HttpRequestBrokerError::Http(_) => RuntimeStopReason::Incomplete,
    }
}

fn stop_reason_for_provider_error(kind: NativeOastProviderErrorKind) -> RuntimeStopReason {
    match outcome_for_provider_error(kind) {
        XmlExternalEntityReviewOutcome::Cancelled => RuntimeStopReason::Cancelled,
        XmlExternalEntityReviewOutcome::BudgetExhausted => RuntimeStopReason::BudgetExhausted,
        _ => RuntimeStopReason::Incomplete,
    }
}

#[derive(Clone, Copy)]
struct XmlExternalEntityDispatchShape {
    stage: DecisionExecutionStage,
    origin: Option<DecisionActionOrigin>,
}

fn dispatch_shape(role: XmlExternalEntityDocumentRole) -> XmlExternalEntityDispatchShape {
    match role {
        XmlExternalEntityDocumentRole::Control | XmlExternalEntityDocumentRole::Replay => {
            XmlExternalEntityDispatchShape {
                stage: DecisionExecutionStage::Passive,
                origin: Some(DecisionActionOrigin::Planned),
            }
        },
        XmlExternalEntityDocumentRole::Candidate => XmlExternalEntityDispatchShape {
            stage: DecisionExecutionStage::Active,
            origin: None,
        },
    }
}

struct TargetAccounting {
    request_count: u8,
    request_body_bytes: u64,
    response_bytes: u64,
    complete: bool,
}

fn target_accounting(
    authority: &SharedWebRuntimeAuthority,
    expected_body_lengths: &[u64],
    target_complete: bool,
) -> TargetAccounting {
    let audit = authority.request_accounting().dispatch_audit();
    let receipts = audit
        .receipts()
        .iter()
        .filter(|receipt| receipt.action_id() == XML_EXTERNAL_ENTITY_REVIEW_ACTION_ID)
        .collect::<Vec<_>>();
    let request_body_bytes = receipts.iter().fold(0_u64, |total, receipt| {
        total.saturating_add(receipt.request_body_bytes())
    });
    let response_bytes = receipts.iter().fold(0_u64, |total, receipt| {
        total.saturating_add(receipt.response_bytes())
    });
    let shape_complete = receipts.len() == XML_EXTERNAL_ENTITY_TARGET_REQUESTS
        && expected_body_lengths.len() == XML_EXTERNAL_ENTITY_TARGET_REQUESTS
        && receipts.iter().enumerate().all(|(index, receipt)| {
            let role = [
                XmlExternalEntityDocumentRole::Control,
                XmlExternalEntityDocumentRole::Candidate,
                XmlExternalEntityDocumentRole::Replay,
            ][index];
            let dispatch = dispatch_shape(role);
            receipt.stage() == dispatch.stage
                && receipt.origin() == dispatch.origin
                && receipt.request_body_bytes() == expected_body_lengths[index]
                && receipt.outcome() == TransportDispatchOutcome::Completed
        });
    TargetAccounting {
        request_count: u8::try_from(receipts.len()).unwrap_or(u8::MAX),
        request_body_bytes,
        response_bytes,
        complete: target_complete && audit.omitted_receipt_count() == 0 && shape_complete,
    }
}

fn provider_accounting_is_complete(provider: &NativeOastProviderAdapter) -> bool {
    let receipts = provider.receipts();
    let minimum = 1 + 3 + 1 + 3 + 1;
    receipts.len() >= minimum
        && receipts.len() <= MAX_XML_EXTERNAL_ENTITY_PROVIDER_REQUESTS
        && receipts
            .iter()
            .enumerate()
            .all(|(index, receipt)| usize::from(receipt.request_count()) == index + 1)
        && receipts
            .first()
            .is_some_and(|receipt| receipt.operation() == NativeOastProviderOperation::Register)
        && receipts.get(1..4).is_some_and(|allocations| {
            allocations
                .iter()
                .all(|receipt| receipt.operation() == NativeOastProviderOperation::AllocateCallback)
        })
        && receipts[4..receipts.len() - 1]
            .iter()
            .all(|receipt| receipt.operation() == NativeOastProviderOperation::Poll)
        && receipts
            .last()
            .is_some_and(|receipt| receipt.operation() == NativeOastProviderOperation::Cleanup)
        && provider.admitted_provider_requests()
            == u16::try_from(receipts.len()).unwrap_or(u16::MAX)
}

fn classify_outcome(
    authority: &SharedWebRuntimeAuthority,
    facts: &RuntimeFacts,
) -> XmlExternalEntityReviewOutcome {
    let lifecycle_complete = facts.target_complete
        && facts.target_accounting_complete
        && facts.provider_accounting_complete;
    if (authority.cancellation().is_cancelled()
        || facts.stop_reason == Some(RuntimeStopReason::Cancelled))
        && !lifecycle_complete
    {
        return XmlExternalEntityReviewOutcome::Cancelled;
    }
    if !facts.preflight_clean {
        return XmlExternalEntityReviewOutcome::PreflightContaminated;
    }
    if !facts.control_events.is_empty() {
        return XmlExternalEntityReviewOutcome::ControlCallbackObserved;
    }
    if facts.stop_reason == Some(RuntimeStopReason::BudgetExhausted) {
        return XmlExternalEntityReviewOutcome::BudgetExhausted;
    }
    if !facts.cleanup_verified {
        return XmlExternalEntityReviewOutcome::CleanupIncomplete;
    }
    if facts.phase_contaminated {
        return XmlExternalEntityReviewOutcome::CorrelationMismatch;
    }
    if facts.stop_reason == Some(RuntimeStopReason::Incomplete)
        || !facts.target_complete
        || !facts.target_accounting_complete
        || !facts.provider_accounting_complete
    {
        return XmlExternalEntityReviewOutcome::Incomplete;
    }
    match (
        facts.candidate_events.is_empty(),
        facts.replay_events.is_empty(),
    ) {
        (true, true) => XmlExternalEntityReviewOutcome::NoCallback,
        (false, true) => XmlExternalEntityReviewOutcome::CandidateOnly,
        (true, false) => XmlExternalEntityReviewOutcome::ReplayOnly,
        (false, false) if facts.candidate_events.is_disjoint(&facts.replay_events) => {
            XmlExternalEntityReviewOutcome::RepeatedExternalEntityResolutionObserved
        },
        (false, false) => XmlExternalEntityReviewOutcome::CorrelationMismatch,
    }
}

const fn is_stopped_outcome(outcome: XmlExternalEntityReviewOutcome) -> bool {
    matches!(
        outcome,
        XmlExternalEntityReviewOutcome::Cancelled
            | XmlExternalEntityReviewOutcome::BudgetExhausted
            | XmlExternalEntityReviewOutcome::Incomplete
            | XmlExternalEntityReviewOutcome::CleanupIncomplete
    )
}

fn outcome_for_provider_error(kind: NativeOastProviderErrorKind) -> XmlExternalEntityReviewOutcome {
    match kind {
        NativeOastProviderErrorKind::Cancelled => XmlExternalEntityReviewOutcome::Cancelled,
        NativeOastProviderErrorKind::RuntimeBudget(_)
        | NativeOastProviderErrorKind::ParentBudgetTooSmall
        | NativeOastProviderErrorKind::RequestLimit
        | NativeOastProviderErrorKind::RequestByteLimit
        | NativeOastProviderErrorKind::ResponseByteLimit
        | NativeOastProviderErrorKind::PollLimit
        | NativeOastProviderErrorKind::DeadlineExceeded => {
            XmlExternalEntityReviewOutcome::BudgetExhausted
        },
        _ => XmlExternalEntityReviewOutcome::Incomplete,
    }
}

async fn terminal_with_provider(
    policy: &crate::xml_external_entity_review::XmlExternalEntityReviewPolicy,
    authority: &SharedWebRuntimeAuthority,
    mut facts: RuntimeFacts,
    mut provider: NativeOastProviderAdapter,
    outcome: XmlExternalEntityReviewOutcome,
    expected_body_lengths: Option<&[u64]>,
) -> Result<XmlExternalEntityRuntimeResult, XmlExternalEntityRuntimeError> {
    facts.cleanup_verified = provider
        .cleanup()
        .await
        .as_ref()
        .is_ok_and(|receipt| receipt.cleanup_verified());
    facts.provider_accounting_complete = false;
    terminal_result(
        policy,
        authority,
        facts,
        Some(&provider),
        outcome,
        expected_body_lengths,
    )
}

async fn cleanup_then_error(
    mut provider: NativeOastProviderAdapter,
    error: XmlExternalEntityRuntimeError,
) -> Result<XmlExternalEntityRuntimeResult, XmlExternalEntityRuntimeError> {
    let _ = provider.cleanup().await;
    Err(error)
}

fn terminal_result(
    policy: &crate::xml_external_entity_review::XmlExternalEntityReviewPolicy,
    authority: &SharedWebRuntimeAuthority,
    mut facts: RuntimeFacts,
    provider: Option<&NativeOastProviderAdapter>,
    outcome: XmlExternalEntityReviewOutcome,
    expected_body_lengths: Option<&[u64]>,
) -> Result<XmlExternalEntityRuntimeResult, XmlExternalEntityRuntimeError> {
    let lengths = expected_body_lengths.unwrap_or(&[]);
    let target = target_accounting(authority, lengths, false);
    facts.target_request_body_bytes = target.request_body_bytes;
    facts.target_response_bytes = target.response_bytes;
    facts.target_accounting_complete = false;
    let provider_requests =
        provider.map_or(0, NativeOastProviderAdapter::admitted_provider_requests);
    let audit = audit(
        policy,
        &facts,
        target.request_count,
        provider_requests,
        false,
        outcome,
    )?;
    Ok(XmlExternalEntityRuntimeResult::Stopped { audit })
}

fn audit(
    policy: &crate::xml_external_entity_review::XmlExternalEntityReviewPolicy,
    facts: &RuntimeFacts,
    target_request_count: u8,
    provider_request_count: u16,
    item_projected: bool,
    outcome: XmlExternalEntityReviewOutcome,
) -> Result<XmlExternalEntityReviewAudit, XmlExternalEntityRuntimeError> {
    XmlExternalEntityReviewAudit::from_runtime(
        policy,
        XmlExternalEntityAuditFacts {
            outcome,
            target_request_count,
            provider_request_count: u8::try_from(provider_request_count).unwrap_or(u8::MAX),
            active_verification_count: u8::from(target_request_count >= 2),
            target_request_body_bytes: facts.target_request_body_bytes,
            target_response_bytes: facts.target_response_bytes,
            target_complete: facts.target_complete,
            preflight_clean: facts.preflight_clean,
            control_callback_observed: !facts.control_events.is_empty(),
            candidate_callback_observed: !facts.candidate_events.is_empty(),
            replay_callback_observed: !facts.replay_events.is_empty(),
            callback_targets_distinct: facts.callback_targets_distinct,
            event_identities_distinct: !facts.phase_contaminated
                && !facts.candidate_events.is_empty()
                && !facts.replay_events.is_empty()
                && facts.candidate_events.is_disjoint(&facts.replay_events),
            cleanup_verified: facts.cleanup_verified,
            target_accounting_complete: facts.target_accounting_complete,
            provider_accounting_complete: facts.provider_accounting_complete,
            item_projected,
        },
    )
    .map_err(|_| XmlExternalEntityRuntimeError::Invariant)
}

fn commit_positive_evidence(
    knowledge: &KnowledgeBase,
    subject: &EntityId,
    policy: &crate::xml_external_entity_review::XmlExternalEntityReviewPolicy,
) -> Result<(Vec<EvidenceId>, Vec<EvidenceId>), XmlExternalEntityRuntimeError> {
    let control = [
        (PREFLIGHT_CLEAN, true),
        (CONTROL_CALLBACK_ABSENT, true),
        (TARGET_ACCOUNTING_COMPLETE, true),
    ];
    let candidate = [
        (CANDIDATE_CALLBACK_CORRELATED, true),
        (REPLAY_CALLBACK_CORRELATED, true),
        (EVENT_IDENTITIES_DISTINCT, true),
        (CLEANUP_VERIFIED, true),
        (PROVIDER_ACCOUNTING_COMPLETE, true),
    ];
    let mut evidence = Vec::with_capacity(control.len() + candidate.len());
    for (name, value) in control.into_iter().chain(candidate) {
        let predicate = KnowledgePredicate::new(XML_EXTERNAL_ENTITY_EVIDENCE_NAMESPACE, name)
            .map_err(|_| XmlExternalEntityRuntimeError::Invariant)?;
        let source = EvidenceSource::new(XML_EXTERNAL_ENTITY_EVIDENCE_COMPONENT, name)
            .and_then(|source| source.with_correlation_id(policy.policy_id().to_wire()))
            .map_err(|_| XmlExternalEntityRuntimeError::Invariant)?;
        evidence.push(Evidence::new(
            subject.clone(),
            EvidenceKind::Custom(XML_EXTERNAL_ENTITY_EVIDENCE_CATEGORY.to_owned()),
            predicate,
            EvidenceValue::Boolean(value),
            source,
            ConfidenceScore::MAX,
        ));
    }
    let control_len = control.len();
    let control_ids = evidence[..control_len]
        .iter()
        .map(|item| item.id().clone())
        .collect::<Vec<_>>();
    let candidate_ids = evidence[control_len..]
        .iter()
        .map(|item| item.id().clone())
        .collect::<Vec<_>>();
    knowledge
        .insert_evidence_batch(evidence)
        .map_err(|_| XmlExternalEntityRuntimeError::Invariant)?;
    Ok((control_ids, candidate_ids))
}

fn positive_evidence_contract(
    knowledge: &KnowledgeBase,
    subject: &EntityId,
    policy_id: &str,
    control_ids: &[EvidenceId],
    candidate_ids: &[EvidenceId],
) -> bool {
    let expected_control = [
        PREFLIGHT_CLEAN,
        CONTROL_CALLBACK_ABSENT,
        TARGET_ACCOUNTING_COMPLETE,
    ];
    let expected_candidate = [
        CANDIDATE_CALLBACK_CORRELATED,
        REPLAY_CALLBACK_CORRELATED,
        EVENT_IDENTITIES_DISTINCT,
        CLEANUP_VERIFIED,
        PROVIDER_ACCOUNTING_COMPLETE,
    ];
    control_ids.len() == expected_control.len()
        && candidate_ids.len() == expected_candidate.len()
        && control_ids
            .iter()
            .zip(expected_control)
            .chain(candidate_ids.iter().zip(expected_candidate))
            .all(|(id, name)| {
                knowledge.evidence(id).is_some_and(|evidence| {
                    evidence.subject() == subject
                        && matches!(
                            evidence.kind(),
                            EvidenceKind::Custom(category)
                                if category == XML_EXTERNAL_ENTITY_EVIDENCE_CATEGORY
                        )
                        && evidence.predicate().namespace()
                            == XML_EXTERNAL_ENTITY_EVIDENCE_NAMESPACE
                        && evidence.predicate().name() == name
                        && evidence.value() == &EvidenceValue::Boolean(true)
                        && evidence.source().component() == XML_EXTERNAL_ENTITY_EVIDENCE_COMPONENT
                        && evidence.source().method() == name
                        && evidence.source().correlation_id() == Some(policy_id)
                })
            })
}

pub(super) fn project_xml_external_entity_item(
    context: &mut AssessmentProjectionContext,
    knowledge: &KnowledgeBase,
    review: &CommittedXmlExternalEntityReview,
) -> Result<(), AssessmentItemProjectionError> {
    if review.audit.outcome()
        != XmlExternalEntityReviewOutcome::RepeatedExternalEntityResolutionObserved
        || !review.audit.item_projected()
        || !context.has_subject(&review.subject)
        || !positive_evidence_contract(
            knowledge,
            &review.subject,
            review.audit.policy_id(),
            &review.control_evidence_ids,
            &review.candidate_evidence_ids,
        )
    {
        return Err(AssessmentItemProjectionError::MissingEvidence);
    }
    for evidence_id in review
        .control_evidence_ids
        .iter()
        .chain(&review.candidate_evidence_ids)
    {
        context.register_evidence(knowledge, evidence_id)?;
    }
    context.project_differential(
        &XML_EXTERNAL_ENTITY_CAPABILITY,
        knowledge,
        &review.subject,
        &AssessmentItemTarget::subject(),
        &review.control_evidence_ids,
        &review.candidate_evidence_ids,
    )
}

fn provider_configuration(
    origin: &PublicOrigin,
    assessment_id: &str,
    epoch: [u8; 32],
    administrator: Vec<u8>,
    limits: NativeOastProviderLimits,
    execution_mode: XmlExternalEntityExecutionMode,
) -> Result<NativeOastProviderConfiguration, crate::native_oast_provider::NativeOastProviderError> {
    #[cfg(test)]
    if execution_mode == XmlExternalEntityExecutionMode::OwnedNumericLoopbackTest {
        return NativeOastProviderConfiguration::for_loopback(
            origin.clone(),
            assessment_id,
            epoch,
            administrator,
            limits,
        );
    }
    let _ = execution_mode;
    NativeOastProviderConfiguration::new(
        origin.as_str(),
        assessment_id,
        epoch,
        administrator,
        limits,
    )
}

fn random_entropy() -> Result<[u8; 32], XmlExternalEntityRuntimeError> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| XmlExternalEntityRuntimeError::Invariant)?;
    if bytes == [0_u8; 32] {
        return Err(XmlExternalEntityRuntimeError::Invariant);
    }
    Ok(bytes)
}

fn assessment_identity(subject: &EntityId, policy_id: [u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"security.xml-external-entity.assessment-id/v1\0");
    digest.update(subject.as_str().as_bytes());
    digest.update(policy_id);
    format!("assessment-{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::xml_external_entity_review::XmlExternalEntityReviewPolicy;

    fn loopback_policy() -> XmlExternalEntityReviewPolicy {
        XmlExternalEntityReviewPolicy::for_owned_loopback(
            url::Url::parse("http://127.0.0.1:39090/application/").unwrap(),
            url::Url::parse("http://127.0.0.1:39090/application/xml").unwrap(),
            PublicOrigin::from_test_loopback(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                39091,
            ))
            .unwrap(),
            1,
            250,
            5_000,
        )
        .unwrap()
    }

    #[test]
    fn positive_evidence_requires_exact_subject_policy_and_ordered_identities() {
        let policy = loopback_policy();
        let subject = EntityId::new("endpoint:http://127.0.0.1:39090/application/").unwrap();
        let knowledge = KnowledgeBase::new();
        let (control, candidate) = commit_positive_evidence(&knowledge, &subject, &policy).unwrap();
        let policy_id = policy.policy_id().to_wire();
        assert!(positive_evidence_contract(
            &knowledge, &subject, &policy_id, &control, &candidate,
        ));

        let other_subject = EntityId::new("endpoint:http://127.0.0.1:39090/sibling/").unwrap();
        assert!(!positive_evidence_contract(
            &knowledge,
            &other_subject,
            &policy_id,
            &control,
            &candidate,
        ));
        assert!(!positive_evidence_contract(
            &knowledge,
            &subject,
            "xml-external-entity-policy-sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            &control,
            &candidate,
        ));

        let mut reordered = candidate.clone();
        reordered.swap(0, 1);
        assert!(!positive_evidence_contract(
            &knowledge, &subject, &policy_id, &control, &reordered,
        ));
        let duplicated = vec![control[0].clone(), control[0].clone(), control[2].clone()];
        assert!(!positive_evidence_contract(
            &knowledge,
            &subject,
            &policy_id,
            &duplicated,
            &candidate,
        ));
    }
}
