//! Bounded supplied-session orchestration under the assessment's shared authority.

use std::time::Duration;

use serde::{
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserializer, Serialize,
};
use sha2::{Digest, Sha256};
use termivar_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    KnowledgePredicate,
};

use super::{authority::SharedWebRuntimeAuthority, RuntimeExecution};
use crate::{
    http_evidence::{
        CollectedHttpResponse, HttpRequestBroker, SuppliedSessionCookieUpdateClassification,
        SuppliedSessionCookieUpdateObservation, SuppliedSessionRequestError,
    },
    supplied_session_review::{
        SuppliedSessionCookieSummary, SuppliedSessionCookieUpdatePolicy, SuppliedSessionCredential,
        SuppliedSessionCredentialMechanism, SuppliedSessionPolicy, SuppliedSessionPolicyVersion,
        SuppliedSessionRequestDescriptor, SuppliedSessionRequestPurpose,
        MAX_SUPPLIED_SESSION_CHECKPOINTS, MAX_SUPPLIED_SESSION_RESOURCES,
    },
    DecisionActionOrigin, DecisionExecutionLimits, DecisionExecutionStage, KnowledgeBase,
};

/// Sealed runtime observer for consumers of health-qualified supplied-session
/// resource responses. Implementations may reduce a body while it is alive,
/// but can publish only after receiving the exact committed S01 receipt.
pub(super) trait SuppliedSessionCommittedResourceObserver: Send + Sync {
    fn begin(
        &self,
        policy: &SuppliedSessionPolicy,
        resources: &[(SuppliedSessionRequestDescriptor, String)],
    ) -> Result<(), ()>;

    fn stage_response(
        &self,
        sequence: u8,
        policy: &SuppliedSessionPolicy,
        descriptor: &SuppliedSessionRequestDescriptor,
        response: &CollectedHttpResponse,
    ) -> Result<(), ()>;

    fn commit_response(
        &self,
        sequence: u8,
        policy: &SuppliedSessionPolicy,
        descriptor: &SuppliedSessionRequestDescriptor,
        receipt: &CommittedSuppliedSessionResourceReceipt,
        knowledge: &KnowledgeBase,
    ) -> Result<(), ()>;

    fn discard_response(&self, sequence: u8);

    fn fail(&self);
}

/// Exact, value-safe proof that S01 committed one resource only after its
/// immediately following healthy checkpoint. Fields are intentionally sealed.
pub(super) struct CommittedSuppliedSessionResourceReceipt {
    #[cfg(feature = "wordpress-review")]
    sequence: u8,
    #[cfg(feature = "wordpress-review")]
    resource_reference: String,
    #[cfg(feature = "wordpress-review")]
    policy_reference: String,
    #[cfg(feature = "wordpress-review")]
    application_reference: String,
    #[cfg(feature = "wordpress-review")]
    principal_reference: String,
    #[cfg(feature = "wordpress-review")]
    credential_mechanism: SuppliedSessionCredentialMechanism,
    #[cfg(feature = "wordpress-review")]
    epoch: u8,
    evidence_reference: String,
    #[cfg(feature = "wordpress-review")]
    expected_evidence: Evidence,
}

#[cfg(feature = "wordpress-review")]
impl CommittedSuppliedSessionResourceReceipt {
    pub(super) const fn sequence(&self) -> u8 {
        self.sequence
    }

    pub(super) fn resource_reference(&self) -> &str {
        &self.resource_reference
    }

    pub(super) fn evidence_reference(&self) -> &str {
        &self.evidence_reference
    }

    pub(super) fn is_valid_for(
        &self,
        sequence: u8,
        policy: &SuppliedSessionPolicy,
        descriptor: &SuppliedSessionRequestDescriptor,
        knowledge: &KnowledgeBase,
    ) -> bool {
        EvidenceId::parse(self.evidence_reference.clone())
            .ok()
            .and_then(|id| {
                knowledge.inspect_evidence(&id, |stored| stored == &self.expected_evidence)
            })
            == Some(true)
            && self.sequence == sequence
            && self.resource_reference == descriptor.target_reference()
            && self.policy_reference == policy.policy_reference()
            && self.application_reference == policy.application_reference()
            && self.principal_reference == policy.principal_reference()
            && self.credential_mechanism == policy.credential_mechanism()
            && self.epoch == 1
            && descriptor.validate()
            && descriptor.purpose() == SuppliedSessionRequestPurpose::Resource
            && self.expected_evidence.kind() == &EvidenceKind::Authentication
            && self.expected_evidence.predicate().namespace() == RESOURCE_COMMIT_EVIDENCE_NAMESPACE
            && self.expected_evidence.predicate().name() == RESOURCE_COMMIT_EVIDENCE_PREDICATE
    }
}

/// Stable saved-audit schema for the supplied-session child.
pub const SUPPLIED_SESSION_AUDIT_SCHEMA: &str = "security.supplied-session-audit/v1";
/// Strict saved-audit schema for supplied-cookie sessions.
pub const SUPPLIED_SESSION_COOKIE_AUDIT_SCHEMA: &str = "security.supplied-session-audit/v2";
/// Stable capability identity. This audit-only V1 emits no assessment item.
pub const SUPPLIED_SESSION_CAPABILITY_ID: &str = "session.supplied-context-assessment@1";

const HEALTH_JSON_MAX_DEPTH: usize = 16;
const HEALTH_JSON_MAX_NODES: usize = 512;
const HEALTH_JSON_MAX_KEY_BYTES: usize = 256;
const RESOURCE_COMMIT_EVIDENCE_DOMAIN: &[u8] = b"security.supplied-session-resource-evidence.v1\0";
const HEALTH_COMMIT_EVIDENCE_DOMAIN: &[u8] = b"security.supplied-session-health-evidence.v1\0";
const RESOURCE_COMMIT_EVIDENCE_PREFIX: &str = "supplied-session-resource-evidence-sha256";
const HEALTH_COMMIT_EVIDENCE_PREFIX: &str = "supplied-session-checkpoint-evidence-sha256";
const RESOURCE_COMMIT_EVIDENCE_NAMESPACE: &str = "session.supplied-context-assessment";
const RESOURCE_COMMIT_EVIDENCE_PREDICATE: &str = "protected-resource-response-committed";
const RESOURCE_HEALTH_UNQUALIFIED_EVIDENCE_PREDICATE: &str =
    "protected-resource-response-health-unqualified";
const HEALTH_COMMIT_EVIDENCE_PREDICATE: &str = "health-checkpoint-observation-committed";
const RESOURCE_COMMIT_EVIDENCE_COMPONENT: &str = "supplied-session.runtime";
const RESOURCE_COMMIT_EVIDENCE_METHOD_V1: &str = "descriptor-bound-complete-authorization-get";
const HEALTH_COMMIT_EVIDENCE_METHOD_V1: &str = "descriptor-bound-health-authorization-get";
const RESOURCE_COMMIT_EVIDENCE_METHOD_V2: &str = "descriptor-bound-complete-supplied-cookie-get";
const HEALTH_COMMIT_EVIDENCE_METHOD_V2: &str = "descriptor-bound-health-supplied-cookie-get";
const SUPPLIED_SESSION_NON_BROWSER_COOKIE_SEMANTICS: &str =
    "attributes_preserved_not_browser_csrf_emulation";

/// Assurance attached to the principal label used for this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionPrincipalAssurance {
    /// The principal alias was declared by the operator, not authenticated as identity truth.
    OperatorDeclared,
}

/// The closed health predicate implemented by V1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionHealthOracleKind {
    /// A configured top-level JSON member must be the boolean `true`.
    JsonBooleanTrue,
}

/// Value-free description of the configured health oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuppliedSessionHealthOracleAudit {
    kind: SuppliedSessionHealthOracleKind,
    field_reference: String,
}

impl SuppliedSessionHealthOracleAudit {
    pub const fn kind(&self) -> SuppliedSessionHealthOracleKind {
        self.kind
    }

    pub fn field_reference(&self) -> &str {
        &self.field_reference
    }
}

/// Overall bounded child outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionAuditOutcome {
    Complete,
    StartupUnhealthy,
    SessionLost,
    ResourceUnavailable,
    RuntimeLimit,
    Cancelled,
    /// A selected cookie was reissued; V2 stopped without applying it.
    CredentialUpdateRequired,
    /// A response cookie update could not be classified within V2's bounds.
    CredentialUpdateUnusable,
}

/// Authenticated resource coverage established by committed resource responses and checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionCoverage {
    Complete,
    Partial,
    None,
}

/// Position of one health check in the fixed schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionHealthCheckpointPhase {
    Startup,
    SubjectBoundary,
    Terminal,
}

/// Health interpretation at one actually dispatched checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionHealthOutcome {
    Healthy,
    Unhealthy,
    Indeterminate,
}

/// Completeness of a health-check response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionBodyState {
    Complete,
    Incomplete,
    Unavailable,
}

/// Whether the closed health predicate was evaluated successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionPredicateOutcome {
    Matched,
    NotMatched,
    NotEvaluated,
}

/// Outcome of one selected protected-resource request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionResourceOutcome {
    Committed,
    /// A complete response was observed, but the following health checkpoint
    /// did not qualify it as authenticated coverage.
    HealthUnqualified,
    HttpError,
    RedirectRefused,
    Incomplete,
    TransportFailed,
    NotDispatched,
}

/// One value-free, actually dispatched health checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebAssessmentSuppliedSessionCheckpointAudit {
    sequence: u8,
    evidence_reference: Option<String>,
    phase: SuppliedSessionHealthCheckpointPhase,
    after_subject_count: u8,
    outcome: SuppliedSessionHealthOutcome,
    status: Option<u16>,
    body_state: SuppliedSessionBodyState,
    predicate: SuppliedSessionPredicateOutcome,
    response_bytes: u64,
    #[serde(skip)]
    cookie_update: Option<SuppliedSessionResponseCookieUpdate>,
}

impl WebAssessmentSuppliedSessionCheckpointAudit {
    pub const fn sequence(&self) -> u8 {
        self.sequence
    }
    pub fn evidence_reference(&self) -> Option<&str> {
        self.evidence_reference.as_deref()
    }
    pub const fn phase(&self) -> SuppliedSessionHealthCheckpointPhase {
        self.phase
    }
    pub const fn after_subject_count(&self) -> u8 {
        self.after_subject_count
    }
    pub const fn outcome(&self) -> SuppliedSessionHealthOutcome {
        self.outcome
    }
    pub const fn status(&self) -> Option<u16> {
        self.status
    }
    pub const fn body_state(&self) -> SuppliedSessionBodyState {
        self.body_state
    }
    pub const fn predicate(&self) -> SuppliedSessionPredicateOutcome {
        self.predicate
    }
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }
}

/// One selected protected resource and its value-free execution result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebAssessmentSuppliedSessionResourceAudit {
    sequence: u8,
    resource_reference: String,
    evidence_reference: Option<String>,
    outcome: SuppliedSessionResourceOutcome,
    status: Option<u16>,
    response_bytes: u64,
    epoch: u8,
    #[serde(skip)]
    cookie_update: Option<SuppliedSessionResponseCookieUpdate>,
}

impl WebAssessmentSuppliedSessionResourceAudit {
    pub const fn sequence(&self) -> u8 {
        self.sequence
    }
    pub fn resource_reference(&self) -> &str {
        &self.resource_reference
    }
    pub fn evidence_reference(&self) -> Option<&str> {
        self.evidence_reference.as_deref()
    }
    pub const fn outcome(&self) -> SuppliedSessionResourceOutcome {
        self.outcome
    }
    pub const fn status(&self) -> Option<u16> {
        self.status
    }
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }
    pub const fn epoch(&self) -> u8 {
        self.epoch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuppliedSessionResponseCookieUpdateKind {
    None,
    UnselectedOnly,
    Selected,
    Unusable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SuppliedSessionResponseCookieUpdate {
    kind: SuppliedSessionResponseCookieUpdateKind,
    selected_count: u8,
    unselected_count: u8,
}

/// Redaction-safe static cookie-policy aggregate for audit V2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SuppliedSessionCookiePolicyAudit {
    declared_count: u8,
    host_only_count: u8,
    domain_count: u8,
    secure_count: u8,
    http_only_count: u8,
    session_count: u8,
    persistent_count: u8,
    same_site_missing_count: u8,
    same_site_strict_count: u8,
    same_site_lax_count: u8,
    same_site_none_count: u8,
    update_policy: SuppliedSessionCookieUpdatePolicy,
}

impl SuppliedSessionCookiePolicyAudit {
    pub const fn declared_count(&self) -> u8 {
        self.declared_count
    }
    pub const fn host_only_count(&self) -> u8 {
        self.host_only_count
    }
    pub const fn domain_count(&self) -> u8 {
        self.domain_count
    }
    pub const fn secure_count(&self) -> u8 {
        self.secure_count
    }
    pub const fn http_only_count(&self) -> u8 {
        self.http_only_count
    }
    pub const fn session_count(&self) -> u8 {
        self.session_count
    }
    pub const fn persistent_count(&self) -> u8 {
        self.persistent_count
    }
    pub const fn same_site_missing_count(&self) -> u8 {
        self.same_site_missing_count
    }
    pub const fn same_site_strict_count(&self) -> u8 {
        self.same_site_strict_count
    }
    pub const fn same_site_lax_count(&self) -> u8 {
        self.same_site_lax_count
    }
    pub const fn same_site_none_count(&self) -> u8 {
        self.same_site_none_count
    }
    pub const fn update_policy(&self) -> SuppliedSessionCookieUpdatePolicy {
        self.update_policy
    }
    pub const fn browser_semantics(&self) -> &'static str {
        SUPPLIED_SESSION_NON_BROWSER_COOKIE_SEMANTICS
    }
}

/// Redaction-safe dynamic cookie lifecycle aggregate for audit V2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SuppliedSessionCookieLifecycleAudit {
    initial_epoch: u8,
    final_epoch: u8,
    selected_update_response_count: u8,
    unselected_update_response_count: u8,
    update_classification_failure_count: u8,
    updates_applied: u8,
}

impl SuppliedSessionCookieLifecycleAudit {
    pub const fn initial_epoch(&self) -> u8 {
        self.initial_epoch
    }
    pub const fn final_epoch(&self) -> u8 {
        self.final_epoch
    }
    pub const fn selected_update_response_count(&self) -> u8 {
        self.selected_update_response_count
    }
    pub const fn unselected_update_response_count(&self) -> u8 {
        self.unselected_update_response_count
    }
    pub const fn update_classification_failure_count(&self) -> u8 {
        self.update_classification_failure_count
    }
    pub const fn updates_applied(&self) -> u8 {
        self.updates_applied
    }
}

/// Redaction-safe audit for one explicitly selected supplied-session child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebAssessmentSuppliedSessionAudit {
    schema: &'static str,
    capability_id: &'static str,
    policy_reference: String,
    application_reference: String,
    principal_reference: String,
    principal_alias: String,
    principal_assurance: SuppliedSessionPrincipalAssurance,
    credential_mechanism: SuppliedSessionCredentialMechanism,
    health_oracle: SuppliedSessionHealthOracleAudit,
    outcome: SuppliedSessionAuditOutcome,
    coverage: SuppliedSessionCoverage,
    checkpoints: Vec<WebAssessmentSuppliedSessionCheckpointAudit>,
    resources: Vec<WebAssessmentSuppliedSessionResourceAudit>,
    selected_resource_count: u8,
    dispatched_resource_count: u8,
    committed_resource_count: u8,
    dispatched_request_count: u8,
    response_bytes: u64,
    response_byte_limit: u64,
    response_byte_limit_exceeded: bool,
    refresh_performed: bool,
    anonymous_fallback_performed: bool,
    continuous_authentication_established: bool,
    exploit_execution_performed: bool,
    impact_validation_performed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookie_policy: Option<SuppliedSessionCookiePolicyAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookie_lifecycle: Option<SuppliedSessionCookieLifecycleAudit>,
}

impl WebAssessmentSuppliedSessionAudit {
    pub const fn schema(&self) -> &'static str {
        self.schema
    }
    pub const fn capability_id(&self) -> &'static str {
        self.capability_id
    }
    pub fn policy_reference(&self) -> &str {
        &self.policy_reference
    }
    pub fn application_reference(&self) -> &str {
        &self.application_reference
    }
    pub fn principal_reference(&self) -> &str {
        &self.principal_reference
    }
    /// Explicitly non-secret operator assertion, not authenticated identity truth.
    pub fn principal_alias(&self) -> &str {
        &self.principal_alias
    }
    pub const fn principal_assurance(&self) -> SuppliedSessionPrincipalAssurance {
        self.principal_assurance
    }
    pub const fn credential_mechanism(&self) -> SuppliedSessionCredentialMechanism {
        self.credential_mechanism
    }
    pub const fn health_oracle(&self) -> &SuppliedSessionHealthOracleAudit {
        &self.health_oracle
    }
    pub const fn outcome(&self) -> SuppliedSessionAuditOutcome {
        self.outcome
    }
    pub const fn coverage(&self) -> SuppliedSessionCoverage {
        self.coverage
    }
    pub fn checkpoints(&self) -> &[WebAssessmentSuppliedSessionCheckpointAudit] {
        &self.checkpoints
    }
    pub fn resources(&self) -> &[WebAssessmentSuppliedSessionResourceAudit] {
        &self.resources
    }
    pub const fn selected_resource_count(&self) -> u8 {
        self.selected_resource_count
    }
    pub const fn dispatched_resource_count(&self) -> u8 {
        self.dispatched_resource_count
    }
    pub const fn committed_resource_count(&self) -> u8 {
        self.committed_resource_count
    }
    pub const fn dispatched_request_count(&self) -> u8 {
        self.dispatched_request_count
    }
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }
    /// Configured child byte budget. Actual transport accounting may exceed it
    /// by the broker's final delivered chunk and is never clamped in the audit.
    pub const fn response_byte_limit(&self) -> u64 {
        self.response_byte_limit
    }
    pub const fn response_byte_limit_exceeded(&self) -> bool {
        self.response_byte_limit_exceeded
    }
    pub const fn refresh_performed(&self) -> bool {
        self.refresh_performed
    }
    pub const fn anonymous_fallback_performed(&self) -> bool {
        self.anonymous_fallback_performed
    }
    pub const fn continuous_authentication_established(&self) -> bool {
        self.continuous_authentication_established
    }
    pub const fn exploit_execution_performed(&self) -> bool {
        self.exploit_execution_performed
    }
    pub const fn impact_validation_performed(&self) -> bool {
        self.impact_validation_performed
    }
    pub const fn cookie_policy(&self) -> Option<&SuppliedSessionCookiePolicyAudit> {
        self.cookie_policy.as_ref()
    }
    pub const fn cookie_lifecycle(&self) -> Option<&SuppliedSessionCookieLifecycleAudit> {
        self.cookie_lifecycle.as_ref()
    }
}

pub(super) struct SuppliedSessionRuntimeConfig {
    policy: SuppliedSessionPolicy,
    credential: SuppliedSessionCredential,
    requests: HttpRequestBroker,
    health: SuppliedSessionRequestDescriptor,
    resources: Vec<(SuppliedSessionRequestDescriptor, String)>,
}

impl SuppliedSessionRuntimeConfig {
    pub(super) fn new<C>(
        policy: SuppliedSessionPolicy,
        credential: C,
        authority: &SharedWebRuntimeAuthority,
    ) -> Result<Self, ()>
    where
        C: Into<SuppliedSessionCredential>,
    {
        let credential = credential.into();
        if policy.credential_mechanism() != credential.mechanism() {
            return Err(());
        }
        let requests = authority
            .requests()
            .isolated_supplied_session()
            .map_err(|_| ())?;
        let health = SuppliedSessionRequestDescriptor::health(&policy);
        let resources = policy
            .execution_resources()
            .map(|(target, reference)| {
                SuppliedSessionRequestDescriptor::resource(&policy, target, reference)
                    .map(|descriptor| (descriptor, reference.to_owned()))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(())?;
        Ok(Self {
            policy,
            credential,
            requests,
            health,
            resources,
        })
    }

    pub(super) async fn execute(
        self,
        authority: &SharedWebRuntimeAuthority,
        resource_observer: Option<&dyn SuppliedSessionCommittedResourceObserver>,
    ) -> WebAssessmentSuppliedSessionAudit {
        let selected_resource_count = u8::try_from(self.resources.len()).unwrap_or(u8::MAX);
        let timing = authority.start();
        let local_deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(self.policy.max_wall_time_ms()));
        let deadline = earliest_deadline(timing.deadline(), local_deadline);
        let mut state = ExecutionState::new(&self.policy, selected_resource_count);
        if resource_observer
            .is_some_and(|observer| observer.begin(&self.policy, &self.resources).is_err())
        {
            resource_observer.expect("observer remains present").fail();
        }
        let dispatch_context = DispatchContext {
            authority,
            requests: &self.requests,
            credential: &self.credential,
            policy: &self.policy,
            deadline,
        };
        let resource_commit_context = ResourceCommitContext {
            policy: &self.policy,
            knowledge: authority.knowledge(),
            observer: resource_observer,
        };

        let startup = dispatch(
            &dispatch_context,
            &self.health,
            state.dispatch_budget(),
            DecisionActionOrigin::Bootstrap,
            SuppliedSessionRequestPurpose::Health,
        )
        .await;
        match state.record_health(
            startup,
            &self.health,
            SuppliedSessionHealthCheckpointPhase::Startup,
            0,
            &self.policy,
            authority.knowledge(),
        ) {
            Continue::Yes => {},
            Continue::No(outcome) => {
                state.outcome = outcome;
                state.add_not_dispatched(&self.resources);
                return state.finish(self.policy);
            },
        }

        for (index, (descriptor, reference)) in self.resources.iter().enumerate() {
            let sequence = u8::try_from(index).unwrap_or(u8::MAX);
            let resource = dispatch(
                &dispatch_context,
                descriptor,
                state.dispatch_budget(),
                DecisionActionOrigin::Planned,
                SuppliedSessionRequestPurpose::Resource,
            )
            .await;
            let staged = match state.record_resource(
                sequence,
                descriptor,
                reference,
                resource,
                resource_commit_context,
            ) {
                ResourceContinuation::AwaitingHealth(staged) => staged,
                ResourceContinuation::No(outcome) => {
                    state.outcome = outcome;
                    state.add_not_dispatched(&self.resources[index + 1..]);
                    return state.finish(self.policy);
                },
            };

            let phase = if index + 1 == self.resources.len() {
                SuppliedSessionHealthCheckpointPhase::Terminal
            } else {
                SuppliedSessionHealthCheckpointPhase::SubjectBoundary
            };
            let health = dispatch(
                &dispatch_context,
                &self.health,
                state.dispatch_budget_with_pending_resource(staged),
                DecisionActionOrigin::Planned,
                SuppliedSessionRequestPurpose::Health,
            )
            .await;
            let after_subject_count = u8::try_from(index + 1).unwrap_or(u8::MAX);
            match state.record_health(
                health,
                &self.health,
                phase,
                after_subject_count,
                &self.policy,
                authority.knowledge(),
            ) {
                Continue::Yes => {
                    if let Continue::No(outcome) = state.record_health_qualified_resource(
                        sequence,
                        descriptor,
                        reference,
                        staged,
                        resource_commit_context,
                    ) {
                        state.outcome = outcome;
                        state.add_not_dispatched(&self.resources[index + 1..]);
                        return state.finish(self.policy);
                    }
                },
                Continue::No(outcome) => {
                    state.record_health_unqualified_resource(
                        sequence,
                        descriptor,
                        reference,
                        staged,
                        &self.policy,
                        authority.knowledge(),
                    );
                    if let Some(observer) = resource_observer {
                        observer.discard_response(sequence);
                    }
                    state.outcome = outcome;
                    state.add_not_dispatched(&self.resources[index + 1..]);
                    return state.finish(self.policy);
                },
            }
        }
        state.outcome = SuppliedSessionAuditOutcome::Complete;
        state.finish(self.policy)
    }
}

struct ExecutionState {
    checkpoints: Vec<WebAssessmentSuppliedSessionCheckpointAudit>,
    resources: Vec<WebAssessmentSuppliedSessionResourceAudit>,
    outcome: SuppliedSessionAuditOutcome,
    selected_resource_count: u8,
    response_bytes: u64,
}

#[derive(Clone, Copy)]
struct ResourceCommitContext<'a> {
    policy: &'a SuppliedSessionPolicy,
    knowledge: &'a KnowledgeBase,
    observer: Option<&'a dyn SuppliedSessionCommittedResourceObserver>,
}

impl ExecutionState {
    fn new(policy: &SuppliedSessionPolicy, selected_resource_count: u8) -> Self {
        debug_assert!(policy.resource_count() <= MAX_SUPPLIED_SESSION_RESOURCES);
        Self {
            checkpoints: Vec::with_capacity(MAX_SUPPLIED_SESSION_CHECKPOINTS),
            resources: Vec::with_capacity(MAX_SUPPLIED_SESSION_RESOURCES),
            outcome: SuppliedSessionAuditOutcome::RuntimeLimit,
            selected_resource_count,
            response_bytes: 0,
        }
    }

    fn dispatched_request_count(&self) -> u8 {
        let dispatched_resources = self
            .resources
            .iter()
            .filter(|resource| resource.outcome != SuppliedSessionResourceOutcome::NotDispatched)
            .count();
        u8::try_from(self.checkpoints.len())
            .unwrap_or(u8::MAX)
            .saturating_add(u8::try_from(dispatched_resources).unwrap_or(u8::MAX))
    }

    fn dispatch_budget(&self) -> DispatchBudget {
        DispatchBudget {
            accounted_response_bytes: self.response_bytes,
            dispatched_requests: self.dispatched_request_count(),
        }
    }

    fn dispatch_budget_with_pending_resource(
        &self,
        staged: StagedSuppliedSessionResource,
    ) -> DispatchBudget {
        DispatchBudget {
            accounted_response_bytes: self.response_bytes.saturating_add(staged.response_bytes),
            dispatched_requests: self.dispatched_request_count().saturating_add(1),
        }
    }

    fn record_health(
        &mut self,
        dispatch: DispatchResult,
        descriptor: &SuppliedSessionRequestDescriptor,
        phase: SuppliedSessionHealthCheckpointPhase,
        after_subject_count: u8,
        policy: &SuppliedSessionPolicy,
        knowledge: &KnowledgeBase,
    ) -> Continue {
        let is_startup = phase == SuppliedSessionHealthCheckpointPhase::Startup;
        let sequence = u8::try_from(self.checkpoints.len()).unwrap_or(u8::MAX);
        let (record, stop) = match dispatch {
            DispatchResult::Response {
                response,
                bytes,
                exact_target,
                cookie_update,
            } => {
                let mut record = classify_health(
                    *response,
                    bytes,
                    exact_target,
                    cookie_update,
                    HealthCheckpointPosition {
                        sequence,
                        phase,
                        after_subject_count,
                    },
                    policy,
                );
                bind_health_evidence(
                    &mut record,
                    policy,
                    descriptor,
                    Some(exact_target),
                    knowledge,
                );
                let stop = cookie_update_stop_outcome(record.cookie_update)
                    .or_else(|| health_stop_outcome(record.outcome, is_startup));
                (Some(record), stop)
            },
            DispatchResult::Transport { bytes, dispatched } => {
                let record = dispatched.then(|| {
                    committed_health_unavailable(
                        policy,
                        descriptor,
                        sequence,
                        phase,
                        after_subject_count,
                        bytes,
                        knowledge,
                    )
                });
                (
                    record,
                    Some(SuppliedSessionAuditOutcome::ResourceUnavailable),
                )
            },
            DispatchResult::RuntimeLimit { bytes, dispatched } => {
                let record = dispatched.then(|| {
                    committed_health_unavailable(
                        policy,
                        descriptor,
                        sequence,
                        phase,
                        after_subject_count,
                        bytes,
                        knowledge,
                    )
                });
                (record, Some(SuppliedSessionAuditOutcome::RuntimeLimit))
            },
            DispatchResult::Cancelled { bytes, dispatched } => {
                let record = dispatched.then(|| {
                    committed_health_unavailable(
                        policy,
                        descriptor,
                        sequence,
                        phase,
                        after_subject_count,
                        bytes,
                        knowledge,
                    )
                });
                (record, Some(SuppliedSessionAuditOutcome::Cancelled))
            },
            DispatchResult::InvalidDescriptor => {
                (None, Some(SuppliedSessionAuditOutcome::ResourceUnavailable))
            },
        };
        if let Some(record) = record {
            self.response_bytes = self.response_bytes.saturating_add(record.response_bytes);
            self.checkpoints.push(record);
        }
        stop.map_or(Continue::Yes, Continue::No)
    }

    fn record_resource(
        &mut self,
        sequence: u8,
        descriptor: &SuppliedSessionRequestDescriptor,
        reference: &str,
        dispatch: DispatchResult,
        context: ResourceCommitContext<'_>,
    ) -> ResourceContinuation {
        let (record, stop) = match dispatch {
            DispatchResult::Response {
                response,
                bytes,
                exact_target,
                cookie_update,
            } => {
                let staged = stage_resource_response(&response, bytes, exact_target, cookie_update);
                if let Some(outcome) = cookie_update_stop_outcome(staged.cookie_update) {
                    let record = commit_health_unqualified_resource(
                        sequence,
                        descriptor,
                        reference,
                        context.policy,
                        context.knowledge,
                        staged,
                        None,
                    );
                    self.response_bytes = self.response_bytes.saturating_add(record.response_bytes);
                    self.resources.push(record);
                    return ResourceContinuation::No(outcome);
                }
                if staged_resource_can_await_health(descriptor, reference, staged) {
                    if let Some(observer) = context.observer {
                        if observer
                            .stage_response(sequence, context.policy, descriptor, &response)
                            .is_err()
                        {
                            observer.fail();
                        }
                    }
                    return ResourceContinuation::AwaitingHealth(staged);
                }
                let record = commit_staged_resource(
                    sequence,
                    descriptor,
                    reference,
                    context.policy,
                    context.knowledge,
                    staged,
                    None,
                );
                let outcome = record.outcome;
                let stop = (outcome != SuppliedSessionResourceOutcome::Committed)
                    .then_some(SuppliedSessionAuditOutcome::ResourceUnavailable);
                (record, stop)
            },
            DispatchResult::Transport { bytes, dispatched } => {
                if !dispatched {
                    self.resources
                        .push(resource_not_dispatched(sequence, reference));
                    return ResourceContinuation::No(
                        SuppliedSessionAuditOutcome::ResourceUnavailable,
                    );
                }
                (
                    resource_transport_failure(sequence, reference, bytes),
                    Some(SuppliedSessionAuditOutcome::ResourceUnavailable),
                )
            },
            DispatchResult::RuntimeLimit { bytes, dispatched } => {
                if !dispatched {
                    self.resources
                        .push(resource_not_dispatched(sequence, reference));
                    return ResourceContinuation::No(SuppliedSessionAuditOutcome::RuntimeLimit);
                }
                (
                    resource_transport_failure(sequence, reference, bytes),
                    Some(SuppliedSessionAuditOutcome::RuntimeLimit),
                )
            },
            DispatchResult::Cancelled { bytes, dispatched } => {
                if !dispatched {
                    self.resources
                        .push(resource_not_dispatched(sequence, reference));
                    return ResourceContinuation::No(SuppliedSessionAuditOutcome::Cancelled);
                }
                (
                    resource_transport_failure(sequence, reference, bytes),
                    Some(SuppliedSessionAuditOutcome::Cancelled),
                )
            },
            DispatchResult::InvalidDescriptor => {
                self.resources
                    .push(resource_not_dispatched(sequence, reference));
                return ResourceContinuation::No(SuppliedSessionAuditOutcome::ResourceUnavailable);
            },
        };
        self.response_bytes = self.response_bytes.saturating_add(record.response_bytes);
        self.resources.push(record);
        ResourceContinuation::No(stop.unwrap_or(SuppliedSessionAuditOutcome::ResourceUnavailable))
    }

    fn record_health_qualified_resource(
        &mut self,
        sequence: u8,
        descriptor: &SuppliedSessionRequestDescriptor,
        reference: &str,
        staged: StagedSuppliedSessionResource,
        context: ResourceCommitContext<'_>,
    ) -> Continue {
        let qualifying_checkpoint = self.checkpoints.last().and_then(|checkpoint| {
            (checkpoint.outcome == SuppliedSessionHealthOutcome::Healthy
                && checkpoint.after_subject_count == sequence.saturating_add(1))
            .then_some(checkpoint.evidence_reference.as_deref())
            .flatten()
        });
        let (record, receipt) = commit_staged_resource_with_receipt(
            sequence,
            descriptor,
            reference,
            context.policy,
            context.knowledge,
            staged,
            qualifying_checkpoint,
        );
        let committed = record.outcome == SuppliedSessionResourceOutcome::Committed;
        if let (Some(observer), Some(receipt)) = (context.observer, receipt.as_ref()) {
            if observer
                .commit_response(
                    sequence,
                    context.policy,
                    descriptor,
                    receipt,
                    context.knowledge,
                )
                .is_err()
            {
                observer.fail();
            }
        } else if let Some(observer) = context.observer {
            observer.discard_response(sequence);
        }
        self.response_bytes = self.response_bytes.saturating_add(record.response_bytes);
        self.resources.push(record);
        if committed {
            Continue::Yes
        } else {
            Continue::No(SuppliedSessionAuditOutcome::ResourceUnavailable)
        }
    }

    fn record_health_unqualified_resource(
        &mut self,
        sequence: u8,
        descriptor: &SuppliedSessionRequestDescriptor,
        reference: &str,
        staged: StagedSuppliedSessionResource,
        policy: &SuppliedSessionPolicy,
        knowledge: &KnowledgeBase,
    ) {
        let checkpoint_reference = self.checkpoints.last().and_then(|checkpoint| {
            (checkpoint.after_subject_count == sequence.saturating_add(1))
                .then_some(checkpoint.evidence_reference.as_deref())
                .flatten()
        });
        let record = commit_health_unqualified_resource(
            sequence,
            descriptor,
            reference,
            policy,
            knowledge,
            staged,
            checkpoint_reference,
        );
        self.response_bytes = self.response_bytes.saturating_add(record.response_bytes);
        self.resources.push(record);
    }

    fn add_not_dispatched(&mut self, resources: &[(SuppliedSessionRequestDescriptor, String)]) {
        for (_, reference) in resources {
            let sequence = u8::try_from(self.resources.len()).unwrap_or(u8::MAX);
            self.resources
                .push(resource_not_dispatched(sequence, reference));
        }
    }

    fn finish(self, policy: SuppliedSessionPolicy) -> WebAssessmentSuppliedSessionAudit {
        let response_byte_limit = policy.max_total_response_bytes();
        let cookie_policy = policy
            .cookie_summary()
            .map(|summary| cookie_policy_audit(summary, &policy));
        let cookie_lifecycle = cookie_policy
            .is_some()
            .then(|| cookie_lifecycle_audit(&self.checkpoints, &self.resources));
        let dispatched_resource_count = u8::try_from(
            self.resources
                .iter()
                .filter(|resource| {
                    resource.outcome != SuppliedSessionResourceOutcome::NotDispatched
                })
                .count(),
        )
        .unwrap_or(u8::MAX);
        let committed_resource_count = u8::try_from(
            self.resources
                .iter()
                .filter(|resource| resource.outcome == SuppliedSessionResourceOutcome::Committed)
                .count(),
        )
        .unwrap_or(u8::MAX);
        let coverage = if self.outcome == SuppliedSessionAuditOutcome::Complete
            && committed_resource_count == self.selected_resource_count
        {
            SuppliedSessionCoverage::Complete
        } else if committed_resource_count == 0 {
            SuppliedSessionCoverage::None
        } else {
            SuppliedSessionCoverage::Partial
        };
        let dispatched_request_count = u8::try_from(self.checkpoints.len())
            .unwrap_or(u8::MAX)
            .saturating_add(dispatched_resource_count);
        debug_assert_eq!(
            self.resources.len(),
            usize::from(self.selected_resource_count)
        );
        debug_assert!(self
            .checkpoints
            .iter()
            .enumerate()
            .all(
                |(index, checkpoint)| checkpoint.sequence == u8::try_from(index).unwrap_or(u8::MAX)
            ));
        debug_assert!(self.checkpoints.iter().all(|checkpoint| {
            checkpoint.outcome == SuppliedSessionHealthOutcome::Indeterminate
                || checkpoint.evidence_reference.is_some()
        }));
        debug_assert!(self
            .resources
            .iter()
            .enumerate()
            .all(|(index, resource)| resource.sequence == u8::try_from(index).unwrap_or(u8::MAX)));
        debug_assert!(self.resources.iter().all(|resource| {
            matches!(
                resource.outcome,
                SuppliedSessionResourceOutcome::Committed
                    | SuppliedSessionResourceOutcome::HealthUnqualified
            ) == resource.evidence_reference.is_some()
        }));
        debug_assert_eq!(
            self.response_bytes,
            self.checkpoints
                .iter()
                .map(WebAssessmentSuppliedSessionCheckpointAudit::response_bytes)
                .sum::<u64>()
                .saturating_add(
                    self.resources
                        .iter()
                        .map(WebAssessmentSuppliedSessionResourceAudit::response_bytes)
                        .sum::<u64>()
                )
        );
        WebAssessmentSuppliedSessionAudit {
            schema: match policy.version() {
                SuppliedSessionPolicyVersion::V1 => SUPPLIED_SESSION_AUDIT_SCHEMA,
                SuppliedSessionPolicyVersion::V2 => SUPPLIED_SESSION_COOKIE_AUDIT_SCHEMA,
            },
            capability_id: SUPPLIED_SESSION_CAPABILITY_ID,
            policy_reference: policy.policy_reference().to_owned(),
            application_reference: policy.application_reference().to_owned(),
            principal_reference: policy.principal_reference().to_owned(),
            principal_alias: policy.principal_alias().to_owned(),
            principal_assurance: SuppliedSessionPrincipalAssurance::OperatorDeclared,
            credential_mechanism: policy.credential_mechanism(),
            health_oracle: SuppliedSessionHealthOracleAudit {
                kind: SuppliedSessionHealthOracleKind::JsonBooleanTrue,
                field_reference: policy.health_field_reference().to_owned(),
            },
            outcome: self.outcome,
            coverage,
            checkpoints: self.checkpoints,
            resources: self.resources,
            selected_resource_count: self.selected_resource_count,
            dispatched_resource_count,
            committed_resource_count,
            dispatched_request_count,
            response_bytes: self.response_bytes,
            response_byte_limit,
            response_byte_limit_exceeded: self.response_bytes > response_byte_limit,
            refresh_performed: false,
            anonymous_fallback_performed: false,
            continuous_authentication_established: false,
            exploit_execution_performed: false,
            impact_validation_performed: false,
            cookie_policy,
            cookie_lifecycle,
        }
    }
}

fn cookie_policy_audit(
    summary: SuppliedSessionCookieSummary,
    policy: &SuppliedSessionPolicy,
) -> SuppliedSessionCookiePolicyAudit {
    SuppliedSessionCookiePolicyAudit {
        declared_count: u8::try_from(summary.cookie_count()).unwrap_or(u8::MAX),
        host_only_count: u8::try_from(summary.host_only_count()).unwrap_or(u8::MAX),
        domain_count: u8::try_from(summary.domain_count()).unwrap_or(u8::MAX),
        secure_count: u8::try_from(summary.secure_count()).unwrap_or(u8::MAX),
        http_only_count: u8::try_from(summary.http_only_count()).unwrap_or(u8::MAX),
        session_count: u8::try_from(summary.session_count()).unwrap_or(u8::MAX),
        persistent_count: u8::try_from(summary.persistent_count()).unwrap_or(u8::MAX),
        same_site_missing_count: u8::try_from(summary.same_site_missing_count()).unwrap_or(u8::MAX),
        same_site_strict_count: u8::try_from(summary.same_site_strict_count()).unwrap_or(u8::MAX),
        same_site_lax_count: u8::try_from(summary.same_site_lax_count()).unwrap_or(u8::MAX),
        same_site_none_count: u8::try_from(summary.same_site_none_count()).unwrap_or(u8::MAX),
        update_policy: policy
            .cookie_update_policy()
            .expect("cookie policy summary requires an update policy"),
    }
}

fn cookie_lifecycle_audit(
    checkpoints: &[WebAssessmentSuppliedSessionCheckpointAudit],
    resources: &[WebAssessmentSuppliedSessionResourceAudit],
) -> SuppliedSessionCookieLifecycleAudit {
    let updates = checkpoints
        .iter()
        .filter_map(|record| record.cookie_update)
        .chain(resources.iter().filter_map(|record| record.cookie_update));
    let mut selected_update_response_count = 0_u8;
    let mut unselected_update_response_count = 0_u8;
    let mut update_classification_failure_count = 0_u8;
    for update in updates {
        if update.selected_count > 0 {
            selected_update_response_count = selected_update_response_count.saturating_add(1);
        }
        if update.unselected_count > 0 {
            unselected_update_response_count = unselected_update_response_count.saturating_add(1);
        }
        if update.kind == SuppliedSessionResponseCookieUpdateKind::Unusable {
            update_classification_failure_count =
                update_classification_failure_count.saturating_add(1);
        }
    }
    SuppliedSessionCookieLifecycleAudit {
        initial_epoch: 1,
        final_epoch: 1,
        selected_update_response_count,
        unselected_update_response_count,
        update_classification_failure_count,
        updates_applied: 0,
    }
}

fn health_stop_outcome(
    outcome: SuppliedSessionHealthOutcome,
    is_startup: bool,
) -> Option<SuppliedSessionAuditOutcome> {
    match outcome {
        SuppliedSessionHealthOutcome::Healthy => None,
        SuppliedSessionHealthOutcome::Unhealthy if is_startup => {
            Some(SuppliedSessionAuditOutcome::StartupUnhealthy)
        },
        SuppliedSessionHealthOutcome::Unhealthy => Some(SuppliedSessionAuditOutcome::SessionLost),
        SuppliedSessionHealthOutcome::Indeterminate => {
            Some(SuppliedSessionAuditOutcome::ResourceUnavailable)
        },
    }
}

enum Continue {
    Yes,
    No(SuppliedSessionAuditOutcome),
}

enum ResourceContinuation {
    AwaitingHealth(StagedSuppliedSessionResource),
    No(SuppliedSessionAuditOutcome),
}

enum DispatchResult {
    Response {
        response: Box<CollectedHttpResponse>,
        bytes: u64,
        exact_target: bool,
        cookie_update: Option<SuppliedSessionResponseCookieUpdate>,
    },
    Transport {
        bytes: u64,
        dispatched: bool,
    },
    RuntimeLimit {
        bytes: u64,
        dispatched: bool,
    },
    Cancelled {
        bytes: u64,
        dispatched: bool,
    },
    InvalidDescriptor,
}

struct DispatchContext<'a> {
    authority: &'a SharedWebRuntimeAuthority,
    requests: &'a HttpRequestBroker,
    credential: &'a SuppliedSessionCredential,
    policy: &'a SuppliedSessionPolicy,
    deadline: Option<tokio::time::Instant>,
}

#[derive(Clone, Copy)]
struct DispatchBudget {
    accounted_response_bytes: u64,
    dispatched_requests: u8,
}

#[derive(Clone, Copy)]
struct HealthCheckpointPosition {
    sequence: u8,
    phase: SuppliedSessionHealthCheckpointPhase,
    after_subject_count: u8,
}

async fn dispatch(
    context: &DispatchContext<'_>,
    descriptor: &SuppliedSessionRequestDescriptor,
    budget: DispatchBudget,
    origin: DecisionActionOrigin,
    expected_purpose: SuppliedSessionRequestPurpose,
) -> DispatchResult {
    if descriptor.purpose() != expected_purpose {
        return DispatchResult::InvalidDescriptor;
    }
    if context.authority.cancellation().is_cancelled() {
        return DispatchResult::Cancelled {
            bytes: 0,
            dispatched: false,
        };
    }
    if context
        .deadline
        .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        || budget.accounted_response_bytes >= context.policy.max_total_response_bytes()
        || budget.dispatched_requests >= context.policy.max_session_requests()
    {
        return DispatchResult::RuntimeLimit {
            bytes: 0,
            dispatched: false,
        };
    }
    let remaining = context
        .policy
        .max_total_response_bytes()
        .saturating_sub(budget.accounted_response_bytes);
    let response_limit =
        remaining.min(u64::try_from(context.policy.max_response_body_bytes()).unwrap_or(u64::MAX));
    if response_limit == 0 {
        return DispatchResult::RuntimeLimit {
            bytes: 0,
            dispatched: false,
        };
    }
    let limits = DecisionExecutionLimits::new().with_max_response_body_bytes(response_limit);
    let before = context.authority.request_accounting().snapshot();
    let execution = context.requests.collect_supplied_session_get_for_runtime(
        DecisionExecutionStage::Passive,
        Some(origin),
        limits,
        descriptor,
        context.policy,
        context.credential,
    );
    let result = super::await_execution(
        context.authority.cancellation(),
        context.deadline,
        execution,
    )
    .await;
    let after = context.authority.request_accounting().snapshot();
    let dispatched = after.total_requests() > before.total_requests();
    let bytes = after
        .response_bytes()
        .saturating_sub(before.response_bytes());
    match result {
        RuntimeExecution::Completed(Ok(response)) => {
            let exact_target = response.final_url() == descriptor.target();
            let cookie_update = response_cookie_update(context.policy, &response, exact_target);
            DispatchResult::Response {
                response: Box::new(response),
                bytes,
                exact_target,
                cookie_update,
            }
        },
        RuntimeExecution::Completed(Err(SuppliedSessionRequestError::RuntimeLimit)) => {
            DispatchResult::RuntimeLimit { bytes, dispatched }
        },
        RuntimeExecution::Completed(Err(SuppliedSessionRequestError::Http)) => {
            DispatchResult::Transport { bytes, dispatched }
        },
        RuntimeExecution::Completed(Err(SuppliedSessionRequestError::InvalidDescriptor)) => {
            DispatchResult::InvalidDescriptor
        },
        RuntimeExecution::Cancelled => DispatchResult::Cancelled { bytes, dispatched },
        RuntimeExecution::WallTimeExceeded => DispatchResult::RuntimeLimit { bytes, dispatched },
    }
}

fn cookie_update_stop_outcome(
    update: Option<SuppliedSessionResponseCookieUpdate>,
) -> Option<SuppliedSessionAuditOutcome> {
    match update.map(|value| value.kind) {
        Some(SuppliedSessionResponseCookieUpdateKind::Selected) => {
            Some(SuppliedSessionAuditOutcome::CredentialUpdateRequired)
        },
        Some(SuppliedSessionResponseCookieUpdateKind::Unusable) => {
            Some(SuppliedSessionAuditOutcome::CredentialUpdateUnusable)
        },
        None
        | Some(SuppliedSessionResponseCookieUpdateKind::None)
        | Some(SuppliedSessionResponseCookieUpdateKind::UnselectedOnly) => None,
    }
}

fn response_cookie_update(
    policy: &SuppliedSessionPolicy,
    response: &CollectedHttpResponse,
    exact_target: bool,
) -> Option<SuppliedSessionResponseCookieUpdate> {
    if policy.version() != SuppliedSessionPolicyVersion::V2 {
        return None;
    }
    if !exact_target {
        return Some(SuppliedSessionResponseCookieUpdate {
            kind: SuppliedSessionResponseCookieUpdateKind::Unusable,
            selected_count: 0,
            unselected_count: 0,
        });
    }
    Some(response.supplied_session_cookie_updates(policy).into())
}

impl From<SuppliedSessionCookieUpdateObservation> for SuppliedSessionResponseCookieUpdate {
    fn from(observation: SuppliedSessionCookieUpdateObservation) -> Self {
        let kind = match observation.classification() {
            SuppliedSessionCookieUpdateClassification::None => {
                SuppliedSessionResponseCookieUpdateKind::None
            },
            SuppliedSessionCookieUpdateClassification::UnselectedOnly => {
                SuppliedSessionResponseCookieUpdateKind::UnselectedOnly
            },
            SuppliedSessionCookieUpdateClassification::Selected => {
                SuppliedSessionResponseCookieUpdateKind::Selected
            },
            SuppliedSessionCookieUpdateClassification::Unusable => {
                SuppliedSessionResponseCookieUpdateKind::Unusable
            },
        };
        Self {
            kind,
            selected_count: observation.selected_count(),
            unselected_count: observation.unselected_count(),
        }
    }
}

fn earliest_deadline(
    parent: Option<tokio::time::Instant>,
    local: Option<tokio::time::Instant>,
) -> Option<tokio::time::Instant> {
    match (parent, local) {
        (Some(parent), Some(local)) => Some(parent.min(local)),
        (Some(parent), None) => Some(parent),
        (None, Some(local)) => Some(local),
        (None, None) => None,
    }
}

fn classify_health(
    response: CollectedHttpResponse,
    bytes: u64,
    exact_target: bool,
    cookie_update: Option<SuppliedSessionResponseCookieUpdate>,
    position: HealthCheckpointPosition,
    policy: &SuppliedSessionPolicy,
) -> WebAssessmentSuppliedSessionCheckpointAudit {
    let status = response.status();
    let complete = response.body_complete();
    let body_state = if complete {
        SuppliedSessionBodyState::Complete
    } else {
        SuppliedSessionBodyState::Incomplete
    };
    let predicate =
        if exact_target && complete && status == 200 && response.has_json_compatible_media_type() {
            if strict_top_level_boolean(response.body(), policy.health_json_field()) == Some(true) {
                SuppliedSessionPredicateOutcome::Matched
            } else {
                SuppliedSessionPredicateOutcome::NotMatched
            }
        } else {
            SuppliedSessionPredicateOutcome::NotEvaluated
        };
    let outcome = if predicate == SuppliedSessionPredicateOutcome::Matched {
        SuppliedSessionHealthOutcome::Healthy
    } else if complete {
        SuppliedSessionHealthOutcome::Unhealthy
    } else {
        SuppliedSessionHealthOutcome::Indeterminate
    };
    WebAssessmentSuppliedSessionCheckpointAudit {
        sequence: position.sequence,
        evidence_reference: None,
        phase: position.phase,
        after_subject_count: position.after_subject_count,
        outcome,
        status: Some(status),
        body_state,
        predicate,
        response_bytes: bytes,
        cookie_update,
    }
}

fn health_unavailable(
    sequence: u8,
    phase: SuppliedSessionHealthCheckpointPhase,
    after_subject_count: u8,
    bytes: u64,
) -> WebAssessmentSuppliedSessionCheckpointAudit {
    WebAssessmentSuppliedSessionCheckpointAudit {
        sequence,
        evidence_reference: None,
        phase,
        after_subject_count,
        outcome: SuppliedSessionHealthOutcome::Indeterminate,
        status: None,
        body_state: SuppliedSessionBodyState::Unavailable,
        predicate: SuppliedSessionPredicateOutcome::NotEvaluated,
        response_bytes: bytes,
        cookie_update: None,
    }
}

fn committed_health_unavailable(
    policy: &SuppliedSessionPolicy,
    descriptor: &SuppliedSessionRequestDescriptor,
    sequence: u8,
    phase: SuppliedSessionHealthCheckpointPhase,
    after_subject_count: u8,
    response_bytes: u64,
    knowledge: &KnowledgeBase,
) -> WebAssessmentSuppliedSessionCheckpointAudit {
    let mut record = health_unavailable(sequence, phase, after_subject_count, response_bytes);
    bind_health_evidence(&mut record, policy, descriptor, None, knowledge);
    record
}

fn bind_health_evidence(
    checkpoint: &mut WebAssessmentSuppliedSessionCheckpointAudit,
    policy: &SuppliedSessionPolicy,
    descriptor: &SuppliedSessionRequestDescriptor,
    exact_response_target: Option<bool>,
    knowledge: &KnowledgeBase,
) {
    checkpoint.evidence_reference = commit_health_evidence(
        policy,
        descriptor,
        checkpoint,
        exact_response_target,
        knowledge,
    );
    if checkpoint.evidence_reference.is_none() {
        checkpoint.outcome = SuppliedSessionHealthOutcome::Indeterminate;
        checkpoint.predicate = SuppliedSessionPredicateOutcome::NotEvaluated;
    }
}

/// Commits a redaction-safe checkpoint receipt to the parent knowledge store.
/// A complete health predicate cannot qualify resource coverage unless this
/// transaction succeeds and the immutable record can be read back exactly.
fn commit_health_evidence(
    policy: &SuppliedSessionPolicy,
    descriptor: &SuppliedSessionRequestDescriptor,
    checkpoint: &WebAssessmentSuppliedSessionCheckpointAudit,
    exact_response_target: Option<bool>,
    knowledge: &KnowledgeBase,
) -> Option<String> {
    if !descriptor.validate()
        || descriptor.purpose() != SuppliedSessionRequestPurpose::Health
        || exact_response_target == Some(false)
    {
        return None;
    }
    let status = checkpoint
        .status
        .map_or_else(|| "unavailable".to_owned(), |status| status.to_string());
    let target_state = if exact_response_target == Some(true) {
        "exact"
    } else {
        "unavailable"
    };
    let mut binding = format!(
        "policy={};application={};health_field={};purpose=health;sequence={};phase={};after_subject_count={};target={target_state};status={status};body_state={};predicate={};outcome={};response_bytes={}",
        policy.policy_reference(),
        policy.application_reference(),
        policy.health_field_reference(),
        checkpoint.sequence,
        checkpoint_phase_token(checkpoint.phase),
        checkpoint.after_subject_count,
        body_state_token(checkpoint.body_state),
        predicate_token(checkpoint.predicate),
        health_outcome_token(checkpoint.outcome),
        checkpoint.response_bytes,
    );
    append_cookie_update_binding(policy, &mut binding, checkpoint.cookie_update);
    commit_value_safe_evidence(
        policy,
        policy.health_field_reference(),
        HEALTH_COMMIT_EVIDENCE_DOMAIN,
        HEALTH_COMMIT_EVIDENCE_PREFIX,
        HEALTH_COMMIT_EVIDENCE_PREDICATE,
        health_commit_evidence_method(policy),
        binding,
        knowledge,
    )
}

fn checkpoint_phase_token(phase: SuppliedSessionHealthCheckpointPhase) -> &'static str {
    match phase {
        SuppliedSessionHealthCheckpointPhase::Startup => "startup",
        SuppliedSessionHealthCheckpointPhase::SubjectBoundary => "subject_boundary",
        SuppliedSessionHealthCheckpointPhase::Terminal => "terminal",
    }
}

fn health_outcome_token(outcome: SuppliedSessionHealthOutcome) -> &'static str {
    match outcome {
        SuppliedSessionHealthOutcome::Healthy => "healthy",
        SuppliedSessionHealthOutcome::Unhealthy => "unhealthy",
        SuppliedSessionHealthOutcome::Indeterminate => "indeterminate",
    }
}

fn body_state_token(state: SuppliedSessionBodyState) -> &'static str {
    match state {
        SuppliedSessionBodyState::Complete => "complete",
        SuppliedSessionBodyState::Incomplete => "incomplete",
        SuppliedSessionBodyState::Unavailable => "unavailable",
    }
}

fn predicate_token(predicate: SuppliedSessionPredicateOutcome) -> &'static str {
    match predicate {
        SuppliedSessionPredicateOutcome::Matched => "matched",
        SuppliedSessionPredicateOutcome::NotMatched => "not_matched",
        SuppliedSessionPredicateOutcome::NotEvaluated => "not_evaluated",
    }
}

/// Body-free staging record awaiting the following health checkpoint.
///
/// The collected response is reduced immediately, so neither its body nor
/// headers can enter the shared knowledge base or saved audit. A complete 200
/// remains staged until its immediately following committed health checkpoint
/// qualifies it. Only then may it become authenticated `Committed` coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StagedSuppliedSessionResource {
    status: u16,
    response_bytes: u64,
    exact_target: bool,
    body_complete: bool,
    cookie_update: Option<SuppliedSessionResponseCookieUpdate>,
}

fn stage_resource_response(
    response: &CollectedHttpResponse,
    response_bytes: u64,
    exact_target: bool,
    cookie_update: Option<SuppliedSessionResponseCookieUpdate>,
) -> StagedSuppliedSessionResource {
    StagedSuppliedSessionResource {
        status: response.status(),
        response_bytes,
        exact_target,
        body_complete: response.body_complete(),
        cookie_update,
    }
}

fn staged_resource_can_await_health(
    descriptor: &SuppliedSessionRequestDescriptor,
    expected_reference: &str,
    staged: StagedSuppliedSessionResource,
) -> bool {
    descriptor.validate()
        && descriptor.purpose() == SuppliedSessionRequestPurpose::Resource
        && descriptor.target_reference() == expected_reference
        && staged.exact_target
        && staged.body_complete
        && staged.status == 200
}

fn commit_staged_resource(
    sequence: u8,
    descriptor: &SuppliedSessionRequestDescriptor,
    expected_reference: &str,
    policy: &SuppliedSessionPolicy,
    knowledge: &KnowledgeBase,
    staged: StagedSuppliedSessionResource,
    qualifying_checkpoint_reference: Option<&str>,
) -> WebAssessmentSuppliedSessionResourceAudit {
    commit_staged_resource_with_receipt(
        sequence,
        descriptor,
        expected_reference,
        policy,
        knowledge,
        staged,
        qualifying_checkpoint_reference,
    )
    .0
}

fn commit_staged_resource_with_receipt(
    sequence: u8,
    descriptor: &SuppliedSessionRequestDescriptor,
    expected_reference: &str,
    policy: &SuppliedSessionPolicy,
    knowledge: &KnowledgeBase,
    staged: StagedSuppliedSessionResource,
    qualifying_checkpoint_reference: Option<&str>,
) -> (
    WebAssessmentSuppliedSessionResourceAudit,
    Option<CommittedSuppliedSessionResourceReceipt>,
) {
    let descriptor_is_exact = descriptor.validate()
        && descriptor.purpose() == SuppliedSessionRequestPurpose::Resource
        && descriptor.target_reference() == expected_reference;
    let (outcome, receipt) = if (300..400).contains(&staged.status) {
        (SuppliedSessionResourceOutcome::RedirectRefused, None)
    } else if !descriptor_is_exact || !staged.exact_target || !staged.body_complete {
        (SuppliedSessionResourceOutcome::Incomplete, None)
    } else if staged.status == 200 {
        match qualifying_checkpoint_reference.and_then(|checkpoint_reference| {
            commit_resource_evidence(
                ResourceEvidenceCommitInput {
                    #[cfg(feature = "wordpress-review")]
                    sequence,
                    descriptor,
                    resource_reference: expected_reference,
                    response_bytes: staged.response_bytes,
                    cookie_update: staged.cookie_update,
                    qualifying_checkpoint_reference: checkpoint_reference,
                },
                policy,
                knowledge,
            )
        }) {
            Some(receipt) => (SuppliedSessionResourceOutcome::Committed, Some(receipt)),
            None => (SuppliedSessionResourceOutcome::Incomplete, None),
        }
    } else {
        (SuppliedSessionResourceOutcome::HttpError, None)
    };
    let evidence_reference = receipt
        .as_ref()
        .map(|receipt| receipt.evidence_reference.clone());
    (
        WebAssessmentSuppliedSessionResourceAudit {
            sequence,
            resource_reference: expected_reference.to_owned(),
            evidence_reference,
            outcome,
            status: Some(staged.status),
            response_bytes: staged.response_bytes,
            epoch: 1,
            cookie_update: staged.cookie_update,
        },
        receipt,
    )
}

fn commit_health_unqualified_resource(
    sequence: u8,
    descriptor: &SuppliedSessionRequestDescriptor,
    expected_reference: &str,
    policy: &SuppliedSessionPolicy,
    knowledge: &KnowledgeBase,
    staged: StagedSuppliedSessionResource,
    checkpoint_reference: Option<&str>,
) -> WebAssessmentSuppliedSessionResourceAudit {
    let evidence_reference =
        staged_resource_can_await_health(descriptor, expected_reference, staged)
            .then(|| {
                commit_health_unqualified_resource_evidence(
                    policy,
                    descriptor,
                    expected_reference,
                    staged.response_bytes,
                    staged.cookie_update,
                    checkpoint_reference,
                    knowledge,
                )
            })
            .flatten();
    WebAssessmentSuppliedSessionResourceAudit {
        sequence,
        resource_reference: expected_reference.to_owned(),
        outcome: if evidence_reference.is_some() {
            SuppliedSessionResourceOutcome::HealthUnqualified
        } else {
            SuppliedSessionResourceOutcome::Incomplete
        },
        evidence_reference,
        status: Some(staged.status),
        response_bytes: staged.response_bytes,
        epoch: 1,
        cookie_update: staged.cookie_update,
    }
}

/// Commits one value-safe resource receipt to the assessment's parent knowledge
/// transaction. The retained record includes only typed references, purpose,
/// status, byte count, and outcome; it never includes the URL, response body,
/// headers, authorization value, or a digest of the authorization value.
struct ResourceEvidenceCommitInput<'a> {
    #[cfg(feature = "wordpress-review")]
    sequence: u8,
    descriptor: &'a SuppliedSessionRequestDescriptor,
    resource_reference: &'a str,
    response_bytes: u64,
    cookie_update: Option<SuppliedSessionResponseCookieUpdate>,
    qualifying_checkpoint_reference: &'a str,
}

fn commit_resource_evidence(
    input: ResourceEvidenceCommitInput<'_>,
    policy: &SuppliedSessionPolicy,
    knowledge: &KnowledgeBase,
) -> Option<CommittedSuppliedSessionResourceReceipt> {
    if !input.descriptor.validate()
        || input.descriptor.purpose() != SuppliedSessionRequestPurpose::Resource
        || input.descriptor.target_reference() != input.resource_reference
    {
        return None;
    }
    require_committed_health_evidence(input.qualifying_checkpoint_reference, knowledge)?;
    let mut binding = format!(
        "policy={};application={};resource={};purpose=resource;status=200;response_bytes={};qualifying_checkpoint={};outcome=committed",
        policy.policy_reference(),
        policy.application_reference(),
        input.resource_reference,
        input.response_bytes,
        input.qualifying_checkpoint_reference,
    );
    append_cookie_update_binding(policy, &mut binding, input.cookie_update);
    let evidence_reference = commit_value_safe_evidence(
        policy,
        input.resource_reference,
        RESOURCE_COMMIT_EVIDENCE_DOMAIN,
        RESOURCE_COMMIT_EVIDENCE_PREFIX,
        RESOURCE_COMMIT_EVIDENCE_PREDICATE,
        resource_commit_evidence_method(policy),
        binding,
        knowledge,
    )?;
    #[cfg(feature = "wordpress-review")]
    let expected_evidence = {
        let evidence_id = EvidenceId::parse(evidence_reference.clone()).ok()?;
        knowledge.inspect_evidence(&evidence_id, Clone::clone)?
    };
    Some(CommittedSuppliedSessionResourceReceipt {
        #[cfg(feature = "wordpress-review")]
        sequence: input.sequence,
        #[cfg(feature = "wordpress-review")]
        resource_reference: input.resource_reference.to_owned(),
        #[cfg(feature = "wordpress-review")]
        policy_reference: policy.policy_reference().to_owned(),
        #[cfg(feature = "wordpress-review")]
        application_reference: policy.application_reference().to_owned(),
        #[cfg(feature = "wordpress-review")]
        principal_reference: policy.principal_reference().to_owned(),
        #[cfg(feature = "wordpress-review")]
        credential_mechanism: policy.credential_mechanism(),
        #[cfg(feature = "wordpress-review")]
        epoch: 1,
        evidence_reference,
        #[cfg(feature = "wordpress-review")]
        expected_evidence,
    })
}

fn commit_health_unqualified_resource_evidence(
    policy: &SuppliedSessionPolicy,
    descriptor: &SuppliedSessionRequestDescriptor,
    resource_reference: &str,
    response_bytes: u64,
    cookie_update: Option<SuppliedSessionResponseCookieUpdate>,
    checkpoint_reference: Option<&str>,
    knowledge: &KnowledgeBase,
) -> Option<String> {
    if !descriptor.validate()
        || descriptor.purpose() != SuppliedSessionRequestPurpose::Resource
        || descriptor.target_reference() != resource_reference
    {
        return None;
    }
    if let Some(reference) = checkpoint_reference {
        require_committed_health_evidence(reference, knowledge)?;
    }
    let checkpoint = checkpoint_reference.unwrap_or("unavailable");
    let mut binding = format!(
        "policy={};application={};resource={resource_reference};purpose=resource;status=200;response_bytes={response_bytes};qualifying_checkpoint={checkpoint};outcome=health_unqualified",
        policy.policy_reference(),
        policy.application_reference(),
    );
    append_cookie_update_binding(policy, &mut binding, cookie_update);
    commit_value_safe_evidence(
        policy,
        resource_reference,
        RESOURCE_COMMIT_EVIDENCE_DOMAIN,
        RESOURCE_COMMIT_EVIDENCE_PREFIX,
        RESOURCE_HEALTH_UNQUALIFIED_EVIDENCE_PREDICATE,
        resource_commit_evidence_method(policy),
        binding,
        knowledge,
    )
}

fn health_commit_evidence_method(policy: &SuppliedSessionPolicy) -> &'static str {
    match policy.version() {
        SuppliedSessionPolicyVersion::V1 => HEALTH_COMMIT_EVIDENCE_METHOD_V1,
        SuppliedSessionPolicyVersion::V2 => HEALTH_COMMIT_EVIDENCE_METHOD_V2,
    }
}

fn resource_commit_evidence_method(policy: &SuppliedSessionPolicy) -> &'static str {
    match policy.version() {
        SuppliedSessionPolicyVersion::V1 => RESOURCE_COMMIT_EVIDENCE_METHOD_V1,
        SuppliedSessionPolicyVersion::V2 => RESOURCE_COMMIT_EVIDENCE_METHOD_V2,
    }
}

fn append_cookie_update_binding(
    policy: &SuppliedSessionPolicy,
    binding: &mut String,
    update: Option<SuppliedSessionResponseCookieUpdate>,
) {
    if policy.version() != SuppliedSessionPolicyVersion::V2 {
        return;
    }
    let update = update.unwrap_or(SuppliedSessionResponseCookieUpdate {
        kind: SuppliedSessionResponseCookieUpdateKind::None,
        selected_count: 0,
        unselected_count: 0,
    });
    use std::fmt::Write as _;
    let _ = write!(
        binding,
        ";cookie_update={};selected_update_count={};unselected_update_count={}",
        cookie_update_token(update.kind),
        update.selected_count,
        update.unselected_count,
    );
}

fn cookie_update_token(kind: SuppliedSessionResponseCookieUpdateKind) -> &'static str {
    match kind {
        SuppliedSessionResponseCookieUpdateKind::None => "none",
        SuppliedSessionResponseCookieUpdateKind::UnselectedOnly => "unselected_only",
        SuppliedSessionResponseCookieUpdateKind::Selected => "selected",
        SuppliedSessionResponseCookieUpdateKind::Unusable => "unusable",
    }
}

fn require_committed_health_evidence(reference: &str, knowledge: &KnowledgeBase) -> Option<()> {
    let evidence_id = EvidenceId::parse(reference).ok()?;
    knowledge
        .inspect_evidence(&evidence_id, |evidence| {
            evidence.kind() == &EvidenceKind::Authentication
                && evidence.predicate().namespace() == RESOURCE_COMMIT_EVIDENCE_NAMESPACE
                && evidence.predicate().name() == HEALTH_COMMIT_EVIDENCE_PREDICATE
        })?
        .then_some(())
}

#[allow(clippy::too_many_arguments)]
fn commit_value_safe_evidence(
    policy: &SuppliedSessionPolicy,
    correlation_reference: &str,
    digest_domain: &[u8],
    evidence_prefix: &str,
    predicate_name: &str,
    method: &str,
    binding: String,
    knowledge: &KnowledgeBase,
) -> Option<String> {
    let mut digest = Sha256::new();
    digest.update(digest_domain);
    digest.update(binding.as_bytes());
    let evidence_reference = format!("{evidence_prefix}:{:x}", digest.finalize());
    let evidence_id = EvidenceId::parse(evidence_reference.clone()).ok()?;
    let subject = EntityId::new(policy.application_reference().to_owned()).ok()?;
    let predicate =
        KnowledgePredicate::new(RESOURCE_COMMIT_EVIDENCE_NAMESPACE, predicate_name).ok()?;
    let source = EvidenceSource::new(RESOURCE_COMMIT_EVIDENCE_COMPONENT, method)
        .and_then(|source| source.with_correlation_id(correlation_reference.to_owned()))
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

fn resource_transport_failure(
    sequence: u8,
    reference: &str,
    bytes: u64,
) -> WebAssessmentSuppliedSessionResourceAudit {
    WebAssessmentSuppliedSessionResourceAudit {
        sequence,
        resource_reference: reference.to_owned(),
        evidence_reference: None,
        outcome: SuppliedSessionResourceOutcome::TransportFailed,
        status: None,
        response_bytes: bytes,
        epoch: 1,
        cookie_update: None,
    }
}

fn resource_not_dispatched(
    sequence: u8,
    reference: &str,
) -> WebAssessmentSuppliedSessionResourceAudit {
    WebAssessmentSuppliedSessionResourceAudit {
        sequence,
        resource_reference: reference.to_owned(),
        evidence_reference: None,
        outcome: SuppliedSessionResourceOutcome::NotDispatched,
        status: None,
        response_bytes: 0,
        epoch: 1,
        cookie_update: None,
    }
}

#[derive(Clone, Copy)]
enum StrictHealthValue {
    Bool(bool),
    Other,
}

struct StrictHealthSeed<'a> {
    depth: usize,
    nodes: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for StrictHealthSeed<'_> {
    type Value = StrictHealthValue;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > HEALTH_JSON_MAX_DEPTH || *self.nodes >= HEALTH_JSON_MAX_NODES {
            return Err(serde::de::Error::custom("bounded health JSON limit"));
        }
        *self.nodes += 1;
        deserializer.deserialize_any(StrictHealthVisitor {
            depth: self.depth,
            nodes: self.nodes,
        })
    }
}

struct StrictHealthVisitor<'a> {
    depth: usize,
    nodes: &'a mut usize,
}

impl<'de> Visitor<'de> for StrictHealthVisitor<'_> {
    type Value = StrictHealthValue;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON")
    }
    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictHealthValue::Bool(value))
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(StrictHealthValue::Other)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(StrictHealthValue::Other)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(StrictHealthValue::Other)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictHealthValue::Other)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictHealthValue::Other)
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > HEALTH_JSON_MAX_KEY_BYTES {
            return Err(E::custom("bounded health JSON string"));
        }
        Ok(StrictHealthValue::Other)
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(StrictHealthSeed {
                depth: self.depth + 1,
                nodes: self.nodes,
            })?
            .is_some()
        {}
        Ok(StrictHealthValue::Other)
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > HEALTH_JSON_MAX_KEY_BYTES || !seen.insert(key) {
                return Err(serde::de::Error::custom(
                    "duplicate or oversized health JSON key",
                ));
            }
            let _ = map.next_value_seed(StrictHealthSeed {
                depth: self.depth + 1,
                nodes: self.nodes,
            })?;
        }
        Ok(StrictHealthValue::Other)
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
                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a bounded JSON object")
                }
                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut seen = std::collections::BTreeSet::new();
                    let mut selected = None;
                    while let Some(key) = map.next_key::<String>()? {
                        if key.len() > HEALTH_JSON_MAX_KEY_BYTES || !seen.insert(key.clone()) {
                            return Err(serde::de::Error::custom(
                                "duplicate or oversized health JSON key",
                            ));
                        }
                        let value = map.next_value_seed(StrictHealthSeed {
                            depth: 1,
                            nodes: self.nodes,
                        })?;
                        if key == self.field {
                            selected = match value {
                                StrictHealthValue::Bool(value) => Some(value),
                                StrictHealthValue::Other => None,
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
    .ok()?;
    decoder.end().ok()?;
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supplied_session_review::{SuppliedSessionAuthorization, SuppliedSessionCookies};
    use crate::web_runtime::{WebAssessmentRuntimeBuilder, WebAssessmentRuntimeError};
    #[cfg(feature = "wordpress-review")]
    use crate::wordpress_review::WordPressReviewInputs;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Mutex,
    };

    fn policy(application: &url::Url) -> SuppliedSessionPolicy {
        SuppliedSessionPolicy::parse_toml(
            application,
            br#"schema = "security.supplied-session-policy/v1"
principal_alias = "fixture-principal"
credential_mechanism = "authorization_header"
health_path = "/app/session-health"
health_json_field = "authenticated"
resources = ["/app/private"]
max_session_requests = 3
max_total_response_bytes = 65536
max_response_body_bytes = 16384
max_wall_time_ms = 5000
"#,
        )
        .unwrap()
    }

    fn cookie_policy(application: &url::Url) -> SuppliedSessionPolicy {
        let bytes = format!(
            r#"schema = "security.supplied-session-policy/v2"
principal_alias = "cookie-fixture-principal"
credential_mechanism = "cookie_jar"
cookie_update_policy = "stop_on_selected_cookie"
health_path = "/app/session-health"
health_json_field = "authenticated"
resources = ["/app/private"]
max_session_requests = 3
max_total_response_bytes = 65536
max_response_body_bytes = 16384
max_wall_time_ms = 5000

[[cookies]]
id = "session-secret"
name = "session"
domain = "{}"
host_only = true
path = "/app/"
secure = false
http_only = true
same_site = "lax"
"#,
            application.host_str().unwrap()
        );
        SuppliedSessionPolicy::parse_toml(application, bytes.as_bytes()).unwrap()
    }

    fn cookie_credential(policy: &SuppliedSessionPolicy) -> SuppliedSessionCookies {
        SuppliedSessionCookies::parse_tsv(
            policy,
            b"session-secret\tCOOKIE-RUNTIME-CANARY\n".to_vec(),
            1,
        )
        .unwrap()
    }

    fn committed_health_qualification(
        policy: &SuppliedSessionPolicy,
        knowledge: &KnowledgeBase,
    ) -> String {
        let descriptor = SuppliedSessionRequestDescriptor::health(policy);
        let mut checkpoint = WebAssessmentSuppliedSessionCheckpointAudit {
            sequence: 1,
            evidence_reference: None,
            phase: SuppliedSessionHealthCheckpointPhase::Terminal,
            after_subject_count: 1,
            outcome: SuppliedSessionHealthOutcome::Healthy,
            status: Some(200),
            body_state: SuppliedSessionBodyState::Complete,
            predicate: SuppliedSessionPredicateOutcome::Matched,
            response_bytes: 22,
            cookie_update: None,
        };
        bind_health_evidence(&mut checkpoint, policy, &descriptor, Some(true), knowledge);
        checkpoint
            .evidence_reference
            .expect("fixture health receipt must commit")
    }

    #[test]
    fn strict_health_json_rejects_duplicates_and_non_boolean_values() {
        assert_eq!(
            strict_top_level_boolean(br#"{"authenticated":true}"#, "authenticated"),
            Some(true)
        );
        assert_eq!(
            strict_top_level_boolean(br#"{"authenticated":false}"#, "authenticated"),
            Some(false)
        );
        assert_eq!(
            strict_top_level_boolean(br#"{"authenticated":"true"}"#, "authenticated"),
            None
        );
        assert_eq!(
            strict_top_level_boolean(
                br#"{"authenticated":true,"authenticated":false}"#,
                "authenticated"
            ),
            None
        );
        assert_eq!(
            strict_top_level_boolean(br#"[true]"#, "authenticated"),
            None
        );
    }

    #[test]
    fn only_a_complete_negative_post_startup_checkpoint_claims_session_loss() {
        assert_eq!(
            health_stop_outcome(SuppliedSessionHealthOutcome::Healthy, true),
            None
        );
        assert_eq!(
            health_stop_outcome(SuppliedSessionHealthOutcome::Unhealthy, true),
            Some(SuppliedSessionAuditOutcome::StartupUnhealthy)
        );
        assert_eq!(
            health_stop_outcome(SuppliedSessionHealthOutcome::Indeterminate, true),
            Some(SuppliedSessionAuditOutcome::ResourceUnavailable)
        );
        assert_eq!(
            health_stop_outcome(SuppliedSessionHealthOutcome::Unhealthy, false),
            Some(SuppliedSessionAuditOutcome::SessionLost)
        );
        assert_eq!(
            health_stop_outcome(SuppliedSessionHealthOutcome::Indeterminate, false),
            Some(SuppliedSessionAuditOutcome::ResourceUnavailable)
        );
    }

    #[test]
    fn health_truth_requires_a_parent_knowledge_commit() {
        let application = url::Url::parse("https://example.test/app/").unwrap();
        let policy = policy(&application);
        let descriptor = SuppliedSessionRequestDescriptor::health(&policy);
        let healthy = || WebAssessmentSuppliedSessionCheckpointAudit {
            sequence: 0,
            evidence_reference: None,
            phase: SuppliedSessionHealthCheckpointPhase::Startup,
            after_subject_count: 0,
            outcome: SuppliedSessionHealthOutcome::Healthy,
            status: Some(200),
            body_state: SuppliedSessionBodyState::Complete,
            predicate: SuppliedSessionPredicateOutcome::Matched,
            response_bytes: 22,
            cookie_update: None,
        };

        let committed_knowledge = KnowledgeBase::new();
        let mut committed = healthy();
        bind_health_evidence(
            &mut committed,
            &policy,
            &descriptor,
            Some(true),
            &committed_knowledge,
        );
        assert_eq!(committed.outcome(), SuppliedSessionHealthOutcome::Healthy);
        let evidence_reference = committed
            .evidence_reference()
            .expect("healthy checkpoint must have a committed receipt")
            .to_owned();

        let conflicting = Evidence::with_id(
            EvidenceId::parse(evidence_reference).unwrap(),
            EntityId::new("supplied-session-conflict-fixture").unwrap(),
            EvidenceKind::Authentication,
            KnowledgePredicate::new("fixture", "conflict").unwrap(),
            EvidenceValue::Boolean(false),
            EvidenceSource::new("fixture", "conflict").unwrap(),
            ConfidenceScore::MAX,
        );
        let conflicting_knowledge = KnowledgeBase::new();
        conflicting_knowledge.insert_evidence(conflicting).unwrap();
        let mut rejected = healthy();
        bind_health_evidence(
            &mut rejected,
            &policy,
            &descriptor,
            Some(true),
            &conflicting_knowledge,
        );
        assert_eq!(rejected.evidence_reference(), None);
        assert_eq!(
            rejected.outcome(),
            SuppliedSessionHealthOutcome::Indeterminate
        );
        assert_eq!(
            rejected.predicate(),
            SuppliedSessionPredicateOutcome::NotEvaluated
        );

        let mut wrong_target = healthy();
        bind_health_evidence(
            &mut wrong_target,
            &policy,
            &descriptor,
            Some(false),
            &KnowledgeBase::new(),
        );
        assert_eq!(wrong_target.evidence_reference(), None);
        assert_eq!(
            wrong_target.outcome(),
            SuppliedSessionHealthOutcome::Indeterminate
        );
    }

    #[test]
    fn resource_commit_revalidates_descriptor_and_complete_response_receipt() {
        let application = url::Url::parse("https://example.test/app/").unwrap();
        let policy = policy(&application);
        let (target, reference) = policy.execution_resources().next().unwrap();
        let descriptor = SuppliedSessionRequestDescriptor::resource(&policy, target, reference)
            .expect("fixture resource descriptor");
        let complete = StagedSuppliedSessionResource {
            status: 200,
            response_bytes: 17,
            exact_target: true,
            body_complete: true,
            cookie_update: None,
        };
        let knowledge = KnowledgeBase::new();
        assert_eq!(
            commit_staged_resource(
                0,
                &descriptor,
                reference,
                &policy,
                &knowledge,
                complete,
                None,
            )
            .outcome(),
            SuppliedSessionResourceOutcome::Incomplete,
            "a complete 200 is not authenticated coverage without its following health receipt"
        );
        let qualifier = committed_health_qualification(&policy, &knowledge);
        let committed = commit_staged_resource(
            0,
            &descriptor,
            reference,
            &policy,
            &knowledge,
            complete,
            Some(&qualifier),
        );
        assert_eq!(
            committed.outcome(),
            SuppliedSessionResourceOutcome::Committed
        );
        let evidence_reference = committed
            .evidence_reference()
            .expect("knowledge commit must leave an opaque receipt")
            .to_owned();
        assert_eq!(knowledge.stats().evidence, 2);

        let conflicting = Evidence::with_id(
            EvidenceId::parse(evidence_reference).unwrap(),
            EntityId::new("supplied-session-conflict-fixture").unwrap(),
            EvidenceKind::Authentication,
            KnowledgePredicate::new("fixture", "conflict").unwrap(),
            EvidenceValue::Boolean(false),
            EvidenceSource::new("fixture", "conflict").unwrap(),
            ConfidenceScore::MAX,
        );
        let conflicting_knowledge = KnowledgeBase::new();
        let conflicting_qualifier = committed_health_qualification(&policy, &conflicting_knowledge);
        conflicting_knowledge.insert_evidence(conflicting).unwrap();
        let rejected = commit_staged_resource(
            0,
            &descriptor,
            reference,
            &policy,
            &conflicting_knowledge,
            complete,
            Some(&conflicting_qualifier),
        );
        assert_eq!(
            rejected.outcome(),
            SuppliedSessionResourceOutcome::Incomplete
        );
        assert_eq!(rejected.evidence_reference(), None);

        for mutation in [
            StagedSuppliedSessionResource {
                exact_target: false,
                ..complete
            },
            StagedSuppliedSessionResource {
                body_complete: false,
                ..complete
            },
        ] {
            assert_eq!(
                commit_staged_resource(
                    0,
                    &descriptor,
                    reference,
                    &policy,
                    &KnowledgeBase::new(),
                    mutation,
                    None,
                )
                .outcome(),
                SuppliedSessionResourceOutcome::Incomplete
            );
        }
        assert_eq!(
            commit_staged_resource(
                0,
                &descriptor,
                "supplied-session-resource-sha256:wrong",
                &policy,
                &KnowledgeBase::new(),
                complete,
                None,
            )
            .outcome(),
            SuppliedSessionResourceOutcome::Incomplete
        );
        assert_eq!(
            commit_staged_resource(
                0,
                &descriptor,
                reference,
                &policy,
                &KnowledgeBase::new(),
                StagedSuppliedSessionResource {
                    status: 302,
                    ..complete
                },
                None,
            )
            .outcome(),
            SuppliedSessionResourceOutcome::RedirectRefused
        );
        assert_eq!(
            commit_staged_resource(
                0,
                &descriptor,
                reference,
                &policy,
                &KnowledgeBase::new(),
                StagedSuppliedSessionResource {
                    status: 403,
                    ..complete
                },
                None,
            )
            .outcome(),
            SuppliedSessionResourceOutcome::HttpError
        );
    }

    #[test]
    fn committed_resource_receipt_revalidates_the_full_session_binding() {
        let application = url::Url::parse("https://example.test/app/").unwrap();
        let policy = policy(&application);
        let (target, reference) = policy.execution_resources().next().unwrap();
        let descriptor = SuppliedSessionRequestDescriptor::resource(&policy, target, reference)
            .expect("fixture resource descriptor");
        let staged = StagedSuppliedSessionResource {
            status: 200,
            response_bytes: 17,
            exact_target: true,
            body_complete: true,
            cookie_update: None,
        };
        let knowledge = KnowledgeBase::new();
        let qualifier = committed_health_qualification(&policy, &knowledge);
        let (audit, receipt) = commit_staged_resource_with_receipt(
            0,
            &descriptor,
            reference,
            &policy,
            &knowledge,
            staged,
            Some(&qualifier),
        );
        assert_eq!(audit.outcome(), SuppliedSessionResourceOutcome::Committed);
        let mut receipt = receipt.expect("complete qualified response must mint a sealed receipt");
        assert!(receipt.is_valid_for(0, &policy, &descriptor, &knowledge));

        receipt.epoch = 2;
        assert!(!receipt.is_valid_for(0, &policy, &descriptor, &knowledge));
        receipt.epoch = 1;
        receipt.principal_reference = "supplied-session-principal-9999".to_owned();
        assert!(!receipt.is_valid_for(0, &policy, &descriptor, &knowledge));
        receipt.principal_reference = policy.principal_reference().to_owned();
        receipt.credential_mechanism = SuppliedSessionCredentialMechanism::CookieJar;
        assert!(!receipt.is_valid_for(0, &policy, &descriptor, &knowledge));
        receipt.credential_mechanism = SuppliedSessionCredentialMechanism::AuthorizationHeader;
        receipt.application_reference =
            "supplied-session-application-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned();
        assert!(!receipt.is_valid_for(0, &policy, &descriptor, &knowledge));
        receipt.application_reference = policy.application_reference().to_owned();
        receipt.policy_reference =
            "supplied-session-policy-sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned();
        assert!(!receipt.is_valid_for(0, &policy, &descriptor, &knowledge));
        receipt.policy_reference = policy.policy_reference().to_owned();
        receipt.resource_reference =
            "supplied-session-resource-sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_owned();
        assert!(!receipt.is_valid_for(0, &policy, &descriptor, &knowledge));
        receipt.resource_reference = descriptor.target_reference().to_owned();
        assert!(!receipt.is_valid_for(1, &policy, &descriptor, &knowledge));
        assert!(receipt.is_valid_for(0, &policy, &descriptor, &knowledge));
    }

    #[test]
    fn builder_rejects_cleartext_non_loopback_and_application_mismatch() {
        let insecure = url::Url::parse("http://example.test/app/").unwrap();
        let error = WebAssessmentRuntimeBuilder::new(insecure.clone())
            .with_supplied_session_review(
                policy(&insecure),
                SuppliedSessionAuthorization::new("Bearer REDACTED-CANARY").unwrap(),
            )
            .build()
            .err()
            .expect("cleartext non-loopback session must be rejected");
        assert!(matches!(
            error,
            WebAssessmentRuntimeError::InsecureSuppliedSessionTransport
        ));

        let selected = url::Url::parse("https://example.test/app/").unwrap();
        let other = url::Url::parse("https://example.test/other/").unwrap();
        let other_policy = SuppliedSessionPolicy::parse_toml(
            &other,
            br#"schema = "security.supplied-session-policy/v1"
principal_alias = "fixture-principal"
credential_mechanism = "authorization_header"
health_path = "/other/session-health"
health_json_field = "authenticated"
resources = ["/other/private"]
max_session_requests = 3
max_total_response_bytes = 65536
max_response_body_bytes = 16384
max_wall_time_ms = 5000
"#,
        )
        .unwrap();
        let error = WebAssessmentRuntimeBuilder::new(selected)
            .with_supplied_session_review(
                other_policy,
                SuppliedSessionAuthorization::new("Bearer REDACTED-CANARY").unwrap(),
            )
            .build()
            .err()
            .expect("policy bound to another application must be rejected");
        assert!(matches!(
            error,
            WebAssessmentRuntimeError::SuppliedSessionApplicationMismatch
        ));
    }

    #[cfg(feature = "wordpress-review")]
    #[test]
    fn wordpress_supplied_session_selection_requires_every_runtime_input() {
        let application = url::Url::parse("https://example.test/app/").unwrap();
        let authorization =
            || SuppliedSessionAuthorization::new("Bearer REDACTED-WORDPRESS-CANARY").unwrap();

        let missing_all = WebAssessmentRuntimeBuilder::new(application.clone())
            .with_wordpress_supplied_session()
            .build()
            .err()
            .expect("integration without either child must fail preflight");
        assert!(matches!(
            missing_all,
            WebAssessmentRuntimeError::WordPressSuppliedSessionRequiresInputs
        ));

        let missing_session = WebAssessmentRuntimeBuilder::new(application.clone())
            .with_wordpress_review(WordPressReviewInputs::new(None, None))
            .with_wordpress_discovery()
            .with_wordpress_supplied_session()
            .build()
            .err()
            .expect("WordPress discovery without a supplied session must fail preflight");
        assert!(matches!(
            missing_session,
            WebAssessmentRuntimeError::WordPressSuppliedSessionRequiresInputs
        ));

        let missing_discovery = WebAssessmentRuntimeBuilder::new(application.clone())
            .with_wordpress_review(WordPressReviewInputs::new(None, None))
            .with_supplied_session_review(policy(&application), authorization())
            .with_wordpress_supplied_session()
            .build()
            .err()
            .expect("integration without metadata discovery must fail preflight");
        assert!(matches!(
            missing_discovery,
            WebAssessmentRuntimeError::WordPressSuppliedSessionRequiresInputs
        ));

        WebAssessmentRuntimeBuilder::new(application.clone())
            .with_wordpress_review(WordPressReviewInputs::new(None, None))
            .with_wordpress_discovery()
            .with_supplied_session_review(policy(&application), authorization())
            .with_wordpress_supplied_session()
            .build()
            .expect("complete integration selection must build");
    }

    #[tokio::test]
    async fn normal_runtime_runs_session_before_anonymous_bfs_and_keeps_bodies_private() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let observed = Arc::new(Mutex::new(Vec::<(String, bool, bool)>::new()));
        let server_observed = observed.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n")
                        || request.len() > 16 * 1024
                    {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let path = text
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("")
                    .to_owned();
                let has_authorization = text.lines().any(|line| {
                    line.eq_ignore_ascii_case("authorization: Bearer SECRET-RUNTIME-CANARY")
                });
                let has_cookie = text
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("cookie:"));
                server_observed
                    .lock()
                    .await
                    .push((path.clone(), has_authorization, has_cookie));
                let (media_type, body) = match path.as_str() {
                    "/app/session-health" => ("application/json", r#"{"authenticated":true}"#),
                    "/app/private" => ("text/html", "PRIVATE-BODY-MUST-NOT-BE-RETAINED"),
                    _ => ("text/html", "<!doctype html><title>public root</title>"),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {media_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        let application = url::Url::parse(&format!("http://{address}/app/")).unwrap();
        let mut runtime = WebAssessmentRuntimeBuilder::new(application.clone())
            .with_supplied_session_review(
                policy(&application),
                SuppliedSessionAuthorization::new("Bearer SECRET-RUNTIME-CANARY").unwrap(),
            )
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();
        let audit = report
            .supplied_session_audit()
            .expect("selected child must retain an audit");
        assert_eq!(audit.capability_id(), SUPPLIED_SESSION_CAPABILITY_ID);
        assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::Complete);
        assert_eq!(audit.coverage(), SuppliedSessionCoverage::Complete);
        assert_eq!(audit.selected_resource_count(), 1);
        assert_eq!(audit.dispatched_resource_count(), 1);
        assert_eq!(audit.committed_resource_count(), 1);
        assert_eq!(audit.dispatched_request_count(), 3);
        assert_eq!(audit.checkpoints().len(), 2);
        assert_eq!(audit.checkpoints()[0].sequence(), 0);
        assert!(audit.checkpoints()[0]
            .evidence_reference()
            .is_some_and(|reference| reference.starts_with(HEALTH_COMMIT_EVIDENCE_PREFIX)));
        assert_eq!(audit.checkpoints()[0].after_subject_count(), 0);
        assert_eq!(
            audit.checkpoints()[0].phase(),
            SuppliedSessionHealthCheckpointPhase::Startup
        );
        assert_eq!(audit.checkpoints()[1].sequence(), 1);
        assert!(audit.checkpoints()[1]
            .evidence_reference()
            .is_some_and(|reference| reference.starts_with(HEALTH_COMMIT_EVIDENCE_PREFIX)));
        assert_eq!(audit.checkpoints()[1].after_subject_count(), 1);
        assert_eq!(
            audit.checkpoints()[1].phase(),
            SuppliedSessionHealthCheckpointPhase::Terminal
        );
        assert_eq!(audit.resources()[0].sequence(), 0);
        assert_eq!(
            audit.resources()[0].outcome(),
            SuppliedSessionResourceOutcome::Committed
        );
        assert_eq!(audit.resources()[0].epoch(), 1);
        let evidence_reference = audit.resources()[0]
            .evidence_reference()
            .expect("committed resource must retain its knowledge receipt");
        assert!(evidence_reference.starts_with(RESOURCE_COMMIT_EVIDENCE_PREFIX));
        let evidence_id = EvidenceId::parse(evidence_reference).unwrap();
        assert_eq!(
            runtime
                .knowledge()
                .inspect_evidence(&evidence_id, |evidence| {
                    evidence.kind() == &EvidenceKind::Authentication
                        && evidence.predicate().namespace() == RESOURCE_COMMIT_EVIDENCE_NAMESPACE
                        && evidence.predicate().name() == RESOURCE_COMMIT_EVIDENCE_PREDICATE
                }),
            Some(true)
        );
        for checkpoint in audit.checkpoints() {
            let evidence_id = EvidenceId::parse(checkpoint.evidence_reference().unwrap()).unwrap();
            assert_eq!(
                runtime
                    .knowledge()
                    .inspect_evidence(&evidence_id, |evidence| {
                        evidence.kind() == &EvidenceKind::Authentication
                            && evidence.predicate().namespace()
                                == RESOURCE_COMMIT_EVIDENCE_NAMESPACE
                            && evidence.predicate().name() == HEALTH_COMMIT_EVIDENCE_PREDICATE
                    }),
                Some(true)
            );
        }
        assert_eq!(
            audit.response_bytes(),
            audit
                .checkpoints()
                .iter()
                .map(WebAssessmentSuppliedSessionCheckpointAudit::response_bytes)
                .chain(
                    audit
                        .resources()
                        .iter()
                        .map(WebAssessmentSuppliedSessionResourceAudit::response_bytes),
                )
                .sum::<u64>()
        );
        let saved = serde_json::to_string(audit).unwrap();
        assert_eq!(audit.principal_alias(), "fixture-principal");
        assert!(saved.contains(r#""principal_alias":"fixture-principal""#));
        for forbidden in [
            "SECRET-RUNTIME-CANARY",
            "PRIVATE-BODY-MUST-NOT-BE-RETAINED",
            "/app/private",
        ] {
            assert!(!saved.contains(forbidden));
        }

        let observed = observed.lock().await.clone();
        assert!(
            observed.len() >= 4,
            "session plus ordinary root must execute"
        );
        assert_eq!(observed[0], ("/app/session-health".to_owned(), true, false));
        assert_eq!(observed[1], ("/app/private".to_owned(), true, false));
        assert_eq!(observed[2], ("/app/session-health".to_owned(), true, false));
        assert_eq!(observed[3], ("/app/".to_owned(), false, false));
        server.abort();
    }

    #[cfg(feature = "wordpress-review")]
    #[tokio::test]
    async fn wordpress_integration_commits_health_qualified_html_before_anonymous_metadata() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let observed = Arc::new(Mutex::new(Vec::<(String, bool)>::new()));
        let server_observed = observed.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n")
                        || request.len() > 16 * 1024
                    {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&request);
                let request_line = request.lines().next().unwrap_or_default();
                let method = request_line
                    .split_ascii_whitespace()
                    .next()
                    .unwrap_or_default();
                let path = request_line
                    .split_ascii_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_owned();
                let authorized = request.lines().any(|line| {
                    line.eq_ignore_ascii_case("authorization: Bearer WORDPRESS-SESSION-CANARY")
                });
                server_observed
                    .lock()
                    .await
                    .push((path.clone(), authorized));
                let (media_type, body) = match path.as_str() {
                    "/app/" => (
                        "text/html",
                        r#"<meta name="generator" content="WordPress 6.9.4">
                           <link rel="https://api.w.org/" href="/app/wp-json/">
                           <link rel="stylesheet" href="/app/wp-content/themes/session-theme/style.css">"#,
                    ),
                    "/app/session-health" => ("application/json", r#"{"authenticated":true}"#),
                    "/app/private" => (
                        "text/html",
                        r#"<script src="/app/wp-content/plugins/private-component/assets/site.js"></script>
                           <link rel="stylesheet" href="/app/wp-content/plugins/private-component/assets/site.css">"#,
                    ),
                    "/app/wp-json/" => ("application/json", r#"{"namespaces":["wp/v2"]}"#),
                    "/app/wp-content/themes/session-theme/style.css" => (
                        "text/css",
                        "/*\nTheme Name: Session Theme\nVersion: 1.5\n*/\n",
                    ),
                    "/app/wp-content/plugins/private-component/readme.txt" => (
                        "text/plain",
                        "=== Private Component ===\nStable tag: 9.9.9\n",
                    ),
                    _ => ("text/plain", "not found"),
                };
                let status = if body == "not found" {
                    "404 Not Found"
                } else {
                    "200 OK"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {media_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
                if method.is_empty() {
                    break;
                }
            }
        });

        let application = url::Url::parse(&format!("http://{address}/app/")).unwrap();
        let mut runtime = WebAssessmentRuntimeBuilder::new(application.clone())
            .with_wordpress_review(WordPressReviewInputs::new(None, None))
            .with_wordpress_discovery()
            .with_supplied_session_review(
                policy(&application),
                SuppliedSessionAuthorization::new("Bearer WORDPRESS-SESSION-CANARY").unwrap(),
            )
            .with_wordpress_supplied_session()
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();
        let session = report.supplied_session_audit().unwrap();
        assert_eq!(session.outcome(), SuppliedSessionAuditOutcome::Complete);
        assert_eq!(session.committed_resource_count(), 1);
        let wordpress = report.wordpress_review_audit().unwrap();
        let discovery = wordpress.discovery().unwrap();
        let pages = discovery.supplied_session_pages().unwrap();
        assert_eq!(pages.selected_count(), 1);
        assert_eq!(pages.committed_count(), 1);
        assert_eq!(pages.accepted_count(), 1);
        assert_eq!(pages.rejected_count(), 0);
        assert_eq!(pages.not_established_count(), 0);
        assert_eq!(pages.not_evaluated_count(), 0);
        assert_eq!(pages.pages().len(), 1);
        let page = &pages.pages()[0];
        assert_eq!(page.association().as_str(), "accepted");
        assert_eq!(page.outcome().as_str(), "accepted");
        assert!(page.resource_evidence_reference().is_some());
        assert_eq!(page.evidence_ids().len(), 1);

        let private_source = discovery
            .sources()
            .iter()
            .find(|source| source.component_slug() == Some("private-component"))
            .expect("health-qualified private page must nominate one plugin readme");
        assert!(private_source.source_page_references().is_empty());
        assert_eq!(
            private_source.source_supplied_session_page_references(),
            [page.context_page_reference()]
        );
        assert!(discovery
            .sources()
            .iter()
            .filter(|source| source.component_slug() != Some("private-component"))
            .all(|source| source.source_supplied_session_page_references().is_empty()));

        let observed = observed.lock().await.clone();
        let root_index = observed
            .iter()
            .position(|(path, authorized)| path == "/app/" && !authorized)
            .unwrap();
        let startup_index = observed
            .iter()
            .position(|(path, authorized)| path == "/app/session-health" && *authorized)
            .unwrap();
        let metadata_index = observed
            .iter()
            .position(|(path, authorized)| {
                path == "/app/wp-content/plugins/private-component/readme.txt" && !authorized
            })
            .unwrap();
        assert!(root_index < startup_index && startup_index < metadata_index);
        assert_eq!(
            observed
                .iter()
                .filter(|(path, _)| path == "/app/private")
                .count(),
            1
        );
        assert!(observed
            .iter()
            .all(|(path, authorized)| { !path.starts_with("/app/wp-content/") || !authorized }));
        server.abort();
    }

    async fn run_cookie_update_fixture(
        set_cookie: &'static str,
        update_path: &'static str,
    ) -> (WebAssessmentSuppliedSessionAudit, Vec<(String, bool, bool)>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let observed = Arc::new(Mutex::new(Vec::<(String, bool, bool)>::new()));
        let server_observed = observed.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n")
                        || request.len() > 16 * 1024
                    {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let path = text
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("")
                    .to_owned();
                let exact_cookie = text
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("cookie: session=COOKIE-RUNTIME-CANARY"));
                let has_authorization = text
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("authorization:"));
                server_observed
                    .lock()
                    .await
                    .push((path.clone(), exact_cookie, has_authorization));
                let (media_type, body) = match path.as_str() {
                    "/app/session-health" => ("application/json", r#"{"authenticated":true}"#),
                    "/app/private" => ("text/html", "COOKIE-PRIVATE-BODY-MUST-NOT-BE-RETAINED"),
                    _ => ("text/html", "<title>public root</title>"),
                };
                let update = if path == update_path { set_cookie } else { "" };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {media_type}\r\n{update}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        let application = url::Url::parse(&format!("http://{address}/app/")).unwrap();
        let policy = cookie_policy(&application);
        let cookies = cookie_credential(&policy);
        let mut runtime = WebAssessmentRuntimeBuilder::new(application)
            .with_supplied_session_review(policy, cookies)
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();
        let audit = report.supplied_session_audit().unwrap().clone();
        let observed = observed.lock().await.clone();
        server.abort();
        (audit, observed)
    }

    #[tokio::test]
    async fn selected_cookie_update_stops_before_following_health_and_is_value_free() {
        let (audit, observed) = run_cookie_update_fixture(
            "Set-Cookie: session=ROTATED-SECRET; Path=/app/\r\n",
            "/app/private",
        )
        .await;
        assert_eq!(audit.schema(), SUPPLIED_SESSION_COOKIE_AUDIT_SCHEMA);
        assert_eq!(
            audit.outcome(),
            SuppliedSessionAuditOutcome::CredentialUpdateRequired
        );
        assert_eq!(audit.coverage(), SuppliedSessionCoverage::None);
        assert_eq!(audit.dispatched_request_count(), 2);
        assert_eq!(audit.checkpoints().len(), 1);
        assert_eq!(audit.resources().len(), 1);
        assert_eq!(
            audit.resources()[0].outcome(),
            SuppliedSessionResourceOutcome::HealthUnqualified
        );
        let lifecycle = audit.cookie_lifecycle().unwrap();
        assert_eq!(lifecycle.selected_update_response_count(), 1);
        assert_eq!(lifecycle.unselected_update_response_count(), 0);
        assert_eq!(lifecycle.update_classification_failure_count(), 0);
        assert_eq!(lifecycle.initial_epoch(), 1);
        assert_eq!(lifecycle.final_epoch(), 1);
        assert_eq!(lifecycle.updates_applied(), 0);
        assert_eq!(observed[0], ("/app/session-health".to_owned(), true, false));
        assert_eq!(observed[1], ("/app/private".to_owned(), true, false));
        assert!(observed
            .iter()
            .skip(2)
            .all(|(_, has_cookie, _)| !has_cookie));
        let saved = serde_json::to_string(&audit).unwrap();
        for forbidden in [
            "COOKIE-RUNTIME-CANARY",
            "ROTATED-SECRET",
            "COOKIE-PRIVATE-BODY-MUST-NOT-BE-RETAINED",
        ] {
            assert!(!saved.contains(forbidden));
        }
    }

    #[tokio::test]
    async fn unselected_cookie_update_does_not_mutate_or_stop_the_session() {
        let (audit, observed) =
            run_cookie_update_fixture("Set-Cookie: analytics=OPAQUE; Path=/\r\n", "/app/private")
                .await;
        assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::Complete);
        assert_eq!(audit.coverage(), SuppliedSessionCoverage::Complete);
        assert_eq!(audit.dispatched_request_count(), 3);
        assert_eq!(audit.checkpoints().len(), 2);
        assert_eq!(audit.committed_resource_count(), 1);
        let lifecycle = audit.cookie_lifecycle().unwrap();
        assert_eq!(lifecycle.selected_update_response_count(), 0);
        assert_eq!(lifecycle.unselected_update_response_count(), 1);
        assert_eq!(lifecycle.update_classification_failure_count(), 0);
        assert_eq!(lifecycle.updates_applied(), 0);
        assert_eq!(
            &observed[..3],
            &[
                ("/app/session-health".to_owned(), true, false),
                ("/app/private".to_owned(), true, false),
                ("/app/session-health".to_owned(), true, false),
            ]
        );
    }

    #[tokio::test]
    async fn selected_startup_cookie_update_stops_before_any_resource() {
        let (audit, observed) = run_cookie_update_fixture(
            "Set-Cookie: session=ROTATED-AT-STARTUP; Path=/app/\r\n",
            "/app/session-health",
        )
        .await;
        assert_eq!(
            audit.outcome(),
            SuppliedSessionAuditOutcome::CredentialUpdateRequired
        );
        assert_eq!(audit.coverage(), SuppliedSessionCoverage::None);
        assert_eq!(audit.dispatched_request_count(), 1);
        assert_eq!(audit.dispatched_resource_count(), 0);
        assert_eq!(audit.committed_resource_count(), 0);
        assert_eq!(audit.checkpoints().len(), 1);
        assert!(audit
            .resources()
            .iter()
            .all(|resource| resource.outcome() == SuppliedSessionResourceOutcome::NotDispatched));
        let lifecycle = audit.cookie_lifecycle().unwrap();
        assert_eq!(lifecycle.selected_update_response_count(), 1);
        assert_eq!(lifecycle.update_classification_failure_count(), 0);
        assert_eq!(lifecycle.updates_applied(), 0);
        assert_eq!(observed[0], ("/app/session-health".to_owned(), true, false));
        assert!(observed
            .iter()
            .skip(1)
            .all(|(_, has_cookie, has_authorization)| !has_cookie && !has_authorization));
        assert!(observed.iter().any(|(path, _, _)| path == "/app/"));
        assert!(!serde_json::to_string(&audit)
            .unwrap()
            .contains("ROTATED-AT-STARTUP"));
    }

    #[tokio::test]
    async fn unusable_cookie_update_stops_without_guessing_selected_names() {
        let (audit, observed) = run_cookie_update_fixture(
            "Set-Cookie: bad name=UNUSABLE-COOKIE-CANARY; Path=/app/\r\n",
            "/app/private",
        )
        .await;
        assert_eq!(
            audit.outcome(),
            SuppliedSessionAuditOutcome::CredentialUpdateUnusable
        );
        assert_eq!(audit.coverage(), SuppliedSessionCoverage::None);
        assert_eq!(audit.dispatched_request_count(), 2);
        assert_eq!(audit.dispatched_resource_count(), 1);
        assert_eq!(audit.committed_resource_count(), 0);
        assert_eq!(
            audit.resources()[0].outcome(),
            SuppliedSessionResourceOutcome::HealthUnqualified
        );
        let lifecycle = audit.cookie_lifecycle().unwrap();
        assert_eq!(lifecycle.selected_update_response_count(), 0);
        assert_eq!(lifecycle.unselected_update_response_count(), 0);
        assert_eq!(lifecycle.update_classification_failure_count(), 1);
        assert_eq!(lifecycle.updates_applied(), 0);
        assert_eq!(
            &observed[..2],
            &[
                ("/app/session-health".to_owned(), true, false),
                ("/app/private".to_owned(), true, false),
            ]
        );
        assert!(!serde_json::to_string(&audit)
            .unwrap()
            .contains("UNUSABLE-COOKIE-CANARY"));
    }

    #[tokio::test]
    async fn unhealthy_post_resource_checkpoint_prevents_authenticated_coverage() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let observed = Arc::new(Mutex::new(Vec::<(String, bool)>::new()));
        let health_count = Arc::new(Mutex::new(0_u8));
        let server_observed = observed.clone();
        let server_health_count = health_count.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n")
                        || request.len() > 16 * 1024
                    {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let path = text
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("")
                    .to_owned();
                let authorized = text.lines().any(|line| {
                    line.eq_ignore_ascii_case("authorization: Bearer HEALTH-LOSS-CANARY")
                });
                server_observed
                    .lock()
                    .await
                    .push((path.clone(), authorized));
                let (media_type, body) = match path.as_str() {
                    "/app/session-health" => {
                        let mut count = server_health_count.lock().await;
                        *count = count.saturating_add(1);
                        if *count == 1 {
                            ("application/json", r#"{"authenticated":true}"#)
                        } else {
                            ("application/json", r#"{"authenticated":false}"#)
                        }
                    },
                    "/app/private" => (
                        "text/html",
                        "<form>LOGIN-PAGE-BODY-MUST-NOT-BE-RETAINED</form>",
                    ),
                    _ => ("text/html", "<!doctype html><title>public root</title>"),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {media_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        let application = url::Url::parse(&format!("http://{address}/app/")).unwrap();
        let mut runtime = WebAssessmentRuntimeBuilder::new(application.clone())
            .with_supplied_session_review(
                policy(&application),
                SuppliedSessionAuthorization::new("Bearer HEALTH-LOSS-CANARY").unwrap(),
            )
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();
        let audit = report.supplied_session_audit().unwrap();
        assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::SessionLost);
        assert_eq!(audit.coverage(), SuppliedSessionCoverage::None);
        assert_eq!(audit.selected_resource_count(), 1);
        assert_eq!(audit.dispatched_resource_count(), 1);
        assert_eq!(audit.committed_resource_count(), 0);
        assert_eq!(audit.dispatched_request_count(), 3);
        assert_eq!(audit.checkpoints().len(), 2);
        assert_eq!(
            audit.checkpoints()[0].outcome(),
            SuppliedSessionHealthOutcome::Healthy
        );
        assert_eq!(
            audit.checkpoints()[1].outcome(),
            SuppliedSessionHealthOutcome::Unhealthy
        );
        assert_eq!(audit.resources().len(), 1);
        assert_eq!(
            audit.resources()[0].outcome(),
            SuppliedSessionResourceOutcome::HealthUnqualified
        );
        assert_eq!(audit.resources()[0].status(), Some(200));
        let evidence_reference = audit.resources()[0]
            .evidence_reference()
            .expect("observed but health-unqualified response keeps a value-safe receipt");
        let evidence_id = EvidenceId::parse(evidence_reference).unwrap();
        assert_eq!(
            runtime
                .knowledge()
                .inspect_evidence(&evidence_id, |evidence| {
                    evidence.kind() == &EvidenceKind::Authentication
                        && evidence.predicate().namespace() == RESOURCE_COMMIT_EVIDENCE_NAMESPACE
                        && evidence.predicate().name()
                            == RESOURCE_HEALTH_UNQUALIFIED_EVIDENCE_PREDICATE
                }),
            Some(true)
        );
        let saved = serde_json::to_string(audit).unwrap();
        for forbidden in [
            "HEALTH-LOSS-CANARY",
            "LOGIN-PAGE-BODY-MUST-NOT-BE-RETAINED",
            "/app/private",
        ] {
            assert!(!saved.contains(forbidden));
        }

        let observed = observed.lock().await.clone();
        assert_eq!(
            &observed[..3],
            &[
                ("/app/session-health".to_owned(), true),
                ("/app/private".to_owned(), true),
                ("/app/session-health".to_owned(), true),
            ]
        );
        server.abort();
    }

    #[tokio::test]
    async fn hostile_resource_redirect_is_not_followed_or_committed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let observed = Arc::new(Mutex::new(Vec::<String>::new()));
        let server_observed = observed.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n")
                        || request.len() > 16 * 1024
                    {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let path = text
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap_or("")
                    .to_owned();
                server_observed.lock().await.push(path.clone());
                let response = match path.as_str() {
                    "/app/session-health" => concat!(
                        "HTTP/1.1 200 OK\r\n",
                        "Content-Type: application/json\r\n",
                        "Content-Length: 22\r\n",
                        "Connection: close\r\n\r\n",
                        "{\"authenticated\":true}"
                    )
                    .to_owned(),
                    "/app/private" => concat!(
                        "HTTP/1.1 302 Found\r\n",
                        "Location: /app/redirect-sink\r\n",
                        "Content-Length: 0\r\n",
                        "Connection: close\r\n\r\n"
                    )
                    .to_owned(),
                    "/app/redirect-sink" => concat!(
                        "HTTP/1.1 200 OK\r\n",
                        "Content-Type: text/html\r\n",
                        "Content-Length: 21\r\n",
                        "Connection: close\r\n\r\n",
                        "REDIRECT-WAS-FOLLOWED"
                    )
                    .to_owned(),
                    _ => concat!(
                        "HTTP/1.1 200 OK\r\n",
                        "Content-Type: text/html\r\n",
                        "Content-Length: 19\r\n",
                        "Connection: close\r\n\r\n",
                        "<title>root</title>"
                    )
                    .to_owned(),
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        let application = url::Url::parse(&format!("http://{address}/app/")).unwrap();
        let mut runtime = WebAssessmentRuntimeBuilder::new(application.clone())
            .with_supplied_session_review(
                policy(&application),
                SuppliedSessionAuthorization::new("Bearer REDIRECT-TEST-CANARY").unwrap(),
            )
            .build()
            .unwrap();
        let report = runtime.analyze().await.unwrap();
        let audit = report.supplied_session_audit().unwrap();
        assert_eq!(
            audit.outcome(),
            SuppliedSessionAuditOutcome::ResourceUnavailable
        );
        assert_eq!(audit.coverage(), SuppliedSessionCoverage::None);
        assert_eq!(audit.dispatched_request_count(), 2);
        assert_eq!(audit.checkpoints().len(), 1);
        assert_eq!(audit.resources().len(), 1);
        assert_eq!(
            audit.resources()[0].outcome(),
            SuppliedSessionResourceOutcome::RedirectRefused
        );
        assert_eq!(audit.resources()[0].status(), Some(302));
        assert_eq!(audit.resources()[0].evidence_reference(), None);

        let observed = observed.lock().await.clone();
        assert!(observed.iter().any(|path| path == "/app/private"));
        assert!(
            observed.iter().all(|path| path != "/app/redirect-sink"),
            "the session client must never follow even a same-origin Location"
        );
        server.abort();
    }

    #[tokio::test]
    async fn pre_cancelled_parent_dispatches_nothing_and_commits_no_session_evidence() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let application = url::Url::parse(&format!("http://{address}/app/")).unwrap();
        let cancellation = tokio_util::sync::CancellationToken::new();
        cancellation.cancel();
        let mut runtime = WebAssessmentRuntimeBuilder::new(application.clone())
            .cancellation_token(cancellation)
            .with_supplied_session_review(
                policy(&application),
                SuppliedSessionAuthorization::new("Bearer CANCELLED-TEST-CANARY").unwrap(),
            )
            .build()
            .unwrap();

        let report = runtime.analyze().await.unwrap();
        let audit = report.supplied_session_audit().unwrap();
        assert_eq!(audit.outcome(), SuppliedSessionAuditOutcome::Cancelled);
        assert_eq!(audit.coverage(), SuppliedSessionCoverage::None);
        assert_eq!(audit.dispatched_request_count(), 0);
        assert_eq!(audit.dispatched_resource_count(), 0);
        assert_eq!(audit.committed_resource_count(), 0);
        assert_eq!(audit.response_bytes(), 0);
        assert!(audit.checkpoints().is_empty());
        assert_eq!(audit.resources().len(), 1);
        assert_eq!(
            audit.resources()[0].outcome(),
            SuppliedSessionResourceOutcome::NotDispatched
        );
        assert_eq!(audit.resources()[0].evidence_reference(), None);
        assert_eq!(runtime.knowledge().stats().evidence, 0);
        assert_eq!(report.usage().total_requests(), 0);
        assert!(report.transport().is_empty());

        let no_connection =
            tokio::time::timeout(Duration::from_millis(50), listener.accept()).await;
        assert!(
            no_connection.is_err(),
            "pre-cancelled authority must not open a socket"
        );
    }
}
