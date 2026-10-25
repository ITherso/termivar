//! One explicitly selected refresh phase of the existing supplied-session run.
//! Returned token inequality is not proof of provider replay detection.

use std::time::Duration;

use serde::Serialize;
use termivar_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    KnowledgePredicate,
};

use super::{
    oauth_code::CommittedOAuthCodeReceipt, DispatchBudget, RuntimeExecution,
    SharedWebRuntimeAuthority, SuppliedSessionAuditOutcome, SuppliedSessionBodyState,
    SuppliedSessionCredential, SuppliedSessionHealthCheckpointPhase, SuppliedSessionHealthOutcome,
    SuppliedSessionPolicy, SuppliedSessionPolicyVersion, SuppliedSessionPredicateOutcome,
    SuppliedSessionResourceOutcome, WebAssessmentSuppliedSessionCheckpointAudit,
    WebAssessmentSuppliedSessionResourceAudit, RESOURCE_COMMIT_EVIDENCE_NAMESPACE,
};
use crate::{
    http_evidence::{OAuthCodeRequestBroker, OAuthCodeRequestError, OAuthRefreshRequestDescriptor},
    knowledge::KnowledgeAuthority,
    supplied_session_review::oauth_refresh::{
        parse_renewable_token_response, OAuthRefreshFormBody, OAuthRefreshToken,
    },
    DecisionExecutionLimits, KnowledgeBase,
};

const REFRESH_PREDICATE: &str = "oauth-refresh-credential-committed";
const REFRESH_DOMAIN: &[u8] = b"security.supplied-session-oauth-refresh-evidence.v1\0";
const REFRESH_PREFIX: &str = "supplied-session-oauth-refresh-evidence-sha256";

#[cfg(test)]
#[path = "oauth_refresh_tests.rs"]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionOAuthRefreshOutcome {
    NotReached,
    Cancelled,
    RuntimeLimit,
    ContextUnavailable,
    TransportFailed,
    Throttled,
    ResponseRejected,
    CommitFailed,
    CredentialCommitted,
}

impl SuppliedSessionOAuthRefreshOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotReached => "not_reached",
            Self::Cancelled => "cancelled",
            Self::RuntimeLimit => "runtime_limit",
            Self::ContextUnavailable => "context_unavailable",
            Self::TransportFailed => "transport_failed",
            Self::Throttled => "throttled",
            Self::ResponseRejected => "response_rejected",
            Self::CommitFailed => "commit_failed",
            Self::CredentialCommitted => "credential_committed",
        }
    }
}

/// Value-free renewal facts; neither saved state nor this audit mints a permit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuppliedSessionOAuthRefreshAudit {
    profile: &'static str,
    idp_reference: String,
    refresh_policy_reference: String,
    after_resource_count: u8,
    max_attempts: u8,
    token_interpretation: &'static str,
    rotation_assurance: &'static str,
    server_replay_detection_established: bool,
    initial_epoch: u8,
    final_epoch: u8,
    request_attempt_count: u8,
    request_admitted_count: u8,
    response_completed_count: u8,
    credential_commit_count: u8,
    status: Option<u16>,
    body_state: SuppliedSessionBodyState,
    response_bytes: u64,
    configured_token_response_byte_limit: u64,
    token_response_validated: bool,
    response_scope_matched: Option<bool>,
    declared_token_lifetime_seconds: Option<u64>,
    replacement_refresh_token_received: Option<bool>,
    replacement_value_differs: Option<bool>,
    prior_credential_evidence_reference: Option<String>,
    boundary_resource_evidence_reference: Option<String>,
    boundary_health_evidence_reference: Option<String>,
    evidence_reference: Option<String>,
    health: Option<Box<WebAssessmentSuppliedSessionCheckpointAudit>>,
    outcome: SuppliedSessionOAuthRefreshOutcome,
}

impl SuppliedSessionOAuthRefreshAudit {
    pub(super) fn selected(policy: &SuppliedSessionPolicy) -> Option<Self> {
        if policy.version() != SuppliedSessionPolicyVersion::V6 {
            return None;
        }
        let code = policy.oauth_code_policy()?;
        let refresh = policy.oauth_refresh_policy()?;
        Some(Self {
            profile: refresh.profile(),
            idp_reference: code.binding_reference().to_owned(),
            refresh_policy_reference: refresh.binding_reference().to_owned(),
            after_resource_count: refresh.after_resource_count(),
            max_attempts: refresh.max_attempts(),
            token_interpretation: "opaque_bearer_not_oidc_identity",
            rotation_assurance: "replacement_value_observed_not_server_revocation",
            server_replay_detection_established: false,
            initial_epoch: 1,
            final_epoch: 1,
            request_attempt_count: 0,
            request_admitted_count: 0,
            response_completed_count: 0,
            credential_commit_count: 0,
            status: None,
            body_state: SuppliedSessionBodyState::Unavailable,
            response_bytes: 0,
            configured_token_response_byte_limit: u64::try_from(code.max_token_response_bytes())
                .ok()?,
            token_response_validated: false,
            response_scope_matched: None,
            declared_token_lifetime_seconds: None,
            replacement_refresh_token_received: None,
            replacement_value_differs: None,
            prior_credential_evidence_reference: None,
            boundary_resource_evidence_reference: None,
            boundary_health_evidence_reference: None,
            evidence_reference: None,
            health: None,
            outcome: SuppliedSessionOAuthRefreshOutcome::NotReached,
        })
    }

    pub const fn outcome(&self) -> SuppliedSessionOAuthRefreshOutcome {
        self.outcome
    }
    pub fn refresh_policy_reference(&self) -> &str {
        &self.refresh_policy_reference
    }
    pub const fn initial_epoch(&self) -> u8 {
        self.initial_epoch
    }
    pub const fn final_epoch(&self) -> u8 {
        self.final_epoch
    }
    pub const fn request_attempt_count(&self) -> u8 {
        self.request_attempt_count
    }
    pub const fn response_completed_count(&self) -> u8 {
        self.response_completed_count
    }
    pub const fn replacement_refresh_token_received(&self) -> Option<bool> {
        self.replacement_refresh_token_received
    }
    pub const fn replacement_value_differs(&self) -> Option<bool> {
        self.replacement_value_differs
    }
    pub const fn request_admitted_count(&self) -> u8 {
        self.request_admitted_count
    }
    pub const fn credential_commit_count(&self) -> u8 {
        self.credential_commit_count
    }
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }
    pub fn health(&self) -> Option<&WebAssessmentSuppliedSessionCheckpointAudit> {
        self.health.as_deref()
    }
    pub(super) fn set_health(&mut self, health: WebAssessmentSuppliedSessionCheckpointAudit) {
        self.health = Some(Box::new(health));
    }
    pub(super) fn context_unavailable(&mut self) {
        self.outcome = SuppliedSessionOAuthRefreshOutcome::ContextUnavailable;
    }

    /// Links the typed child to this completed runtime audit. This validation
    /// neither creates a receipt nor imports saved data into runtime authority.
    pub(crate) fn is_consistent_for(
        &self,
        audit: &super::WebAssessmentSuppliedSessionAudit,
    ) -> bool {
        let Some(code) = audit.oauth_code() else {
            return false;
        };
        if !self.is_consistent()
            || audit.schema() != super::SUPPLIED_SESSION_OAUTH_REFRESH_AUDIT_SCHEMA
            || audit.selected_resource_count() != 2
            || audit.resources().len() != 2
            || audit.checkpoints().len() > 3
            || self.idp_reference != code.idp_reference()
            || self.configured_token_response_byte_limit
                != code.configured_token_response_byte_limit()
            || audit.refresh_performed() != (self.credential_commit_count == 1)
            || audit.checkpoints().iter().enumerate().any(|(index, row)| {
                row.epoch()
                    != if self.final_epoch == 2 && index == 2 {
                        2
                    } else {
                        1
                    }
            })
            || audit.resources().iter().enumerate().any(|(index, row)| {
                row.epoch()
                    != if self.final_epoch == 2 && index == 1 {
                        2
                    } else {
                        1
                    }
            })
        {
            return false;
        }
        if code.credential_commit_count() == 0 {
            return self.outcome == SuppliedSessionOAuthRefreshOutcome::NotReached;
        }
        let first = &audit.resources()[0];
        let second = &audit.resources()[1];
        if self.outcome != SuppliedSessionOAuthRefreshOutcome::NotReached
            && (first.outcome() != SuppliedSessionResourceOutcome::Committed
                || audit
                    .checkpoints()
                    .get(1)
                    .is_none_or(|health| health.outcome() != SuppliedSessionHealthOutcome::Healthy))
        {
            return false;
        }
        if self.request_attempt_count == 1
            && (self.prior_credential_evidence_reference.as_deref() != code.evidence_reference()
                || self.boundary_resource_evidence_reference.as_deref()
                    != first.evidence_reference()
                || self.boundary_health_evidence_reference.as_deref()
                    != audit
                        .checkpoints()
                        .get(1)
                        .and_then(|row| row.evidence_reference()))
        {
            return false;
        }
        if self.credential_commit_count == 0
            && (second.outcome() != SuppliedSessionResourceOutcome::NotDispatched
                || audit.checkpoints().len() > 2)
        {
            return false;
        }
        let renewed_health = self.health().map(|health| health.outcome());
        if second.outcome() != SuppliedSessionResourceOutcome::NotDispatched
            && renewed_health != Some(SuppliedSessionHealthOutcome::Healthy)
        {
            return false;
        }
        match self.outcome {
            SuppliedSessionOAuthRefreshOutcome::NotReached => !matches!(
                audit.outcome(),
                SuppliedSessionAuditOutcome::Complete
                    | SuppliedSessionAuditOutcome::OAuthRefreshUnavailable
            ),
            SuppliedSessionOAuthRefreshOutcome::Cancelled => {
                audit.outcome() == SuppliedSessionAuditOutcome::Cancelled
            },
            SuppliedSessionOAuthRefreshOutcome::RuntimeLimit => {
                audit.outcome() == SuppliedSessionAuditOutcome::RuntimeLimit
            },
            SuppliedSessionOAuthRefreshOutcome::CredentialCommitted => {
                if renewed_health == Some(SuppliedSessionHealthOutcome::Unhealthy) {
                    audit.outcome() == SuppliedSessionAuditOutcome::SessionLost
                } else if renewed_health != Some(SuppliedSessionHealthOutcome::Healthy) {
                    matches!(
                        audit.outcome(),
                        SuppliedSessionAuditOutcome::RuntimeLimit
                            | SuppliedSessionAuditOutcome::Cancelled
                            | SuppliedSessionAuditOutcome::ResourceUnavailable
                    )
                } else {
                    !matches!(
                        audit.outcome(),
                        SuppliedSessionAuditOutcome::OAuthRefreshUnavailable
                            | SuppliedSessionAuditOutcome::OAuthCodeExchangeUnavailable
                    )
                }
            },
            _ => audit.outcome() == SuppliedSessionAuditOutcome::OAuthRefreshUnavailable,
        }
    }

    pub(crate) fn is_consistent(&self) -> bool {
        let reference = |value: &str, prefix: &str| {
            value.strip_prefix(prefix).is_some_and(|tail| {
                tail.len() == 64
                    && tail
                        .bytes()
                        .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
            })
        };
        let complete = self.body_state == SuppliedSessionBodyState::Complete;
        let response_present = self.body_state != SuppliedSessionBodyState::Unavailable;
        let parsed = self.response_scope_matched == Some(true)
            && self
                .declared_token_lifetime_seconds
                .is_some_and(|n| (1..=3600).contains(&n))
            && self.replacement_refresh_token_received == Some(true)
            && self.replacement_value_differs == Some(true);
        let bound = self
            .prior_credential_evidence_reference
            .as_deref()
            .is_some_and(|r| reference(r, "supplied-session-oauth-code-evidence-sha256:"))
            && self
                .boundary_resource_evidence_reference
                .as_deref()
                .is_some_and(|r| reference(r, "supplied-session-resource-evidence-sha256:"))
            && self
                .boundary_health_evidence_reference
                .as_deref()
                .is_some_and(|r| reference(r, "supplied-session-checkpoint-evidence-sha256:"));
        if self.profile != "scheduled-public-bearer-refresh/v1"
            || !reference(&self.idp_reference, "oauth-code-policy-sha256:")
            || !reference(
                &self.refresh_policy_reference,
                "oauth-refresh-policy-sha256:",
            )
            || self.after_resource_count != 1
            || self.max_attempts != 1
            || self.token_interpretation != "opaque_bearer_not_oidc_identity"
            || self.rotation_assurance != "replacement_value_observed_not_server_revocation"
            || self.server_replay_detection_established
            || self.initial_epoch != 1
            || self.final_epoch != 1 + self.credential_commit_count
            || self.request_attempt_count > 1
            || self.request_admitted_count > self.request_attempt_count
            || self.response_completed_count > self.request_admitted_count
            || self.response_completed_count != u8::from(complete)
            || self.credential_commit_count > u8::from(self.token_response_validated)
            || self.status.is_some() != response_present
            || self
                .status
                .is_some_and(|status| !(100..=599).contains(&status))
            || (response_present || self.response_bytes > 0) && self.request_admitted_count != 1
            || !(1..=32768).contains(&self.configured_token_response_byte_limit)
            || self.token_response_validated != parsed
            || (!parsed
                && (self.response_scope_matched.is_some()
                    || self.declared_token_lifetime_seconds.is_some()
                    || self.replacement_refresh_token_received.is_some()
                    || self.replacement_value_differs.is_some()))
            || (parsed
                && (!complete
                    || self.status != Some(200)
                    || self.response_bytes == 0
                    || self.response_bytes > self.configured_token_response_byte_limit))
            || self.request_attempt_count == 1 && !bound
            || self.credential_commit_count != u8::from(self.evidence_reference.is_some())
            || self
                .evidence_reference
                .as_deref()
                .is_some_and(|r| !reference(r, "supplied-session-oauth-refresh-evidence-sha256:"))
        {
            return false;
        }
        if let Some(health) = self.health() {
            if self.credential_commit_count != 1
                || health.epoch() != 2
                || health.phase() != SuppliedSessionHealthCheckpointPhase::Renewal
                || health.sequence() != 2
                || health.after_subject_count() != 1
            {
                return false;
            }
        }
        match self.outcome {
            SuppliedSessionOAuthRefreshOutcome::NotReached => {
                self.request_attempt_count == 0
                    && self.response_bytes == 0
                    && self.status.is_none()
                    && self.prior_credential_evidence_reference.is_none()
                    && self.boundary_resource_evidence_reference.is_none()
                    && self.boundary_health_evidence_reference.is_none()
                    && self.health.is_none()
            },
            SuppliedSessionOAuthRefreshOutcome::CredentialCommitted => {
                self.credential_commit_count == 1
            },
            _ => self.credential_commit_count == 0 && self.health.is_none(),
        }
    }
}

/// Exact read-back evidence, not an audit row accepted by shape alone.
struct BoundaryEvidence {
    reference: String,
    expected: Evidence,
}

fn credential_binding(
    policy: &SuppliedSessionPolicy,
    code_reference: &str,
    resource_reference: &str,
    health_reference: &str,
    response_bytes: u64,
    lifetime: u64,
) -> Option<String> {
    let idp = policy.oauth_code_policy()?;
    let refresh = policy.oauth_refresh_policy()?;
    Some(format!(
        "policy={};application={};idp={};refresh_policy={};purpose=oauth_refresh;prior_credential={code_reference};boundary_resource={resource_reference};boundary_health={health_reference};initial_epoch=1;final_epoch=2;status=200;body_state=complete;response_bytes={response_bytes};scope=exact_supported_echo;declared_lifetime={lifetime};replacement_value_differs=true;revocation=not_established;outcome=credential_committed",
        policy.policy_reference(), policy.application_reference(), idp.binding_reference(), refresh.binding_reference()
    ))
}

impl BoundaryEvidence {
    #[allow(clippy::too_many_arguments)]
    fn read(
        policy: &SuppliedSessionPolicy,
        knowledge: &KnowledgeBase,
        reference: &str,
        domain: &[u8],
        prefix: &str,
        predicate: &str,
        method: &str,
        correlation: &str,
        binding: String,
    ) -> Option<Self> {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(binding.as_bytes());
        let expected_reference = format!("{prefix}:{:x}", digest.finalize());
        if reference != expected_reference {
            return None;
        }
        let id = EvidenceId::parse(reference).ok()?;
        // Validate the existing observation, not a new observation stamped at
        // validation time. Preserve its timestamp and direct-evidence origin
        // while independently reconstructing every authority-bearing field.
        let observed_at = knowledge.inspect_evidence(&id, Evidence::observed_at_ms)?;
        let expected = Evidence::with_id_at(
            id.clone(),
            EntityId::new(policy.application_reference().to_owned()).ok()?,
            EvidenceKind::Authentication,
            KnowledgePredicate::new(RESOURCE_COMMIT_EVIDENCE_NAMESPACE, predicate).ok()?,
            EvidenceValue::Text(binding),
            EvidenceSource::new(super::RESOURCE_COMMIT_EVIDENCE_COMPONENT, method)
                .and_then(|source| source.with_correlation_id(correlation.to_owned()))
                .ok()?,
            ConfidenceScore::MAX,
            observed_at,
        );
        (knowledge.inspect_evidence(&id, |stored| stored == &expected) == Some(true)).then_some(
            Self {
                reference: reference.to_owned(),
                expected,
            },
        )
    }
    fn remains_committed(&self, knowledge: &KnowledgeBase) -> bool {
        EvidenceId::parse(&self.reference)
            .ok()
            .and_then(|id| knowledge.inspect_evidence(&id, |stored| stored == &self.expected))
            == Some(true)
    }
}

/// Sealed borrowed authority for the ONE refresh request. All source evidence
/// is checked both here and again inside the request broker at dispatch.
pub(crate) struct OAuthRefreshDispatchPermit<'a> {
    policy: &'a SuppliedSessionPolicy,
    knowledge: &'a KnowledgeBase,
    code: &'a CommittedOAuthCodeReceipt,
    token: &'a OAuthRefreshToken,
    resource: BoundaryEvidence,
    health: BoundaryEvidence,
}

impl<'a> OAuthRefreshDispatchPermit<'a> {
    fn from_boundary(
        context: &OAuthRefreshContext<'a>,
        token: &'a OAuthRefreshToken,
    ) -> Option<Self> {
        let policy = context.policy;
        if policy.version() != SuppliedSessionPolicyVersion::V6
            || context.budget.dispatched_requests != 4
            || !token.matches_policy(policy)
            || !context
                .code
                .is_valid_for(policy, context.authority.knowledge())
            || context.resource.sequence() != 0
            || context.resource.epoch() != 1
            || context.resource.status() != Some(200)
            || context.resource.outcome() != SuppliedSessionResourceOutcome::Committed
            || context.health.sequence() != 1
            || context.health.epoch() != 1
            || context.health.phase() != SuppliedSessionHealthCheckpointPhase::SubjectBoundary
            || context.health.after_subject_count() != 1
            || context.health.status() != Some(200)
            || context.health.outcome() != SuppliedSessionHealthOutcome::Healthy
            || context.health.body_state() != SuppliedSessionBodyState::Complete
            || context.health.predicate() != SuppliedSessionPredicateOutcome::Matched
        {
            return None;
        }
        let (_, expected_resource) = policy.execution_resources().next()?;
        if context.resource.resource_reference() != expected_resource {
            return None;
        }
        let health_reference = context.health.evidence_reference()?;
        let health_binding = format!(
            "policy={};application={};health_field={};purpose=health;sequence=1;phase=subject_boundary;after_subject_count=1;target=exact;status=200;body_state=complete;predicate=matched;outcome=healthy;response_bytes={};epoch=1",
            policy.policy_reference(),policy.application_reference(),policy.health_field_reference(),
            context.health.response_bytes());
        let health = BoundaryEvidence::read(
            policy,
            context.authority.knowledge(),
            health_reference,
            super::HEALTH_COMMIT_EVIDENCE_DOMAIN,
            super::HEALTH_COMMIT_EVIDENCE_PREFIX,
            super::HEALTH_COMMIT_EVIDENCE_PREDICATE,
            "supplied-session-health/v6",
            policy.health_field_reference(),
            health_binding,
        )?;
        let resource_binding = format!(
            "policy={};application={};resource={};purpose=resource;status=200;response_bytes={};qualifying_checkpoint={};outcome=committed;epoch=1",
            policy.policy_reference(),policy.application_reference(),expected_resource,
            context.resource.response_bytes(),health_reference);
        let resource = BoundaryEvidence::read(
            policy,
            context.authority.knowledge(),
            context.resource.evidence_reference()?,
            super::RESOURCE_COMMIT_EVIDENCE_DOMAIN,
            super::RESOURCE_COMMIT_EVIDENCE_PREFIX,
            super::RESOURCE_COMMIT_EVIDENCE_PREDICATE,
            "supplied-session-resource/v6",
            expected_resource,
            resource_binding,
        )?;
        Some(Self {
            policy,
            knowledge: context.authority.knowledge(),
            code: context.code,
            token,
            resource,
            health,
        })
    }

    pub(crate) fn is_valid_for(
        &self,
        policy: &SuppliedSessionPolicy,
        mint: &crate::web_runtime::OAuthRefreshMintToken,
    ) -> bool {
        mint.is_valid_for(policy, self.knowledge)
            && policy.policy_reference() == self.policy.policy_reference()
            && self.code.is_valid_for(policy, self.knowledge)
            && self.token.matches_policy(policy)
            && self.resource.remains_committed(self.knowledge)
            && self.health.remains_committed(self.knowledge)
    }

    pub(crate) fn compose_form_body(
        &self,
        policy: &SuppliedSessionPolicy,
    ) -> Result<OAuthRefreshFormBody, crate::supplied_session_review::OAuthCodeInputError> {
        self.token.compose_form_body(policy)
    }
}

pub(super) struct CommittedOAuthRefreshReceipt {
    knowledge_authority: KnowledgeAuthority,
    policy_reference: String,
    application_reference: String,
    idp_reference: String,
    refresh_reference: String,
    principal_alias: String,
    prior_credential_reference: String,
    resource: BoundaryEvidence,
    health: BoundaryEvidence,
    evidence_reference: String,
    expected_evidence: Evidence,
    response_bytes: u64,
    declared_lifetime_seconds: u64,
}

impl CommittedOAuthRefreshReceipt {
    pub(super) fn is_valid_for(
        &self,
        policy: &SuppliedSessionPolicy,
        code: &CommittedOAuthCodeReceipt,
        knowledge: &KnowledgeBase,
    ) -> bool {
        let Some(binding) = credential_binding(
            policy,
            &self.prior_credential_reference,
            &self.resource.reference,
            &self.health.reference,
            self.response_bytes,
            self.declared_lifetime_seconds,
        ) else {
            return false;
        };
        self.knowledge_authority.is_same_as(knowledge.authority())
            && policy.version() == SuppliedSessionPolicyVersion::V6
            && policy.policy_reference() == self.policy_reference
            && policy.application_reference() == self.application_reference
            && policy.principal_alias() == self.principal_alias
            && policy
                .oauth_code_policy()
                .is_some_and(|idp| idp.binding_reference() == self.idp_reference)
            && policy
                .oauth_refresh_policy()
                .is_some_and(|refresh| refresh.binding_reference() == self.refresh_reference)
            && code.is_valid_for(policy, knowledge)
            && code.evidence_reference() == self.prior_credential_reference
            && self.resource.remains_committed(knowledge)
            && self.health.remains_committed(knowledge)
            && (1..=32768).contains(&self.response_bytes)
            && (1..=3600).contains(&self.declared_lifetime_seconds)
            && BoundaryEvidence::read(
                policy,
                knowledge,
                &self.evidence_reference,
                REFRESH_DOMAIN,
                REFRESH_PREFIX,
                REFRESH_PREDICATE,
                "descriptor-bound-scheduled-oauth-refresh",
                &self.refresh_reference,
                binding,
            )
            .is_some_and(|expected| expected.expected == self.expected_evidence)
    }
}

pub(super) struct AcquiredOAuthRefreshCredential {
    pub(super) credential: SuppliedSessionCredential,
    pub(super) receipt: CommittedOAuthRefreshReceipt,
    pub(super) declared_lifetime: Duration,
}

pub(super) struct OAuthRefreshContext<'a> {
    pub(super) authority: &'a SharedWebRuntimeAuthority,
    pub(super) requests: &'a OAuthCodeRequestBroker,
    pub(super) descriptor: &'a OAuthRefreshRequestDescriptor,
    pub(super) policy: &'a SuppliedSessionPolicy,
    pub(super) code: &'a CommittedOAuthCodeReceipt,
    pub(super) resource: &'a WebAssessmentSuppliedSessionResourceAudit,
    pub(super) health: &'a WebAssessmentSuppliedSessionCheckpointAudit,
    pub(super) deadline: Option<tokio::time::Instant>,
    pub(super) budget: DispatchBudget,
}

pub(super) async fn execute_refresh<'a>(
    context: OAuthRefreshContext<'a>,
    token: &'a OAuthRefreshToken,
) -> (
    SuppliedSessionOAuthRefreshAudit,
    Result<AcquiredOAuthRefreshCredential, SuppliedSessionAuditOutcome>,
) {
    let mut audit = SuppliedSessionOAuthRefreshAudit::selected(context.policy)
        .expect("only explicit V6 reaches refresh");
    if context.authority.cancellation().is_cancelled() {
        audit.outcome = SuppliedSessionOAuthRefreshOutcome::Cancelled;
        return (audit, Err(SuppliedSessionAuditOutcome::Cancelled));
    }
    if context
        .deadline
        .is_some_and(|end| tokio::time::Instant::now() >= end)
        || context.budget.dispatched_requests >= context.policy.max_session_requests()
        || context.budget.accounted_response_bytes >= context.policy.max_total_response_bytes()
    {
        audit.outcome = SuppliedSessionOAuthRefreshOutcome::RuntimeLimit;
        return (audit, Err(SuppliedSessionAuditOutcome::RuntimeLimit));
    }
    let Some(permit) = OAuthRefreshDispatchPermit::from_boundary(&context, token) else {
        audit.outcome = SuppliedSessionOAuthRefreshOutcome::ContextUnavailable;
        return (
            audit,
            Err(SuppliedSessionAuditOutcome::OAuthRefreshUnavailable),
        );
    };
    audit.prior_credential_evidence_reference = Some(context.code.evidence_reference().to_owned());
    audit.boundary_resource_evidence_reference = Some(permit.resource.reference.clone());
    audit.boundary_health_evidence_reference = Some(permit.health.reference.clone());
    let remaining = context
        .policy
        .max_total_response_bytes()
        .saturating_sub(context.budget.accounted_response_bytes);
    let body_limit = remaining.min(audit.configured_token_response_byte_limit);
    let before = context.authority.request_accounting().snapshot();
    audit.request_attempt_count = 1;
    let execution = super::boxed_dispatch_execution(|| {
        context.requests.collect_refresh(
            context.descriptor,
            context.policy,
            &permit,
            DecisionExecutionLimits::new().with_max_response_body_bytes(body_limit),
        )
    });
    let result = super::super::await_execution(
        context.authority.cancellation(),
        context.deadline,
        execution,
    )
    .await;
    let after = context.authority.request_accounting().snapshot();
    let admitted = after
        .total_requests()
        .saturating_sub(before.total_requests());
    audit.request_admitted_count = u8::try_from(admitted).unwrap_or(u8::MAX);
    audit.response_bytes = after
        .response_bytes()
        .saturating_sub(before.response_bytes());
    if admitted > 1 {
        audit.outcome = SuppliedSessionOAuthRefreshOutcome::CommitFailed;
        return (
            audit,
            Err(SuppliedSessionAuditOutcome::OAuthRefreshUnavailable),
        );
    }
    let response = match result {
        RuntimeExecution::Completed(Ok(response)) => response,
        RuntimeExecution::Cancelled => {
            audit.outcome = SuppliedSessionOAuthRefreshOutcome::Cancelled;
            return (audit, Err(SuppliedSessionAuditOutcome::Cancelled));
        },
        RuntimeExecution::WallTimeExceeded
        | RuntimeExecution::Completed(Err(OAuthCodeRequestError::RuntimeLimit)) => {
            audit.outcome = SuppliedSessionOAuthRefreshOutcome::RuntimeLimit;
            return (audit, Err(SuppliedSessionAuditOutcome::RuntimeLimit));
        },
        RuntimeExecution::Completed(Err(OAuthCodeRequestError::Http)) => {
            audit.outcome = SuppliedSessionOAuthRefreshOutcome::TransportFailed;
            return (
                audit,
                Err(SuppliedSessionAuditOutcome::OAuthRefreshUnavailable),
            );
        },
        RuntimeExecution::Completed(Err(_)) => {
            audit.outcome = SuppliedSessionOAuthRefreshOutcome::ContextUnavailable;
            return (
                audit,
                Err(SuppliedSessionAuditOutcome::OAuthRefreshUnavailable),
            );
        },
    };
    audit.status = Some(response.status);
    audit.body_state = if response.complete {
        SuppliedSessionBodyState::Complete
    } else {
        SuppliedSessionBodyState::Incomplete
    };
    audit.response_completed_count = u8::from(response.complete);
    if audit.response_bytes > body_limit {
        audit.outcome = SuppliedSessionOAuthRefreshOutcome::RuntimeLimit;
        return (audit, Err(SuppliedSessionAuditOutcome::RuntimeLimit));
    }
    if response.status == 429 {
        audit.outcome = SuppliedSessionOAuthRefreshOutcome::Throttled;
        return (
            audit,
            Err(SuppliedSessionAuditOutcome::OAuthRefreshUnavailable),
        );
    }
    if admitted != 1
        || response.status != 200
        || !response.complete
        || !response.representation_supported
    {
        audit.outcome = SuppliedSessionOAuthRefreshOutcome::ResponseRejected;
        return (
            audit,
            Err(SuppliedSessionAuditOutcome::OAuthRefreshUnavailable),
        );
    }
    let parsed = match parse_renewable_token_response(context.policy, response.body, Some(token)) {
        Ok(parsed) => parsed,
        Err(_) => {
            audit.outcome = SuppliedSessionOAuthRefreshOutcome::ResponseRejected;
            return (
                audit,
                Err(SuppliedSessionAuditOutcome::OAuthRefreshUnavailable),
            );
        },
    };
    let lifetime = parsed.expires_in_seconds();
    let differs = parsed.replacement_value_differs();
    let (authorization, replacement_refresh) = match parsed.into_parts() {
        Ok(parts) => parts,
        Err(_) => {
            audit.outcome = SuppliedSessionOAuthRefreshOutcome::ResponseRejected;
            return (
                audit,
                Err(SuppliedSessionAuditOutcome::OAuthRefreshUnavailable),
            );
        },
    };
    // No second renewal is authorized. Do not retain its unused secret.
    drop(replacement_refresh);
    audit.token_response_validated = true;
    audit.response_scope_matched = Some(true);
    audit.declared_token_lifetime_seconds = Some(lifetime);
    audit.replacement_refresh_token_received = Some(true);
    audit.replacement_value_differs = differs;
    let idp = context
        .policy
        .oauth_code_policy()
        .expect("validated IdP binding");
    let refresh = context
        .policy
        .oauth_refresh_policy()
        .expect("validated refresh binding");
    let binding = credential_binding(
        context.policy,
        context.code.evidence_reference(),
        &permit.resource.reference,
        &permit.health.reference,
        audit.response_bytes,
        lifetime,
    )
    .expect("validated refresh binding");
    let receipt = super::commit_value_safe_evidence(
        context.policy,
        refresh.binding_reference(),
        REFRESH_DOMAIN,
        REFRESH_PREFIX,
        REFRESH_PREDICATE,
        "descriptor-bound-scheduled-oauth-refresh",
        binding,
        context.authority.knowledge(),
    )
    .and_then(|reference| {
        let id = EvidenceId::parse(&reference).ok()?;
        let expected_evidence = context
            .authority
            .knowledge()
            .inspect_evidence(&id, Clone::clone)?;
        let receipt = CommittedOAuthRefreshReceipt {
            knowledge_authority: context.authority.knowledge().authority().clone(),
            policy_reference: context.policy.policy_reference().to_owned(),
            application_reference: context.policy.application_reference().to_owned(),
            idp_reference: idp.binding_reference().to_owned(),
            refresh_reference: refresh.binding_reference().to_owned(),
            principal_alias: context.policy.principal_alias().to_owned(),
            prior_credential_reference: context.code.evidence_reference().to_owned(),
            resource: permit.resource,
            health: permit.health,
            evidence_reference: reference,
            expected_evidence,
            response_bytes: audit.response_bytes,
            declared_lifetime_seconds: lifetime,
        };
        receipt
            .is_valid_for(context.policy, context.code, context.authority.knowledge())
            .then_some(receipt)
    });
    let Some(receipt) = receipt else {
        audit.outcome = SuppliedSessionOAuthRefreshOutcome::CommitFailed;
        return (
            audit,
            Err(SuppliedSessionAuditOutcome::OAuthRefreshUnavailable),
        );
    };
    audit.evidence_reference = Some(receipt.evidence_reference.clone());
    audit.credential_commit_count = 1;
    audit.final_epoch = 2;
    audit.outcome = SuppliedSessionOAuthRefreshOutcome::CredentialCommitted;
    (
        audit,
        Ok(AcquiredOAuthRefreshCredential {
            credential: SuppliedSessionCredential::Authorization(authorization),
            receipt,
            declared_lifetime: Duration::from_secs(lifetime),
        }),
    )
}
