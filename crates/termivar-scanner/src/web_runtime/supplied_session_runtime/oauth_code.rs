//! Private imported-code acquisition, before the existing Bearer health loop.
//!
//! The external authorization, its S256 selection and user-agent binding are
//! operator assertions. A successful redemption is not OIDC identity validation
//! or proof that this client initiated/secured the front-channel transaction.

use std::time::Duration;

use serde::Serialize;
use termivar_core::{Evidence, EvidenceId, EvidenceKind};

use super::{
    commit_value_safe_evidence, DispatchBudget, RuntimeExecution, SharedWebRuntimeAuthority,
    SuppliedSessionAuditOutcome, SuppliedSessionBodyState, SuppliedSessionCredential,
    SuppliedSessionPolicy, SuppliedSessionPolicyVersion, RESOURCE_COMMIT_EVIDENCE_NAMESPACE,
};
use crate::{
    http_evidence::{OAuthCodeRequestBroker, OAuthCodeRequestDescriptor, OAuthCodeRequestError},
    supplied_session_review::{oauth_code::parse_token_response, SuppliedSessionOAuthGrant},
    DecisionExecutionLimits, KnowledgeBase,
};

#[cfg(test)]
#[path = "oauth_code_tests.rs"]
pub(super) mod tests;

const ACQUISITION_PREDICATE: &str = "oauth-code-credential-acquisition-committed";

/// Closed result of the single selected IdP operation, separate from health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SuppliedSessionOAuthCodeOutcome {
    NotDispatched,
    Cancelled,
    RuntimeLimit,
    GrantUnavailable,
    TransportFailed,
    Throttled,
    ResponseRejected,
    CommitFailed,
    CredentialCommitted,
}

impl SuppliedSessionOAuthCodeOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotDispatched => "not_dispatched",
            Self::Cancelled => "cancelled",
            Self::RuntimeLimit => "runtime_limit",
            Self::GrantUnavailable => "grant_unavailable",
            Self::TransportFailed => "transport_failed",
            Self::Throttled => "throttled",
            Self::ResponseRejected => "response_rejected",
            Self::CommitFailed => "commit_failed",
            Self::CredentialCommitted => "credential_committed",
        }
    }
}

/// Value-free V5 acquisition facts. It is not an executable IdP permit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuppliedSessionOAuthCodeAudit {
    profile: &'static str,
    transport_profile: String,
    idp_reference: String,
    transaction_context_assurance: &'static str,
    pkce_assurance: &'static str,
    token_interpretation: &'static str,
    authorization_initiated: bool,
    browser_callback_received: bool,
    state_nonce_verified: bool,
    oidc_identity_validation_performed: bool,
    token_signature_validation_performed: bool,
    request_attempt_count: u8,
    request_admitted_count: u8,
    response_completed_count: u8,
    credential_commit_count: u8,
    verifier_in_admitted_request: bool,
    status: Option<u16>,
    body_state: SuppliedSessionBodyState,
    response_bytes: u64,
    configured_token_response_byte_limit: u64,
    token_response_validated: bool,
    response_scope_matched: Option<bool>,
    declared_token_lifetime_seconds: Option<u64>,
    refresh_token_returned: Option<bool>,
    evidence_reference: Option<String>,
    outcome: SuppliedSessionOAuthCodeOutcome,
}

impl SuppliedSessionOAuthCodeAudit {
    pub(super) fn selected(policy: &SuppliedSessionPolicy) -> Option<Self> {
        let idp = policy.oauth_code_policy()?;
        Some(Self {
            profile: "external-public-code-s256-bearer/v1",
            transport_profile: idp.transport_profile().to_owned(),
            idp_reference: idp.binding_reference().to_owned(),
            transaction_context_assurance: "operator_declared_external_transaction",
            pkce_assurance: "imported_s256_context_not_remote_enforcement",
            token_interpretation: "opaque_bearer_not_oidc_identity",
            authorization_initiated: false,
            browser_callback_received: false,
            state_nonce_verified: false,
            oidc_identity_validation_performed: false,
            token_signature_validation_performed: false,
            request_attempt_count: 0,
            request_admitted_count: 0,
            response_completed_count: 0,
            credential_commit_count: 0,
            verifier_in_admitted_request: false,
            status: None,
            body_state: SuppliedSessionBodyState::Unavailable,
            response_bytes: 0,
            configured_token_response_byte_limit: u64::try_from(idp.max_token_response_bytes())
                .unwrap_or(u64::MAX),
            token_response_validated: false,
            response_scope_matched: None,
            declared_token_lifetime_seconds: None,
            refresh_token_returned: None,
            evidence_reference: None,
            outcome: SuppliedSessionOAuthCodeOutcome::NotDispatched,
        })
    }

    pub fn idp_reference(&self) -> &str {
        &self.idp_reference
    }
    pub const fn outcome(&self) -> SuppliedSessionOAuthCodeOutcome {
        self.outcome
    }
    pub const fn request_attempt_count(&self) -> u8 {
        self.request_attempt_count
    }
    pub const fn request_admitted_count(&self) -> u8 {
        self.request_admitted_count
    }
    pub const fn response_completed_count(&self) -> u8 {
        self.response_completed_count
    }
    pub const fn credential_commit_count(&self) -> u8 {
        self.credential_commit_count
    }
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }
    pub const fn configured_token_response_byte_limit(&self) -> u64 {
        self.configured_token_response_byte_limit
    }
    pub const fn declared_token_lifetime_seconds(&self) -> Option<u64> {
        self.declared_token_lifetime_seconds
    }
    pub fn evidence_reference(&self) -> Option<&str> {
        self.evidence_reference.as_deref()
    }

    pub(crate) fn is_consistent(&self) -> bool {
        let digest = |value: &str, prefix: &str| {
            value.strip_prefix(prefix).is_some_and(|rest| {
                rest.len() == 64
                    && rest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
        };
        let complete = self.body_state == SuppliedSessionBodyState::Complete;
        let has_response = self.body_state != SuppliedSessionBodyState::Unavailable;
        let valid_token_facts = self
            .declared_token_lifetime_seconds
            .is_some_and(|seconds| (1..=3_600).contains(&seconds))
            && self.response_scope_matched == Some(true)
            && self.refresh_token_returned.is_some();
        if self.profile != "external-public-code-s256-bearer/v1"
            || !matches!(
                self.transport_profile.as_str(),
                "verified-https/v1" | "owned-numeric-loopback-http/v1"
            )
            || !digest(&self.idp_reference, "oauth-code-policy-sha256:")
            || self.transaction_context_assurance != "operator_declared_external_transaction"
            || self.pkce_assurance != "imported_s256_context_not_remote_enforcement"
            || self.token_interpretation != "opaque_bearer_not_oidc_identity"
            || self.authorization_initiated
            || self.browser_callback_received
            || self.state_nonce_verified
            || self.oidc_identity_validation_performed
            || self.token_signature_validation_performed
            || self.request_attempt_count > 1
            || self.request_admitted_count > self.request_attempt_count
            || self.response_completed_count > self.request_admitted_count
            || self.credential_commit_count > u8::from(self.token_response_validated)
            || self.verifier_in_admitted_request != (self.request_admitted_count == 1)
            || self.response_completed_count != u8::from(complete)
            || self.status.is_some() != has_response
            || self
                .status
                .is_some_and(|status| !(100..=599).contains(&status))
            || (has_response || self.response_bytes > 0) && self.request_admitted_count != 1
            || !(1..=32_768).contains(&self.configured_token_response_byte_limit)
            || self.token_response_validated != valid_token_facts
            || (!self.token_response_validated
                && (self.declared_token_lifetime_seconds.is_some()
                    || self.response_scope_matched.is_some()
                    || self.refresh_token_returned.is_some()))
            || self.token_response_validated
                && (!complete
                    || self.status != Some(200)
                    || self.response_bytes == 0
                    || self.response_bytes > self.configured_token_response_byte_limit)
            || (self.credential_commit_count == 1) != self.evidence_reference.is_some()
            || self.evidence_reference.as_deref().is_some_and(|reference| {
                !digest(reference, "supplied-session-oauth-code-evidence-sha256:")
            })
        {
            return false;
        }
        match self.outcome {
            SuppliedSessionOAuthCodeOutcome::NotDispatched => {
                self.request_attempt_count == 0
                    && !has_response
                    && self.response_bytes == 0
                    && !self.token_response_validated
            },
            SuppliedSessionOAuthCodeOutcome::Cancelled
            | SuppliedSessionOAuthCodeOutcome::RuntimeLimit => {
                !self.token_response_validated && self.credential_commit_count == 0
            },
            SuppliedSessionOAuthCodeOutcome::GrantUnavailable => {
                self.request_attempt_count == 1
                    && self.request_admitted_count == 0
                    && !has_response
                    && self.response_bytes == 0
            },
            SuppliedSessionOAuthCodeOutcome::TransportFailed => {
                self.request_attempt_count == 1 && !has_response && !self.token_response_validated
            },
            SuppliedSessionOAuthCodeOutcome::Throttled => {
                self.request_admitted_count == 1
                    && self.status == Some(429)
                    && !self.token_response_validated
            },
            SuppliedSessionOAuthCodeOutcome::ResponseRejected => {
                self.request_admitted_count == 1 && has_response && !self.token_response_validated
            },
            SuppliedSessionOAuthCodeOutcome::CommitFailed => {
                self.request_admitted_count == 1
                    && self.token_response_validated
                    && self.credential_commit_count == 0
            },
            SuppliedSessionOAuthCodeOutcome::CredentialCommitted => {
                self.request_admitted_count == 1
                    && self.token_response_validated
                    && self.credential_commit_count == 1
            },
        }
    }
}

/// A saved string cannot construct this health-loop qualification.
pub(super) struct CommittedOAuthCodeReceipt {
    knowledge_authority: crate::knowledge::KnowledgeAuthority,
    policy_reference: String,
    application_reference: String,
    idp_reference: String,
    evidence_reference: String,
    principal_alias: String,
    expected_evidence: Evidence,
}

impl CommittedOAuthCodeReceipt {
    pub(super) fn evidence_reference(&self) -> &str {
        &self.evidence_reference
    }

    pub(super) fn is_valid_for(
        &self,
        policy: &SuppliedSessionPolicy,
        knowledge: &KnowledgeBase,
    ) -> bool {
        self.knowledge_authority.is_same_as(knowledge.authority())
            && matches!(
                policy.version(),
                SuppliedSessionPolicyVersion::V5 | SuppliedSessionPolicyVersion::V6
            )
            && policy.policy_reference() == self.policy_reference
            && policy.application_reference() == self.application_reference
            && policy.principal_alias() == self.principal_alias
            && policy
                .oauth_code_policy()
                .is_some_and(|idp| idp.binding_reference() == self.idp_reference)
            && self.expected_evidence.kind() == &EvidenceKind::Authentication
            && self.expected_evidence.predicate().namespace() == RESOURCE_COMMIT_EVIDENCE_NAMESPACE
            && self.expected_evidence.predicate().name() == ACQUISITION_PREDICATE
            && EvidenceId::parse(&self.evidence_reference)
                .ok()
                .and_then(|id| {
                    knowledge.inspect_evidence(&id, |stored| stored == &self.expected_evidence)
                })
                == Some(true)
    }
}

pub(super) struct AcquiredOAuthCodeCredential {
    pub(super) credential: SuppliedSessionCredential,
    pub(super) receipt: CommittedOAuthCodeReceipt,
    pub(super) declared_lifetime: Duration,
    pub(super) refresh_token:
        Option<crate::supplied_session_review::oauth_refresh::OAuthRefreshToken>,
}

pub(super) struct OAuthCodeAcquisitionContext<'a> {
    pub(super) authority: &'a SharedWebRuntimeAuthority,
    pub(super) requests: &'a OAuthCodeRequestBroker,
    pub(super) descriptor: &'a OAuthCodeRequestDescriptor,
    pub(super) policy: &'a SuppliedSessionPolicy,
    pub(super) deadline: Option<tokio::time::Instant>,
    pub(super) budget: DispatchBudget,
}

pub(super) async fn acquire(
    context: OAuthCodeAcquisitionContext<'_>,
    grant: &SuppliedSessionOAuthGrant,
) -> (
    SuppliedSessionOAuthCodeAudit,
    Result<AcquiredOAuthCodeCredential, SuppliedSessionAuditOutcome>,
) {
    let mut audit = SuppliedSessionOAuthCodeAudit::selected(context.policy)
        .expect("only a validated V5 policy reaches code acquisition");
    if context.authority.cancellation().is_cancelled() {
        audit.outcome = SuppliedSessionOAuthCodeOutcome::Cancelled;
        return (audit, Err(SuppliedSessionAuditOutcome::Cancelled));
    }
    if context
        .deadline
        .is_some_and(|end| tokio::time::Instant::now() >= end)
        || context.budget.dispatched_requests >= context.policy.max_session_requests()
        || context.budget.accounted_response_bytes >= context.policy.max_total_response_bytes()
    {
        audit.outcome = SuppliedSessionOAuthCodeOutcome::RuntimeLimit;
        return (audit, Err(SuppliedSessionAuditOutcome::RuntimeLimit));
    }
    let remaining = context
        .policy
        .max_total_response_bytes()
        .saturating_sub(context.budget.accounted_response_bytes);
    let body_limit = remaining.min(audit.configured_token_response_byte_limit);
    let before = context.authority.request_accounting().snapshot();
    audit.request_attempt_count = 1;
    let execution = super::boxed_dispatch_execution(|| {
        context.requests.collect(
            context.descriptor,
            context.policy,
            grant,
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
    audit.verifier_in_admitted_request = admitted == 1;
    audit.response_bytes = after
        .response_bytes()
        .saturating_sub(before.response_bytes());
    // Never quietly truncate an unexpected concurrent ledger change to one.
    if admitted > 1 {
        audit.outcome = SuppliedSessionOAuthCodeOutcome::CommitFailed;
        return (
            audit,
            Err(SuppliedSessionAuditOutcome::OAuthCodeExchangeUnavailable),
        );
    }
    let response = match result {
        RuntimeExecution::Completed(Ok(response)) => response,
        RuntimeExecution::Cancelled => {
            audit.outcome = SuppliedSessionOAuthCodeOutcome::Cancelled;
            return (audit, Err(SuppliedSessionAuditOutcome::Cancelled));
        },
        RuntimeExecution::WallTimeExceeded
        | RuntimeExecution::Completed(Err(OAuthCodeRequestError::RuntimeLimit)) => {
            audit.outcome = SuppliedSessionOAuthCodeOutcome::RuntimeLimit;
            return (audit, Err(SuppliedSessionAuditOutcome::RuntimeLimit));
        },
        RuntimeExecution::Completed(Err(OAuthCodeRequestError::Http)) => {
            audit.outcome = SuppliedSessionOAuthCodeOutcome::TransportFailed;
            return (
                audit,
                Err(SuppliedSessionAuditOutcome::OAuthCodeExchangeUnavailable),
            );
        },
        RuntimeExecution::Completed(Err(
            OAuthCodeRequestError::InvalidDescriptor
            | OAuthCodeRequestError::GrantExpired
            | OAuthCodeRequestError::AlreadyAttempted,
        )) => {
            audit.outcome = SuppliedSessionOAuthCodeOutcome::GrantUnavailable;
            return (
                audit,
                Err(SuppliedSessionAuditOutcome::OAuthCodeExchangeUnavailable),
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
        audit.outcome = SuppliedSessionOAuthCodeOutcome::RuntimeLimit;
        return (audit, Err(SuppliedSessionAuditOutcome::RuntimeLimit));
    }
    if response.status == 429 {
        audit.outcome = SuppliedSessionOAuthCodeOutcome::Throttled;
        return (
            audit,
            Err(SuppliedSessionAuditOutcome::OAuthCodeExchangeUnavailable),
        );
    }
    if admitted != 1
        || response.status != 200
        || !response.complete
        || !response.representation_supported
    {
        audit.outcome = SuppliedSessionOAuthCodeOutcome::ResponseRejected;
        return (
            audit,
            Err(SuppliedSessionAuditOutcome::OAuthCodeExchangeUnavailable),
        );
    }
    let idp = context
        .policy
        .oauth_code_policy()
        .expect("validated V5 IdP binding");
    let parsed = if context.policy.version() == SuppliedSessionPolicyVersion::V6 {
        crate::supplied_session_review::oauth_refresh::parse_renewable_token_response(
            context.policy,
            response.body,
            None,
        )
        .and_then(|parsed| {
            let lifetime = parsed.expires_in_seconds();
            let (authorization, refresh_token) = parsed.into_parts()?;
            Ok((authorization, lifetime, true, Some(refresh_token)))
        })
    } else {
        parse_token_response(idp, response.body).and_then(|parsed| {
            let lifetime = parsed.expires_in_seconds();
            let refresh_returned = parsed.refresh_token_returned();
            let authorization = parsed.into_authorization()?;
            Ok((authorization, lifetime, refresh_returned, None))
        })
    };
    let (authorization, lifetime, refresh_returned, refresh_token) = match parsed {
        Ok(value) => value,
        Err(_) => {
            audit.outcome = SuppliedSessionOAuthCodeOutcome::ResponseRejected;
            return (
                audit,
                Err(SuppliedSessionAuditOutcome::OAuthCodeExchangeUnavailable),
            );
        },
    };
    audit.token_response_validated = true;
    audit.response_scope_matched = Some(true);
    audit.declared_token_lifetime_seconds = Some(lifetime);
    audit.refresh_token_returned = Some(refresh_returned);
    let binding = format!(
        "policy={};application={};idp={};purpose=oauth_code_exchange;status=200;body_state=complete;response_bytes={};scope=exact_supported_echo;declared_lifetime={lifetime};refresh_returned={refresh_returned};context=operator_declared_external;token=opaque_bearer;outcome=credential_committed",
        context.policy.policy_reference(), context.policy.application_reference(),
        idp.binding_reference(), audit.response_bytes,
    );
    let receipt = commit_value_safe_evidence(
        context.policy,
        idp.binding_reference(),
        b"security.supplied-session-oauth-code-evidence.v1\0",
        "supplied-session-oauth-code-evidence-sha256",
        ACQUISITION_PREDICATE,
        "descriptor-bound-imported-code-exchange",
        binding,
        context.authority.knowledge(),
    )
    .and_then(|reference| {
        let id = EvidenceId::parse(&reference).ok()?;
        let expected_evidence = context
            .authority
            .knowledge()
            .inspect_evidence(&id, Clone::clone)?;
        let receipt = CommittedOAuthCodeReceipt {
            knowledge_authority: context.authority.knowledge().authority().clone(),
            policy_reference: context.policy.policy_reference().to_owned(),
            application_reference: context.policy.application_reference().to_owned(),
            idp_reference: idp.binding_reference().to_owned(),
            principal_alias: context.policy.principal_alias().to_owned(),
            evidence_reference: reference,
            expected_evidence,
        };
        receipt
            .is_valid_for(context.policy, context.authority.knowledge())
            .then_some(receipt)
    });
    let Some(receipt) = receipt else {
        audit.outcome = SuppliedSessionOAuthCodeOutcome::CommitFailed;
        return (
            audit,
            Err(SuppliedSessionAuditOutcome::OAuthCodeExchangeUnavailable),
        );
    };
    audit.evidence_reference = Some(receipt.evidence_reference.clone());
    audit.credential_commit_count = 1;
    audit.outcome = SuppliedSessionOAuthCodeOutcome::CredentialCommitted;
    (
        audit,
        Ok(AcquiredOAuthCodeCredential {
            credential: SuppliedSessionCredential::Authorization(authorization),
            receipt,
            declared_lifetime: Duration::from_secs(lifetime),
            refresh_token,
        }),
    )
}
