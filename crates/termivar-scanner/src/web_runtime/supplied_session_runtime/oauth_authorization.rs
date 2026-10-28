//! One private, metered loopback response reception. Parsed form data alone is
//! not authority: dispatch requires the exact committed callback proof below.

use std::time::Duration;

use serde::Serialize;
use termivar_core::{Evidence, EvidenceId, EvidenceKind};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use zeroize::Zeroizing;

use super::{
    commit_value_safe_evidence, earliest_deadline, SharedWebRuntimeAuthority,
    SuppliedSessionPolicy, SuppliedSessionPolicyVersion, RESOURCE_COMMIT_EVIDENCE_NAMESPACE,
};
use crate::{
    runtime_budget::{RequestAccountingLease, TransportDispatchOutcome},
    supplied_session_review::{
        oauth_authorization::{
            OAuthAuthorizationCodeParts, OAuthAuthorizationResponse, PendingOAuthAuthorization,
        },
        SuppliedSessionOAuthAuthorization,
    },
    web_runtime::authority::OAuthAuthorizationCallbackMint,
    DecisionExecutionStage, KnowledgeBase,
};

const ACTION: &str = "web.review.supplied-session.oauth-authorization-callback";
const PREDICATE: &str = "oauth-authorization-callback-committed";
const MAX_HEADERS: usize = 4096;
const MAX_FORM: usize = 8192;
const MAX_HEADER_COUNT: usize = 32;
const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 44\r\nCache-Control: no-store\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\nTermivar received this single-use response.\n";

/// Closed reception result, not an identity/authentication verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppliedSessionOAuthAuthorizationOutcome {
    NotStarted,
    RuntimeLimit,
    Cancelled,
    ListenerUnavailable,
    HandoffFailed,
    ReceptionFailed,
    ResponseRejected,
    ProviderError,
    CommitFailed,
    CallbackCommitted,
}

/// Value-safe collection facts. Inbound callback reservation is distinct from
/// outgoing token/health/resource requests; both use the same parent ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuppliedSessionOAuthAuthorizationAudit {
    profile: &'static str,
    authorization_policy_reference: String,
    configured_wait_ms: u64,
    reservation_count: u8,
    listener_bound: bool,
    handoff_written: bool,
    accepted_connection_count: u8,
    completed_form_count: u8,
    state_validated: bool,
    issuer_validated: bool,
    callback_commit_count: u8,
    ingress_bytes: u64,
    reply_bytes_written: u64,
    elapsed_ms: u64,
    listener_closed: bool,
    unknown_parameter_count: u8,
    provider_error_class: Option<&'static str>,
    evidence_reference: Option<String>,
    oidc_nonce_validation_performed: bool,
    oidc_identity_validation_performed: bool,
    token_signature_validation_performed: bool,
    outcome: SuppliedSessionOAuthAuthorizationOutcome,
}

impl SuppliedSessionOAuthAuthorizationAudit {
    pub(super) fn selected(policy: &SuppliedSessionPolicy) -> Option<Self> {
        let config = policy.oauth_authorization_policy()?;
        Some(Self {
            profile: "loopback-form-post-state/v1",
            authorization_policy_reference: config.binding_reference().to_owned(),
            configured_wait_ms: config.max_wait_ms(),
            reservation_count: 0,
            listener_bound: false,
            handoff_written: false,
            accepted_connection_count: 0,
            completed_form_count: 0,
            state_validated: false,
            issuer_validated: false,
            callback_commit_count: 0,
            ingress_bytes: 0,
            reply_bytes_written: 0,
            elapsed_ms: 0,
            listener_closed: true,
            unknown_parameter_count: 0,
            provider_error_class: None,
            evidence_reference: None,
            oidc_nonce_validation_performed: false,
            oidc_identity_validation_performed: false,
            token_signature_validation_performed: false,
            outcome: SuppliedSessionOAuthAuthorizationOutcome::NotStarted,
        })
    }

    pub const fn reservation_count(&self) -> u8 {
        self.reservation_count
    }
    pub const fn accepted_connection_count(&self) -> u8 {
        self.accepted_connection_count
    }
    pub const fn callback_commit_count(&self) -> u8 {
        self.callback_commit_count
    }
    pub const fn state_validated(&self) -> bool {
        self.state_validated
    }
    pub const fn issuer_validated(&self) -> bool {
        self.issuer_validated
    }
    pub const fn ingress_bytes(&self) -> u64 {
        self.ingress_bytes
    }
    pub const fn outcome(&self) -> SuppliedSessionOAuthAuthorizationOutcome {
        self.outcome
    }
    pub fn authorization_policy_reference(&self) -> &str {
        &self.authorization_policy_reference
    }

    pub(crate) fn is_consistent(&self) -> bool {
        let reference = |s: &str, prefix: &str| {
            s.strip_prefix(prefix).is_some_and(|v| {
                v.len() == 64
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
            })
        };
        let basic = self.profile == "loopback-form-post-state/v1"
            && reference(
                &self.authorization_policy_reference,
                "oauth-authorization-policy-sha256:",
            )
            && (1..=30000).contains(&self.configured_wait_ms)
            && self.reservation_count <= 1
            && self.accepted_connection_count <= self.reservation_count
            && self.completed_form_count <= self.accepted_connection_count
            && (self.completed_form_count == 0 || self.ingress_bytes > 0)
            && self.callback_commit_count
                <= u8::from(self.state_validated && self.issuer_validated)
            && self.state_validated == self.issuer_validated
            && (!self.state_validated || self.completed_form_count == 1)
            && (!self.handoff_written || self.listener_bound)
            && (!self.listener_bound || self.reservation_count == 1)
            && (self.accepted_connection_count == 0 || self.handoff_written)
            && (self.ingress_bytes == 0 || self.accepted_connection_count == 1)
            && self.ingress_bytes <= (MAX_HEADERS + MAX_FORM + 1) as u64
            && self.reply_bytes_written <= REPLY.len() as u64
            && (self.reply_bytes_written == 0 || self.completed_form_count == 1)
            && self.listener_closed
            && self.unknown_parameter_count <= 16
            && (self.unknown_parameter_count == 0 || self.state_validated)
            && !self.oidc_nonce_validation_performed
            && !self.oidc_identity_validation_performed
            && !self.token_signature_validation_performed
            && (self.evidence_reference.is_some() == (self.callback_commit_count == 1))
            && self.evidence_reference.as_deref().is_none_or(|s| {
                reference(s, "supplied-session-oauth-authorization-evidence-sha256:")
            })
            && self.provider_error_class.is_none_or(|s| {
                matches!(
                    s,
                    "invalid_request"
                        | "unauthorized_client"
                        | "access_denied"
                        | "unsupported_response_type"
                        | "invalid_scope"
                        | "server_error"
                        | "temporarily_unavailable"
                        | "other"
                )
            })
            && (self.provider_error_class.is_some()
                == (self.outcome == SuppliedSessionOAuthAuthorizationOutcome::ProviderError))
            && (self.provider_error_class.is_none() || self.state_validated)
            && (self.outcome != SuppliedSessionOAuthAuthorizationOutcome::CallbackCommitted
                || self.callback_commit_count == 1)
            && (self.callback_commit_count != 1
                || self.outcome == SuppliedSessionOAuthAuthorizationOutcome::CallbackCommitted);
        basic
            && match self.outcome {
                SuppliedSessionOAuthAuthorizationOutcome::NotStarted => {
                    self.reservation_count == 0
                        && !self.listener_bound
                        && !self.handoff_written
                        && self.accepted_connection_count == 0
                        && self.completed_form_count == 0
                        && !self.state_validated
                        && self.ingress_bytes == 0
                        && self.reply_bytes_written == 0
                },
                SuppliedSessionOAuthAuthorizationOutcome::ListenerUnavailable => {
                    self.reservation_count == 1
                        && !self.listener_bound
                        && !self.handoff_written
                        && self.accepted_connection_count == 0
                },
                SuppliedSessionOAuthAuthorizationOutcome::HandoffFailed => {
                    self.reservation_count == 1
                        && self.listener_bound
                        && !self.handoff_written
                        && self.accepted_connection_count == 0
                },
                SuppliedSessionOAuthAuthorizationOutcome::ReceptionFailed => {
                    self.reservation_count == 1 && self.handoff_written && !self.state_validated
                },
                SuppliedSessionOAuthAuthorizationOutcome::ResponseRejected => {
                    self.reservation_count == 1
                        && self.handoff_written
                        && self.accepted_connection_count == 1
                        && !self.state_validated
                },
                SuppliedSessionOAuthAuthorizationOutcome::ProviderError => {
                    self.completed_form_count == 1
                        && self.state_validated
                        && self.callback_commit_count == 0
                },
                SuppliedSessionOAuthAuthorizationOutcome::CallbackCommitted => {
                    self.completed_form_count == 1
                        && self.state_validated
                        && self.callback_commit_count == 1
                },
                SuppliedSessionOAuthAuthorizationOutcome::CommitFailed => {
                    self.callback_commit_count == 0
                },
                SuppliedSessionOAuthAuthorizationOutcome::RuntimeLimit
                | SuppliedSessionOAuthAuthorizationOutcome::Cancelled => {
                    self.callback_commit_count == 0 && !self.state_validated
                },
            }
    }
}

/// Not constructible from saved data, a form fixture, or an imported TSV.
pub(super) struct CommittedOAuthAuthorizationReceipt {
    knowledge_authority: crate::knowledge::KnowledgeAuthority,
    policy_reference: String,
    application_reference: String,
    authorization_reference: String,
    idp_reference: String,
    principal_alias: String,
    transaction_reference: String,
    evidence_reference: String,
    expected_evidence: Evidence,
}

impl CommittedOAuthAuthorizationReceipt {
    pub(super) fn is_valid_for(
        &self,
        policy: &SuppliedSessionPolicy,
        knowledge: &KnowledgeBase,
    ) -> bool {
        policy.version() == SuppliedSessionPolicyVersion::V7
            && self.knowledge_authority.is_same_as(knowledge.authority())
            && self.policy_reference == policy.policy_reference()
            && self.application_reference == policy.application_reference()
            && self.principal_alias == policy.principal_alias()
            && policy
                .oauth_authorization_policy()
                .is_some_and(|p| p.binding_reference() == self.authorization_reference)
            && policy
                .oauth_code_policy()
                .is_some_and(|p| p.binding_reference() == self.idp_reference)
            && self.expected_evidence.kind() == &EvidenceKind::Authentication
            && self.expected_evidence.predicate().namespace() == RESOURCE_COMMIT_EVIDENCE_NAMESPACE
            && self.expected_evidence.predicate().name() == PREDICATE
            && self.expected_evidence.source().correlation_id()
                == Some(self.transaction_reference.as_str())
            && EvidenceId::parse(&self.evidence_reference)
                .ok()
                .and_then(|id| {
                    knowledge.inspect_evidence(&id, |value| value == &self.expected_evidence)
                })
                == Some(true)
    }
}

/// Guarded values plus committed proof; the broker revalidates the proof and
/// monotonic freshness immediately before its single token dispatch.
pub(crate) struct OAuthAuthorizationDispatchPermit {
    parts: OAuthAuthorizationCodeParts,
    receipt: CommittedOAuthAuthorizationReceipt,
    knowledge: KnowledgeBase,
    deadline: tokio::time::Instant,
}

impl OAuthAuthorizationDispatchPermit {
    pub(super) const fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }
    pub(crate) fn is_valid_for(
        &self,
        policy: &SuppliedSessionPolicy,
        mint: &crate::web_runtime::OAuthCodeMintToken,
    ) -> bool {
        tokio::time::Instant::now() < self.deadline
            && mint.is_valid_for_knowledge(policy, &self.knowledge)
            && self.receipt.is_valid_for(policy, &self.knowledge)
            && self.parts.policy_reference == self.receipt.policy_reference
            && self.parts.idp_reference == self.receipt.idp_reference
            && self.parts.authorization_reference == self.receipt.authorization_reference
            && self.parts.principal_alias == self.receipt.principal_alias
            && self.parts.transaction_reference == self.receipt.transaction_reference
            && self.parts.unknown_parameter_count <= 16
    }

    pub(crate) fn compose_form_body(
        &self,
        policy: &SuppliedSessionPolicy,
    ) -> Result<Zeroizing<String>, ()> {
        let idp = policy.oauth_code_policy().ok_or(())?;
        if !self.receipt.is_valid_for(policy, &self.knowledge)
            || tokio::time::Instant::now() >= self.deadline
        {
            return Err(());
        }
        let mut body = Zeroizing::new(String::new());
        {
            let mut form = url::form_urlencoded::Serializer::new(&mut *body);
            form.append_pair("grant_type", "authorization_code");
            form.append_pair("code", &self.parts.code);
            form.append_pair("client_id", idp.client_id());
            form.append_pair("redirect_uri", idp.redirect_uri().as_str());
            form.append_pair("code_verifier", &self.parts.verifier);
        }
        if body.len() > 16 * 1024 {
            return Err(());
        }
        Ok(body)
    }

    pub(super) fn into_receipt(self) -> CommittedOAuthAuthorizationReceipt {
        self.receipt
    }
}

pub(super) async fn receive(
    authority: &SharedWebRuntimeAuthority,
    mint: OAuthAuthorizationCallbackMint,
    policy: &SuppliedSessionPolicy,
    mut output: crate::supplied_session_review::SuppliedSessionOAuthAuthorization,
) -> (
    SuppliedSessionOAuthAuthorizationAudit,
    Result<OAuthAuthorizationDispatchPermit, ()>,
) {
    let mut audit =
        SuppliedSessionOAuthAuthorizationAudit::selected(policy).expect("validated V7 policy");
    let started = tokio::time::Instant::now();
    let result = receive_inner(authority, mint, policy, &mut output, &mut audit).await;
    audit.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    // receive_inner owns listener/stream; both are dropped before publication.
    audit.listener_closed = true;
    (audit, result)
}

async fn receive_inner(
    authority: &SharedWebRuntimeAuthority,
    mint: OAuthAuthorizationCallbackMint,
    policy: &SuppliedSessionPolicy,
    output: &mut SuppliedSessionOAuthAuthorization,
    audit: &mut SuppliedSessionOAuthAuthorizationAudit,
) -> Result<OAuthAuthorizationDispatchPermit, ()> {
    use SuppliedSessionOAuthAuthorizationOutcome as O;
    if !mint.is_valid_for(policy, authority.knowledge()) {
        audit.outcome = O::CommitFailed;
        return Err(());
    }
    let config = policy.oauth_authorization_policy().ok_or(())?;
    let idp = policy.oauth_code_policy().ok_or(())?;
    let end = earliest_deadline(
        authority.start().deadline(),
        tokio::time::Instant::now().checked_add(Duration::from_millis(config.max_wait_ms())),
    )
    .ok_or(())?;
    if authority.cancellation().is_cancelled() {
        audit.outcome = O::Cancelled;
        return Err(());
    }
    if tokio::time::Instant::now() >= end {
        audit.outcome = O::RuntimeLimit;
        return Err(());
    }
    let mut lease = authority
        .request_accounting()
        .try_begin_with_request_body_bytes(ACTION, DecisionExecutionStage::Passive, None, 0)
        .map_err(|_| {
            audit.outcome = O::RuntimeLimit;
        })?;
    audit.reservation_count = 1;
    let result = async {
    let transaction = PendingOAuthAuthorization::generate(idp, config, policy.policy_reference(), policy.principal_alias(), end.into_std())
        .map_err(|_| { audit.outcome = O::CommitFailed; })?;
    let transaction_reference = transaction.transaction_reference().to_owned();
    let listener = TcpListener::bind(config.callback_socket()).await.map_err(|_| { audit.outcome = O::ListenerUnavailable; })?;
    audit.listener_bound = true;
    let url = transaction.authorization_url().map_err(|_| { audit.outcome = O::HandoffFailed; })?;
    if authority.cancellation().is_cancelled() { audit.outcome = O::Cancelled; return Err(()); }
    if tokio::time::Instant::now() >= end { audit.outcome = O::RuntimeLimit; return Err(()); }
    output.write_authorization_url(&url).map_err(|_| { audit.outcome = O::HandoffFailed; })?;
    drop(url);
    audit.handoff_written = true;
    if authority.cancellation().is_cancelled() { audit.outcome = O::Cancelled; return Err(()); }
    if tokio::time::Instant::now() >= end { audit.outcome = O::RuntimeLimit; return Err(()); }
    let accepted = tokio::select! {
        biased;
        _ = authority.cancellation().cancelled() => { audit.outcome = O::Cancelled; return Err(()); },
        _ = tokio::time::sleep_until(end) => { audit.outcome = O::RuntimeLimit; return Err(()); },
        accepted = listener.accept() => accepted.map_err(|_| { audit.outcome = O::ReceptionFailed; })?,
    };
    // A failed or malicious first connection cannot cause another accept.
    drop(listener);
    let (mut stream, peer) = accepted;
    audit.accepted_connection_count = 1;
    if !peer.ip().is_loopback() { audit.outcome = O::ResponseRejected; return Err(()); }
    let form = read_form(&mut stream, &mut lease, authority, end, config.callback_host(), idp.issuer().origin().ascii_serialization().as_str(), audit).await;
    let form = match form { Ok(form) => form, Err(()) => return Err(()) };
    audit.completed_form_count = 1;
    let response = transaction.accept_form_post(form, std::time::Instant::now());
    let result = match response {
        Ok(OAuthAuthorizationResponse::Code(code)) => {
            if code.policy_reference() != policy.policy_reference()
                || code.idp_reference() != idp.binding_reference()
                || code.authorization_reference() != config.binding_reference()
                || code.principal_alias() != policy.principal_alias()
                || code.transaction_reference() != transaction_reference
            { audit.outcome = O::CommitFailed; return Err(()); }
            audit.state_validated = true; audit.issuer_validated = true;
            audit.unknown_parameter_count = u8::try_from(code.unknown_parameter_count()).unwrap_or(u8::MAX);
            let parts = code.into_parts();
            let binding = format!("policy={};application={};idp={};authorization={};principal={};transaction={};purpose=oauth_authorization_callback;state=matched;issuer=matched;form=complete;ingress_bytes={}",
                policy.policy_reference(), policy.application_reference(), parts.idp_reference, parts.authorization_reference,
                policy.principal_alias(), parts.transaction_reference, audit.ingress_bytes);
            let receipt = commit_value_safe_evidence(policy, &parts.transaction_reference,
                b"security.supplied-session-oauth-authorization-evidence.v1\0",
                "supplied-session-oauth-authorization-evidence-sha256", PREDICATE,
                "client-initiated-loopback-form-post", binding, authority.knowledge())
                .and_then(|reference| {
                    let id = EvidenceId::parse(&reference).ok()?;
                    let expected_evidence = authority.knowledge().inspect_evidence(&id, Clone::clone)?;
                    let receipt = CommittedOAuthAuthorizationReceipt {
                        knowledge_authority: authority.knowledge().authority().clone(),
                        policy_reference: policy.policy_reference().to_owned(), application_reference: policy.application_reference().to_owned(),
                        authorization_reference: parts.authorization_reference.clone(), idp_reference: parts.idp_reference.clone(),
                        principal_alias: policy.principal_alias().to_owned(), transaction_reference: parts.transaction_reference.clone(),
                        evidence_reference: reference, expected_evidence,
                    };
                    receipt.is_valid_for(policy, authority.knowledge()).then_some(receipt)
                });
            if let Some(receipt) = receipt {
                audit.evidence_reference = Some(receipt.evidence_reference.clone());
                audit.callback_commit_count = 1; audit.outcome = O::CallbackCommitted;
                let deadline = earliest_deadline(authority.start().deadline(), tokio::time::Instant::now()
                    .checked_add(Duration::from_millis(policy.max_wall_time_ms()))).ok_or(())?;
                Ok(OAuthAuthorizationDispatchPermit { parts, receipt, knowledge: authority.knowledge().clone(), deadline })
            } else { audit.outcome = O::CommitFailed; Err(()) }
        },
        Ok(OAuthAuthorizationResponse::Error(error)) => {
            if error.policy_reference() != policy.policy_reference()
                || error.idp_reference() != idp.binding_reference()
                || error.authorization_reference() != config.binding_reference()
                || error.principal_alias() != policy.principal_alias()
                || error.transaction_reference() != transaction_reference
            { audit.outcome = O::CommitFailed; return Err(()); }
            audit.state_validated = true; audit.issuer_validated = true;
            audit.unknown_parameter_count = u8::try_from(error.unknown_parameter_count()).unwrap_or(u8::MAX);
            audit.provider_error_class = Some(error.class().as_str());
            audit.outcome = O::ProviderError; Err(())
        },
        Err(_) => { audit.outcome = O::ResponseRejected; Err(()) },
    };
    // Identical inert reply regardless of semantic result; no code/state or
    // provider prose is reflected. Count writes, not unprovable peer receipt.
    for chunk in REPLY.chunks(512) {
        let written = tokio::select! {
            biased;
            _ = authority.cancellation().cancelled() => break,
            _ = tokio::time::sleep_until(end) => break,
            written = stream.write(chunk) => written,
        };
        match written { Ok(n) => { audit.reply_bytes_written += u64::try_from(n).unwrap_or(u64::MAX); if n != chunk.len() { break; } }, Err(_) => break }
    }
    result
    }.await;
    let transport_outcome = if audit.completed_form_count == 1 {
        TransportDispatchOutcome::Completed
    } else if audit.outcome == O::Cancelled {
        TransportDispatchOutcome::Cancelled
    } else if audit.outcome == O::RuntimeLimit {
        if lease.response_budget_reached() || lease.remaining_response_bytes() == 0 {
            TransportDispatchOutcome::ResponseBudgetReached
        } else {
            TransportDispatchOutcome::RequestTimeout
        }
    } else {
        TransportDispatchOutcome::TransportFailure
    };
    lease.finish(transport_outcome);
    result
}

async fn read_form(
    stream: &mut TcpStream,
    lease: &mut RequestAccountingLease,
    authority: &SharedWebRuntimeAuthority,
    end: tokio::time::Instant,
    host: &str,
    origin: &str,
    audit: &mut SuppliedSessionOAuthAuthorizationAudit,
) -> Result<Vec<u8>, ()> {
    use SuppliedSessionOAuthAuthorizationOutcome as O;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_HEADERS + MAX_FORM));
    let mut expected = None;
    loop {
        if authority.cancellation().is_cancelled() {
            audit.outcome = O::Cancelled;
            return Err(());
        }
        if tokio::time::Instant::now() >= end || lease.remaining_response_bytes() == 0 {
            audit.outcome = O::RuntimeLimit;
            return Err(());
        }
        // One byte beyond the cap detects overflow without unbounded reads.
        let remaining = (MAX_HEADERS + MAX_FORM + 1)
            .saturating_sub(bytes.len())
            .min(1024);
        if remaining == 0 {
            audit.outcome = O::ResponseRejected;
            return Err(());
        }
        let mut chunk = Zeroizing::new([0_u8; 1024]);
        let read = {
            let gate = tokio::select! {
                biased;
                _ = authority.cancellation().cancelled() => { audit.outcome = O::Cancelled; return Err(()); },
                _ = tokio::time::sleep_until(end) => { audit.outcome = O::RuntimeLimit; return Err(()); },
                gate = lease.acquire_response_read() => gate,
            };
            if lease.remaining_response_bytes() == 0 {
                audit.outcome = O::RuntimeLimit;
                return Err(());
            }
            let read = tokio::select! {
                biased;
                _ = authority.cancellation().cancelled() => { audit.outcome = O::Cancelled; return Err(()); },
                _ = tokio::time::sleep_until(end) => { audit.outcome = O::RuntimeLimit; return Err(()); },
                read = stream.read(&mut chunk[..remaining]) => read,
            };
            let read = read.map_err(|_| {
                audit.outcome = O::ReceptionFailed;
            })?;
            let count = u64::try_from(read).unwrap_or(u64::MAX);
            audit.ingress_bytes = audit.ingress_bytes.saturating_add(count);
            if lease.observe_response_bytes(count) < count {
                audit.outcome = O::RuntimeLimit;
                return Err(());
            }
            drop(gate);
            read
        };
        if read == 0 {
            audit.outcome = O::ReceptionFailed;
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if expected.is_none() {
            if let Some(position) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let header_end = position + 4;
                if header_end > MAX_HEADERS {
                    audit.outcome = O::ResponseRejected;
                    return Err(());
                }
                let length = parse_headers(&bytes[..position], host, origin).ok_or_else(|| {
                    audit.outcome = O::ResponseRejected;
                })?;
                expected = Some((header_end, length));
            } else if bytes.len() >= MAX_HEADERS {
                audit.outcome = O::ResponseRejected;
                return Err(());
            }
        }
        if let Some((header_end, length)) = expected {
            if bytes.len() > header_end + length {
                audit.outcome = O::ResponseRejected;
                return Err(());
            }
            if bytes.len() == header_end + length {
                let mut body = Zeroizing::new(Vec::new());
                body.extend_from_slice(&bytes[header_end..]);
                return Ok(std::mem::take(&mut *body));
            }
        }
    }
}

fn parse_headers(bytes: &[u8], expected_host: &str, expected_origin: &str) -> Option<usize> {
    let text = std::str::from_utf8(bytes).ok()?;
    if bytes
        .iter()
        .any(|b| !matches!(b, b'\r' | b'\n' | 0x20..=0x7e))
    {
        return None;
    }
    let mut lines = text.split("\r\n");
    if lines.next()? != "POST /termivar/oauth/callback HTTP/1.1" {
        return None;
    }
    let mut host = None;
    let mut content_type = None;
    let mut length = None;
    let mut origin = None;
    for (index, line) in lines.enumerate() {
        if index >= MAX_HEADER_COUNT || line.starts_with(' ') || line.contains(['\r', '\n']) {
            return None;
        }
        let (key, value) = line.split_once(':')?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return None;
        }
        let value = value.trim_matches(' ');
        match key.to_ascii_lowercase().as_str() {
            "host" if host.is_none() => host = Some(value),
            "content-type" if content_type.is_none() => content_type = Some(value),
            "content-length" if length.is_none() => {
                if value.is_empty()
                    || value.len() > 4
                    || !value.bytes().all(|b| b.is_ascii_digit())
                    || value.starts_with('0')
                {
                    return None;
                }
                length = Some(value.parse::<usize>().ok()?);
            },
            "origin" if origin.is_none() => origin = Some(value),
            "host"
            | "content-type"
            | "content-length"
            | "origin"
            | "transfer-encoding"
            | "expect"
            | "upgrade"
            | "content-encoding"
            | "authorization"
            | "proxy-authorization"
            | "cookie" => return None,
            _ => {},
        }
    }
    if host? != expected_host || origin.is_some_and(|v| v != expected_origin) {
        return None;
    }
    let mut media = content_type?.split(';');
    if !media
        .next()?
        .trim()
        .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    {
        return None;
    }
    match (media.next(), media.next()) {
        (None, None) => {},
        (Some(p), None) if p.trim().eq_ignore_ascii_case("charset=utf-8") => {},
        _ => return None,
    }
    length.filter(|n| (1..=MAX_FORM).contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_receipt_requires_exact_committed_authority_and_context() {
        let application = url::Url::parse("https://application.test/app/").unwrap();
        let source = r#"schema="security.supplied-session-policy/v7"
principal_alias="original-proof-principal"
credential_mechanism="authorization_header"
credential_acquisition="client_initiated_oauth_pkce"
health_path="/app/health"
health_json_field="authenticated"
resources=["/app/read-only"]
max_session_requests=4
max_total_response_bytes=65536
max_response_body_bytes=8192
max_wall_time_ms=1000
[oauth_code]
profile="client-initiated-public-code-s256-bearer/v1"
transport_profile="verified-https/v1"
issuer="https://issuer.test/realm"
token_endpoint="https://issuer.test/realm/token"
client_id="original-proof-public-client"
redirect_uri="http://127.0.0.1:43123/termivar/oauth/callback"
scopes=["canary-read"]
max_token_response_bytes=8192
[oauth_authorization]
profile="loopback-form-post-state/v1"
authorization_endpoint="https://issuer.test/realm/authorize"
max_wait_ms=1000
"#;
        let policy = SuppliedSessionPolicy::parse_toml(&application, source.as_bytes()).unwrap();
        let mut unstarted = SuppliedSessionOAuthAuthorizationAudit::selected(&policy).unwrap();
        assert!(unstarted.is_consistent());
        unstarted.unknown_parameter_count = 1;
        assert!(
            !unstarted.is_consistent(),
            "extension facts cannot precede state and issuer qualification"
        );
        let knowledge = KnowledgeBase::default();
        let transaction = format!("oauth-authorization-transaction:{}", "A".repeat(43));
        // Test-only private proof construction; this fixture cannot be imported
        // or used to mint a production listener/dispatch permit.
        let reference = commit_value_safe_evidence(
            &policy,
            &transaction,
            b"original.synthetic.callback-proof.v1\0",
            "supplied-session-oauth-authorization-evidence-sha256",
            PREDICATE,
            "original-synthetic-proof",
            "original value-safe test proof".to_owned(),
            &knowledge,
        )
        .unwrap();
        let id = EvidenceId::parse(&reference).unwrap();
        let expected = knowledge.inspect_evidence(&id, Clone::clone).unwrap();
        let mut receipt = CommittedOAuthAuthorizationReceipt {
            knowledge_authority: knowledge.authority().clone(),
            policy_reference: policy.policy_reference().to_owned(),
            application_reference: policy.application_reference().to_owned(),
            authorization_reference: policy
                .oauth_authorization_policy()
                .unwrap()
                .binding_reference()
                .to_owned(),
            idp_reference: policy
                .oauth_code_policy()
                .unwrap()
                .binding_reference()
                .to_owned(),
            principal_alias: policy.principal_alias().to_owned(),
            transaction_reference: transaction.clone(),
            evidence_reference: reference.clone(),
            expected_evidence: expected.clone(),
        };
        assert!(receipt.is_valid_for(&policy, &knowledge));
        assert!(receipt.is_valid_for(&policy, &knowledge.clone()));
        let foreign = KnowledgeBase::default();
        foreign.insert_evidence(expected).unwrap();
        assert!(
            !receipt.is_valid_for(&policy, &foreign),
            "copied saved shape cannot replace knowledge authority"
        );
        receipt.transaction_reference.push('B');
        assert!(
            !receipt.is_valid_for(&policy, &knowledge),
            "transaction correlation must be exact"
        );
        receipt.transaction_reference = transaction;
        receipt.evidence_reference = format!(
            "supplied-session-oauth-authorization-evidence-sha256:{}",
            "0".repeat(64)
        );
        assert!(
            !receipt.is_valid_for(&policy, &knowledge),
            "missing committed evidence cannot qualify"
        );
        receipt.evidence_reference = reference;
        let changed = source.replace("original-proof-principal", "another-proof-principal");
        assert_ne!(changed, source);
        let changed = SuppliedSessionPolicy::parse_toml(&application, changed.as_bytes()).unwrap();
        assert!(!receipt.is_valid_for(&changed, &knowledge));
        assert!(receipt.is_valid_for(&policy, &knowledge));
    }

    #[test]
    fn callback_framing_is_exact_bounded_and_never_accepts_credential_headers() {
        let valid = b"POST /termivar/oauth/callback HTTP/1.1\r\nHost: 127.0.0.1:43123\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 17";
        assert_eq!(
            parse_headers(valid, "127.0.0.1:43123", "https://issuer.example"),
            Some(17)
        );
        let valid = std::str::from_utf8(valid).unwrap();
        for replacement in [
            "GET /termivar/oauth/callback HTTP/1.1",
            "POST /termivar/oauth/callback?code=secret HTTP/1.1",
            "POST http://127.0.0.1:43123/termivar/oauth/callback HTTP/1.1",
        ] {
            assert_eq!(
                parse_headers(
                    valid
                        .replacen("POST /termivar/oauth/callback HTTP/1.1", replacement, 1)
                        .as_bytes(),
                    "127.0.0.1:43123",
                    "https://issuer.example"
                ),
                None
            );
        }
        for line in [
            "Host: localhost:43123",
            "Content-Length: 17",
            "Transfer-Encoding: chunked",
            "Expect: 100-continue",
            "Content-Encoding: gzip",
            "Authorization: synthetic-canary",
            "Cookie: synthetic=canary",
            "Origin: https://foreign.example",
        ] {
            assert_eq!(
                parse_headers(
                    format!("{valid}\r\n{line}").as_bytes(),
                    "127.0.0.1:43123",
                    "https://issuer.example"
                ),
                None
            );
        }
        for line in [
            "X-Ignored: a\nContent-Length: 999",
            "X-Ignored: a\rContent-Length: 999",
        ] {
            assert_eq!(
                parse_headers(
                    format!("{valid}\r\n{line}").as_bytes(),
                    "127.0.0.1:43123",
                    "https://issuer.example"
                ),
                None
            );
        }
        for n in ["0", "017", "8193", "12000", "true", "+17"] {
            assert_eq!(
                parse_headers(
                    valid
                        .replace("Length: 17", &format!("Length: {n}"))
                        .as_bytes(),
                    "127.0.0.1:43123",
                    "https://issuer.example"
                ),
                None
            );
        }
        assert!(REPLY.len() < 512);
        let body = REPLY.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(REPLY.len() - body, 44);
    }
}

#[cfg(test)]
#[path = "oauth_authorization_tests.rs"]
mod runtime_tests;
