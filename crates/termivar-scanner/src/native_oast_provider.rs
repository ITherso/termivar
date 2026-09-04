//! Sealed native-provider authority for one web assessment.
//!
//! This module is intentionally crate-private. It narrows the assessment's
//! existing request accounting, cancellation, and deadline authority to one
//! exact provider origin and four fixed management operations. It adds no
//! target action, report, finding, or independently finalized runtime.

use std::{collections::BTreeMap, fmt, time::Duration};

use sha2::{Digest, Sha256};
use termivar_oast::{
    AdminToken, CallbackId, CallbackTarget, EventCursor, NativeOastBoundaryRejection,
    NativeOastClient, NativeOastClientBoundary, NativeOastClientError, NativeOastClientErrorKind,
    NativeOastClientOperation, NativeOastDispatchAccounting, PollResponse, PublicOrigin, SessionId,
    SessionRequest, SessionToken, POLL_SCHEMA,
};
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use crate::{
    oast::{
        OastAssessmentId, OastAuthorityEpoch, OastAuthorityLimits, OastCorrelation,
        OastCorrelationAuthority, OastCorrelationState, OastCorrelationToken, OastEvent,
        OastEventKey, OastHttpEvent, OastHttpMethod, OastHttpScheme, OastLifetime,
        OastMonotonicTime, OastPollBudget, OastPollReceipt, OastProtocolSet,
        OastRegistrationReceipt,
    },
    runtime_budget::{
        RequestAccountingBroker, RequestAccountingLease, RequestAccountingSnapshot,
        TransportDispatchOutcome,
    },
    web_runtime::NativeOastProviderMintToken,
    DecisionExecutionStage, RuntimeBudget, RuntimeBudgetDimension, RuntimeLimitExceeded,
    VerificationCase,
};

pub(crate) const NATIVE_OAST_PROVIDER_ACTION_ID: &str = "web.auxiliary.native-oast-provider";
#[cfg_attr(
    all(
        not(test),
        feature = "oast-native-provider",
        not(feature = "ssrf-oast-review")
    ),
    expect(dead_code, reason = "consumed by the sealed PR B limits constructor")
)]
pub(crate) const HARD_MAX_NATIVE_OAST_REGISTRATIONS: u16 = 1;
#[cfg_attr(
    all(
        not(test),
        feature = "oast-native-provider",
        not(feature = "ssrf-oast-review")
    ),
    expect(dead_code, reason = "consumed by the sealed PR B limits constructor")
)]
pub(crate) const HARD_MAX_NATIVE_OAST_CALLBACKS: u16 = 8;
#[cfg_attr(
    all(
        not(test),
        feature = "oast-native-provider",
        not(feature = "ssrf-oast-review")
    ),
    expect(dead_code, reason = "consumed by the sealed PR B limits constructor")
)]
pub(crate) const HARD_MAX_NATIVE_OAST_PROVIDER_REQUESTS: u16 = 64;
#[cfg_attr(
    all(
        not(test),
        feature = "oast-native-provider",
        not(feature = "ssrf-oast-review")
    ),
    expect(dead_code, reason = "consumed by the sealed PR B limits constructor")
)]
pub(crate) const HARD_MAX_NATIVE_OAST_POLLS: u16 = 32;
#[cfg_attr(
    all(
        not(test),
        feature = "oast-native-provider",
        not(feature = "ssrf-oast-review")
    ),
    expect(dead_code, reason = "consumed by the sealed PR B limits constructor")
)]
pub(crate) const HARD_MAX_NATIVE_OAST_PROVIDER_REQUEST_BYTES: u64 = 64 * 1_024;
#[cfg_attr(
    all(
        not(test),
        feature = "oast-native-provider",
        not(feature = "ssrf-oast-review")
    ),
    expect(dead_code, reason = "consumed by the sealed PR B limits constructor")
)]
pub(crate) const HARD_MAX_NATIVE_OAST_PROVIDER_RESPONSE_BYTES: u64 = 2 * 1_024 * 1_024;
#[cfg_attr(
    all(
        not(test),
        feature = "oast-native-provider",
        not(feature = "ssrf-oast-review")
    ),
    expect(dead_code, reason = "consumed by the sealed PR B limits constructor")
)]
pub(crate) const HARD_MAX_NATIVE_OAST_PROVIDER_WALL_TIME_MS: u64 = 120_000;

const PROVIDER_ORIGIN_FINGERPRINT_DOMAIN: &[u8] =
    b"security.native-oast-provider.origin-fingerprint/v1\0";
const PROVIDER_EVENT_KEY_DOMAIN: &[u8] = b"security.native-oast-provider.event-key/v1\0";

/// Exact fixed native-provider operation classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeOastProviderOperation {
    Register,
    AllocateCallback,
    Poll,
    Cleanup,
}

/// Adapter lifecycle. There is no transition back to an earlier state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeOastProviderLifecycle {
    Configured,
    Registered,
    CallbackAllocated,
    Polling,
    Closing,
    Closed,
}

/// Checked narrowing ceilings for one provider session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeOastProviderLimits {
    max_registrations: u16,
    max_callbacks: u16,
    max_provider_requests: u16,
    max_polls: u16,
    max_provider_request_bytes: u64,
    max_provider_response_bytes: u64,
    max_provider_wall_time_ms: u64,
}

#[cfg_attr(
    all(not(test), feature = "oast-native-provider"),
    expect(
        dead_code,
        reason = "sealed PR B configuration is consumed only by the separately gated ssrf-oast-review capability"
    )
)]
impl NativeOastProviderLimits {
    pub(crate) fn new(
        max_registrations: u16,
        max_callbacks: u16,
        max_provider_requests: u16,
        max_polls: u16,
        max_provider_request_bytes: u64,
        max_provider_response_bytes: u64,
        max_provider_wall_time_ms: u64,
    ) -> Result<Self, NativeOastProviderError> {
        if max_registrations != HARD_MAX_NATIVE_OAST_REGISTRATIONS
            || max_callbacks == 0
            || max_provider_requests < 2
            || max_polls == 0
            || max_provider_request_bytes == 0
            || max_provider_response_bytes == 0
            || max_provider_wall_time_ms == 0
            || max_callbacks > HARD_MAX_NATIVE_OAST_CALLBACKS
            || max_provider_requests > HARD_MAX_NATIVE_OAST_PROVIDER_REQUESTS
            || max_polls > HARD_MAX_NATIVE_OAST_POLLS
            || max_provider_request_bytes > HARD_MAX_NATIVE_OAST_PROVIDER_REQUEST_BYTES
            || max_provider_response_bytes > HARD_MAX_NATIVE_OAST_PROVIDER_RESPONSE_BYTES
            || max_provider_wall_time_ms > HARD_MAX_NATIVE_OAST_PROVIDER_WALL_TIME_MS
        {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::InvalidLimits,
            ));
        }

        Ok(Self {
            max_registrations,
            max_callbacks,
            max_provider_requests,
            max_polls,
            max_provider_request_bytes,
            max_provider_response_bytes,
            max_provider_wall_time_ms,
        })
    }

    pub(crate) const fn max_registrations(self) -> u16 {
        self.max_registrations
    }

    pub(crate) const fn max_callbacks(self) -> u16 {
        self.max_callbacks
    }

    pub(crate) const fn max_provider_requests(self) -> u16 {
        self.max_provider_requests
    }

    pub(crate) const fn max_polls(self) -> u16 {
        self.max_polls
    }

    pub(crate) const fn max_provider_request_bytes(self) -> u64 {
        self.max_provider_request_bytes
    }

    pub(crate) const fn max_provider_response_bytes(self) -> u64 {
        self.max_provider_response_bytes
    }

    pub(crate) const fn max_provider_wall_time(self) -> Duration {
        Duration::from_millis(self.max_provider_wall_time_ms)
    }
}

/// Move-only host input for one exact provider and authority epoch.
pub(crate) struct NativeOastProviderConfiguration {
    origin: PublicOrigin,
    assessment_id: OastAssessmentId,
    epoch: OastAuthorityEpoch,
    administrator: AdminToken,
    limits: NativeOastProviderLimits,
}

#[cfg_attr(
    all(
        not(test),
        feature = "oast-native-provider",
        not(feature = "ssrf-oast-review")
    ),
    expect(
        dead_code,
        reason = "sealed PR B configuration is consumed only by the separately gated ssrf-oast-review capability"
    )
)]
impl NativeOastProviderConfiguration {
    pub(crate) fn new(
        origin: &str,
        assessment_id: &str,
        epoch: [u8; 32],
        administrator: Vec<u8>,
        limits: NativeOastProviderLimits,
    ) -> Result<Self, NativeOastProviderError> {
        // Wrap the secret first so every later validation failure zeroizes it.
        let administrator = AdminToken::new(administrator).map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::ProviderRejected)
        })?;
        let origin = origin.parse().map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::InvalidProviderOrigin)
        })?;
        let assessment_id = OastAssessmentId::new(assessment_id).map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::CorrelationRejected)
        })?;
        let epoch = OastAuthorityEpoch::new(epoch).map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::CorrelationRejected)
        })?;
        Ok(Self {
            origin,
            assessment_id,
            epoch,
            administrator,
            limits,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_loopback(
        origin: PublicOrigin,
        assessment_id: &str,
        epoch: [u8; 32],
        administrator: Vec<u8>,
        limits: NativeOastProviderLimits,
    ) -> Result<Self, NativeOastProviderError> {
        let administrator = AdminToken::new(administrator).map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::ProviderRejected)
        })?;
        let assessment_id = OastAssessmentId::new(assessment_id).map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::CorrelationRejected)
        })?;
        let epoch = OastAuthorityEpoch::new(epoch).map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::CorrelationRejected)
        })?;
        Ok(Self {
            origin,
            assessment_id,
            epoch,
            administrator,
            limits,
        })
    }
}

impl fmt::Debug for NativeOastProviderConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeOastProviderConfiguration")
            .field("origin", &"<fingerprinted>")
            .field("assessment_id", &self.assessment_id)
            .field("epoch", &self.epoch)
            .field("administrator", &"<redacted>")
            .field("limits", &self.limits)
            .finish()
    }
}

/// Stable raw-origin-free identity used by adapter receipts.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NativeOastProviderOriginFingerprint([u8; 32]);

impl fmt::Debug for NativeOastProviderOriginFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeOastProviderOriginFingerprint(<opaque>)")
    }
}

/// Raw-free accounting and lifecycle result for one fixed provider operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeOastProviderReceipt {
    provider_origin: NativeOastProviderOriginFingerprint,
    operation: NativeOastProviderOperation,
    lifecycle_before: NativeOastProviderLifecycle,
    lifecycle_after: NativeOastProviderLifecycle,
    request_count: u16,
    request_bytes: u64,
    response_bytes: u64,
    callback_allocations: u16,
    poll_number: u16,
    accepted_http_events: u16,
    duplicate_http_events: u64,
    expired: bool,
    cleanup_attempted: bool,
    cleanup_verified: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct NativeOastProviderReceiptFacts {
    accepted_http_events: u16,
    duplicate_http_events: u64,
    expired: bool,
    cleanup_verified: bool,
}

#[cfg_attr(
    all(not(test), feature = "oast-native-provider"),
    expect(
        dead_code,
        reason = "sealed PR B receipts are consumed only by the separately gated ssrf-oast-review capability"
    )
)]
impl NativeOastProviderReceipt {
    pub(crate) fn provider_origin(&self) -> &NativeOastProviderOriginFingerprint {
        &self.provider_origin
    }

    pub(crate) const fn operation(&self) -> NativeOastProviderOperation {
        self.operation
    }

    pub(crate) const fn lifecycle_before(&self) -> NativeOastProviderLifecycle {
        self.lifecycle_before
    }

    pub(crate) const fn lifecycle_after(&self) -> NativeOastProviderLifecycle {
        self.lifecycle_after
    }

    pub(crate) const fn request_count(&self) -> u16 {
        self.request_count
    }

    pub(crate) const fn request_bytes(&self) -> u64 {
        self.request_bytes
    }

    pub(crate) const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    pub(crate) const fn callback_allocations(&self) -> u16 {
        self.callback_allocations
    }

    pub(crate) const fn poll_number(&self) -> u16 {
        self.poll_number
    }

    pub(crate) const fn accepted_http_events(&self) -> u16 {
        self.accepted_http_events
    }

    pub(crate) const fn duplicate_http_events(&self) -> u64 {
        self.duplicate_http_events
    }

    pub(crate) const fn expired(&self) -> bool {
        self.expired
    }

    pub(crate) const fn cleanup_attempted(&self) -> bool {
        self.cleanup_attempted
    }

    pub(crate) const fn cleanup_verified(&self) -> bool {
        self.cleanup_verified
    }
}

/// Closed raw-free adapter failure classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeOastProviderErrorKind {
    InvalidLimits,
    InvalidProviderOrigin,
    ProviderTargetOriginOverlap,
    AuthorityAlreadyMinted,
    ParentBudgetTooSmall,
    OperationNotPermitted,
    InvalidLifecycle,
    RegistrationLimit,
    CallbackLimit,
    RequestLimit,
    RequestByteLimit,
    ResponseByteLimit,
    PollLimit,
    Cancelled,
    DeadlineExceeded,
    RuntimeBudget(RuntimeBudgetDimension),
    ProviderRejected,
    ProviderResponseInvalid,
    ProviderSessionMismatch,
    ProviderCallbackMismatch,
    ProviderPageIncomplete,
    ProviderExpired,
    CorrelationRejected,
    CleanupUnverified,
    InternalInvariant,
}

/// Static error plus an optional raw-free receipt for an attempted operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeOastProviderError {
    kind: NativeOastProviderErrorKind,
    receipt: Option<NativeOastProviderReceipt>,
}

impl NativeOastProviderError {
    const fn new(kind: NativeOastProviderErrorKind) -> Self {
        Self {
            kind,
            receipt: None,
        }
    }

    pub(crate) const fn internal_invariant() -> Self {
        Self::new(NativeOastProviderErrorKind::InternalInvariant)
    }

    pub(crate) const fn authority_already_minted() -> Self {
        Self::new(NativeOastProviderErrorKind::AuthorityAlreadyMinted)
    }

    fn with_receipt(kind: NativeOastProviderErrorKind, receipt: NativeOastProviderReceipt) -> Self {
        Self {
            kind,
            receipt: Some(receipt),
        }
    }

    pub(crate) const fn kind(&self) -> NativeOastProviderErrorKind {
        self.kind
    }

    #[cfg_attr(
        all(not(test), feature = "oast-native-provider"),
        expect(
            dead_code,
            reason = "raw-free error receipts are consumed by PR B tests"
        )
    )]
    pub(crate) const fn receipt(&self) -> Option<&NativeOastProviderReceipt> {
        self.receipt.as_ref()
    }
}

impl fmt::Display for NativeOastProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            NativeOastProviderErrorKind::InvalidLimits => "native OAST provider limits are invalid",
            NativeOastProviderErrorKind::InvalidProviderOrigin => {
                "native OAST provider origin is invalid"
            },
            NativeOastProviderErrorKind::ProviderTargetOriginOverlap => {
                "native OAST provider and target origins overlap"
            },
            NativeOastProviderErrorKind::AuthorityAlreadyMinted => {
                "native OAST provider authority was already minted"
            },
            NativeOastProviderErrorKind::ParentBudgetTooSmall => {
                "native OAST provider grant exceeds remaining assessment budget"
            },
            NativeOastProviderErrorKind::OperationNotPermitted => {
                "native OAST provider operation is not permitted"
            },
            NativeOastProviderErrorKind::InvalidLifecycle => {
                "native OAST provider lifecycle transition is invalid"
            },
            NativeOastProviderErrorKind::RegistrationLimit => {
                "native OAST provider registration limit was reached"
            },
            NativeOastProviderErrorKind::CallbackLimit => {
                "native OAST provider callback limit was reached"
            },
            NativeOastProviderErrorKind::RequestLimit => {
                "native OAST provider request limit was reached"
            },
            NativeOastProviderErrorKind::RequestByteLimit => {
                "native OAST provider request-byte limit was reached"
            },
            NativeOastProviderErrorKind::ResponseByteLimit => {
                "native OAST provider response-byte limit was reached"
            },
            NativeOastProviderErrorKind::PollLimit => "native OAST provider poll limit was reached",
            NativeOastProviderErrorKind::Cancelled => {
                "native OAST provider authority was cancelled"
            },
            NativeOastProviderErrorKind::DeadlineExceeded => {
                "native OAST provider deadline elapsed"
            },
            NativeOastProviderErrorKind::RuntimeBudget(_) => {
                "native OAST provider traffic exceeded assessment budget"
            },
            NativeOastProviderErrorKind::ProviderRejected => {
                "native OAST provider rejected the operation"
            },
            NativeOastProviderErrorKind::ProviderResponseInvalid => {
                "native OAST provider response is invalid"
            },
            NativeOastProviderErrorKind::ProviderSessionMismatch => {
                "native OAST provider session correlation failed"
            },
            NativeOastProviderErrorKind::ProviderCallbackMismatch => {
                "native OAST provider callback correlation failed"
            },
            NativeOastProviderErrorKind::ProviderPageIncomplete => {
                "native OAST provider poll page is incomplete"
            },
            NativeOastProviderErrorKind::ProviderExpired => "native OAST provider session expired",
            NativeOastProviderErrorKind::CorrelationRejected => {
                "native OAST correlation state rejected the operation"
            },
            NativeOastProviderErrorKind::CleanupUnverified => {
                "native OAST provider cleanup was not verified"
            },
            NativeOastProviderErrorKind::InternalInvariant => {
                "native OAST provider adapter invariant failed"
            },
        })
    }
}

impl std::error::Error for NativeOastProviderError {}

pub(crate) struct NativeOastProviderPermit {
    provider_origin_url: Url,
    provider_origin_fingerprint: NativeOastProviderOriginFingerprint,
    limits: NativeOastProviderLimits,
    accounting: RequestAccountingBroker,
    cancellation: CancellationToken,
    deadline: tokio::time::Instant,
    active_lease: Option<RequestAccountingLease>,
    provider_requests: u16,
    provider_request_bytes: u64,
    provider_response_bytes: u64,
    last_boundary_error: Option<NativeOastProviderErrorKind>,
}

impl fmt::Debug for NativeOastProviderPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeOastProviderPermit")
            .field("provider_origin", &self.provider_origin_fingerprint)
            .field("limits", &self.limits)
            .field("provider_requests", &self.provider_requests)
            .field("provider_request_bytes", &self.provider_request_bytes)
            .field("provider_response_bytes", &self.provider_response_bytes)
            .field("active_dispatch", &self.active_lease.is_some())
            .finish()
    }
}

impl NativeOastProviderPermit {
    fn mint(
        provider_origin: PublicOrigin,
        target_origin: &str,
        limits: NativeOastProviderLimits,
        accounting: RequestAccountingBroker,
        parent_budget: RuntimeBudget,
        cancellation: CancellationToken,
        parent_deadline: Option<tokio::time::Instant>,
    ) -> Result<Self, NativeOastProviderError> {
        let provider_origin_url = Url::parse(provider_origin.as_str()).map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::InvalidProviderOrigin)
        })?;
        if !provider_scheme_allowed(&provider_origin_url)
            || provider_origin_url.as_str() != provider_origin.as_str()
        {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::InvalidProviderOrigin,
            ));
        }
        let target_origin_url = parse_canonical_target_origin(target_origin)?;
        if same_exact_origin(&provider_origin_url, &target_origin_url) {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::ProviderTargetOriginOverlap,
            ));
        }

        require_parent_capacity(limits, parent_budget, accounting.snapshot())?;
        let now = tokio::time::Instant::now();
        let child_deadline = now
            .checked_add(limits.max_provider_wall_time())
            .ok_or_else(|| {
                NativeOastProviderError::new(NativeOastProviderErrorKind::InvalidLimits)
            })?;
        let deadline = parent_deadline.map_or(child_deadline, |parent| parent.min(child_deadline));
        if cancellation.is_cancelled() {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::Cancelled,
            ));
        }
        if now >= deadline {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::DeadlineExceeded,
            ));
        }

        Ok(Self {
            provider_origin_fingerprint: provider_origin_fingerprint(&provider_origin),
            provider_origin_url,
            limits,
            accounting,
            cancellation,
            deadline,
            active_lease: None,
            provider_requests: 0,
            provider_request_bytes: 0,
            provider_response_bytes: 0,
            last_boundary_error: None,
        })
    }

    #[cfg_attr(
        all(not(test), feature = "oast-native-provider"),
        expect(
            dead_code,
            reason = "exact-origin seam is exercised by PR B tests and fuzzing"
        )
    )]
    pub(crate) fn permits_url(&self, candidate: &Url) -> bool {
        same_exact_origin(&self.provider_origin_url, candidate)
    }

    fn begin_dispatch(
        &mut self,
        operation: NativeOastProviderOperation,
        request_bytes: u64,
        request_body_bytes: u64,
    ) -> Result<(), NativeOastProviderError> {
        if self.active_lease.is_some() {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::InternalInvariant,
            ));
        }
        if !matches!(
            operation,
            NativeOastProviderOperation::Register
                | NativeOastProviderOperation::AllocateCallback
                | NativeOastProviderOperation::Poll
                | NativeOastProviderOperation::Cleanup
        ) {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::OperationNotPermitted,
            ));
        }
        if self.cancellation.is_cancelled() {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::Cancelled,
            ));
        }
        if tokio::time::Instant::now() >= self.deadline {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::DeadlineExceeded,
            ));
        }
        if self.provider_requests >= self.limits.max_provider_requests {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::RequestLimit,
            ));
        }
        if self.provider_response_bytes >= self.limits.max_provider_response_bytes {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::ResponseByteLimit,
            ));
        }
        let next_request_bytes = self
            .provider_request_bytes
            .checked_add(request_bytes)
            .filter(|total| *total <= self.limits.max_provider_request_bytes)
            .ok_or_else(|| {
                NativeOastProviderError::new(NativeOastProviderErrorKind::RequestByteLimit)
            })?;

        let lease = self
            .accounting
            .try_begin_with_request_body_bytes(
                NATIVE_OAST_PROVIDER_ACTION_ID,
                DecisionExecutionStage::Passive,
                None,
                request_body_bytes,
            )
            .map_err(runtime_budget_error)?;
        self.provider_requests = self.provider_requests.saturating_add(1);
        self.provider_request_bytes = next_request_bytes;
        self.active_lease = Some(lease);
        Ok(())
    }

    fn remember_boundary_error(&mut self, error: &NativeOastProviderError) {
        self.last_boundary_error = Some(error.kind());
    }

    fn take_boundary_error(&mut self) -> Option<NativeOastProviderErrorKind> {
        self.last_boundary_error.take()
    }

    fn remaining_response_bytes(&self) -> u64 {
        let local = self
            .limits
            .max_provider_response_bytes
            .saturating_sub(self.provider_response_bytes);
        self.active_lease
            .as_ref()
            .map_or(0, |lease| local.min(lease.remaining_response_bytes()))
    }

    fn observe_response_bytes(&mut self, observed: u64) -> u64 {
        let Some(lease) = self.active_lease.as_mut() else {
            return 0;
        };
        let parent_retained = lease.observe_response_bytes(observed);
        let local_remaining = self
            .limits
            .max_provider_response_bytes
            .saturating_sub(self.provider_response_bytes);
        self.provider_response_bytes = self.provider_response_bytes.saturating_add(observed);
        parent_retained.min(local_remaining)
    }

    fn finish_dispatch(&mut self, outcome: TransportDispatchOutcome) {
        if let Some(mut lease) = self.active_lease.take() {
            lease.finish(outcome);
        }
    }
}

fn require_parent_capacity(
    limits: NativeOastProviderLimits,
    budget: RuntimeBudget,
    snapshot: RequestAccountingSnapshot,
) -> Result<(), NativeOastProviderError> {
    let remaining_requests = budget
        .max_total_requests()
        .saturating_sub(snapshot.total_requests());
    let remaining_response_bytes = budget
        .max_response_bytes()
        .saturating_sub(snapshot.response_bytes());
    if u32::from(limits.max_provider_requests) > remaining_requests
        || limits.max_provider_response_bytes > remaining_response_bytes
    {
        return Err(NativeOastProviderError::new(
            NativeOastProviderErrorKind::ParentBudgetTooSmall,
        ));
    }
    Ok(())
}

fn runtime_budget_error(limit: RuntimeLimitExceeded) -> NativeOastProviderError {
    NativeOastProviderError::new(NativeOastProviderErrorKind::RuntimeBudget(
        limit.dimension(),
    ))
}

fn provider_scheme_allowed(provider: &Url) -> bool {
    if provider.scheme() == "https"
        && matches!(provider.host(), Some(Host::Domain(_)))
        && provider.port_or_known_default() == Some(443)
    {
        return true;
    }
    #[cfg(test)]
    {
        provider.scheme() == "http"
            && provider.host().is_some_and(|host| {
                matches!(host, Host::Ipv4(address) if address.is_loopback())
                    || matches!(host, Host::Ipv6(address) if address.is_loopback())
            })
    }
    #[cfg(not(test))]
    false
}

fn same_exact_origin(expected: &Url, candidate: &Url) -> bool {
    expected.scheme() == candidate.scheme()
        && expected.host() == candidate.host()
        && expected.port_or_known_default() == candidate.port_or_known_default()
        && candidate.username().is_empty()
        && candidate.password().is_none()
}

fn parse_canonical_target_origin(source: &str) -> Result<Url, NativeOastProviderError> {
    let parsed = Url::parse(source).map_err(|_| {
        NativeOastProviderError::new(NativeOastProviderErrorKind::InternalInvariant)
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(NativeOastProviderError::new(
            NativeOastProviderErrorKind::InternalInvariant,
        ));
    }
    Ok(parsed)
}

pub(crate) fn provider_origin_fingerprint(
    origin: &PublicOrigin,
) -> NativeOastProviderOriginFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_ORIGIN_FINGERPRINT_DOMAIN);
    hash_field(&mut hasher, origin.as_str().as_bytes());
    NativeOastProviderOriginFingerprint(hasher.finalize().into())
}

fn provider_event_key(
    provider: &NativeOastProviderOriginFingerprint,
    session_id: &str,
    callback_id: &CallbackId,
    event_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_EVENT_KEY_DOMAIN);
    hash_field(&mut hasher, &provider.0);
    hash_field(&mut hasher, session_id.as_bytes());
    hash_field(&mut hasher, callback_id.as_str().as_bytes());
    hash_field(&mut hasher, event_id.as_bytes());
    hasher.finalize().into()
}

pub(crate) fn reduce_provider_http_event(
    provider: &NativeOastProviderOriginFingerprint,
    session_id: &str,
    callback_id: &CallbackId,
    event_id: &str,
    scheme: OastHttpScheme,
) -> Result<OastEvent, NativeOastProviderError> {
    let event_key = OastEventKey::new(provider_event_key(
        provider,
        session_id,
        callback_id,
        event_id,
    ))
    .map_err(|_| NativeOastProviderError::internal_invariant())?;
    // The provider proves an HTTP interaction but intentionally retains
    // neither GET/HEAD nor body bytes. `false` means no non-empty body was
    // observed or retained, not proof that the callback carried no body.
    Ok(OastEvent::Http(
        event_key,
        OastHttpEvent::new(scheme, OastHttpMethod::Unknown, false),
    ))
}

fn hash_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(field);
}

/// Borrowed, raw-free facts used to validate one provider poll page before
/// any live correlation state changes.
///
/// The concrete provider response is reduced to this shape by the adapter.
/// Keeping the validator independent of transport makes malformed-page
/// behavior deterministic without exposing response bodies or wire values.
#[derive(Clone, Copy)]
pub(crate) struct NativeOastPollPageFacts<'a> {
    pub(crate) schema: &'a str,
    pub(crate) expected_session: &'a SessionId,
    pub(crate) observed_session: &'a SessionId,
    pub(crate) previous_cursor: EventCursor,
    pub(crate) next_cursor: EventCursor,
    pub(crate) complete: bool,
    pub(crate) expired: bool,
    pub(crate) expected_callbacks: &'a [CallbackId],
    pub(crate) observed_callbacks: &'a [CallbackId],
    pub(crate) correlations_ready: bool,
}

/// Validates the exact scanner-side poll-page contract without transport or
/// mutation. The native client has already rejected malformed JSON and event
/// ordering; this layer enforces adapter session, callback, completion,
/// expiry, cursor, and correlation authority.
pub(crate) fn validate_provider_poll_page(
    facts: NativeOastPollPageFacts<'_>,
) -> Result<(), NativeOastProviderErrorKind> {
    if facts.schema != POLL_SCHEMA {
        return Err(NativeOastProviderErrorKind::ProviderResponseInvalid);
    }
    if facts.observed_session != facts.expected_session {
        return Err(NativeOastProviderErrorKind::ProviderSessionMismatch);
    }
    if !facts.complete {
        return Err(NativeOastProviderErrorKind::ProviderPageIncomplete);
    }
    if facts.expired {
        return Err(NativeOastProviderErrorKind::ProviderExpired);
    }
    if facts.next_cursor < facts.previous_cursor {
        return Err(NativeOastProviderErrorKind::ProviderResponseInvalid);
    }
    if facts
        .observed_callbacks
        .iter()
        .any(|callback| !facts.expected_callbacks.contains(callback))
    {
        return Err(NativeOastProviderErrorKind::ProviderCallbackMismatch);
    }
    if !facts.correlations_ready {
        return Err(NativeOastProviderErrorKind::CorrelationRejected);
    }
    Ok(())
}

struct NativeOastProviderSession {
    id: SessionId,
    token: SessionToken,
    cursor: EventCursor,
    lifetime_ms: u64,
}

impl fmt::Debug for NativeOastProviderSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeOastProviderSession")
            .field("id", &"<opaque>")
            .field("token", &"<redacted>")
            .field("cursor", &self.cursor)
            .field("lifetime_ms", &self.lifetime_ms)
            .finish()
    }
}

struct NativeOastProviderCallback {
    correlation: OastCorrelation,
}

/// One move-only callback allocation ready for a future explicitly authorized
/// target action. The target never enters an adapter receipt.
#[cfg_attr(
    all(
        not(test),
        feature = "oast-native-provider",
        not(feature = "ssrf-oast-review")
    ),
    expect(
        dead_code,
        reason = "sealed PR B allocation is consumed only by the separately gated ssrf-oast-review capability"
    )
)]
pub(crate) struct NativeOastAllocatedCallback {
    ordinal: u16,
    callback_id: CallbackId,
    target: CallbackTarget,
    correlation_receipt: OastRegistrationReceipt,
    provider_receipt: NativeOastProviderReceipt,
}

#[cfg_attr(
    all(not(test), feature = "oast-native-provider"),
    expect(
        dead_code,
        reason = "sealed PR B allocation is consumed only by the separately gated ssrf-oast-review capability"
    )
)]
impl NativeOastAllocatedCallback {
    pub(crate) const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub(crate) const fn callback_id(&self) -> &CallbackId {
        &self.callback_id
    }

    pub(crate) fn target(&self) -> &CallbackTarget {
        &self.target
    }

    pub(crate) fn correlation_receipt(&self) -> &OastRegistrationReceipt {
        &self.correlation_receipt
    }

    pub(crate) fn provider_receipt(&self) -> &NativeOastProviderReceipt {
        &self.provider_receipt
    }

    pub(crate) fn take_target(self) -> CallbackTarget {
        self.target
    }
}

impl fmt::Debug for NativeOastAllocatedCallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeOastAllocatedCallback")
            .field("ordinal", &self.ordinal)
            .field("target", &"<redacted>")
            .field("correlation_receipt", &self.correlation_receipt)
            .field("provider_receipt", &self.provider_receipt)
            .finish()
    }
}

/// One atomically reduced provider page plus the correlation receipts it
/// committed. Provider session, callback, and event identifiers stay private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeOastPollOutcome {
    provider_receipt: NativeOastProviderReceipt,
    correlation_receipts: Vec<OastPollReceipt>,
}

#[cfg_attr(
    all(not(test), feature = "oast-native-provider"),
    expect(
        dead_code,
        reason = "sealed PR B poll result is consumed only by the separately gated ssrf-oast-review capability"
    )
)]
impl NativeOastPollOutcome {
    pub(crate) fn provider_receipt(&self) -> &NativeOastProviderReceipt {
        &self.provider_receipt
    }

    pub(crate) fn correlation_receipts(&self) -> &[OastPollReceipt] {
        &self.correlation_receipts
    }
}

/// Sealed lifecycle adapter. It owns one provider client, one narrowing
/// permit, and one correlation authority; it performs no work in `Drop`.
#[cfg_attr(
    all(
        not(test),
        feature = "oast-native-provider",
        not(feature = "ssrf-oast-review")
    ),
    expect(
        dead_code,
        reason = "sealed PR B authority is consumed only by the separately gated ssrf-oast-review capability"
    )
)]
pub(crate) struct NativeOastProviderAdapter {
    client: NativeOastClient,
    permit: NativeOastProviderPermit,
    correlations: OastCorrelationAuthority,
    administrator: Option<AdminToken>,
    session: Option<NativeOastProviderSession>,
    callbacks: BTreeMap<CallbackId, NativeOastProviderCallback>,
    lifecycle: NativeOastProviderLifecycle,
    registration_attempted: bool,
    callback_attempts: u16,
    poll_attempts: u16,
    cleanup_attempted: bool,
    clock_origin: tokio::time::Instant,
    receipts: Vec<NativeOastProviderReceipt>,
}

#[cfg(all(test, feature = "oast-native-provider"))]
mod permit_tests {
    use super::*;

    const ADMIN_SECRET: &[u8] = b"NATIVE-OAST-ADMIN-MUST-NOT-LEAK-EC8D42";

    fn limits() -> NativeOastProviderLimits {
        NativeOastProviderLimits::new(1, 2, 8, 3, 4_096, 1_024, 10_000).unwrap()
    }

    fn permit(limits: NativeOastProviderLimits, budget: RuntimeBudget) -> NativeOastProviderPermit {
        NativeOastProviderPermit::mint(
            "https://oast.example.test/".parse().unwrap(),
            "https://target.example.test/",
            limits,
            RequestAccountingBroker::new(budget),
            budget,
            CancellationToken::new(),
            tokio::time::Instant::now().checked_add(Duration::from_secs(30)),
        )
        .unwrap()
    }

    #[test]
    fn limits_are_nonzero_hard_bounded_and_require_one_session_registration() {
        assert_eq!(limits().max_registrations(), 1);
        assert_eq!(limits().max_callbacks(), 2);
        assert_eq!(limits().max_provider_requests(), 8);
        assert_eq!(limits().max_polls(), 3);
        assert_eq!(limits().max_provider_request_bytes(), 4_096);
        assert_eq!(limits().max_provider_response_bytes(), 1_024);
        assert_eq!(limits().max_provider_wall_time(), Duration::from_secs(10));

        for invalid in [
            NativeOastProviderLimits::new(0, 1, 2, 1, 1, 1, 1),
            NativeOastProviderLimits::new(2, 1, 2, 1, 1, 1, 1),
            NativeOastProviderLimits::new(1, 0, 2, 1, 1, 1, 1),
            NativeOastProviderLimits::new(1, 1, 1, 1, 1, 1, 1),
            NativeOastProviderLimits::new(1, 1, 2, 0, 1, 1, 1),
            NativeOastProviderLimits::new(1, 1, 2, 1, 0, 1, 1),
            NativeOastProviderLimits::new(1, 1, 2, 1, 1, 0, 1),
            NativeOastProviderLimits::new(1, 1, 2, 1, 1, 1, 0),
            NativeOastProviderLimits::new(1, HARD_MAX_NATIVE_OAST_CALLBACKS + 1, 2, 1, 1, 1, 1),
            NativeOastProviderLimits::new(
                1,
                1,
                HARD_MAX_NATIVE_OAST_PROVIDER_REQUESTS + 1,
                1,
                1,
                1,
                1,
            ),
            NativeOastProviderLimits::new(1, 1, 2, HARD_MAX_NATIVE_OAST_POLLS + 1, 1, 1, 1),
            NativeOastProviderLimits::new(
                1,
                1,
                2,
                1,
                HARD_MAX_NATIVE_OAST_PROVIDER_REQUEST_BYTES + 1,
                1,
                1,
            ),
            NativeOastProviderLimits::new(
                1,
                1,
                2,
                1,
                1,
                HARD_MAX_NATIVE_OAST_PROVIDER_RESPONSE_BYTES + 1,
                1,
            ),
            NativeOastProviderLimits::new(
                1,
                1,
                2,
                1,
                1,
                1,
                HARD_MAX_NATIVE_OAST_PROVIDER_WALL_TIME_MS + 1,
            ),
        ] {
            assert_eq!(
                invalid.unwrap_err().kind(),
                NativeOastProviderErrorKind::InvalidLimits
            );
        }
    }

    #[test]
    fn provider_permit_is_exact_origin_and_never_accepts_the_target_origin() {
        let permit = permit(limits(), RuntimeBudget::default());
        assert!(permit.permits_url(&Url::parse("https://oast.example.test/v1/sessions").unwrap()));
        for rejected in [
            "https://target.example.test/",
            "https://other.example.test/v1/sessions",
            "http://oast.example.test/v1/sessions",
            "https://user@oast.example.test/v1/sessions",
        ] {
            assert!(!permit.permits_url(&Url::parse(rejected).unwrap()));
        }

        let overlap = NativeOastProviderPermit::mint(
            "https://target.example.test/".parse().unwrap(),
            "https://target.example.test/",
            limits(),
            RequestAccountingBroker::new(RuntimeBudget::default()),
            RuntimeBudget::default(),
            CancellationToken::new(),
            tokio::time::Instant::now().checked_add(Duration::from_secs(1)),
        )
        .unwrap_err();
        assert_eq!(
            overlap.kind(),
            NativeOastProviderErrorKind::ProviderTargetOriginOverlap
        );
    }

    #[test]
    fn permit_fails_closed_when_child_grant_exceeds_remaining_parent_capacity() {
        let budget = RuntimeBudget::default()
            .with_max_total_requests(7)
            .with_max_response_bytes(1_023);
        for constrained in [
            budget,
            RuntimeBudget::default().with_max_response_bytes(1_023),
        ] {
            let error = NativeOastProviderPermit::mint(
                "https://oast.example.test/".parse().unwrap(),
                "https://target.example.test/",
                limits(),
                RequestAccountingBroker::new(constrained),
                constrained,
                CancellationToken::new(),
                tokio::time::Instant::now().checked_add(Duration::from_secs(1)),
            )
            .unwrap_err();
            assert_eq!(
                error.kind(),
                NativeOastProviderErrorKind::ParentBudgetTooSmall
            );
        }
    }

    #[test]
    fn provider_dispatches_share_parent_accounting_and_enforce_child_request_limits() {
        let budget = RuntimeBudget::default();
        let accounting = RequestAccountingBroker::new(budget);
        let mut permit = NativeOastProviderPermit::mint(
            "https://oast.example.test/".parse().unwrap(),
            "https://target.example.test/",
            NativeOastProviderLimits::new(1, 1, 2, 1, 128, 128, 1_000).unwrap(),
            accounting.clone(),
            budget,
            CancellationToken::new(),
            tokio::time::Instant::now().checked_add(Duration::from_secs(1)),
        )
        .unwrap();

        permit
            .begin_dispatch(NativeOastProviderOperation::Register, 64, 32)
            .unwrap();
        assert_eq!(permit.observe_response_bytes(17), 17);
        permit.finish_dispatch(TransportDispatchOutcome::Completed);
        permit
            .begin_dispatch(NativeOastProviderOperation::Cleanup, 24, 0)
            .unwrap();
        permit.finish_dispatch(TransportDispatchOutcome::Completed);
        assert_eq!(
            permit
                .begin_dispatch(NativeOastProviderOperation::Poll, 24, 0)
                .unwrap_err()
                .kind(),
            NativeOastProviderErrorKind::RequestLimit
        );

        let snapshot = accounting.snapshot();
        assert_eq!(snapshot.total_requests(), 2);
        assert_eq!(snapshot.passive_requests(), 2);
        assert_eq!(snapshot.active_verifications(), 0);
        assert_eq!(snapshot.request_body_bytes(), 32);
        assert_eq!(snapshot.response_bytes(), 17);
        assert_eq!(accounting.dispatch_audit().receipts().len(), 2);
    }

    #[test]
    fn provider_request_and_response_byte_ceilings_fail_closed() {
        let budget = RuntimeBudget::default();
        let mut permit = permit(
            NativeOastProviderLimits::new(1, 1, 4, 1, 4, 5, 1_000).unwrap(),
            budget,
        );
        assert_eq!(
            permit
                .begin_dispatch(NativeOastProviderOperation::Register, 5, 1)
                .unwrap_err()
                .kind(),
            NativeOastProviderErrorKind::RequestByteLimit
        );
        permit
            .begin_dispatch(NativeOastProviderOperation::Register, 4, 1)
            .unwrap();
        assert_eq!(permit.observe_response_bytes(7), 5);
        permit.finish_dispatch(TransportDispatchOutcome::ResponseBudgetReached);
        assert_eq!(
            permit
                .begin_dispatch(NativeOastProviderOperation::Cleanup, 1, 0)
                .unwrap_err()
                .kind(),
            NativeOastProviderErrorKind::ResponseByteLimit
        );
    }

    #[test]
    fn cancellation_and_parent_deadline_are_checked_before_accounting() {
        let budget = RuntimeBudget::default();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = NativeOastProviderPermit::mint(
            "https://oast.example.test/".parse().unwrap(),
            "https://target.example.test/",
            limits(),
            RequestAccountingBroker::new(budget),
            budget,
            cancellation,
            tokio::time::Instant::now().checked_add(Duration::from_secs(1)),
        )
        .unwrap_err();
        assert_eq!(cancelled.kind(), NativeOastProviderErrorKind::Cancelled);

        let elapsed = NativeOastProviderPermit::mint(
            "https://oast.example.test/".parse().unwrap(),
            "https://target.example.test/",
            limits(),
            RequestAccountingBroker::new(budget),
            budget,
            CancellationToken::new(),
            Some(tokio::time::Instant::now()),
        )
        .unwrap_err();
        assert_eq!(
            elapsed.kind(),
            NativeOastProviderErrorKind::DeadlineExceeded
        );
    }

    #[test]
    fn configuration_receipts_and_errors_are_raw_free_and_secret_safe() {
        let config = NativeOastProviderConfiguration::new(
            "https://oast.example.test/",
            "assessment:test",
            [7; 32],
            ADMIN_SECRET.to_vec(),
            limits(),
        )
        .unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("oast.example.test"));
        assert!(!debug.contains("MUST-NOT-LEAK"));

        let origin: PublicOrigin = "https://oast.example.test/".parse().unwrap();
        let receipt = NativeOastProviderReceipt {
            provider_origin: provider_origin_fingerprint(&origin),
            operation: NativeOastProviderOperation::Poll,
            lifecycle_before: NativeOastProviderLifecycle::CallbackAllocated,
            lifecycle_after: NativeOastProviderLifecycle::Polling,
            request_count: 3,
            request_bytes: 19,
            response_bytes: 31,
            callback_allocations: 2,
            poll_number: 1,
            accepted_http_events: 1,
            duplicate_http_events: 2,
            expired: false,
            cleanup_attempted: false,
            cleanup_verified: false,
        };
        assert_eq!(receipt.operation(), NativeOastProviderOperation::Poll);
        assert_eq!(
            receipt.lifecycle_before(),
            NativeOastProviderLifecycle::CallbackAllocated
        );
        assert_eq!(
            receipt.lifecycle_after(),
            NativeOastProviderLifecycle::Polling
        );
        assert_eq!(receipt.request_count(), 3);
        assert_eq!(receipt.request_bytes(), 19);
        assert_eq!(receipt.response_bytes(), 31);
        assert_eq!(receipt.callback_allocations(), 2);
        assert_eq!(receipt.poll_number(), 1);
        assert_eq!(receipt.accepted_http_events(), 1);
        assert_eq!(receipt.duplicate_http_events(), 2);
        assert!(!receipt.expired());
        assert!(!receipt.cleanup_attempted());
        assert!(!receipt.cleanup_verified());
        assert_eq!(
            format!("{:?}", receipt.provider_origin()),
            "NativeOastProviderOriginFingerprint(<opaque>)"
        );
        let error = NativeOastProviderError::with_receipt(
            NativeOastProviderErrorKind::ProviderRejected,
            receipt,
        );
        assert!(error.receipt().is_some());
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("oast.example.test"));
        assert!(!rendered.contains("MUST-NOT-LEAK"));
    }

    #[test]
    fn event_keys_are_domain_separated_and_bind_every_provider_identity() {
        let origin = provider_origin_fingerprint(
            &"https://oast.example.test/"
                .parse::<PublicOrigin>()
                .unwrap(),
        );
        let callback: CallbackId = "BwcHBwcHBwcHBwcHBwcHBw".parse().unwrap();
        let base = provider_event_key(&origin, "BQUFBQUFBQUFBQUFBQUFBQ", &callback, "event-one");
        assert_ne!(
            base,
            provider_event_key(&origin, "BgYGBgYGBgYGBgYGBgYGBg", &callback, "event-one")
        );
        let other_callback: CallbackId = "CAgICAgICAgICAgICAgICA".parse().unwrap();
        assert_ne!(
            base,
            provider_event_key(
                &origin,
                "BQUFBQUFBQUFBQUFBQUFBQ",
                &other_callback,
                "event-one"
            )
        );
        assert_ne!(
            base,
            provider_event_key(&origin, "BQUFBQUFBQUFBQUFBQUFBQ", &callback, "event-two")
        );
    }

    #[test]
    fn poll_page_fact_validation_fails_closed_before_correlation_mutation() {
        let session: SessionId = "BQUFBQUFBQUFBQUFBQUFBQ".parse().unwrap();
        let other_session: SessionId = "BgYGBgYGBgYGBgYGBgYGBg".parse().unwrap();
        let callback: CallbackId = "BwcHBwcHBwcHBwcHBwcHBw".parse().unwrap();
        let other_callback: CallbackId = "CAgICAgICAgICAgICAgICA".parse().unwrap();
        let expected_callbacks = [callback.clone()];
        let observed_callbacks = [callback];
        let previous_cursor = EventCursor::new(2).unwrap();
        let base = NativeOastPollPageFacts {
            schema: POLL_SCHEMA,
            expected_session: &session,
            observed_session: &session,
            previous_cursor,
            next_cursor: previous_cursor,
            complete: true,
            expired: false,
            expected_callbacks: &expected_callbacks,
            observed_callbacks: &observed_callbacks,
            correlations_ready: true,
        };
        assert_eq!(validate_provider_poll_page(base), Ok(()));
        assert_eq!(
            validate_provider_poll_page(NativeOastPollPageFacts {
                schema: "security.termivar-oast.poll/v2",
                ..base
            }),
            Err(NativeOastProviderErrorKind::ProviderResponseInvalid)
        );
        assert_eq!(
            validate_provider_poll_page(NativeOastPollPageFacts {
                observed_session: &other_session,
                ..base
            }),
            Err(NativeOastProviderErrorKind::ProviderSessionMismatch)
        );
        assert_eq!(
            validate_provider_poll_page(NativeOastPollPageFacts {
                complete: false,
                ..base
            }),
            Err(NativeOastProviderErrorKind::ProviderPageIncomplete)
        );
        assert_eq!(
            validate_provider_poll_page(NativeOastPollPageFacts {
                expired: true,
                ..base
            }),
            Err(NativeOastProviderErrorKind::ProviderExpired)
        );
        assert_eq!(
            validate_provider_poll_page(NativeOastPollPageFacts {
                next_cursor: EventCursor::new(1).unwrap(),
                ..base
            }),
            Err(NativeOastProviderErrorKind::ProviderResponseInvalid)
        );
        assert_eq!(
            validate_provider_poll_page(NativeOastPollPageFacts {
                observed_callbacks: std::slice::from_ref(&other_callback),
                ..base
            }),
            Err(NativeOastProviderErrorKind::ProviderCallbackMismatch)
        );
        assert_eq!(
            validate_provider_poll_page(NativeOastPollPageFacts {
                correlations_ready: false,
                ..base
            }),
            Err(NativeOastProviderErrorKind::CorrelationRejected)
        );
    }
}

impl fmt::Debug for NativeOastProviderAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeOastProviderAdapter")
            .field("permit", &self.permit)
            .field("correlations", &self.correlations)
            .field("administrator", &"<redacted>")
            .field("session", &self.session)
            .field("callbacks", &self.callbacks.len())
            .field("lifecycle", &self.lifecycle)
            .field("registration_attempted", &self.registration_attempted)
            .field("callback_attempts", &self.callback_attempts)
            .field("poll_attempts", &self.poll_attempts)
            .field("cleanup_attempted", &self.cleanup_attempted)
            .field("receipts", &self.receipts.len())
            .finish()
    }
}

#[cfg_attr(
    all(not(test), feature = "oast-native-provider"),
    expect(
        dead_code,
        reason = "sealed PR B authority is consumed only by the separately gated ssrf-oast-review capability"
    )
)]
impl NativeOastProviderAdapter {
    pub(crate) fn mint(
        _authority: NativeOastProviderMintToken,
        configuration: NativeOastProviderConfiguration,
        target_origin: &str,
        accounting: RequestAccountingBroker,
        parent_budget: RuntimeBudget,
        cancellation: CancellationToken,
        parent_deadline: Option<tokio::time::Instant>,
    ) -> Result<Self, NativeOastProviderError> {
        let NativeOastProviderConfiguration {
            origin,
            assessment_id,
            epoch,
            administrator,
            limits,
        } = configuration;
        let client = NativeOastClient::new(origin.clone()).map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::ProviderRejected)
        })?;
        let correlation_limits = OastAuthorityLimits::new(
            limits.max_callbacks,
            limits.max_polls,
            termivar_oast::HARD_MAX_POLL_EVENTS_PER_RESPONSE,
            termivar_oast::HARD_MAX_EVENTS_PER_SESSION,
            limits.max_provider_wall_time_ms,
        )
        .map_err(|_| NativeOastProviderError::new(NativeOastProviderErrorKind::InvalidLimits))?;
        let permit = NativeOastProviderPermit::mint(
            origin,
            target_origin,
            limits,
            accounting,
            parent_budget,
            cancellation,
            parent_deadline,
        )?;
        Ok(Self {
            client,
            permit,
            correlations: OastCorrelationAuthority::new(epoch, assessment_id, correlation_limits),
            administrator: Some(administrator),
            session: None,
            callbacks: BTreeMap::new(),
            lifecycle: NativeOastProviderLifecycle::Configured,
            registration_attempted: false,
            callback_attempts: 0,
            poll_attempts: 0,
            cleanup_attempted: false,
            clock_origin: tokio::time::Instant::now(),
            receipts: Vec::new(),
        })
    }

    pub(crate) const fn lifecycle(&self) -> NativeOastProviderLifecycle {
        self.lifecycle
    }

    pub(crate) fn receipts(&self) -> &[NativeOastProviderReceipt] {
        &self.receipts
    }

    pub(crate) fn accounting_snapshot(&self) -> RequestAccountingSnapshot {
        self.permit.accounting.snapshot()
    }

    pub(crate) async fn register(
        &mut self,
    ) -> Result<NativeOastProviderReceipt, NativeOastProviderError> {
        let before = self.lifecycle;
        if !lifecycle_allows(before, NativeOastProviderOperation::Register)
            || self.registration_attempted
        {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::RegistrationLimit,
            ));
        }
        self.registration_attempted = true;
        let administrator = self.administrator.take().ok_or_else(|| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::RegistrationLimit)
        })?;
        let request = SessionRequest::new(
            self.permit.limits.max_provider_wall_time_ms,
            self.permit.limits.max_callbacks,
            termivar_oast::HARD_MAX_EVENTS_PER_SESSION,
            self.permit.limits.max_polls,
        );
        let result = self
            .client
            .register(administrator, request, &mut self.permit)
            .await;
        let dispatch = match result {
            Ok(dispatch) => dispatch,
            Err(error) => {
                return Err(self.client_failure(
                    NativeOastProviderOperation::Register,
                    before,
                    error,
                ))
            },
        };
        self.permit
            .finish_dispatch(TransportDispatchOutcome::Completed);
        let accounting = dispatch.accounting();
        let registration = dispatch.into_value();
        let session_id = registration.session_id().clone();
        let lifetime_ms = registration.expires_after_ms();
        let session_token = registration.take_session_token();
        self.session = Some(NativeOastProviderSession {
            id: session_id,
            token: session_token,
            cursor: EventCursor::default(),
            lifetime_ms,
        });
        self.lifecycle = NativeOastProviderLifecycle::Registered;
        Ok(self.record_receipt(
            NativeOastProviderOperation::Register,
            before,
            self.lifecycle,
            accounting,
            NativeOastProviderReceiptFacts::default(),
        ))
    }

    pub(crate) async fn allocate_callback(
        &mut self,
        verification_case: VerificationCase,
        token: OastCorrelationToken,
    ) -> Result<NativeOastAllocatedCallback, NativeOastProviderError> {
        let before = self.lifecycle;
        if !lifecycle_allows(before, NativeOastProviderOperation::AllocateCallback) {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::InvalidLifecycle,
            ));
        }
        if self.callback_attempts >= self.permit.limits.max_callbacks {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::CallbackLimit,
            ));
        }
        let session = self.session.as_ref().ok_or_else(|| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::InternalInvariant)
        })?;
        let now = self.monotonic_now();
        let lifetime_ms = session.lifetime_ms.min(
            self.permit
                .deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        );
        let lifetime = OastLifetime::from_millis(lifetime_ms.max(1)).map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::CorrelationRejected)
        })?;
        let poll_budget = OastPollBudget::new(self.permit.limits.max_polls).map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::CorrelationRejected)
        })?;
        let protocols = OastProtocolSet::new(false, true).map_err(|_| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::CorrelationRejected)
        })?;
        let (correlation, correlation_receipt) = self
            .correlations
            .register(
                verification_case,
                token,
                protocols,
                now,
                lifetime,
                poll_budget,
            )
            .map_err(|_| {
                NativeOastProviderError::new(NativeOastProviderErrorKind::CorrelationRejected)
            })?;
        self.callback_attempts = self.callback_attempts.saturating_add(1);

        let result = self
            .client
            .allocate_callback(&session.id, &session.token, &mut self.permit)
            .await;
        let dispatch = match result {
            Ok(dispatch) => dispatch,
            Err(error) => {
                return Err(self.client_failure(
                    NativeOastProviderOperation::AllocateCallback,
                    before,
                    error,
                ));
            },
        };
        self.permit
            .finish_dispatch(TransportDispatchOutcome::Completed);
        let accounting = dispatch.accounting();
        let allocation = dispatch.into_value();
        let callback_id = allocation.callback_id().clone();
        if self.callbacks.contains_key(&callback_id) {
            let receipt = self.record_receipt(
                NativeOastProviderOperation::AllocateCallback,
                before,
                before,
                accounting,
                NativeOastProviderReceiptFacts::default(),
            );
            return Err(NativeOastProviderError::with_receipt(
                NativeOastProviderErrorKind::ProviderCallbackMismatch,
                receipt,
            ));
        }
        let target = allocation.take_target();
        self.callbacks.insert(
            callback_id.clone(),
            NativeOastProviderCallback { correlation },
        );
        self.lifecycle = NativeOastProviderLifecycle::CallbackAllocated;
        let provider_receipt = self.record_receipt(
            NativeOastProviderOperation::AllocateCallback,
            before,
            self.lifecycle,
            accounting,
            NativeOastProviderReceiptFacts::default(),
        );
        Ok(NativeOastAllocatedCallback {
            ordinal: u16::try_from(self.callbacks.len()).unwrap_or(u16::MAX),
            callback_id,
            target,
            correlation_receipt,
            provider_receipt,
        })
    }

    pub(crate) async fn poll(&mut self) -> Result<NativeOastPollOutcome, NativeOastProviderError> {
        let before = self.lifecycle;
        if !lifecycle_allows(before, NativeOastProviderOperation::Poll) {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::InvalidLifecycle,
            ));
        }
        if self.poll_attempts >= self.permit.limits.max_polls {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::PollLimit,
            ));
        }
        self.poll_attempts = self.poll_attempts.saturating_add(1);
        let session = self.session.as_ref().ok_or_else(|| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::InternalInvariant)
        })?;
        let result = self
            .client
            .poll(
                &session.id,
                &session.token,
                session.cursor,
                &mut self.permit,
            )
            .await;
        let dispatch = match result {
            Ok(dispatch) => dispatch,
            Err(error) => {
                return Err(self.client_failure(NativeOastProviderOperation::Poll, before, error));
            },
        };
        self.permit
            .finish_dispatch(TransportDispatchOutcome::Completed);
        let (page, accounting) = dispatch.into_parts();
        let now = self.monotonic_now();

        if let Err(kind) = self.validate_poll_page(&page) {
            let receipt = self.record_receipt(
                NativeOastProviderOperation::Poll,
                before,
                before,
                accounting,
                NativeOastProviderReceiptFacts {
                    duplicate_http_events: page
                        .events()
                        .iter()
                        .map(|event| u64::from(event.duplicate_count()))
                        .sum(),
                    expired: page.expired(),
                    ..NativeOastProviderReceiptFacts::default()
                },
            );
            return Err(NativeOastProviderError::with_receipt(kind, receipt));
        }

        let correlation_receipts = match self.reduce_page_atomically(&page, now) {
            Ok(receipts) => receipts,
            Err(error) => {
                let receipt = self.record_receipt(
                    NativeOastProviderOperation::Poll,
                    before,
                    before,
                    accounting,
                    NativeOastProviderReceiptFacts::default(),
                );
                return Err(NativeOastProviderError::with_receipt(error.kind(), receipt));
            },
        };
        let accepted = correlation_receipts.iter().fold(0_u16, |total, receipt| {
            total.saturating_add(receipt.accepted_events())
        });
        let correlation_duplicates = correlation_receipts.iter().fold(0_u64, |total, receipt| {
            total.saturating_add(u64::from(receipt.duplicate_events()))
        });
        let provider_duplicates = page.events().iter().fold(0_u64, |total, event| {
            total.saturating_add(u64::from(event.duplicate_count()))
        });
        if let Some(session) = self.session.as_mut() {
            session.cursor = page.next_cursor();
        }
        self.lifecycle = NativeOastProviderLifecycle::Polling;
        let provider_receipt = self.record_receipt(
            NativeOastProviderOperation::Poll,
            before,
            self.lifecycle,
            accounting,
            NativeOastProviderReceiptFacts {
                accepted_http_events: accepted,
                duplicate_http_events: correlation_duplicates.saturating_add(provider_duplicates),
                ..NativeOastProviderReceiptFacts::default()
            },
        );
        Ok(NativeOastPollOutcome {
            provider_receipt,
            correlation_receipts,
        })
    }

    pub(crate) async fn cleanup(
        &mut self,
    ) -> Result<NativeOastProviderReceipt, NativeOastProviderError> {
        let before = self.lifecycle;
        if !lifecycle_allows(before, NativeOastProviderOperation::Cleanup) || self.cleanup_attempted
        {
            return Err(NativeOastProviderError::new(
                NativeOastProviderErrorKind::InvalidLifecycle,
            ));
        }
        self.cleanup_attempted = true;
        self.lifecycle = NativeOastProviderLifecycle::Closing;
        let session = self.session.as_ref().ok_or_else(|| {
            NativeOastProviderError::new(NativeOastProviderErrorKind::InternalInvariant)
        })?;
        let result = self
            .client
            .cleanup(&session.id, &session.token, &mut self.permit)
            .await;
        self.lifecycle = NativeOastProviderLifecycle::Closed;
        self.session = None;
        match result {
            Ok(dispatch) => {
                self.permit
                    .finish_dispatch(TransportDispatchOutcome::Completed);
                let (cleanup, accounting) = dispatch.into_parts();
                let verified = cleanup.removed();
                let receipt = self.record_receipt(
                    NativeOastProviderOperation::Cleanup,
                    before,
                    self.lifecycle,
                    accounting,
                    NativeOastProviderReceiptFacts {
                        cleanup_verified: verified,
                        ..NativeOastProviderReceiptFacts::default()
                    },
                );
                if verified {
                    Ok(receipt)
                } else {
                    Err(NativeOastProviderError::with_receipt(
                        NativeOastProviderErrorKind::CleanupUnverified,
                        receipt,
                    ))
                }
            },
            Err(error) => {
                Err(self.client_failure(NativeOastProviderOperation::Cleanup, before, error))
            },
        }
    }

    fn validate_poll_page(&self, page: &PollResponse) -> Result<(), NativeOastProviderErrorKind> {
        let session = self
            .session
            .as_ref()
            .ok_or(NativeOastProviderErrorKind::InternalInvariant)?;
        let expected_callbacks = self.callbacks.keys().cloned().collect::<Vec<_>>();
        let observed_callbacks = page
            .events()
            .iter()
            .map(|event| event.callback_id().clone())
            .collect::<Vec<_>>();
        let correlations_ready = self.callbacks.values().all(|callback| {
            callback.correlation.assessment_id() == self.correlations.assessment_id()
                && callback.correlation.state() == OastCorrelationState::Active
                && callback.correlation.remaining_polls() > 0
        });
        validate_provider_poll_page(NativeOastPollPageFacts {
            schema: page.schema(),
            expected_session: &session.id,
            observed_session: page.session_id(),
            previous_cursor: session.cursor,
            next_cursor: page.next_cursor(),
            complete: page.complete(),
            expired: page.expired(),
            expected_callbacks: &expected_callbacks,
            observed_callbacks: &observed_callbacks,
            correlations_ready,
        })
    }

    fn reduce_page_atomically(
        &mut self,
        page: &PollResponse,
        observed_at: OastMonotonicTime,
    ) -> Result<Vec<OastPollReceipt>, NativeOastProviderError> {
        let session_id = self
            .session
            .as_ref()
            .map(|session| session.id.as_str().to_owned())
            .ok_or_else(|| {
                NativeOastProviderError::new(NativeOastProviderErrorKind::InternalInvariant)
            })?;
        let assessment_id = self.correlations.assessment_id().clone();
        let scheme = if self.permit.provider_origin_url.scheme() == "https" {
            OastHttpScheme::Https
        } else {
            OastHttpScheme::Http
        };
        let mut snapshots = self
            .callbacks
            .iter()
            .map(|(id, callback)| (id.clone(), callback.correlation.transactional_snapshot()))
            .collect::<BTreeMap<_, _>>();
        let mut receipts = Vec::with_capacity(snapshots.len());
        for (callback_id, correlation) in &mut snapshots {
            let verification_case = correlation.verification_case().clone();
            let correlation_id = correlation.correlation_id().clone();
            let mut poll = correlation
                .begin_poll(&assessment_id, &verification_case, observed_at)
                .map_err(|_| {
                    NativeOastProviderError::new(NativeOastProviderErrorKind::CorrelationRejected)
                })?;
            for event in page
                .events()
                .iter()
                .filter(|event| event.callback_id() == callback_id)
            {
                let reduced = reduce_provider_http_event(
                    &self.permit.provider_origin_fingerprint,
                    &session_id,
                    callback_id,
                    event.event_id().as_str(),
                    scheme,
                )?;
                poll.stage_event(&correlation_id, reduced, observed_at)
                    .map_err(|_| {
                        NativeOastProviderError::new(
                            NativeOastProviderErrorKind::CorrelationRejected,
                        )
                    })?;
            }
            receipts.push(poll.finish(observed_at).map_err(|_| {
                NativeOastProviderError::new(NativeOastProviderErrorKind::CorrelationRejected)
            })?);
        }

        // No live correlation changes until the complete page has validated
        // and every snapshot has committed successfully.
        if snapshots.len() != self.callbacks.len() {
            return Err(NativeOastProviderError::internal_invariant());
        }
        self.callbacks = snapshots
            .into_iter()
            .map(|(callback_id, correlation)| {
                (callback_id, NativeOastProviderCallback { correlation })
            })
            .collect();
        Ok(receipts)
    }

    fn monotonic_now(&self) -> OastMonotonicTime {
        OastMonotonicTime::from_millis(
            u64::try_from(self.clock_origin.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
    }

    fn client_failure(
        &mut self,
        operation: NativeOastProviderOperation,
        before: NativeOastProviderLifecycle,
        error: NativeOastClientError,
    ) -> NativeOastProviderError {
        let accounting = error.accounting();
        self.permit
            .finish_dispatch(transport_outcome_for_client_error(error.kind()));
        let kind = match error.kind() {
            NativeOastClientErrorKind::BoundaryRejected(_) => self
                .permit
                .take_boundary_error()
                .unwrap_or(NativeOastProviderErrorKind::OperationNotPermitted),
            NativeOastClientErrorKind::Cancelled => NativeOastProviderErrorKind::Cancelled,
            NativeOastClientErrorKind::DeadlineExceeded => {
                NativeOastProviderErrorKind::DeadlineExceeded
            },
            NativeOastClientErrorKind::ResponseTooLarge => {
                NativeOastProviderErrorKind::ResponseByteLimit
            },
            NativeOastClientErrorKind::CallbackTargetMismatch => {
                NativeOastProviderErrorKind::ProviderCallbackMismatch
            },
            NativeOastClientErrorKind::ProtocolMismatch
            | NativeOastClientErrorKind::MalformedResponse
            | NativeOastClientErrorKind::UnsupportedMedia
            | NativeOastClientErrorKind::ResponseOriginMismatch
            | NativeOastClientErrorKind::AccountingInvariant => {
                NativeOastProviderErrorKind::ProviderResponseInvalid
            },
            NativeOastClientErrorKind::ClientInitialization
            | NativeOastClientErrorKind::RequestConstruction
            | NativeOastClientErrorKind::TransportFailure
            | NativeOastClientErrorKind::UnexpectedStatus => {
                NativeOastProviderErrorKind::ProviderRejected
            },
        };
        let after = self.lifecycle;
        let receipt = self.record_receipt(
            operation,
            before,
            after,
            accounting,
            NativeOastProviderReceiptFacts::default(),
        );
        NativeOastProviderError::with_receipt(kind, receipt)
    }

    fn record_receipt(
        &mut self,
        operation: NativeOastProviderOperation,
        before: NativeOastProviderLifecycle,
        after: NativeOastProviderLifecycle,
        accounting: NativeOastDispatchAccounting,
        facts: NativeOastProviderReceiptFacts,
    ) -> NativeOastProviderReceipt {
        let receipt = self.operation_receipt(operation, before, after, accounting, facts);
        self.receipts.push(receipt.clone());
        receipt
    }

    fn operation_receipt(
        &self,
        operation: NativeOastProviderOperation,
        before: NativeOastProviderLifecycle,
        after: NativeOastProviderLifecycle,
        _accounting: NativeOastDispatchAccounting,
        facts: NativeOastProviderReceiptFacts,
    ) -> NativeOastProviderReceipt {
        NativeOastProviderReceipt {
            provider_origin: self.permit.provider_origin_fingerprint.clone(),
            operation,
            lifecycle_before: before,
            lifecycle_after: after,
            request_count: self.permit.provider_requests,
            request_bytes: self.permit.provider_request_bytes,
            response_bytes: self.permit.provider_response_bytes,
            callback_allocations: u16::try_from(self.callbacks.len()).unwrap_or(u16::MAX),
            poll_number: self.poll_attempts,
            accepted_http_events: facts.accepted_http_events,
            duplicate_http_events: facts.duplicate_http_events,
            expired: facts.expired,
            cleanup_attempted: operation == NativeOastProviderOperation::Cleanup,
            cleanup_verified: facts.cleanup_verified,
        }
    }
}

impl NativeOastClientBoundary for NativeOastProviderPermit {
    fn begin(
        &mut self,
        operation: NativeOastClientOperation,
        request_bytes: u64,
        request_body_bytes: u64,
    ) -> Result<(), NativeOastBoundaryRejection> {
        self.last_boundary_error = None;
        let operation = match operation {
            NativeOastClientOperation::Register => NativeOastProviderOperation::Register,
            NativeOastClientOperation::AllocateCallback => {
                NativeOastProviderOperation::AllocateCallback
            },
            NativeOastClientOperation::Poll => NativeOastProviderOperation::Poll,
            NativeOastClientOperation::Cleanup => NativeOastProviderOperation::Cleanup,
        };
        self.begin_dispatch(operation, request_bytes, request_body_bytes)
            .map_err(|error| {
                let rejection = boundary_rejection_for(error.kind());
                self.remember_boundary_error(&error);
                rejection
            })
    }

    fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation
    }

    fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    fn remaining_response_bytes(&self) -> u64 {
        NativeOastProviderPermit::remaining_response_bytes(self)
    }

    fn observe_response_bytes(&mut self, observed: u64) -> u64 {
        NativeOastProviderPermit::observe_response_bytes(self, observed)
    }
}

pub(crate) const fn lifecycle_allows(
    lifecycle: NativeOastProviderLifecycle,
    operation: NativeOastProviderOperation,
) -> bool {
    match operation {
        NativeOastProviderOperation::Register => {
            matches!(lifecycle, NativeOastProviderLifecycle::Configured)
        },
        NativeOastProviderOperation::AllocateCallback => matches!(
            lifecycle,
            NativeOastProviderLifecycle::Registered
                | NativeOastProviderLifecycle::CallbackAllocated
        ),
        NativeOastProviderOperation::Poll => matches!(
            lifecycle,
            NativeOastProviderLifecycle::CallbackAllocated | NativeOastProviderLifecycle::Polling
        ),
        NativeOastProviderOperation::Cleanup => matches!(
            lifecycle,
            NativeOastProviderLifecycle::Registered
                | NativeOastProviderLifecycle::CallbackAllocated
                | NativeOastProviderLifecycle::Polling
        ),
    }
}

fn boundary_rejection_for(kind: NativeOastProviderErrorKind) -> NativeOastBoundaryRejection {
    match kind {
        NativeOastProviderErrorKind::Cancelled => NativeOastBoundaryRejection::Cancelled,
        NativeOastProviderErrorKind::DeadlineExceeded => {
            NativeOastBoundaryRejection::DeadlineExceeded
        },
        NativeOastProviderErrorKind::RequestLimit
        | NativeOastProviderErrorKind::RequestByteLimit
        | NativeOastProviderErrorKind::ResponseByteLimit
        | NativeOastProviderErrorKind::RuntimeBudget(_)
        | NativeOastProviderErrorKind::ParentBudgetTooSmall => {
            NativeOastBoundaryRejection::BudgetExhausted
        },
        NativeOastProviderErrorKind::InternalInvariant => {
            NativeOastBoundaryRejection::AccountingInvariant
        },
        _ => NativeOastBoundaryRejection::OperationNotPermitted,
    }
}

fn transport_outcome_for_client_error(kind: NativeOastClientErrorKind) -> TransportDispatchOutcome {
    match kind {
        NativeOastClientErrorKind::Cancelled => TransportDispatchOutcome::Cancelled,
        NativeOastClientErrorKind::DeadlineExceeded => TransportDispatchOutcome::RequestTimeout,
        NativeOastClientErrorKind::ResponseTooLarge => {
            TransportDispatchOutcome::ResponseBudgetReached
        },
        _ => TransportDispatchOutcome::TransportFailure,
    }
}

#[cfg(all(test, feature = "oast-native-provider"))]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use termivar_core::EntityId;
    use termivar_oast::{
        serve_provider_on_listener, AdminToken, LoopbackBind, ProviderConfig, ProviderLimits,
        ProviderState, CALLBACK_SCHEMA, NATIVE_OAST_PROTOCOL_REVISION, SESSION_SCHEMA,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use crate::{web_runtime::SharedWebRuntimeAuthority, HttpEvidencePolicy};

    const ADMIN_SECRET: &[u8] = b"NATIVE-OAST-ADMIN-MUST-NOT-LEAK-EC8D42";

    fn adapter_limits(max_callbacks: u16, max_polls: u16) -> NativeOastProviderLimits {
        NativeOastProviderLimits::new(
            1,
            max_callbacks,
            16,
            max_polls,
            32 * 1_024,
            256 * 1_024,
            20_000,
        )
        .unwrap()
    }

    fn verification_case(ordinal: u16) -> VerificationCase {
        VerificationCase::new(
            format!("case:oast:{ordinal}"),
            EntityId::new(format!("subject:oast:{ordinal}")).unwrap(),
            "future.ssrf-oast-review",
            format!("hypothesis:oast:{ordinal}"),
        )
        .unwrap()
        .without_hypothesis_transition()
    }

    async fn loopback_adapter(
        max_callbacks: u16,
        max_polls: u16,
    ) -> (
        NativeOastProviderAdapter,
        RequestAccountingBroker,
        JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let bind = LoopbackBind::new(address).unwrap();
        let origin = PublicOrigin::from_test_loopback(address).unwrap();
        let provider_limits = ProviderLimits::new(
            1,
            max_callbacks,
            termivar_oast::HARD_MAX_EVENTS_PER_SESSION,
            max_polls,
            termivar_oast::HARD_MAX_POLL_EVENTS_PER_RESPONSE,
            20_000,
            16,
        )
        .unwrap();
        let provider = ProviderState::new(
            ProviderConfig::new(bind, origin.clone(), provider_limits),
            AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            let _ = serve_provider_on_listener(listener, provider).await;
        });

        let budget = RuntimeBudget::default();
        let target = Url::parse("https://target.example.test/").unwrap();
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &target,
            HttpEvidencePolicy::for_origin(target.clone()).unwrap(),
            budget,
            CancellationToken::new(),
        )
        .unwrap();
        let accounting = authority.request_accounting().clone();
        let configuration = NativeOastProviderConfiguration::for_loopback(
            origin,
            "assessment:native-oast",
            [11; 32],
            ADMIN_SECRET.to_vec(),
            adapter_limits(max_callbacks, max_polls),
        )
        .unwrap();
        let adapter = authority.mint_native_oast_provider(configuration).unwrap();
        (adapter, accounting, task)
    }

    async fn duplicate_callback_adapter() -> (
        NativeOastProviderAdapter,
        RequestAccountingBroker,
        JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = PublicOrigin::from_test_loopback(address).unwrap();
        let session_id = URL_SAFE_NO_PAD.encode([7_u8; 16]);
        let session_token = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        let callback_id = URL_SAFE_NO_PAD.encode([8_u8; 16]);
        let callback_target = format!("{}c/{session_id}/{callback_id}", origin.as_str());
        let registration = serde_json::to_vec(&serde_json::json!({
            "schema": SESSION_SCHEMA,
            "session_id": session_id,
            "session_token": session_token,
            "expires_after_ms": 1_000,
            "protocol_revision": NATIVE_OAST_PROTOCOL_REVISION,
        }))
        .unwrap();
        let allocation = serde_json::to_vec(&serde_json::json!({
            "schema": CALLBACK_SCHEMA,
            "callback_id": callback_id,
            "callback_target": callback_target,
        }))
        .unwrap();
        let task = tokio::spawn(async move {
            for (status, body) in [
                ("201 Created", registration),
                ("201 Created", allocation.clone()),
                ("201 Created", allocation),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0_u8; 16 * 1_024];
                let _ = stream.read(&mut request).await.unwrap();
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let budget = RuntimeBudget::default();
        let target = Url::parse("https://target.example.test/").unwrap();
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &target,
            HttpEvidencePolicy::for_origin(target.clone()).unwrap(),
            budget,
            CancellationToken::new(),
        )
        .unwrap();
        let accounting = authority.request_accounting().clone();
        let configuration = NativeOastProviderConfiguration::for_loopback(
            origin,
            "assessment:native-oast",
            [11; 32],
            ADMIN_SECRET.to_vec(),
            adapter_limits(2, 1),
        )
        .unwrap();
        let adapter = authority.mint_native_oast_provider(configuration).unwrap();
        (adapter, accounting, task)
    }

    #[test]
    fn lifecycle_operation_matrix_is_closed_and_monotonic() {
        use NativeOastProviderLifecycle as Lifecycle;
        use NativeOastProviderOperation as Operation;

        assert!(lifecycle_allows(Lifecycle::Configured, Operation::Register));
        assert!(lifecycle_allows(
            Lifecycle::Registered,
            Operation::AllocateCallback
        ));
        assert!(lifecycle_allows(
            Lifecycle::CallbackAllocated,
            Operation::Poll
        ));
        assert!(lifecycle_allows(Lifecycle::Polling, Operation::Cleanup));
        for operation in [
            Operation::Register,
            Operation::AllocateCallback,
            Operation::Poll,
            Operation::Cleanup,
        ] {
            assert!(!lifecycle_allows(Lifecycle::Closing, operation));
            assert!(!lifecycle_allows(Lifecycle::Closed, operation));
        }
        assert!(!lifecycle_allows(Lifecycle::Configured, Operation::Poll));
        assert!(!lifecycle_allows(
            Lifecycle::Polling,
            Operation::AllocateCallback
        ));
    }

    #[test]
    fn provider_http_reduction_is_truthful_and_raw_free() {
        let origin: PublicOrigin = "https://oast.example.test/".parse().unwrap();
        let fingerprint = provider_origin_fingerprint(&origin);
        let callback: CallbackId = "BwcHBwcHBwcHBwcHBwcHBw".parse().unwrap();
        let event = reduce_provider_http_event(
            &fingerprint,
            "BQUFBQUFBQUFBQUFBQUFBQ",
            &callback,
            "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
            OastHttpScheme::Https,
        )
        .unwrap();
        let OastEvent::Http(_, event) = event else {
            panic!("native provider must reduce only to HTTP")
        };
        assert_eq!(event.scheme(), OastHttpScheme::Https);
        assert_eq!(event.method(), OastHttpMethod::Unknown);
        assert!(!event.body_present());
        let rendered = format!("{event:?} {fingerprint:?}");
        assert!(!rendered.contains("oast.example.test"));
        assert!(!rendered.contains(callback.as_str()));
    }

    #[tokio::test]
    async fn loopback_lifecycle_reduces_one_duplicate_suppressed_http_event_and_cleans_up() {
        let (mut adapter, accounting, task) = loopback_adapter(1, 2).await;
        let registration = adapter.register().await.unwrap();
        assert_eq!(
            registration.lifecycle_before(),
            NativeOastProviderLifecycle::Configured
        );
        assert_eq!(
            registration.lifecycle_after(),
            NativeOastProviderLifecycle::Registered
        );
        assert_eq!(registration.request_count(), 1);
        assert_eq!(
            adapter.register().await.unwrap_err().kind(),
            NativeOastProviderErrorKind::RegistrationLimit
        );

        let allocation = adapter
            .allocate_callback(
                verification_case(1),
                OastCorrelationToken::new([21; 32]).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allocation.ordinal(), 1);
        assert_eq!(allocation.correlation_receipt().poll_limit(), 2);
        assert_eq!(
            allocation.provider_receipt().lifecycle_after(),
            NativeOastProviderLifecycle::CallbackAllocated
        );
        let callback = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for _ in 0..2 {
            assert_eq!(
                callback
                    .get(allocation.target().as_str())
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::NO_CONTENT
            );
        }

        let poll = adapter.poll().await.unwrap();
        assert_eq!(poll.correlation_receipts().len(), 1);
        assert_eq!(poll.correlation_receipts()[0].accepted_events(), 1);
        assert_eq!(poll.provider_receipt().accepted_http_events(), 1);
        assert_eq!(poll.provider_receipt().duplicate_http_events(), 1);
        assert_eq!(adapter.lifecycle(), NativeOastProviderLifecycle::Polling);

        let empty_replay = adapter.poll().await.unwrap();
        assert_eq!(empty_replay.correlation_receipts()[0].accepted_events(), 0);
        let cleanup = adapter.cleanup().await.unwrap();
        assert!(cleanup.cleanup_attempted());
        assert!(cleanup.cleanup_verified());
        assert_eq!(adapter.lifecycle(), NativeOastProviderLifecycle::Closed);
        assert_eq!(adapter.receipts().len(), 5);
        assert_eq!(accounting.snapshot().total_requests(), 5);
        assert_eq!(accounting.snapshot().passive_requests(), 5);
        assert_eq!(accounting.snapshot().active_verifications(), 0);
        assert!(accounting.snapshot().request_body_bytes() > 0);
        assert!(accounting.snapshot().response_bytes() > 0);
        assert!(accounting
            .dispatch_audit()
            .receipts()
            .iter()
            .all(|receipt| {
                receipt.action_id() == NATIVE_OAST_PROVIDER_ACTION_ID
                    && receipt.stage() == DecisionExecutionStage::Passive
            }));
        task.abort();
    }

    #[tokio::test]
    async fn one_provider_page_commits_every_callback_correlation_as_one_atomic_batch() {
        let (mut adapter, accounting, task) = loopback_adapter(2, 1).await;
        adapter.register().await.unwrap();
        let first = adapter
            .allocate_callback(
                verification_case(1),
                OastCorrelationToken::new([22; 32]).unwrap(),
            )
            .await
            .unwrap();
        let second = adapter
            .allocate_callback(
                verification_case(2),
                OastCorrelationToken::new([23; 32]).unwrap(),
            )
            .await
            .unwrap();
        let callback = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for target in [first.target(), second.target()] {
            assert_eq!(
                callback.get(target.as_str()).send().await.unwrap().status(),
                reqwest::StatusCode::NO_CONTENT
            );
        }

        let poll = adapter.poll().await.unwrap();
        assert_eq!(poll.correlation_receipts().len(), 2);
        assert!(poll
            .correlation_receipts()
            .iter()
            .all(|receipt| receipt.accepted_events() == 1));
        assert_eq!(poll.provider_receipt().accepted_http_events(), 2);
        assert_eq!(poll.provider_receipt().duplicate_http_events(), 0);
        assert!(adapter
            .callbacks
            .values()
            .all(|callback| callback.correlation.unique_events() == 1));

        adapter.cleanup().await.unwrap();
        assert_eq!(accounting.snapshot().total_requests(), 5);
        assert_eq!(accounting.snapshot().passive_requests(), 5);
        assert_eq!(accounting.snapshot().active_verifications(), 0);
        task.abort();
    }

    #[tokio::test]
    async fn duplicate_callback_rejection_records_the_dispatched_request_without_retaining_it() {
        let (mut adapter, accounting, task) = duplicate_callback_adapter().await;
        adapter.register().await.unwrap();
        let first = adapter
            .allocate_callback(
                verification_case(1),
                OastCorrelationToken::new([24; 32]).unwrap(),
            )
            .await
            .unwrap();
        let first_callback_id = first.callback_id().clone();

        let error = adapter
            .allocate_callback(
                verification_case(2),
                OastCorrelationToken::new([25; 32]).unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            NativeOastProviderErrorKind::ProviderCallbackMismatch
        );
        let rejected = error.receipt().unwrap();
        assert_eq!(
            rejected.operation(),
            NativeOastProviderOperation::AllocateCallback
        );
        assert_eq!(
            rejected.lifecycle_before(),
            NativeOastProviderLifecycle::CallbackAllocated
        );
        assert_eq!(rejected.lifecycle_after(), rejected.lifecycle_before());
        assert_eq!(rejected.request_count(), 3);
        assert_eq!(rejected.callback_allocations(), 1);

        assert_eq!(adapter.receipts().len(), 3);
        assert_eq!(adapter.receipts().last(), Some(rejected));
        assert_eq!(accounting.snapshot().total_requests(), 3);
        assert!(
            adapter.receipts().len() <= usize::from(adapter.permit.limits.max_provider_requests())
        );
        assert_eq!(adapter.callbacks.len(), 1);
        assert!(adapter.callbacks.contains_key(&first_callback_id));
        assert_eq!(
            adapter.lifecycle(),
            NativeOastProviderLifecycle::CallbackAllocated
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn callback_and_poll_bounds_fail_before_extra_network() {
        let (mut adapter, accounting, task) = loopback_adapter(1, 1).await;
        adapter.register().await.unwrap();
        let allocation = adapter
            .allocate_callback(
                verification_case(1),
                OastCorrelationToken::new([31; 32]).unwrap(),
            )
            .await
            .unwrap();
        let _target = allocation.take_target();
        assert_eq!(
            adapter.accounting_snapshot(),
            accounting.snapshot(),
            "adapter accounting must be the parent broker state"
        );
        let before_callback_rejection = accounting.snapshot().total_requests();
        assert_eq!(
            adapter
                .allocate_callback(
                    verification_case(2),
                    OastCorrelationToken::new([32; 32]).unwrap(),
                )
                .await
                .unwrap_err()
                .kind(),
            NativeOastProviderErrorKind::CallbackLimit
        );
        assert_eq!(
            accounting.snapshot().total_requests(),
            before_callback_rejection
        );
        adapter.poll().await.unwrap();
        let before_poll_rejection = accounting.snapshot().total_requests();
        assert_eq!(
            adapter.poll().await.unwrap_err().kind(),
            NativeOastProviderErrorKind::PollLimit
        );
        assert_eq!(
            accounting.snapshot().total_requests(),
            before_poll_rejection
        );
        adapter.cleanup().await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn dropping_registered_adapter_performs_no_cleanup_network() {
        let (mut adapter, accounting, task) = loopback_adapter(1, 1).await;
        adapter.register().await.unwrap();
        assert_eq!(accounting.snapshot().total_requests(), 1);
        drop(adapter);
        tokio::task::yield_now().await;
        assert_eq!(accounting.snapshot().total_requests(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn failed_poll_commits_no_correlation_state_and_cleanup_failure_closes() {
        let (mut adapter, accounting, task) = loopback_adapter(1, 2).await;
        adapter.register().await.unwrap();
        let _allocation = adapter
            .allocate_callback(
                verification_case(1),
                OastCorrelationToken::new([41; 32]).unwrap(),
            )
            .await
            .unwrap();
        let before = adapter
            .callbacks
            .values()
            .next()
            .map(|callback| {
                (
                    callback.correlation.remaining_polls(),
                    callback.correlation.unique_events(),
                )
            })
            .unwrap();
        task.abort();
        let _ = task.await;

        let poll_error = adapter.poll().await.unwrap_err();
        assert_eq!(
            poll_error.kind(),
            NativeOastProviderErrorKind::ProviderRejected
        );
        assert!(poll_error.receipt().is_some());
        let after = adapter
            .callbacks
            .values()
            .next()
            .map(|callback| {
                (
                    callback.correlation.remaining_polls(),
                    callback.correlation.unique_events(),
                )
            })
            .unwrap();
        assert_eq!(after, before);
        assert_eq!(
            adapter.lifecycle(),
            NativeOastProviderLifecycle::CallbackAllocated
        );

        let before_cleanup = accounting.snapshot().total_requests();
        let cleanup_error = adapter.cleanup().await.unwrap_err();
        assert_eq!(
            cleanup_error.kind(),
            NativeOastProviderErrorKind::ProviderRejected
        );
        let receipt = cleanup_error.receipt().unwrap();
        assert!(receipt.cleanup_attempted());
        assert!(!receipt.cleanup_verified());
        assert_eq!(adapter.lifecycle(), NativeOastProviderLifecycle::Closed);
        assert_eq!(
            accounting.snapshot().total_requests(),
            before_cleanup + 1,
            "a failed cleanup is still one metered provider dispatch"
        );
        let requests_after_failure = accounting.snapshot().total_requests();
        assert_eq!(
            adapter.cleanup().await.unwrap_err().kind(),
            NativeOastProviderErrorKind::InvalidLifecycle
        );
        assert_eq!(
            accounting.snapshot().total_requests(),
            requests_after_failure
        );
    }

    #[test]
    fn provider_error_vocabulary_is_complete_static_and_raw_free() {
        let kinds = [
            NativeOastProviderErrorKind::InvalidLimits,
            NativeOastProviderErrorKind::InvalidProviderOrigin,
            NativeOastProviderErrorKind::ProviderTargetOriginOverlap,
            NativeOastProviderErrorKind::AuthorityAlreadyMinted,
            NativeOastProviderErrorKind::ParentBudgetTooSmall,
            NativeOastProviderErrorKind::OperationNotPermitted,
            NativeOastProviderErrorKind::InvalidLifecycle,
            NativeOastProviderErrorKind::RegistrationLimit,
            NativeOastProviderErrorKind::CallbackLimit,
            NativeOastProviderErrorKind::RequestLimit,
            NativeOastProviderErrorKind::RequestByteLimit,
            NativeOastProviderErrorKind::ResponseByteLimit,
            NativeOastProviderErrorKind::PollLimit,
            NativeOastProviderErrorKind::Cancelled,
            NativeOastProviderErrorKind::DeadlineExceeded,
            NativeOastProviderErrorKind::RuntimeBudget(RuntimeBudgetDimension::TotalRequests),
            NativeOastProviderErrorKind::ProviderRejected,
            NativeOastProviderErrorKind::ProviderResponseInvalid,
            NativeOastProviderErrorKind::ProviderSessionMismatch,
            NativeOastProviderErrorKind::ProviderCallbackMismatch,
            NativeOastProviderErrorKind::ProviderPageIncomplete,
            NativeOastProviderErrorKind::ProviderExpired,
            NativeOastProviderErrorKind::CorrelationRejected,
            NativeOastProviderErrorKind::CleanupUnverified,
            NativeOastProviderErrorKind::InternalInvariant,
        ];

        for kind in kinds {
            let error = NativeOastProviderError::new(kind);
            let display = error.to_string();
            let debug = format!("{error:?}");
            assert!(!display.is_empty());
            assert!(!display.contains("oast.example.test"));
            assert!(!display.contains("MUST-NOT-LEAK"));
            assert!(!debug.contains("oast.example.test"));
            assert!(!debug.contains("MUST-NOT-LEAK"));
        }

        assert_eq!(
            NativeOastProviderError::internal_invariant().kind(),
            NativeOastProviderErrorKind::InternalInvariant
        );
    }

    #[test]
    fn configuration_rejects_each_untrusted_identity_without_secret_echo() {
        let limits = adapter_limits(1, 1);
        let invalid = [
            NativeOastProviderConfiguration::new(
                "https://oast.example.test/",
                "assessment:native-oast",
                [11; 32],
                Vec::new(),
                limits,
            )
            .unwrap_err(),
            NativeOastProviderConfiguration::new(
                "http://oast.example.test/",
                "assessment:native-oast",
                [11; 32],
                ADMIN_SECRET.to_vec(),
                limits,
            )
            .unwrap_err(),
            NativeOastProviderConfiguration::new(
                "https://oast.example.test/",
                "",
                [11; 32],
                ADMIN_SECRET.to_vec(),
                limits,
            )
            .unwrap_err(),
            NativeOastProviderConfiguration::new(
                "https://oast.example.test/",
                "assessment:native-oast",
                [0; 32],
                ADMIN_SECRET.to_vec(),
                limits,
            )
            .unwrap_err(),
        ];
        assert_eq!(
            invalid[0].kind(),
            NativeOastProviderErrorKind::ProviderRejected
        );
        assert_eq!(
            invalid[1].kind(),
            NativeOastProviderErrorKind::InvalidProviderOrigin
        );
        assert_eq!(
            invalid[2].kind(),
            NativeOastProviderErrorKind::CorrelationRejected
        );
        assert_eq!(
            invalid[3].kind(),
            NativeOastProviderErrorKind::CorrelationRejected
        );
        for error in invalid {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("oast.example.test"));
            assert!(!rendered.contains("MUST-NOT-LEAK"));
        }

        let origin = PublicOrigin::from_test_loopback("127.0.0.1:1".parse().unwrap()).unwrap();
        for error in [
            NativeOastProviderConfiguration::for_loopback(
                origin.clone(),
                "assessment:native-oast",
                [11; 32],
                Vec::new(),
                limits,
            )
            .unwrap_err(),
            NativeOastProviderConfiguration::for_loopback(
                origin.clone(),
                "",
                [11; 32],
                ADMIN_SECRET.to_vec(),
                limits,
            )
            .unwrap_err(),
            NativeOastProviderConfiguration::for_loopback(
                origin,
                "assessment:native-oast",
                [0; 32],
                ADMIN_SECRET.to_vec(),
                limits,
            )
            .unwrap_err(),
        ] {
            assert!(!format!("{error:?} {error}").contains("MUST-NOT-LEAK"));
        }
    }

    #[tokio::test]
    async fn live_adapter_debug_redacts_provider_session_callback_and_secret_state() {
        let (mut adapter, _accounting, task) = loopback_adapter(1, 1).await;
        assert!(!format!("{adapter:?}").contains("MUST-NOT-LEAK"));
        adapter.register().await.unwrap();
        let allocation = adapter
            .allocate_callback(
                verification_case(51),
                OastCorrelationToken::new([51; 32]).unwrap(),
            )
            .await
            .unwrap();

        let target = allocation.target().as_str().to_owned();
        let rendered = format!("{adapter:?} {allocation:?}");
        assert!(!rendered.contains("MUST-NOT-LEAK"));
        assert!(!rendered.contains("127.0.0.1"));
        assert!(!rendered.contains(&target));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("<opaque>"));

        adapter.cleanup().await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn invalid_lifecycle_and_terminal_boundaries_fail_before_network() {
        let (mut adapter, accounting, task) = loopback_adapter(1, 1).await;
        assert_eq!(
            adapter
                .allocate_callback(
                    verification_case(61),
                    OastCorrelationToken::new([61; 32]).unwrap(),
                )
                .await
                .unwrap_err()
                .kind(),
            NativeOastProviderErrorKind::InvalidLifecycle
        );
        assert_eq!(
            adapter.poll().await.unwrap_err().kind(),
            NativeOastProviderErrorKind::InvalidLifecycle
        );
        assert_eq!(
            adapter.cleanup().await.unwrap_err().kind(),
            NativeOastProviderErrorKind::InvalidLifecycle
        );
        assert_eq!(accounting.snapshot().total_requests(), 0);

        adapter.permit.cancellation.cancel();
        let cancelled = adapter.register().await.unwrap_err();
        assert_eq!(cancelled.kind(), NativeOastProviderErrorKind::Cancelled);
        assert_eq!(
            cancelled.receipt().unwrap().operation(),
            NativeOastProviderOperation::Register
        );
        assert_eq!(accounting.snapshot().total_requests(), 0);
        assert_eq!(
            adapter.register().await.unwrap_err().kind(),
            NativeOastProviderErrorKind::RegistrationLimit
        );
        task.abort();

        let (mut elapsed, elapsed_accounting, elapsed_task) = loopback_adapter(1, 1).await;
        elapsed.permit.deadline = tokio::time::Instant::now();
        let deadline = elapsed.register().await.unwrap_err();
        assert_eq!(
            deadline.kind(),
            NativeOastProviderErrorKind::DeadlineExceeded
        );
        assert_eq!(elapsed_accounting.snapshot().total_requests(), 0);
        elapsed_task.abort();
    }

    #[test]
    fn permit_boundary_preserves_invariants_and_shared_budget_failures() {
        let budget = RuntimeBudget::default();
        let mut permit = NativeOastProviderPermit::mint(
            "https://oast.example.test/".parse().unwrap(),
            "https://target.example.test/",
            adapter_limits(1, 1),
            RequestAccountingBroker::new(budget),
            budget,
            CancellationToken::new(),
            tokio::time::Instant::now().checked_add(Duration::from_secs(1)),
        )
        .unwrap();
        assert_eq!(permit.observe_response_bytes(17), 0);
        permit
            .begin_dispatch(NativeOastProviderOperation::Register, 1, 0)
            .unwrap();
        assert_eq!(
            NativeOastClientBoundary::begin(&mut permit, NativeOastClientOperation::Poll, 1, 0,),
            Err(NativeOastBoundaryRejection::AccountingInvariant)
        );
        assert_eq!(
            permit.take_boundary_error(),
            Some(NativeOastProviderErrorKind::InternalInvariant)
        );
        permit.finish_dispatch(TransportDispatchOutcome::Completed);

        let constrained = RuntimeBudget::default().with_max_total_requests(2);
        let accounting = RequestAccountingBroker::new(constrained);
        let mut exhausted = NativeOastProviderPermit::mint(
            "https://oast.example.test/".parse().unwrap(),
            "https://target.example.test/",
            NativeOastProviderLimits::new(1, 1, 2, 1, 128, 128, 1_000).unwrap(),
            accounting.clone(),
            constrained,
            CancellationToken::new(),
            tokio::time::Instant::now().checked_add(Duration::from_secs(1)),
        )
        .unwrap();
        for action in ["test.consume.one", "test.consume.two"] {
            let mut lease = accounting
                .try_begin(action, DecisionExecutionStage::Passive, None)
                .unwrap();
            lease.finish(TransportDispatchOutcome::Completed);
        }
        assert_eq!(
            NativeOastClientBoundary::begin(
                &mut exhausted,
                NativeOastClientOperation::Register,
                1,
                0,
            ),
            Err(NativeOastBoundaryRejection::BudgetExhausted)
        );
        assert_eq!(
            exhausted.take_boundary_error(),
            Some(NativeOastProviderErrorKind::RuntimeBudget(
                RuntimeBudgetDimension::TotalRequests
            ))
        );
        assert_eq!(accounting.snapshot().total_requests(), 2);
    }

    #[test]
    fn boundary_and_transport_error_mapping_is_exact() {
        assert_eq!(
            boundary_rejection_for(NativeOastProviderErrorKind::Cancelled),
            NativeOastBoundaryRejection::Cancelled
        );
        assert_eq!(
            boundary_rejection_for(NativeOastProviderErrorKind::DeadlineExceeded),
            NativeOastBoundaryRejection::DeadlineExceeded
        );
        for kind in [
            NativeOastProviderErrorKind::RequestLimit,
            NativeOastProviderErrorKind::RequestByteLimit,
            NativeOastProviderErrorKind::ResponseByteLimit,
            NativeOastProviderErrorKind::RuntimeBudget(RuntimeBudgetDimension::TotalRequests),
            NativeOastProviderErrorKind::ParentBudgetTooSmall,
        ] {
            assert_eq!(
                boundary_rejection_for(kind),
                NativeOastBoundaryRejection::BudgetExhausted
            );
        }
        assert_eq!(
            boundary_rejection_for(NativeOastProviderErrorKind::InternalInvariant),
            NativeOastBoundaryRejection::AccountingInvariant
        );
        assert_eq!(
            boundary_rejection_for(NativeOastProviderErrorKind::InvalidLifecycle),
            NativeOastBoundaryRejection::OperationNotPermitted
        );

        assert_eq!(
            transport_outcome_for_client_error(NativeOastClientErrorKind::Cancelled),
            TransportDispatchOutcome::Cancelled
        );
        assert_eq!(
            transport_outcome_for_client_error(NativeOastClientErrorKind::DeadlineExceeded),
            TransportDispatchOutcome::RequestTimeout
        );
        assert_eq!(
            transport_outcome_for_client_error(NativeOastClientErrorKind::ResponseTooLarge),
            TransportDispatchOutcome::ResponseBudgetReached
        );
        assert_eq!(
            transport_outcome_for_client_error(NativeOastClientErrorKind::MalformedResponse),
            TransportDispatchOutcome::TransportFailure
        );
    }
}
