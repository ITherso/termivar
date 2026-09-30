//! Bounded active TLS negotiation review for one exact authorized HTTPS peer.
//!
//! The runtime sends only TLS handshake and close-notify bytes. It never sends
//! HTTP, application data, credentials, client certificates, early data, or
//! ALPN offers. Two network-capable cells (TLS 1.3 then TLS 1.2) share the
//! parent assessment's request, response-byte, cancellation, and deadline
//! authority. Legacy rows are explicit zero-network backend limitations.

use std::{
    collections::BTreeSet,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{lookup_host, TcpStream},
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, ServerName},
        ClientConfig, RootCertStore,
    },
    TlsConnector,
};
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use crate::{
    runtime_budget::{RequestAccountingBroker, RequestAccountingLease},
    DecisionExecutionStage, RuntimeBudgetDimension, TransportDispatchOutcome,
    HARD_MAX_TRANSPORT_DISPATCH_RECEIPTS,
};

/// Stable capability identity for active TLS negotiation review.
pub const TLS_NEGOTIATION_REVIEW_CAPABILITY_ID: &str = "web.tls-negotiation-review";
/// Stable audit schema for the active TLS matrix.
pub const TLS_NEGOTIATION_REVIEW_AUDIT_SCHEMA: &str = "security.tls-negotiation-review-audit/v1";
/// Stable policy identity for the fixed initial matrix.
pub const TLS_NEGOTIATION_REVIEW_POLICY_ID: &str = "termivar.active-tls-negotiation-review/v1";
/// Parent-accounted action identity for the TLS 1.3 cell.
pub const TLS_NEGOTIATION_REVIEW_ACTION_TLS13: &str = "web.review.tls-negotiation.tls13@1";
/// Parent-accounted action identity for the TLS 1.2 cell.
pub const TLS_NEGOTIATION_REVIEW_ACTION_TLS12: &str = "web.review.tls-negotiation.tls12@1";

pub(crate) const TLS_NEGOTIATION_ACTIVE_VERIFICATION_ALLOWANCE: u16 = 2;
const MAX_CELL_INGRESS_TLS_BYTES: u64 = 128 * 1024;
const MAX_TOTAL_INGRESS_TLS_BYTES: u64 = 256 * 1024;
const MAX_CELL_EGRESS_TLS_BYTES: u64 = 64 * 1024;
const MAX_TOTAL_EGRESS_TLS_BYTES: u64 = 128 * 1024;
const MAX_RESOLVED_ADDRESSES: usize = 16;
const CELL_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SINGLE_RAW_READ: usize = 16 * 1024;

const NETWORK_CELL_COUNT: usize = 2;
const MATRIX_CELL_COUNT: usize = 5;

/// Returns whether an explicitly selected URL can be represented by the
/// active TLS matrix's exact DNS host/SNI/port authority.
///
/// This is a local preflight predicate. It performs no DNS or network access.
pub fn tls_negotiation_review_target_is_supported(target: &Url) -> bool {
    matches!(target.host(), Some(Host::Domain(host))
        if !host.is_empty() && ServerName::try_from(host.to_owned()).is_ok())
        && target.scheme() == "https"
        && target.username().is_empty()
        && target.password().is_none()
        && target.port_or_known_default().is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CellId {
    Tls13DefaultProvider,
    Tls12DefaultProvider,
    Tls11LegacyProtocol,
    Tls10LegacyProtocol,
    LegacyCipherSuites,
}

impl CellId {
    const fn token(self) -> &'static str {
        match self {
            Self::Tls13DefaultProvider => "tls13_default_provider",
            Self::Tls12DefaultProvider => "tls12_default_provider",
            Self::Tls11LegacyProtocol => "tls11_legacy_protocol",
            Self::Tls10LegacyProtocol => "tls10_legacy_protocol",
            Self::LegacyCipherSuites => "legacy_cipher_suites",
        }
    }

    const fn offered_protocol(self) -> &'static str {
        match self {
            Self::Tls13DefaultProvider => "tls1.3",
            Self::Tls12DefaultProvider => "tls1.2",
            Self::Tls11LegacyProtocol => "tls1.1",
            Self::Tls10LegacyProtocol => "tls1.0",
            Self::LegacyCipherSuites => "legacy_cipher_suites",
        }
    }

    const fn action_id(self) -> Option<&'static str> {
        match self {
            Self::Tls13DefaultProvider => Some(TLS_NEGOTIATION_REVIEW_ACTION_TLS13),
            Self::Tls12DefaultProvider => Some(TLS_NEGOTIATION_REVIEW_ACTION_TLS12),
            Self::Tls11LegacyProtocol | Self::Tls10LegacyProtocol | Self::LegacyCipherSuites => {
                None
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchStatus {
    Dispatched,
    NotDispatched,
}

impl DispatchStatus {
    const fn token(self) -> &'static str {
        match self {
            Self::Dispatched => "dispatched",
            Self::NotDispatched => "not_dispatched",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CellOutcome {
    Negotiated,
    PeerAlertReceived,
    CertificateValidationFailed,
    HandshakeFailed,
    TransportFailed,
    ClientBackendUnsupported,
    ParentAuthorityUnavailable,
    BudgetExhausted,
    Cancelled,
    DeadlineReached,
    NotReached,
}

impl CellOutcome {
    const fn token(self) -> &'static str {
        match self {
            Self::Negotiated => "negotiated",
            Self::PeerAlertReceived => "peer_alert_received",
            Self::CertificateValidationFailed => "certificate_validation_failed",
            Self::HandshakeFailed => "handshake_failed",
            Self::TransportFailed => "transport_failed",
            Self::ClientBackendUnsupported => "client_backend_unsupported",
            Self::ParentAuthorityUnavailable => "parent_authority_unavailable",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Cancelled => "cancelled",
            Self::DeadlineReached => "deadline_reached",
            Self::NotReached => "not_reached",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportState {
    ObservedSupported,
    NotEstablished,
    NotTestedClientBackendUnsupported,
}

impl SupportState {
    const fn token(self) -> &'static str {
        match self {
            Self::ObservedSupported => "observed_supported",
            Self::NotEstablished => "not_established",
            Self::NotTestedClientBackendUnsupported => "not_tested_client_backend_unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportValidation {
    Succeeded,
    NotEstablished,
    NotApplicable,
}

impl TransportValidation {
    const fn token(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::NotEstablished => "not_established",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewTerminal {
    Completed,
    ParentAuthorityUnavailable,
    BudgetExhausted,
    Cancelled,
    DeadlineReached,
}

impl ReviewTerminal {
    const fn token(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::ParentAuthorityUnavailable => "parent_authority_unavailable",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Cancelled => "cancelled",
            Self::DeadlineReached => "deadline_reached",
        }
    }
}

/// One fixed row in the bounded negotiation matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAssessmentTlsNegotiationReviewCell {
    id: CellId,
    dispatch_status: DispatchStatus,
    outcome: CellOutcome,
    support: SupportState,
    transport_validation: TransportValidation,
    negotiated_protocol: Option<&'static str>,
    negotiated_cipher_suite: Option<&'static str>,
    accounted_ingress_tls_bytes: u64,
    observed_egress_tls_bytes: u64,
}

impl WebAssessmentTlsNegotiationReviewCell {
    /// Stable matrix-row identity.
    pub const fn id(&self) -> &'static str {
        self.id.token()
    }

    /// Protocol or legacy family deliberately represented by this row.
    pub const fn offered_protocol(&self) -> &'static str {
        self.id.offered_protocol()
    }

    /// Closed client-backend identity; no server property is inferred from it.
    pub const fn client_backend(&self) -> &'static str {
        "rustls-ring"
    }

    /// Whether a parent-accounted connection attempt was dispatched.
    pub const fn dispatch_status(&self) -> &'static str {
        self.dispatch_status.token()
    }

    /// Closed result of this exact client attempt.
    pub const fn outcome(&self) -> &'static str {
        self.outcome.token()
    }

    /// Narrow support interpretation established by this cell.
    pub const fn support(&self) -> &'static str {
        self.support.token()
    }

    /// Whether standard certificate/transport validation completed.
    pub const fn transport_validation(&self) -> &'static str {
        self.transport_validation.token()
    }

    /// Negotiated protocol only after a successful handshake.
    pub const fn negotiated_protocol(&self) -> Option<&'static str> {
        self.negotiated_protocol
    }

    /// Negotiated cipher suite only after a successful handshake.
    pub const fn negotiated_cipher_suite(&self) -> Option<&'static str> {
        self.negotiated_cipher_suite
    }

    /// Raw TLS ingress bytes charged to the parent response-byte authority.
    pub const fn accounted_ingress_tls_bytes(&self) -> u64 {
        self.accounted_ingress_tls_bytes
    }

    /// Raw TLS egress bytes observed for this handshake, audit-only.
    pub const fn observed_egress_tls_bytes(&self) -> u64 {
        self.observed_egress_tls_bytes
    }

    fn pending(id: CellId) -> Self {
        Self {
            id,
            dispatch_status: DispatchStatus::NotDispatched,
            outcome: CellOutcome::NotReached,
            support: SupportState::NotEstablished,
            transport_validation: TransportValidation::NotEstablished,
            negotiated_protocol: None,
            negotiated_cipher_suite: None,
            accounted_ingress_tls_bytes: 0,
            observed_egress_tls_bytes: 0,
        }
    }

    fn backend_unsupported(id: CellId) -> Self {
        Self {
            id,
            dispatch_status: DispatchStatus::NotDispatched,
            outcome: CellOutcome::ClientBackendUnsupported,
            support: SupportState::NotTestedClientBackendUnsupported,
            transport_validation: TransportValidation::NotApplicable,
            negotiated_protocol: None,
            negotiated_cipher_suite: None,
            accounted_ingress_tls_bytes: 0,
            observed_egress_tls_bytes: 0,
        }
    }
}

/// Value-free bounded active TLS matrix produced by one assessment authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAssessmentTlsNegotiationReviewAudit {
    terminal: ReviewTerminal,
    attempted_connection_count: u8,
    completed_handshake_count: u8,
    accounted_ingress_tls_bytes: u64,
    observed_egress_tls_bytes: u64,
    cells: Vec<WebAssessmentTlsNegotiationReviewCell>,
}

impl WebAssessmentTlsNegotiationReviewAudit {
    /// Stable audit schema.
    pub const fn schema(&self) -> &'static str {
        TLS_NEGOTIATION_REVIEW_AUDIT_SCHEMA
    }

    /// Stable fixed-matrix policy identity.
    pub const fn policy(&self) -> &'static str {
        TLS_NEGOTIATION_REVIEW_POLICY_ID
    }

    /// The audit exists only when explicitly selected.
    pub const fn selected(&self) -> bool {
        true
    }

    /// Overall matrix-processing terminal state.
    pub const fn terminal(&self) -> &'static str {
        self.terminal.token()
    }

    /// Parent-accounted network cells actually admitted.
    pub const fn attempted_connection_count(&self) -> u8 {
        self.attempted_connection_count
    }

    /// Whether every network-capable row reached the parent-accounted dispatch
    /// boundary and matrix processing ended normally. Individual handshakes may
    /// still fail; this is coverage completeness, not server support.
    pub(crate) const fn network_matrix_complete(&self) -> bool {
        matches!(self.terminal, ReviewTerminal::Completed)
            && self.attempted_connection_count == NETWORK_CELL_COUNT as u8
    }

    /// Successfully completed TLS handshakes.
    pub const fn completed_handshake_count(&self) -> u8 {
        self.completed_handshake_count
    }

    /// Aggregate raw TLS ingress charged to the parent response-byte budget.
    pub const fn accounted_ingress_tls_bytes(&self) -> u64 {
        self.accounted_ingress_tls_bytes
    }

    /// Aggregate raw TLS egress observed by this child runtime.
    pub const fn observed_egress_tls_bytes(&self) -> u64 {
        self.observed_egress_tls_bytes
    }

    /// Fixed five-row matrix in policy order.
    pub fn cells(&self) -> &[WebAssessmentTlsNegotiationReviewCell] {
        &self.cells
    }

    pub(crate) fn parent_authority_unavailable() -> Self {
        let mut audit = Self::empty();
        audit.terminal = ReviewTerminal::ParentAuthorityUnavailable;
        for cell in audit.cells.iter_mut().take(NETWORK_CELL_COUNT) {
            cell.outcome = CellOutcome::ParentAuthorityUnavailable;
        }
        audit
    }

    fn empty() -> Self {
        Self {
            terminal: ReviewTerminal::Completed,
            attempted_connection_count: 0,
            completed_handshake_count: 0,
            accounted_ingress_tls_bytes: 0,
            observed_egress_tls_bytes: 0,
            cells: vec![
                WebAssessmentTlsNegotiationReviewCell::pending(CellId::Tls13DefaultProvider),
                WebAssessmentTlsNegotiationReviewCell::pending(CellId::Tls12DefaultProvider),
                WebAssessmentTlsNegotiationReviewCell::backend_unsupported(
                    CellId::Tls11LegacyProtocol,
                ),
                WebAssessmentTlsNegotiationReviewCell::backend_unsupported(
                    CellId::Tls10LegacyProtocol,
                ),
                WebAssessmentTlsNegotiationReviewCell::backend_unsupported(
                    CellId::LegacyCipherSuites,
                ),
            ],
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        if self.cells.len() != MATRIX_CELL_COUNT
            || self.attempted_connection_count > NETWORK_CELL_COUNT as u8
            || self.completed_handshake_count > self.attempted_connection_count
        {
            return false;
        }
        let expected = [
            CellId::Tls13DefaultProvider,
            CellId::Tls12DefaultProvider,
            CellId::Tls11LegacyProtocol,
            CellId::Tls10LegacyProtocol,
            CellId::LegacyCipherSuites,
        ];
        if self
            .cells
            .iter()
            .zip(expected)
            .any(|(cell, id)| cell.id != id)
        {
            return false;
        }
        let attempted = self
            .cells
            .iter()
            .filter(|cell| cell.dispatch_status == DispatchStatus::Dispatched)
            .count();
        let completed = self
            .cells
            .iter()
            .filter(|cell| cell.outcome == CellOutcome::Negotiated)
            .count();
        let ingress = self.cells.iter().try_fold(0_u64, |total, cell| {
            total.checked_add(cell.accounted_ingress_tls_bytes)
        });
        let egress = self.cells.iter().try_fold(0_u64, |total, cell| {
            total.checked_add(cell.observed_egress_tls_bytes)
        });
        if attempted != usize::from(self.attempted_connection_count)
            || completed != usize::from(self.completed_handshake_count)
            || ingress != Some(self.accounted_ingress_tls_bytes)
            || egress != Some(self.observed_egress_tls_bytes)
            || self.accounted_ingress_tls_bytes > MAX_TOTAL_INGRESS_TLS_BYTES
            || self.observed_egress_tls_bytes > MAX_TOTAL_EGRESS_TLS_BYTES
        {
            return false;
        }
        if self.terminal == ReviewTerminal::ParentAuthorityUnavailable
            && self.cells[..NETWORK_CELL_COUNT]
                .iter()
                .any(|cell| cell.outcome != CellOutcome::ParentAuthorityUnavailable)
        {
            return false;
        }
        self.cells.iter().enumerate().all(|(index, cell)| {
            let negotiated = cell.outcome == CellOutcome::Negotiated;
            let fields_are_consistent = negotiated
                == (cell.negotiated_protocol.is_some()
                    && cell.negotiated_cipher_suite.is_some()
                    && cell.support == SupportState::ObservedSupported
                    && cell.transport_validation == TransportValidation::Succeeded);
            let unsupported = matches!(
                cell.id,
                CellId::Tls11LegacyProtocol
                    | CellId::Tls10LegacyProtocol
                    | CellId::LegacyCipherSuites
            );
            let network_row_is_consistent = index >= NETWORK_CELL_COUNT
                || match cell.dispatch_status {
                    DispatchStatus::Dispatched => matches!(
                        cell.outcome,
                        CellOutcome::Negotiated
                            | CellOutcome::PeerAlertReceived
                            | CellOutcome::CertificateValidationFailed
                            | CellOutcome::HandshakeFailed
                            | CellOutcome::TransportFailed
                            | CellOutcome::BudgetExhausted
                            | CellOutcome::Cancelled
                            | CellOutcome::DeadlineReached
                    ),
                    DispatchStatus::NotDispatched => {
                        cell.accounted_ingress_tls_bytes == 0
                            && cell.observed_egress_tls_bytes == 0
                            && matches!(
                                cell.outcome,
                                CellOutcome::ParentAuthorityUnavailable
                                    | CellOutcome::BudgetExhausted
                                    | CellOutcome::Cancelled
                                    | CellOutcome::DeadlineReached
                                    | CellOutcome::NotReached
                            )
                    },
                };
            let negotiated_profile_is_consistent =
                !negotiated || cell.negotiated_protocol == Some(cell.id.offered_protocol());
            let non_negotiated_fields_are_consistent = unsupported
                || negotiated
                || (cell.negotiated_protocol.is_none()
                    && cell.negotiated_cipher_suite.is_none()
                    && cell.support == SupportState::NotEstablished
                    && cell.transport_validation == TransportValidation::NotEstablished);
            fields_are_consistent
                && network_row_is_consistent
                && negotiated_profile_is_consistent
                && non_negotiated_fields_are_consistent
                && cell.accounted_ingress_tls_bytes <= MAX_CELL_INGRESS_TLS_BYTES
                && cell.observed_egress_tls_bytes <= MAX_CELL_EGRESS_TLS_BYTES
                && (!unsupported
                    || (cell.dispatch_status == DispatchStatus::NotDispatched
                        && cell.outcome == CellOutcome::ClientBackendUnsupported
                        && cell.support == SupportState::NotTestedClientBackendUnsupported
                        && cell.transport_validation == TransportValidation::NotApplicable
                        && cell.accounted_ingress_tls_bytes == 0
                        && cell.observed_egress_tls_bytes == 0))
        })
    }
}

/// Closed fixture-only connection/trust data minted by the parent authority.
#[derive(Clone)]
pub(crate) struct TlsNegotiationOwnedTransportProfile {
    resolved_address: SocketAddr,
    root_certificate_der: Vec<u8>,
}

impl TlsNegotiationOwnedTransportProfile {
    pub(crate) fn new(resolved_address: SocketAddr, root_certificate_der: Vec<u8>) -> Self {
        Self {
            resolved_address,
            root_certificate_der,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum TlsNegotiationReviewMintError {
    #[error("TLS negotiation endpoint is outside the selected authority")]
    EndpointOutsideAuthority,
    #[error("TLS negotiation requires one credential-free DNS HTTPS target")]
    UnsupportedTarget,
    #[error("TLS negotiation authority has already been consumed")]
    AuthorityAlreadyMinted,
    #[error("TLS negotiation client configuration is unavailable")]
    ClientConfiguration,
    #[error("TLS negotiation authority invariant failed")]
    InternalInvariant,
}

/// Single-use child runtime minted by [`super::SharedWebRuntimeAuthority`].
pub(crate) struct TlsNegotiationReviewRuntime {
    host: String,
    port: u16,
    fixed_address: Option<SocketAddr>,
    tls13: Arc<ClientConfig>,
    tls12: Arc<ClientConfig>,
    accounting: RequestAccountingBroker,
    cancellation: CancellationToken,
    parent_deadline: Option<tokio::time::Instant>,
}

impl TlsNegotiationReviewRuntime {
    pub(crate) fn new(
        target: &Url,
        accounting: RequestAccountingBroker,
        cancellation: CancellationToken,
        parent_deadline: Option<tokio::time::Instant>,
        owned_profile: Option<TlsNegotiationOwnedTransportProfile>,
    ) -> Result<Self, TlsNegotiationReviewMintError> {
        let Host::Domain(host) = target
            .host()
            .ok_or(TlsNegotiationReviewMintError::UnsupportedTarget)?
        else {
            return Err(TlsNegotiationReviewMintError::UnsupportedTarget);
        };
        if !tls_negotiation_review_target_is_supported(target) {
            return Err(TlsNegotiationReviewMintError::UnsupportedTarget);
        }
        let port = target
            .port_or_known_default()
            .ok_or(TlsNegotiationReviewMintError::UnsupportedTarget)?;
        ServerName::try_from(host.to_owned())
            .map_err(|_| TlsNegotiationReviewMintError::UnsupportedTarget)?;

        let (roots, fixed_address) = match owned_profile {
            Some(profile) => {
                let mut roots = RootCertStore::empty();
                roots
                    .add(CertificateDer::from(profile.root_certificate_der))
                    .map_err(|_| TlsNegotiationReviewMintError::ClientConfiguration)?;
                (roots, Some(profile.resolved_address))
            },
            None => (
                RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
                None,
            ),
        };
        let tls13 = client_config(&roots, &[&rustls::version::TLS13])?;
        let tls12 = client_config(&roots, &[&rustls::version::TLS12])?;
        Ok(Self {
            host: host.to_owned(),
            port,
            fixed_address,
            tls13,
            tls12,
            accounting,
            cancellation,
            parent_deadline,
        })
    }

    pub(crate) async fn execute(mut self) -> WebAssessmentTlsNegotiationReviewAudit {
        let mut audit = WebAssessmentTlsNegotiationReviewAudit::empty();
        // Every dispatched matrix cell must retain the corresponding parent
        // receipt so the final report can reconcile request, byte, stage, and
        // outcome truth. Refuse the child before DNS or transport when earlier
        // work has consumed that bounded evidence capacity.
        let transport = self.accounting.dispatch_audit();
        let receipt_capacity_available = transport.omitted_receipt_count() == 0
            && transport
                .receipts()
                .len()
                .checked_add(NETWORK_CELL_COUNT)
                .is_some_and(|required| required <= HARD_MAX_TRANSPORT_DISPATCH_RECEIPTS);
        if !receipt_capacity_available {
            audit.terminal = ReviewTerminal::BudgetExhausted;
            audit.cells[0].outcome = CellOutcome::BudgetExhausted;
            debug_assert!(audit.is_valid());
            return audit;
        }
        let started = tokio::time::Instant::now();
        let total_deadline =
            earlier_deadline(started.checked_add(TOTAL_TIMEOUT), self.parent_deadline)
                .unwrap_or(started);
        let totals = Arc::new(TotalByteCounters::default());
        let mut resolved_address = self.fixed_address;
        let mut resolution_failed = false;

        for index in 0..NETWORK_CELL_COUNT {
            if resolution_failed {
                break;
            }
            let id = if index == 0 {
                CellId::Tls13DefaultProvider
            } else {
                CellId::Tls12DefaultProvider
            };
            let config = if index == 0 {
                Arc::clone(&self.tls13)
            } else {
                Arc::clone(&self.tls12)
            };
            let stop = self
                .execute_cell(
                    id,
                    config,
                    total_deadline,
                    &totals,
                    &mut resolved_address,
                    &mut resolution_failed,
                    &mut audit.cells[index],
                )
                .await;
            if let Some(terminal) = stop {
                audit.terminal = terminal;
                break;
            }
        }

        audit.attempted_connection_count = u8::try_from(
            audit
                .cells
                .iter()
                .filter(|cell| cell.dispatch_status == DispatchStatus::Dispatched)
                .count(),
        )
        .unwrap_or(u8::MAX);
        audit.completed_handshake_count = u8::try_from(
            audit
                .cells
                .iter()
                .filter(|cell| cell.outcome == CellOutcome::Negotiated)
                .count(),
        )
        .unwrap_or(u8::MAX);
        audit.accounted_ingress_tls_bytes = totals.ingress.load(Ordering::Relaxed);
        audit.observed_egress_tls_bytes = totals.egress.load(Ordering::Relaxed);
        debug_assert!(audit.is_valid());
        audit
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_cell(
        &mut self,
        id: CellId,
        config: Arc<ClientConfig>,
        total_deadline: tokio::time::Instant,
        totals: &Arc<TotalByteCounters>,
        resolved_address: &mut Option<SocketAddr>,
        resolution_failed: &mut bool,
        cell: &mut WebAssessmentTlsNegotiationReviewCell,
    ) -> Option<ReviewTerminal> {
        if self.cancellation.is_cancelled() {
            cell.outcome = CellOutcome::Cancelled;
            return Some(ReviewTerminal::Cancelled);
        }
        let now = tokio::time::Instant::now();
        if now >= total_deadline {
            cell.outcome = CellOutcome::DeadlineReached;
            return Some(ReviewTerminal::DeadlineReached);
        }
        let action_id = id.action_id().expect("network cell has an action identity");
        let mut lease = match self.accounting.try_begin_with_request_body_bytes(
            action_id,
            DecisionExecutionStage::Active,
            None,
            0,
        ) {
            Ok(lease) => lease,
            Err(limit) => {
                cell.outcome = CellOutcome::BudgetExhausted;
                return Some(if limit.dimension() == RuntimeBudgetDimension::WallTime {
                    ReviewTerminal::DeadlineReached
                } else {
                    ReviewTerminal::BudgetExhausted
                });
            },
        };
        cell.dispatch_status = DispatchStatus::Dispatched;
        let cell_deadline = earlier_deadline(now.checked_add(CELL_TIMEOUT), Some(total_deadline))
            .unwrap_or(total_deadline);
        let response_gate = match bounded(
            &self.cancellation,
            cell_deadline,
            lease.acquire_response_read(),
        )
        .await
        {
            Ok(guard) => guard,
            Err(StepStop::Cancelled) => {
                lease.finish(TransportDispatchOutcome::Cancelled);
                cell.outcome = CellOutcome::Cancelled;
                return Some(ReviewTerminal::Cancelled);
            },
            Err(StepStop::Deadline) => {
                lease.finish(TransportDispatchOutcome::RequestTimeout);
                cell.outcome = CellOutcome::DeadlineReached;
                return Some(ReviewTerminal::DeadlineReached);
            },
        };

        if resolved_address.is_none() {
            let resolution = bounded(
                &self.cancellation,
                cell_deadline,
                resolve_one_address(&self.host, self.port),
            )
            .await;
            match resolution {
                Ok(Some(address)) => *resolved_address = Some(address),
                Ok(None) => {
                    lease.finish(TransportDispatchOutcome::TransportFailure);
                    cell.outcome = CellOutcome::TransportFailed;
                    *resolution_failed = true;
                    drop(response_gate);
                    return None;
                },
                Err(StepStop::Deadline) => {
                    lease.finish(TransportDispatchOutcome::RequestTimeout);
                    cell.outcome = CellOutcome::DeadlineReached;
                    *resolution_failed = true;
                    drop(response_gate);
                    return Some(ReviewTerminal::DeadlineReached);
                },
                Err(StepStop::Cancelled) => {
                    lease.finish(TransportDispatchOutcome::Cancelled);
                    cell.outcome = CellOutcome::Cancelled;
                    drop(response_gate);
                    return Some(ReviewTerminal::Cancelled);
                },
            }
        }
        let address = resolved_address.expect("resolution populated before connection");
        let stream = match bounded(
            &self.cancellation,
            cell_deadline,
            TcpStream::connect(address),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => {
                lease.finish(TransportDispatchOutcome::TransportFailure);
                cell.outcome = CellOutcome::TransportFailed;
                drop(response_gate);
                return None;
            },
            Err(StepStop::Cancelled) => {
                lease.finish(TransportDispatchOutcome::Cancelled);
                cell.outcome = CellOutcome::Cancelled;
                drop(response_gate);
                return Some(ReviewTerminal::Cancelled);
            },
            Err(StepStop::Deadline) => {
                lease.finish(TransportDispatchOutcome::RequestTimeout);
                cell.outcome = CellOutcome::DeadlineReached;
                drop(response_gate);
                return Some(ReviewTerminal::DeadlineReached);
            },
        };
        let counters = CellByteCounters::new(Arc::clone(totals));
        let counted = CountedTlsIo::new(stream, &mut lease, counters.clone());
        let server_name = ServerName::try_from(self.host.clone())
            .expect("host was validated before authority mint");
        let handshake = bounded(
            &self.cancellation,
            cell_deadline,
            TlsConnector::from(config)
                .connect(server_name, counted)
                .into_fallible(),
        )
        .await;

        match handshake {
            Ok(Ok(mut tls)) => {
                let connection = tls.get_ref().1;
                let protocol = connection.protocol_version().and_then(protocol_token);
                let cipher = connection
                    .negotiated_cipher_suite()
                    .and_then(|suite| cipher_suite_token(suite.suite()));
                if protocol.is_some() && cipher.is_some() && connection.alpn_protocol().is_none() {
                    let shutdown = bounded(
                        &self.cancellation,
                        cell_deadline,
                        AsyncWriteExt::shutdown(&mut tls),
                    )
                    .await;
                    drop(tls);
                    match shutdown {
                        Err(StepStop::Cancelled) => {
                            cell.outcome = CellOutcome::Cancelled;
                            lease.finish(TransportDispatchOutcome::Cancelled);
                        },
                        Err(StepStop::Deadline) => {
                            cell.outcome = CellOutcome::DeadlineReached;
                            lease.finish(TransportDispatchOutcome::RequestTimeout);
                        },
                        Ok(Ok(())) => {
                            if tls_byte_limit_reached(&lease, &counters, totals) {
                                cell.outcome = CellOutcome::BudgetExhausted;
                                lease.finish(TransportDispatchOutcome::ResponseBudgetReached);
                            } else {
                                cell.outcome = CellOutcome::Negotiated;
                                cell.support = SupportState::ObservedSupported;
                                cell.transport_validation = TransportValidation::Succeeded;
                                cell.negotiated_protocol = protocol;
                                cell.negotiated_cipher_suite = cipher;
                                lease.finish(TransportDispatchOutcome::Completed);
                            }
                        },
                        Ok(Err(_)) => {
                            if tls_byte_limit_reached(&lease, &counters, totals) {
                                cell.outcome = CellOutcome::BudgetExhausted;
                                lease.finish(TransportDispatchOutcome::ResponseBudgetReached);
                            } else {
                                cell.outcome = CellOutcome::TransportFailed;
                                lease.finish(TransportDispatchOutcome::TransportFailure);
                            }
                        },
                    }
                } else {
                    drop(tls);
                    cell.outcome = CellOutcome::HandshakeFailed;
                    lease.finish(TransportDispatchOutcome::TransportFailure);
                }
            },
            Ok(Err((error, counted))) => {
                drop(counted);
                if tls_byte_limit_reached(&lease, &counters, totals) {
                    cell.outcome = CellOutcome::BudgetExhausted;
                    lease.finish(TransportDispatchOutcome::ResponseBudgetReached);
                } else {
                    cell.outcome = classify_handshake_error(&error);
                    lease.finish(TransportDispatchOutcome::TransportFailure);
                }
            },
            Err(StepStop::Cancelled) => {
                cell.outcome = CellOutcome::Cancelled;
                lease.finish(TransportDispatchOutcome::Cancelled);
            },
            Err(StepStop::Deadline) => {
                cell.outcome = CellOutcome::DeadlineReached;
                lease.finish(TransportDispatchOutcome::RequestTimeout);
            },
        }
        cell.accounted_ingress_tls_bytes = counters.ingress.load(Ordering::Relaxed);
        cell.observed_egress_tls_bytes = counters.egress.load(Ordering::Relaxed);
        drop(response_gate);

        match cell.outcome {
            CellOutcome::BudgetExhausted => Some(ReviewTerminal::BudgetExhausted),
            CellOutcome::Cancelled => Some(ReviewTerminal::Cancelled),
            CellOutcome::DeadlineReached => Some(ReviewTerminal::DeadlineReached),
            _ => None,
        }
    }
}

fn tls_byte_limit_reached(
    lease: &RequestAccountingLease,
    counters: &CellByteCounters,
    totals: &TotalByteCounters,
) -> bool {
    lease.response_budget_reached()
        || counters
            .parent_ingress_limit_reached
            .load(Ordering::Relaxed)
        || counters.local_ingress_limit_reached.load(Ordering::Relaxed)
        || counters.local_egress_limit_reached.load(Ordering::Relaxed)
        || counters.ingress.load(Ordering::Relaxed) >= MAX_CELL_INGRESS_TLS_BYTES
        || counters.egress.load(Ordering::Relaxed) >= MAX_CELL_EGRESS_TLS_BYTES
        || totals.ingress.load(Ordering::Relaxed) >= MAX_TOTAL_INGRESS_TLS_BYTES
        || totals.egress.load(Ordering::Relaxed) >= MAX_TOTAL_EGRESS_TLS_BYTES
}

fn client_config(
    roots: &RootCertStore,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<Arc<ClientConfig>, TlsNegotiationReviewMintError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|_| TlsNegotiationReviewMintError::ClientConfiguration)?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols.clear();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

async fn resolve_one_address(host: &str, port: u16) -> Option<SocketAddr> {
    let addresses = lookup_host((host, port)).await.ok()?;
    select_resolved_address(addresses)
}

fn select_resolved_address(addresses: impl Iterator<Item = SocketAddr>) -> Option<SocketAddr> {
    addresses
        .take(MAX_RESOLVED_ADDRESSES)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .next()
}

fn classify_handshake_error(error: &io::Error) -> CellOutcome {
    match error
        .get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::AlertReceived(_)) => CellOutcome::PeerAlertReceived,
        Some(rustls::Error::InvalidCertificate(_)) => CellOutcome::CertificateValidationFailed,
        Some(_) => CellOutcome::HandshakeFailed,
        None => CellOutcome::TransportFailed,
    }
}

fn protocol_token(version: rustls::ProtocolVersion) -> Option<&'static str> {
    match version {
        rustls::ProtocolVersion::TLSv1_3 => Some("tls1.3"),
        rustls::ProtocolVersion::TLSv1_2 => Some("tls1.2"),
        _ => None,
    }
}

fn cipher_suite_token(suite: rustls::CipherSuite) -> Option<&'static str> {
    Some(match suite {
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => "tls13_aes_256_gcm_sha384",
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => "tls13_aes_128_gcm_sha256",
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "tls13_chacha20_poly1305_sha256",
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
            "tls12_ecdhe_ecdsa_aes_256_gcm_sha384"
        },
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
            "tls12_ecdhe_ecdsa_aes_128_gcm_sha256"
        },
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "tls12_ecdhe_ecdsa_chacha20_poly1305_sha256"
        },
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            "tls12_ecdhe_rsa_aes_256_gcm_sha384"
        },
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            "tls12_ecdhe_rsa_aes_128_gcm_sha256"
        },
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "tls12_ecdhe_rsa_chacha20_poly1305_sha256"
        },
        _ => return None,
    })
}

fn earlier_deadline(
    first: Option<tokio::time::Instant>,
    second: Option<tokio::time::Instant>,
) -> Option<tokio::time::Instant> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepStop {
    Cancelled,
    Deadline,
}

async fn bounded<T, F>(
    cancellation: &CancellationToken,
    deadline: tokio::time::Instant,
    future: F,
) -> Result<T, StepStop>
where
    F: Future<Output = T>,
{
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(StepStop::Cancelled),
        result = tokio::time::timeout_at(deadline, future) => {
            result.map_err(|_| StepStop::Deadline)
        },
    }
}

#[derive(Default)]
struct TotalByteCounters {
    ingress: AtomicU64,
    egress: AtomicU64,
}

#[derive(Clone)]
struct CellByteCounters {
    ingress: Arc<AtomicU64>,
    egress: Arc<AtomicU64>,
    totals: Arc<TotalByteCounters>,
    local_ingress_limit_reached: Arc<AtomicBool>,
    local_egress_limit_reached: Arc<AtomicBool>,
    parent_ingress_limit_reached: Arc<AtomicBool>,
}

impl CellByteCounters {
    fn new(totals: Arc<TotalByteCounters>) -> Self {
        Self {
            ingress: Arc::new(AtomicU64::new(0)),
            egress: Arc::new(AtomicU64::new(0)),
            totals,
            local_ingress_limit_reached: Arc::new(AtomicBool::new(false)),
            local_egress_limit_reached: Arc::new(AtomicBool::new(false)),
            parent_ingress_limit_reached: Arc::new(AtomicBool::new(false)),
        }
    }
}

struct CountedTlsIo<'a> {
    inner: TcpStream,
    lease: &'a mut RequestAccountingLease,
    counters: CellByteCounters,
}

impl<'a> CountedTlsIo<'a> {
    fn new(
        inner: TcpStream,
        lease: &'a mut RequestAccountingLease,
        counters: CellByteCounters,
    ) -> Self {
        Self {
            inner,
            lease,
            counters,
        }
    }
}

impl AsyncRead for CountedTlsIo<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let cell_remaining = MAX_CELL_INGRESS_TLS_BYTES
            .saturating_sub(this.counters.ingress.load(Ordering::Relaxed));
        let total_remaining = MAX_TOTAL_INGRESS_TLS_BYTES
            .saturating_sub(this.counters.totals.ingress.load(Ordering::Relaxed));
        let parent_remaining = this.lease.remaining_response_bytes();
        let allowed = u64::try_from(buffer.remaining())
            .unwrap_or(u64::MAX)
            .min(cell_remaining)
            .min(total_remaining)
            .min(parent_remaining)
            .min(MAX_SINGLE_RAW_READ as u64);
        if allowed == 0 {
            if parent_remaining == 0 {
                this.counters
                    .parent_ingress_limit_reached
                    .store(true, Ordering::Relaxed);
            } else {
                this.counters
                    .local_ingress_limit_reached
                    .store(true, Ordering::Relaxed);
            }
            return Poll::Ready(Err(io::Error::other("TLS ingress limit reached")));
        }
        let mut temporary = vec![0_u8; usize::try_from(allowed).unwrap_or(MAX_SINGLE_RAW_READ)];
        let mut temporary_buffer = ReadBuf::new(&mut temporary);
        match Pin::new(&mut this.inner).poll_read(context, &mut temporary_buffer) {
            Poll::Ready(Ok(())) => {
                let read = temporary_buffer.filled().len();
                if read > 0 {
                    buffer.put_slice(&temporary_buffer.filled()[..read]);
                    let read_u64 = u64::try_from(read).unwrap_or(u64::MAX);
                    this.counters.ingress.fetch_add(read_u64, Ordering::Relaxed);
                    this.counters
                        .totals
                        .ingress
                        .fetch_add(read_u64, Ordering::Relaxed);
                    let _ = this.lease.observe_response_bytes(read_u64);
                }
                Poll::Ready(Ok(()))
            },
            other => other,
        }
    }
}

impl AsyncWrite for CountedTlsIo<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        let cell_remaining =
            MAX_CELL_EGRESS_TLS_BYTES.saturating_sub(this.counters.egress.load(Ordering::Relaxed));
        let total_remaining = MAX_TOTAL_EGRESS_TLS_BYTES
            .saturating_sub(this.counters.totals.egress.load(Ordering::Relaxed));
        let allowed = usize::try_from(cell_remaining.min(total_remaining))
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        if !buffer.is_empty() && allowed == 0 {
            this.counters
                .local_egress_limit_reached
                .store(true, Ordering::Relaxed);
            return Poll::Ready(Err(io::Error::other("TLS egress limit reached")));
        }
        match Pin::new(&mut this.inner).poll_write(context, &buffer[..allowed]) {
            Poll::Ready(Ok(written)) => {
                let written = u64::try_from(written).unwrap_or(u64::MAX);
                this.counters.egress.fetch_add(written, Ordering::Relaxed);
                this.counters
                    .totals
                    .egress
                    .fetch_add(written, Ordering::Relaxed);
                Poll::Ready(Ok(usize::try_from(written).unwrap_or(usize::MAX)))
            },
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OwnedTlsMaterial {
        root_der: Vec<u8>,
        leaf_der: Vec<u8>,
        key_der: Vec<u8>,
    }

    struct OwnedTlsAccept {
        protocol: rustls::ProtocolVersion,
        alpn_selected: bool,
        application_bytes: usize,
    }

    fn owned_tls_material(dns_name: &str) -> OwnedTlsMaterial {
        use rcgen::{
            date_time_ymd, BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose,
            IsCa, KeyPair, KeyUsagePurpose,
        };

        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Termivar active TLS test root");
        root_params.not_before = date_time_ymd(2020, 1, 1);
        root_params.not_after = date_time_ymd(2100, 1, 1);
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let root_key = KeyPair::generate().unwrap();
        let root = root_params.self_signed(&root_key).unwrap();

        let mut leaf_params = CertificateParams::new(vec![dns_name.to_owned()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, dns_name);
        leaf_params.not_before = date_time_ymd(2020, 1, 1);
        leaf_params.not_after = date_time_ymd(2100, 1, 1);
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &root, &root_key).unwrap();

        OwnedTlsMaterial {
            root_der: root.der().to_vec(),
            leaf_der: leaf.der().to_vec(),
            key_der: leaf_key.serialize_der(),
        }
    }

    async fn owned_tls_server(
        material: &OwnedTlsMaterial,
        connection_count: usize,
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<OwnedTlsAccept>>) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::AsyncReadExt;
        use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let certificates = vec![CertificateDer::from(material.leaf_der.clone())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.key_der.clone()));
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let task = tokio::spawn(async move {
            let mut accepted = Vec::with_capacity(connection_count);
            for _ in 0..connection_count {
                let (stream, peer) = listener.accept().await.unwrap();
                assert!(peer.ip().is_loopback());
                let mut stream = acceptor.accept(stream).await.unwrap();
                let connection = stream.get_ref().1;
                let protocol = connection.protocol_version().unwrap();
                let alpn_selected = connection.alpn_protocol().is_some();
                let mut application = [0_u8; 1];
                let application_bytes = stream.read(&mut application).await.unwrap();
                accepted.push(OwnedTlsAccept {
                    protocol,
                    alpn_selected,
                    application_bytes,
                });
            }
            accepted
        });
        (address, task)
    }

    #[test]
    fn selected_empty_matrix_has_fixed_order_and_zero_network_legacy_rows() {
        let audit = WebAssessmentTlsNegotiationReviewAudit::empty();
        assert!(audit.is_valid());
        assert!(!audit.network_matrix_complete());
        assert_eq!(
            audit
                .cells()
                .iter()
                .map(|cell| cell.id())
                .collect::<Vec<_>>(),
            vec![
                "tls13_default_provider",
                "tls12_default_provider",
                "tls11_legacy_protocol",
                "tls10_legacy_protocol",
                "legacy_cipher_suites",
            ]
        );
        for cell in &audit.cells()[2..] {
            assert_eq!(cell.dispatch_status(), "not_dispatched");
            assert_eq!(cell.outcome(), "client_backend_unsupported");
            assert_eq!(cell.support(), "not_tested_client_backend_unsupported");
            assert_eq!(cell.transport_validation(), "not_applicable");
            assert_eq!(cell.accounted_ingress_tls_bytes(), 0);
            assert_eq!(cell.observed_egress_tls_bytes(), 0);
        }
    }

    #[test]
    fn parent_unavailable_is_selected_but_never_dispatched() {
        let audit = WebAssessmentTlsNegotiationReviewAudit::parent_authority_unavailable();
        assert!(audit.is_valid());
        assert!(!audit.network_matrix_complete());
        assert_eq!(audit.terminal(), "parent_authority_unavailable");
        assert_eq!(audit.attempted_connection_count(), 0);
        assert_eq!(audit.cells()[0].outcome(), "parent_authority_unavailable");
        assert_eq!(audit.cells()[1].outcome(), "parent_authority_unavailable");
    }

    #[test]
    fn cipher_and_protocol_tokens_are_closed() {
        assert_eq!(
            protocol_token(rustls::ProtocolVersion::TLSv1_3),
            Some("tls1.3")
        );
        assert_eq!(
            cipher_suite_token(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384),
            Some("tls13_aes_256_gcm_sha384")
        );
        assert_eq!(
            cipher_suite_token(rustls::CipherSuite::TLS_NULL_WITH_NULL_NULL),
            None
        );
    }

    #[test]
    fn target_preflight_matches_dns_sni_authority_without_network_access() {
        for target in [
            "https://example.test/",
            "https://xml-target.termivar.test:8443/review",
        ] {
            assert!(tls_negotiation_review_target_is_supported(
                &Url::parse(target).unwrap()
            ));
        }
        for target in [
            "http://example.test/",
            "https://127.0.0.1/",
            "https://user@example.test/",
            "https://-bad.example/",
            "https://bad-.example/",
        ] {
            assert!(!tls_negotiation_review_target_is_supported(
                &Url::parse(target).unwrap()
            ));
        }
    }

    #[test]
    fn address_selection_consumes_at_most_sixteen_answers_in_stable_order() {
        use std::cell::Cell;

        let consumed = Cell::new(0_usize);
        let answers = (1_u8..=17).rev().map(|last_octet| {
            consumed.set(consumed.get() + 1);
            SocketAddr::from(([192, 0, 2, last_octet], 443))
        });
        assert_eq!(
            select_resolved_address(answers),
            Some(SocketAddr::from(([192, 0, 2, 2], 443)))
        );
        assert_eq!(consumed.get(), MAX_RESOLVED_ADDRESSES);

        let duplicate = SocketAddr::from(([192, 0, 2, 20], 443));
        let distinct_after_limit = SocketAddr::from(([192, 0, 2, 1], 443));
        assert_eq!(
            select_resolved_address(
                std::iter::repeat_n(duplicate, MAX_RESOLVED_ADDRESSES)
                    .chain(std::iter::once(distinct_after_limit))
            ),
            Some(duplicate)
        );
    }

    #[test]
    fn tls_byte_limit_classification_includes_close_notify_egress_failure() {
        let accounting = RequestAccountingBroker::new(crate::RuntimeBudget::default());
        let mut lease = accounting
            .try_begin(
                TLS_NEGOTIATION_REVIEW_ACTION_TLS13,
                DecisionExecutionStage::Active,
                None,
            )
            .unwrap();
        let totals = Arc::new(TotalByteCounters::default());
        let counters = CellByteCounters::new(Arc::clone(&totals));

        assert!(!tls_byte_limit_reached(&lease, &counters, &totals));
        counters
            .local_egress_limit_reached
            .store(true, Ordering::Relaxed);
        assert!(tls_byte_limit_reached(&lease, &counters, &totals));
        lease.finish(TransportDispatchOutcome::ResponseBudgetReached);
    }

    #[test]
    fn complete_matrix_requires_both_parent_accounted_network_dispatches() {
        let mut audit = WebAssessmentTlsNegotiationReviewAudit::empty();
        audit.attempted_connection_count = 2;
        for cell in audit.cells.iter_mut().take(NETWORK_CELL_COUNT) {
            cell.dispatch_status = DispatchStatus::Dispatched;
            cell.outcome = CellOutcome::TransportFailed;
        }

        assert!(audit.is_valid());
        assert!(audit.network_matrix_complete());

        audit.attempted_connection_count = 1;
        audit.cells[1] =
            WebAssessmentTlsNegotiationReviewCell::pending(CellId::Tls12DefaultProvider);
        assert!(audit.is_valid());
        assert!(!audit.network_matrix_complete());
    }

    #[tokio::test]
    async fn owned_tls_matrix_negotiates_two_versions_without_application_data() {
        let dns_name = "active-tls.termivar.test";
        let material = owned_tls_material(dns_name);
        let (address, server) = owned_tls_server(&material, NETWORK_CELL_COUNT).await;
        let accounting = RequestAccountingBroker::new(
            crate::RuntimeBudget::default()
                .with_max_total_requests(NETWORK_CELL_COUNT as u32)
                .with_max_active_verifications(NETWORK_CELL_COUNT as u16),
        );
        let target = Url::parse(&format!("https://{dns_name}:{}/review", address.port())).unwrap();
        let runtime = TlsNegotiationReviewRuntime::new(
            &target,
            accounting.clone(),
            CancellationToken::new(),
            None,
            Some(TlsNegotiationOwnedTransportProfile::new(
                address,
                material.root_der,
            )),
        )
        .unwrap();

        let audit = runtime.execute().await;
        let accepted = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("owned TLS server completed")
            .unwrap();

        assert!(audit.is_valid());
        assert!(audit.network_matrix_complete());
        assert_eq!(audit.terminal(), "complete");
        assert_eq!(audit.attempted_connection_count(), 2);
        assert_eq!(audit.completed_handshake_count(), 2);
        assert!(audit.accounted_ingress_tls_bytes() > 0);
        assert!(audit.observed_egress_tls_bytes() > 0);
        assert_eq!(
            audit
                .cells()
                .iter()
                .take(NETWORK_CELL_COUNT)
                .map(|cell| (cell.outcome(), cell.negotiated_protocol()))
                .collect::<Vec<_>>(),
            vec![
                ("negotiated", Some("tls1.3")),
                ("negotiated", Some("tls1.2"))
            ]
        );
        assert_eq!(
            accepted
                .iter()
                .map(|fact| fact.protocol)
                .collect::<Vec<_>>(),
            vec![
                rustls::ProtocolVersion::TLSv1_3,
                rustls::ProtocolVersion::TLSv1_2
            ]
        );
        assert!(accepted
            .iter()
            .all(|fact| !fact.alpn_selected && fact.application_bytes == 0));

        let transport = accounting.dispatch_audit();
        assert_eq!(transport.receipts().len(), NETWORK_CELL_COUNT);
        assert_eq!(transport.omitted_receipt_count(), 0);
        assert!(transport.receipts().iter().all(|receipt| {
            receipt.stage() == DecisionExecutionStage::Active
                && receipt.request_body_bytes() == 0
                && receipt.response_bytes() > 0
                && receipt.outcome() == TransportDispatchOutcome::Completed
        }));
    }

    #[tokio::test]
    async fn cancellation_and_parent_budget_stop_before_any_connection() {
        let dns_name = "active-tls.termivar.test";
        let material = owned_tls_material(dns_name);
        let fixed_address = SocketAddr::from(([127, 0, 0, 1], 9));

        let cancelled_accounting = RequestAccountingBroker::new(crate::RuntimeBudget::default());
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = TlsNegotiationReviewRuntime::new(
            &Url::parse(&format!("https://{dns_name}/")).unwrap(),
            cancelled_accounting.clone(),
            cancellation,
            None,
            Some(TlsNegotiationOwnedTransportProfile::new(
                fixed_address,
                material.root_der.clone(),
            )),
        )
        .unwrap()
        .execute()
        .await;
        assert!(cancelled.is_valid());
        assert_eq!(cancelled.terminal(), "cancelled");
        assert_eq!(cancelled.attempted_connection_count(), 0);
        assert!(cancelled_accounting.dispatch_audit().receipts().is_empty());

        let exhausted_accounting = RequestAccountingBroker::new(
            crate::RuntimeBudget::default()
                .with_max_total_requests(0)
                .with_max_active_verifications(0),
        );
        let exhausted = TlsNegotiationReviewRuntime::new(
            &Url::parse(&format!("https://{dns_name}/")).unwrap(),
            exhausted_accounting.clone(),
            CancellationToken::new(),
            None,
            Some(TlsNegotiationOwnedTransportProfile::new(
                fixed_address,
                material.root_der,
            )),
        )
        .unwrap()
        .execute()
        .await;
        assert!(exhausted.is_valid());
        assert_eq!(exhausted.terminal(), "budget_exhausted");
        assert_eq!(exhausted.attempted_connection_count(), 0);
        assert_eq!(exhausted.cells()[0].outcome(), "budget_exhausted");
        assert!(exhausted_accounting.dispatch_audit().receipts().is_empty());
    }

    #[tokio::test]
    async fn failed_first_handshake_cannot_reset_the_shared_active_limit() {
        let dns_name = "active-tls.termivar.test";
        let material = owned_tls_material(dns_name);
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            drop(stream);
        });
        let accounting = RequestAccountingBroker::new(
            crate::RuntimeBudget::default()
                .with_max_total_requests(2)
                .with_max_active_verifications(1),
        );
        let runtime = TlsNegotiationReviewRuntime::new(
            &Url::parse(&format!("https://{dns_name}:{}/", address.port())).unwrap(),
            accounting.clone(),
            CancellationToken::new(),
            None,
            Some(TlsNegotiationOwnedTransportProfile::new(
                address,
                material.root_der,
            )),
        )
        .unwrap();

        let audit = runtime.execute().await;
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("rejecting server completed")
            .unwrap();

        assert!(audit.is_valid());
        assert_eq!(audit.terminal(), "budget_exhausted");
        assert_eq!(audit.attempted_connection_count(), 1);
        assert_eq!(audit.cells()[0].dispatch_status(), "dispatched");
        assert_eq!(audit.cells()[0].outcome(), "transport_failed");
        assert_eq!(audit.cells()[1].dispatch_status(), "not_dispatched");
        assert_eq!(audit.cells()[1].outcome(), "budget_exhausted");
        let transport = accounting.dispatch_audit();
        assert_eq!(transport.receipts().len(), 1);
        assert_eq!(
            transport.receipts()[0].outcome(),
            TransportDispatchOutcome::TransportFailure
        );
    }

    #[tokio::test]
    async fn receipt_capacity_exhaustion_refuses_before_dns_or_transport() {
        let budget = crate::RuntimeBudget::default().with_max_total_requests(
            u32::try_from(HARD_MAX_TRANSPORT_DISPATCH_RECEIPTS + 2).unwrap(),
        );
        let accounting = RequestAccountingBroker::new(budget);
        for _ in 0..HARD_MAX_TRANSPORT_DISPATCH_RECEIPTS - 1 {
            let mut lease = accounting
                .try_begin("fixture.passive", DecisionExecutionStage::Passive, None)
                .unwrap();
            lease.finish(TransportDispatchOutcome::Completed);
        }
        let target = Url::parse("https://receipt-capacity.invalid/").unwrap();
        let runtime = TlsNegotiationReviewRuntime::new(
            &target,
            accounting.clone(),
            CancellationToken::new(),
            None,
            None,
        )
        .unwrap();

        let audit = runtime.execute().await;

        assert!(audit.is_valid());
        assert!(!audit.network_matrix_complete());
        assert_eq!(audit.terminal(), "budget_exhausted");
        assert_eq!(audit.attempted_connection_count(), 0);
        assert_eq!(audit.cells()[0].dispatch_status(), "not_dispatched");
        assert_eq!(audit.cells()[0].outcome(), "budget_exhausted");
        assert_eq!(audit.cells()[1].outcome(), "not_reached");
        let transport = accounting.dispatch_audit();
        assert_eq!(
            transport.receipts().len(),
            HARD_MAX_TRANSPORT_DISPATCH_RECEIPTS - 1
        );
        assert_eq!(transport.omitted_receipt_count(), 0);
        assert!(transport.receipts().iter().all(|receipt| {
            receipt.action_id() != TLS_NEGOTIATION_REVIEW_ACTION_TLS13
                && receipt.action_id() != TLS_NEGOTIATION_REVIEW_ACTION_TLS12
        }));
    }
}
