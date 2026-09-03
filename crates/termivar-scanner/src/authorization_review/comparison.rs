//! Four-view, raw-value-free authorization differential comparison.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use termivar_core::{
    ApiSurfaceKind, ApiVisibilityDimension, ApiVisibilityPairKind, ApiVisibilityResult,
};
use thiserror::Error;

use super::{
    AuthorizationPrincipalPairProof, AuthorizationResourceScopeId, AuthorizationReviewPolicy,
    AuthorizationReviewPolicyId, AUTHORIZATION_REVIEW_ALGORITHM_VERSION,
};
use crate::{ApiVisibilityComparator, ProfiledApiVisibilityError, ProfiledApiVisibilityView};

/// The four independently dispatched views required by V1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthorizationViewRole {
    /// First primary-principal response.
    PrimaryCandidate,
    /// First peer-principal response.
    PeerCandidate,
    /// Independent primary-principal replay.
    PrimaryReplay,
    /// Independent peer-principal replay.
    PeerReplay,
}

impl AuthorizationViewRole {
    const fn context_id(self) -> &'static str {
        match self {
            Self::PrimaryCandidate => "authorization-review:primary:candidate",
            Self::PeerCandidate => "authorization-review:peer:candidate",
            Self::PrimaryReplay => "authorization-review:primary:replay",
            Self::PeerReplay => "authorization-review:peer:replay",
        }
    }
}

/// Bounded response state supplied by a host/runtime before pure comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthorizationReviewBodyState {
    /// Complete, non-truncated JSON-compatible response captured below.
    CompleteJson,
    /// Media type is not JSON-compatible.
    UnsupportedMedia,
    /// A non-JSON HTML response was observed.
    Html,
    /// Redirect response; it must not be followed.
    Redirect,
    /// Typed rate-limit response.
    RateLimited,
    /// Server-side failure response.
    ServerError,
    /// JSON parsing failed within the bounded parser.
    MalformedJson,
    /// Retained bytes are truncated.
    Truncated,
    /// Transport or response completion was not proven.
    Incomplete,
    /// Shared runtime budget was exhausted.
    BudgetExhausted,
    /// Shared cancellation fired.
    Cancelled,
    /// Challenge or defense engagement made comparison ambiguous.
    DefensiveInterference,
}

/// Normalized, value-free media classification bound to one response view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthorizationReviewMediaClass {
    /// `application/json` or a media type with a `+json` structured suffix.
    JsonCompatible,
    /// An HTML media type.
    Html,
    /// A present normalized media type outside the supported JSON/HTML set.
    Other,
    /// No unambiguous normalized media type was available.
    Missing,
}

/// Scanner-owned response-receipt correlation identity.
///
/// The bytes must be supplied by the host's receipt system, not derived from a
/// credential. Debug output remains value-free.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationViewReceiptId([u8; 32]);

impl AuthorizationViewReceiptId {
    /// Binds one already domain-separated receipt digest.
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }
}

impl fmt::Debug for AuthorizationViewReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationViewReceiptId(<redacted>)")
    }
}

/// Stable receipt for one complete four-view comparison invocation.
///
/// This identity binds only scanner-owned correlation receipts and redacted
/// semantic identities. It never hashes credential or raw response material.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationDifferentialReceiptId([u8; 32]);

impl AuthorizationDifferentialReceiptId {
    /// Returns the prefixed lowercase hexadecimal wire identity.
    pub fn to_wire(self) -> String {
        format!("authorization-differential-sha256:{}", hex(self.0))
    }
}

impl fmt::Debug for AuthorizationDifferentialReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_wire())
    }
}

impl Serialize for AuthorizationDifferentialReceiptId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_wire())
    }
}

/// One role-bound response reduced to bounded fingerprints and typed metadata.
pub struct AuthorizationReviewView {
    role: AuthorizationViewRole,
    policy_id: AuthorizationReviewPolicyId,
    resource_scope_id: AuthorizationResourceScopeId,
    status: Option<u16>,
    media_class: AuthorizationReviewMediaClass,
    state: AuthorizationReviewBodyState,
    selected_paths_resolved: bool,
    material_selected_subtree: bool,
    generic_json_error_envelope: bool,
    receipt_id: AuthorizationViewReceiptId,
    profiled: Option<ProfiledApiVisibilityView>,
}

impl AuthorizationReviewView {
    /// Captures a complete JSON view through the existing value-sensitive API
    /// comparator and immediately discards the raw JSON value.
    pub fn capture_json(
        policy: &AuthorizationReviewPolicy,
        role: AuthorizationViewRole,
        status: u16,
        snapshot: &Value,
        receipt_id: AuthorizationViewReceiptId,
    ) -> Result<Self, AuthorizationReviewViewError> {
        if !(100..=599).contains(&status) {
            return Err(AuthorizationReviewViewError::InvalidStatus);
        }
        let generic_json_error_envelope =
            successful(status) && is_generic_json_error_envelope(policy, snapshot);
        let selected_paths_resolved = policy
            .comparison()
            .selected_paths()
            .iter()
            .all(|path| snapshot.pointer(path.as_str()).is_some());
        let (profiled, material_selected_subtree) = ApiVisibilityComparator::default()
            .capture_profiled_view_with_material(
                policy.comparison(),
                role.context_id(),
                policy.resource_scope_id().to_wire(),
                ApiSurfaceKind::JsonHttp,
                status,
                snapshot,
            )?;
        Ok(Self {
            role,
            policy_id: policy.policy_id(),
            resource_scope_id: policy.resource_scope_id(),
            status: Some(status),
            media_class: AuthorizationReviewMediaClass::JsonCompatible,
            state: AuthorizationReviewBodyState::CompleteJson,
            selected_paths_resolved,
            material_selected_subtree,
            generic_json_error_envelope,
            receipt_id,
            profiled: Some(profiled),
        })
    }

    /// Captures a typed non-comparable terminal response without retaining a body.
    pub fn terminal(
        policy: &AuthorizationReviewPolicy,
        role: AuthorizationViewRole,
        status: Option<u16>,
        media_class: AuthorizationReviewMediaClass,
        state: AuthorizationReviewBodyState,
        receipt_id: AuthorizationViewReceiptId,
    ) -> Result<Self, AuthorizationReviewViewError> {
        let response_required = matches!(
            state,
            AuthorizationReviewBodyState::UnsupportedMedia
                | AuthorizationReviewBodyState::Html
                | AuthorizationReviewBodyState::Redirect
                | AuthorizationReviewBodyState::RateLimited
                | AuthorizationReviewBodyState::ServerError
                | AuthorizationReviewBodyState::MalformedJson
                | AuthorizationReviewBodyState::Truncated
                | AuthorizationReviewBodyState::DefensiveInterference
        );
        let response_forbidden = matches!(
            state,
            AuthorizationReviewBodyState::BudgetExhausted | AuthorizationReviewBodyState::Cancelled
        );
        let media_mismatch = (state == AuthorizationReviewBodyState::Html
            && media_class != AuthorizationReviewMediaClass::Html)
            || (state == AuthorizationReviewBodyState::UnsupportedMedia
                && !matches!(
                    media_class,
                    AuthorizationReviewMediaClass::Other | AuthorizationReviewMediaClass::Missing
                ))
            || (matches!(
                state,
                AuthorizationReviewBodyState::MalformedJson
                    | AuthorizationReviewBodyState::Truncated
            ) && media_class != AuthorizationReviewMediaClass::JsonCompatible);
        if state == AuthorizationReviewBodyState::CompleteJson
            || status.is_some_and(|value| !(100..=599).contains(&value))
            || (response_required && status.is_none())
            || (response_forbidden
                && (status.is_some() || media_class != AuthorizationReviewMediaClass::Missing))
            || media_mismatch
        {
            return Err(AuthorizationReviewViewError::InvalidTerminalState);
        }
        Ok(Self {
            role,
            policy_id: policy.policy_id(),
            resource_scope_id: policy.resource_scope_id(),
            status,
            media_class,
            state,
            selected_paths_resolved: false,
            material_selected_subtree: false,
            generic_json_error_envelope: false,
            receipt_id,
            profiled: None,
        })
    }

    /// Returns the fixed leg role.
    pub const fn role(&self) -> AuthorizationViewRole {
        self.role
    }

    /// Returns the exact status without response material.
    pub const fn status(&self) -> Option<u16> {
        self.status
    }

    /// Returns the normalized response-media class.
    pub const fn media_class(&self) -> AuthorizationReviewMediaClass {
        self.media_class
    }

    /// Returns the bounded response classification.
    pub const fn state(&self) -> AuthorizationReviewBodyState {
        self.state
    }
}

impl fmt::Debug for AuthorizationReviewView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationReviewView")
            .field("role", &self.role)
            .field("policy_id", &self.policy_id)
            .field("resource_scope_id", &self.resource_scope_id)
            .field("status", &self.status)
            .field("media_class", &self.media_class)
            .field("state", &self.state)
            .field("selected_paths_resolved", &self.selected_paths_resolved)
            .field("material_selected_subtree", &self.material_selected_subtree)
            .field(
                "generic_json_error_envelope",
                &self.generic_json_error_envelope,
            )
            .field("receipt_id", &"<redacted>")
            .field("profiled", &"<redacted>")
            .finish()
    }
}

/// View capture failure with no raw response values.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuthorizationReviewViewError {
    /// Existing bounded API canonicalization failed.
    #[error(transparent)]
    Comparison(#[from] ProfiledApiVisibilityError),
    /// A captured response status was outside the HTTP status range.
    #[error("authorization review response status is invalid")]
    InvalidStatus,
    /// Terminal construction was attempted with a complete state or invalid status.
    #[error("authorization review terminal view state is invalid")]
    InvalidTerminalState,
}

/// Equivalence result for the three required comparison dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DimensionEquivalence {
    status: bool,
    fields: bool,
    resources: bool,
}

impl DimensionEquivalence {
    /// Returns whether statuses are equivalent.
    pub const fn status(self) -> bool {
        self.status
    }

    /// Returns whether selected field structure is equivalent.
    pub const fn fields(self) -> bool {
        self.fields
    }

    /// Returns whether selected value-sensitive resources are equivalent.
    pub const fn resources(self) -> bool {
        self.resources
    }

    /// Returns true only when all three dimensions agree.
    pub const fn all(self) -> bool {
        self.status && self.fields && self.resources
    }
}

/// Deterministic non-boolean four-view outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthorizationReviewOutcome {
    /// Host/runtime eligibility was not established.
    NotEligible,
    /// Primary response did not establish a successful JSON baseline.
    PrimaryBaselineInvalid,
    /// Primary candidate and replay were not equivalent.
    PrimaryUnstable,
    /// Peer was consistently denied or not found.
    PeerDenied,
    /// Peer candidate and replay were not equivalent.
    PeerUnstable,
    /// Stable primary and peer statuses differed.
    CrossStatusDifferent,
    /// Field shapes matched while selected resource values differed.
    CrossFieldsEquivalentOnly,
    /// Selected cross-principal resources differed.
    CrossResourcesDifferent,
    /// Both principals independently replayed the same selected representation.
    StableCrossPrincipalEquivalence,
    /// Challenge or defensive behavior invalidated interpretation.
    DefensiveInterference,
    /// Rate limiting invalidated interpretation.
    RateLimited,
    /// A redirect was observed and not followed.
    RedirectObserved,
    /// Response media was not supported JSON.
    UnsupportedMedia,
    /// JSON parsing failed.
    MalformedJson,
    /// A successful response used a generic JSON error-envelope shape.
    GenericJsonErrorEnvelope,
    /// At least one selected path was absent or null-only.
    SelectedPathMissing,
    /// A response was truncated.
    Truncated,
    /// Execution or transport did not complete.
    Incomplete,
    /// Shared budget was exhausted.
    BudgetExhausted,
    /// Host cancellation fired.
    Cancelled,
    /// Internal correlation or contract invariants did not reconcile.
    ContractMismatch,
}

/// Complete raw-value-free differential receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationDifferentialResult {
    algorithm_version: &'static str,
    policy_id: AuthorizationReviewPolicyId,
    resource_scope_id: AuthorizationResourceScopeId,
    receipt_id: AuthorizationDifferentialReceiptId,
    outcome: AuthorizationReviewOutcome,
    primary_stability: Option<DimensionEquivalence>,
    peer_stability: Option<DimensionEquivalence>,
    cross_candidate: Option<DimensionEquivalence>,
    cross_replay: Option<DimensionEquivalence>,
}

impl AuthorizationDifferentialResult {
    /// Compares exactly four role-complete views without performing I/O.
    pub fn compare(
        policy: &AuthorizationReviewPolicy,
        principals: AuthorizationPrincipalPairProof,
        views: [&AuthorizationReviewView; 4],
    ) -> Result<Self, AuthorizationDifferentialError> {
        validate_contract(policy, principals, &views)?;
        let primary_candidate = role(&views, AuthorizationViewRole::PrimaryCandidate)?;
        let peer_candidate = role(&views, AuthorizationViewRole::PeerCandidate)?;
        let primary_replay = role(&views, AuthorizationViewRole::PrimaryReplay)?;
        let peer_replay = role(&views, AuthorizationViewRole::PeerReplay)?;
        let identity = ResultIdentity::new(
            policy,
            primary_candidate,
            peer_candidate,
            primary_replay,
            peer_replay,
        );
        if let Some(outcome) = terminal_outcome(&views) {
            return Ok(Self::terminal(identity, outcome));
        }

        let primary_candidate_status = complete_status(primary_candidate)?;
        let peer_candidate_status = complete_status(peer_candidate)?;
        let primary_replay_status = complete_status(primary_replay)?;
        let peer_replay_status = complete_status(peer_replay)?;

        // All four complete views are already available. Compute every required
        // relationship before classification so negative outcomes still carry
        // the complete, request-free differential audit.
        let primary_stability = compare_dimensions(
            policy,
            "primary-stability",
            primary_candidate,
            primary_replay,
        )?;
        let peer_stability =
            compare_dimensions(policy, "peer-stability", peer_candidate, peer_replay)?;
        let cross_candidate =
            compare_dimensions(policy, "cross-candidate", primary_candidate, peer_candidate)?;
        let cross_replay = compare_dimensions(policy, "cross-replay", primary_replay, peer_replay)?;

        let outcome = if views.iter().any(|view| view.generic_json_error_envelope) {
            AuthorizationReviewOutcome::GenericJsonErrorEnvelope
        } else if !successful(primary_candidate_status) || !successful(primary_replay_status) {
            AuthorizationReviewOutcome::PrimaryBaselineInvalid
        } else if !paths_present(primary_candidate) || !paths_present(primary_replay) {
            AuthorizationReviewOutcome::SelectedPathMissing
        } else if primary_candidate_status != primary_replay_status || !primary_stability.all() {
            AuthorizationReviewOutcome::PrimaryUnstable
        } else if peer_candidate_status == peer_replay_status
            && matches!(peer_candidate_status, 401 | 403 | 404)
        {
            AuthorizationReviewOutcome::PeerDenied
        } else if !successful(peer_candidate_status)
            || !successful(peer_replay_status)
            || peer_candidate_status != peer_replay_status
        {
            AuthorizationReviewOutcome::PeerUnstable
        } else if !paths_present(peer_candidate) || !paths_present(peer_replay) {
            AuthorizationReviewOutcome::SelectedPathMissing
        } else if !peer_stability.all() {
            AuthorizationReviewOutcome::PeerUnstable
        } else if !cross_candidate.status || !cross_replay.status {
            AuthorizationReviewOutcome::CrossStatusDifferent
        } else if !cross_candidate.resources || !cross_replay.resources {
            if cross_candidate.fields && cross_replay.fields {
                AuthorizationReviewOutcome::CrossFieldsEquivalentOnly
            } else {
                AuthorizationReviewOutcome::CrossResourcesDifferent
            }
        } else if !cross_candidate.fields || !cross_replay.fields {
            AuthorizationReviewOutcome::CrossResourcesDifferent
        } else {
            AuthorizationReviewOutcome::StableCrossPrincipalEquivalence
        };
        Ok(Self {
            algorithm_version: AUTHORIZATION_REVIEW_ALGORITHM_VERSION,
            policy_id: identity.policy_id,
            resource_scope_id: identity.resource_scope_id,
            receipt_id: identity.receipt_id,
            outcome,
            primary_stability: Some(primary_stability),
            peer_stability: Some(peer_stability),
            cross_candidate: Some(cross_candidate),
            cross_replay: Some(cross_replay),
        })
    }

    /// Returns the typed terminal classification.
    pub const fn outcome(&self) -> AuthorizationReviewOutcome {
        self.outcome
    }

    /// Returns the exact comparison algorithm revision.
    pub const fn algorithm_version(&self) -> &'static str {
        self.algorithm_version
    }

    /// Returns the policy identity that governed all four views.
    pub const fn policy_id(&self) -> AuthorizationReviewPolicyId {
        self.policy_id
    }

    /// Returns the exact selected-resource scope identity.
    pub const fn resource_scope_id(&self) -> AuthorizationResourceScopeId {
        self.resource_scope_id
    }

    /// Returns the ordered four-view correlation receipt.
    pub const fn receipt_id(&self) -> AuthorizationDifferentialReceiptId {
        self.receipt_id
    }

    /// Returns primary replay stability when comparison reached that stage.
    pub const fn primary_stability(&self) -> Option<DimensionEquivalence> {
        self.primary_stability
    }

    /// Returns peer replay stability when comparison reached that stage.
    pub const fn peer_stability(&self) -> Option<DimensionEquivalence> {
        self.peer_stability
    }

    /// Returns first-round cross-principal equivalence when available.
    pub const fn cross_candidate(&self) -> Option<DimensionEquivalence> {
        self.cross_candidate
    }

    /// Returns replay cross-principal equivalence when available.
    pub const fn cross_replay(&self) -> Option<DimensionEquivalence> {
        self.cross_replay
    }

    fn terminal(identity: ResultIdentity, outcome: AuthorizationReviewOutcome) -> Self {
        Self {
            algorithm_version: AUTHORIZATION_REVIEW_ALGORITHM_VERSION,
            policy_id: identity.policy_id,
            resource_scope_id: identity.resource_scope_id,
            receipt_id: identity.receipt_id,
            outcome,
            primary_stability: None,
            peer_stability: None,
            cross_candidate: None,
            cross_replay: None,
        }
    }
}

/// Internal correlation/comparator failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuthorizationDifferentialError {
    /// The view set did not contain each V1 role exactly once.
    #[error("authorization differential view roles do not reconcile")]
    RoleSetMismatch,
    /// One view was captured under another policy.
    #[error("authorization differential policy identities do not reconcile")]
    PolicyMismatch,
    /// One view was captured for another resource scope.
    #[error("authorization differential resource identities do not reconcile")]
    ResourceMismatch,
    /// Receipt correlation identities were duplicated.
    #[error("authorization differential receipt identities do not reconcile")]
    ReceiptMismatch,
    /// A complete view did not retain the required internal comparison state.
    #[error("authorization differential view contract does not reconcile")]
    ViewContractMismatch,
    /// Existing value-sensitive comparison failed its contract.
    #[error(transparent)]
    Comparison(#[from] ProfiledApiVisibilityError),
}

#[derive(Clone, Copy)]
struct ResultIdentity {
    policy_id: AuthorizationReviewPolicyId,
    resource_scope_id: AuthorizationResourceScopeId,
    receipt_id: AuthorizationDifferentialReceiptId,
}

impl ResultIdentity {
    fn new(
        policy: &AuthorizationReviewPolicy,
        primary_candidate: &AuthorizationReviewView,
        peer_candidate: &AuthorizationReviewView,
        primary_replay: &AuthorizationReviewView,
        peer_replay: &AuthorizationReviewView,
    ) -> Self {
        Self {
            policy_id: policy.policy_id(),
            resource_scope_id: policy.resource_scope_id(),
            receipt_id: differential_receipt_id(
                policy,
                [
                    primary_candidate,
                    peer_candidate,
                    primary_replay,
                    peer_replay,
                ],
            ),
        }
    }
}

fn validate_contract(
    policy: &AuthorizationReviewPolicy,
    _principals: AuthorizationPrincipalPairProof,
    views: &[&AuthorizationReviewView; 4],
) -> Result<(), AuthorizationDifferentialError> {
    let roles = views.iter().map(|view| view.role).collect::<BTreeSet<_>>();
    if roles.len() != 4
        || ![
            AuthorizationViewRole::PrimaryCandidate,
            AuthorizationViewRole::PeerCandidate,
            AuthorizationViewRole::PrimaryReplay,
            AuthorizationViewRole::PeerReplay,
        ]
        .iter()
        .all(|role| roles.contains(role))
    {
        return Err(AuthorizationDifferentialError::RoleSetMismatch);
    }
    if views
        .iter()
        .any(|view| view.policy_id != policy.policy_id())
    {
        return Err(AuthorizationDifferentialError::PolicyMismatch);
    }
    if views
        .iter()
        .any(|view| view.resource_scope_id != policy.resource_scope_id())
    {
        return Err(AuthorizationDifferentialError::ResourceMismatch);
    }
    if views
        .iter()
        .map(|view| view.receipt_id)
        .collect::<BTreeSet<_>>()
        .len()
        != 4
    {
        return Err(AuthorizationDifferentialError::ReceiptMismatch);
    }
    Ok(())
}

fn terminal_outcome(views: &[&AuthorizationReviewView; 4]) -> Option<AuthorizationReviewOutcome> {
    let states = views.iter().map(|view| view.state).collect::<Vec<_>>();
    for (state, outcome) in [
        (
            AuthorizationReviewBodyState::Cancelled,
            AuthorizationReviewOutcome::Cancelled,
        ),
        (
            AuthorizationReviewBodyState::BudgetExhausted,
            AuthorizationReviewOutcome::BudgetExhausted,
        ),
        (
            AuthorizationReviewBodyState::Truncated,
            AuthorizationReviewOutcome::Truncated,
        ),
        (
            AuthorizationReviewBodyState::Incomplete,
            AuthorizationReviewOutcome::Incomplete,
        ),
        (
            AuthorizationReviewBodyState::Redirect,
            AuthorizationReviewOutcome::RedirectObserved,
        ),
        (
            AuthorizationReviewBodyState::RateLimited,
            AuthorizationReviewOutcome::RateLimited,
        ),
        (
            AuthorizationReviewBodyState::DefensiveInterference,
            AuthorizationReviewOutcome::DefensiveInterference,
        ),
        (
            AuthorizationReviewBodyState::MalformedJson,
            AuthorizationReviewOutcome::MalformedJson,
        ),
        (
            AuthorizationReviewBodyState::UnsupportedMedia,
            AuthorizationReviewOutcome::UnsupportedMedia,
        ),
        (
            AuthorizationReviewBodyState::Html,
            AuthorizationReviewOutcome::UnsupportedMedia,
        ),
        (
            AuthorizationReviewBodyState::ServerError,
            AuthorizationReviewOutcome::Incomplete,
        ),
    ] {
        if states.contains(&state) {
            return Some(outcome);
        }
    }
    None
}

fn role<'a>(
    views: &[&'a AuthorizationReviewView; 4],
    expected: AuthorizationViewRole,
) -> Result<&'a AuthorizationReviewView, AuthorizationDifferentialError> {
    views
        .iter()
        .copied()
        .find(|view| view.role == expected)
        .ok_or(AuthorizationDifferentialError::RoleSetMismatch)
}

fn paths_present(view: &AuthorizationReviewView) -> bool {
    view.selected_paths_resolved && view.material_selected_subtree
}

fn is_generic_json_error_envelope(policy: &AuthorizationReviewPolicy, snapshot: &Value) -> bool {
    fn has_error_envelope_shape(value: &Value) -> bool {
        value.as_object().is_some_and(|object| {
            (object.contains_key("error") || object.contains_key("errors"))
                && object.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "error"
                            | "errors"
                            | "message"
                            | "messages"
                            | "code"
                            | "status"
                            | "detail"
                            | "details"
                            | "title"
                            | "type"
                            | "trace_id"
                            | "request_id"
                    )
                })
        })
    }

    has_error_envelope_shape(snapshot)
        || policy
            .comparison()
            .selected_paths()
            .iter()
            .filter_map(|path| snapshot.pointer(path.as_str()))
            .any(has_error_envelope_shape)
}

fn successful(status: u16) -> bool {
    (200..=299).contains(&status)
}

fn complete_status(view: &AuthorizationReviewView) -> Result<u16, AuthorizationDifferentialError> {
    if view.state != AuthorizationReviewBodyState::CompleteJson || view.profiled.is_none() {
        return Err(AuthorizationDifferentialError::ViewContractMismatch);
    }
    view.status
        .ok_or(AuthorizationDifferentialError::ViewContractMismatch)
}

fn compare_dimensions(
    policy: &AuthorizationReviewPolicy,
    pair_name: &str,
    left: &AuthorizationReviewView,
    right: &AuthorizationReviewView,
) -> Result<DimensionEquivalence, AuthorizationDifferentialError> {
    let left = left
        .profiled
        .as_ref()
        .ok_or(AuthorizationDifferentialError::ViewContractMismatch)?;
    let right = right
        .profiled
        .as_ref()
        .ok_or(AuthorizationDifferentialError::ViewContractMismatch)?;
    let comparator = ApiVisibilityComparator::default();
    let compare = |dimension: ApiVisibilityDimension| {
        comparator.compare_profiled(
            policy.comparison(),
            format!(
                "authorization-differential:{}:{}:{}",
                pair_name,
                dimension.as_str(),
                policy.policy_id()
            ),
            ApiVisibilityPairKind::AuthorizationContext,
            dimension,
            left,
            right,
            0,
        )
    };
    Ok(DimensionEquivalence {
        status: compare(ApiVisibilityDimension::Status)?
            .comparison()
            .result()
            == ApiVisibilityResult::Equivalent,
        fields: compare(ApiVisibilityDimension::Fields)?
            .comparison()
            .result()
            == ApiVisibilityResult::Equivalent,
        resources: compare(ApiVisibilityDimension::Resources)?
            .comparison()
            .result()
            == ApiVisibilityResult::Equivalent,
    })
}

fn differential_receipt_id(
    policy: &AuthorizationReviewPolicy,
    views: [&AuthorizationReviewView; 4],
) -> AuthorizationDifferentialReceiptId {
    const DOMAIN: &[u8] = b"security.authorization-differential.receipt.v1\0";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    framed(
        &mut hasher,
        AUTHORIZATION_REVIEW_ALGORITHM_VERSION.as_bytes(),
    );
    framed(&mut hasher, &policy.policy_id().as_bytes());
    framed(&mut hasher, &policy.resource_scope_id().as_bytes());
    for (role, view) in [
        (b"primary-candidate".as_slice(), views[0]),
        (b"peer-candidate".as_slice(), views[1]),
        (b"primary-replay".as_slice(), views[2]),
        (b"peer-replay".as_slice(), views[3]),
    ] {
        framed(&mut hasher, role);
        framed(&mut hasher, &view.receipt_id.0);
    }
    AuthorizationDifferentialReceiptId(hasher.finalize().into())
}

fn framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use url::Url;

    use super::*;
    use crate::authorization_review::{
        AuthorizationPrincipalPair, PeerAuthorizationPrincipal, PrimaryAuthorizationPrincipal,
        AUTHORIZATION_REVIEW_POLICY_SCHEMA,
    };

    fn policy(unordered: bool, ignored: bool) -> AuthorizationReviewPolicy {
        let ignored = if ignored {
            "[\"/data/account/updated_at\"]"
        } else {
            "[]"
        };
        let unordered = if unordered {
            "[\"/data/account/roles\"]"
        } else {
            "[]"
        };
        let source = format!(
            "schema = \"{AUTHORIZATION_REVIEW_POLICY_SCHEMA}\"\nresource = \"/api/accounts/42\"\nresource_handle = \"account-self-profile\"\nexpectation = \"primary-only\"\nmethod = \"GET\"\n[comparison]\nselected_paths = [\"/data/account\"]\nignored_paths = {ignored}\nunordered_array_paths = {unordered}\nmax_diff_paths = 32\n"
        );
        AuthorizationReviewPolicy::parse_toml(
            &Url::parse("https://api.example.test/").unwrap(),
            source.as_bytes(),
        )
        .unwrap()
    }

    fn proof() -> AuthorizationPrincipalPairProof {
        AuthorizationPrincipalPair::new(
            PrimaryAuthorizationPrincipal::new("Bearer primary").unwrap(),
            PeerAuthorizationPrincipal::new("Bearer peer").unwrap(),
        )
        .unwrap()
        .into_proof()
    }

    fn receipt(index: u8) -> AuthorizationViewReceiptId {
        let mut digest = [0_u8; 32];
        digest[0] = index;
        AuthorizationViewReceiptId::from_digest(digest)
    }

    fn json_view(
        policy: &AuthorizationReviewPolicy,
        role: AuthorizationViewRole,
        status: u16,
        body: Value,
    ) -> AuthorizationReviewView {
        AuthorizationReviewView::capture_json(policy, role, status, &body, receipt(role as u8 + 1))
            .unwrap()
    }

    fn quartet(
        policy: &AuthorizationReviewPolicy,
        primary_candidate: Value,
        peer_candidate: Value,
        primary_replay: Value,
        peer_replay: Value,
    ) -> [AuthorizationReviewView; 4] {
        [
            json_view(
                policy,
                AuthorizationViewRole::PrimaryCandidate,
                200,
                primary_candidate,
            ),
            json_view(
                policy,
                AuthorizationViewRole::PeerCandidate,
                200,
                peer_candidate,
            ),
            json_view(
                policy,
                AuthorizationViewRole::PrimaryReplay,
                200,
                primary_replay,
            ),
            json_view(policy, AuthorizationViewRole::PeerReplay, 200, peer_replay),
        ]
    }

    fn compare(
        policy: &AuthorizationReviewPolicy,
        views: &[AuthorizationReviewView; 4],
    ) -> AuthorizationDifferentialResult {
        AuthorizationDifferentialResult::compare(
            policy,
            proof(),
            [&views[0], &views[1], &views[2], &views[3]],
        )
        .unwrap()
    }

    #[test]
    fn four_stable_equivalent_views_are_positive_only_on_all_dimensions() {
        let policy = policy(false, false);
        let body = json!({"data":{"account":{"id":42,"name":"A"}}});
        let views = quartet(&policy, body.clone(), body.clone(), body.clone(), body);
        let result = compare(&policy, &views);
        assert_eq!(
            result.outcome(),
            AuthorizationReviewOutcome::StableCrossPrincipalEquivalence
        );
        assert!(result.primary_stability().unwrap().all());
        assert!(result.peer_stability().unwrap().all());
        assert!(result.cross_candidate().unwrap().all());
        assert!(result.cross_replay().unwrap().all());
        assert_eq!(
            result.algorithm_version(),
            AUTHORIZATION_REVIEW_ALGORITHM_VERSION
        );
        assert_eq!(result.policy_id(), policy.policy_id());
        assert_eq!(result.resource_scope_id(), policy.resource_scope_id());
        assert!(result
            .receipt_id()
            .to_wire()
            .starts_with("authorization-differential-sha256:"));
    }

    #[test]
    fn primary_and_peer_instability_fail_closed() {
        let policy = policy(false, false);
        let one = json!({"data":{"account":{"id":1}}});
        let two = json!({"data":{"account":{"id":2}}});
        let primary_unstable = quartet(&policy, one.clone(), one.clone(), two.clone(), one.clone());
        assert_eq!(
            compare(&policy, &primary_unstable).outcome(),
            AuthorizationReviewOutcome::PrimaryUnstable
        );
        let peer_unstable = quartet(&policy, one.clone(), one.clone(), one, two);
        assert_eq!(
            compare(&policy, &peer_unstable).outcome(),
            AuthorizationReviewOutcome::PeerUnstable
        );
        assert!(compare(&policy, &primary_unstable)
            .cross_candidate()
            .is_some());
        assert!(compare(&policy, &peer_unstable).cross_replay().is_some());
    }

    #[test]
    fn status_baselines_and_cross_statuses_are_classified_without_shortcuts() {
        let policy = policy(false, false);
        let body = json!({"data":{"account":{"id":42}}});

        let mut invalid_primary = quartet(
            &policy,
            body.clone(),
            body.clone(),
            body.clone(),
            body.clone(),
        );
        invalid_primary[0] = json_view(
            &policy,
            AuthorizationViewRole::PrimaryCandidate,
            401,
            body.clone(),
        );
        invalid_primary[2] = json_view(
            &policy,
            AuthorizationViewRole::PrimaryReplay,
            401,
            body.clone(),
        );
        assert_eq!(
            compare(&policy, &invalid_primary).outcome(),
            AuthorizationReviewOutcome::PrimaryBaselineInvalid
        );

        let mut unstable_primary = quartet(
            &policy,
            body.clone(),
            body.clone(),
            body.clone(),
            body.clone(),
        );
        unstable_primary[2] = json_view(
            &policy,
            AuthorizationViewRole::PrimaryReplay,
            201,
            body.clone(),
        );
        assert_eq!(
            compare(&policy, &unstable_primary).outcome(),
            AuthorizationReviewOutcome::PrimaryUnstable
        );

        let mut cross_status = quartet(
            &policy,
            body.clone(),
            body.clone(),
            body.clone(),
            body.clone(),
        );
        cross_status[1] = json_view(
            &policy,
            AuthorizationViewRole::PeerCandidate,
            201,
            body.clone(),
        );
        cross_status[3] = json_view(&policy, AuthorizationViewRole::PeerReplay, 201, body);
        assert_eq!(
            compare(&policy, &cross_status).outcome(),
            AuthorizationReviewOutcome::CrossStatusDifferent
        );
    }

    #[test]
    fn peer_denials_never_become_positive_or_secure_claims() {
        let policy = policy(false, false);
        let body = json!({"data":{"account":{"id":42}}});
        for status in [401, 403, 404] {
            let mut views = quartet(
                &policy,
                body.clone(),
                body.clone(),
                body.clone(),
                body.clone(),
            );
            views[1] = json_view(
                &policy,
                AuthorizationViewRole::PeerCandidate,
                status,
                body.clone(),
            );
            views[3] = json_view(
                &policy,
                AuthorizationViewRole::PeerReplay,
                status,
                body.clone(),
            );
            assert_eq!(
                compare(&policy, &views).outcome(),
                AuthorizationReviewOutcome::PeerDenied
            );
        }

        let mut mixed = quartet(
            &policy,
            body.clone(),
            body.clone(),
            body.clone(),
            body.clone(),
        );
        mixed[1] = json_view(&policy, AuthorizationViewRole::PeerCandidate, 403, body);
        assert_eq!(
            compare(&policy, &mixed).outcome(),
            AuthorizationReviewOutcome::PeerUnstable
        );
    }

    #[test]
    fn field_shape_equality_is_not_resource_equivalence() {
        let policy = policy(false, false);
        let primary = json!({"data":{"account":{"id":42,"name":"primary"}}});
        let peer = json!({"data":{"account":{"id":43,"name":"peer"}}});
        let views = quartet(&policy, primary.clone(), peer.clone(), primary, peer);
        let result = compare(&policy, &views);
        assert_eq!(
            result.outcome(),
            AuthorizationReviewOutcome::CrossFieldsEquivalentOnly
        );
        assert!(result.cross_candidate().unwrap().fields());
        assert!(!result.cross_candidate().unwrap().resources());
    }

    #[test]
    fn repeated_generic_json_error_envelopes_never_become_positive() {
        let policy = policy(false, false);
        let secret = "GENERIC-ERROR-MUST-NOT-LEAK-4F82A1";
        for envelope in [
            json!({"error":{"category":"temporary","detail":secret}}),
            json!({"data":{"account":{"errors":[{"category":"temporary","detail":secret}]}}}),
        ] {
            let views = quartet(
                &policy,
                envelope.clone(),
                envelope.clone(),
                envelope.clone(),
                envelope,
            );
            assert!(views
                .iter()
                .all(|view| { view.state() == AuthorizationReviewBodyState::CompleteJson }));
            let result = compare(&policy, &views);
            assert_eq!(
                result.outcome(),
                AuthorizationReviewOutcome::GenericJsonErrorEnvelope
            );
            assert!(result.primary_stability().unwrap().all());
            assert!(result.peer_stability().unwrap().all());
            assert!(result.cross_candidate().unwrap().all());
            assert!(result.cross_replay().unwrap().all());
            assert!(!format!("{views:?}").contains(secret));
            assert!(!serde_json::to_string(&result).unwrap().contains(secret));
        }

        let resource = json!({"data":{"account":{"id":42}}});
        let error = json!({"data":{"account":{"error":"temporary"}}});
        let views = quartet(
            &policy,
            resource.clone(),
            error,
            resource.clone(),
            resource.clone(),
        );
        assert_eq!(
            compare(&policy, &views).outcome(),
            AuthorizationReviewOutcome::GenericJsonErrorEnvelope
        );

        let denied = json!({"error":"denied"});
        let views = [
            json_view(
                &policy,
                AuthorizationViewRole::PrimaryCandidate,
                200,
                resource.clone(),
            ),
            json_view(
                &policy,
                AuthorizationViewRole::PeerCandidate,
                403,
                denied.clone(),
            ),
            json_view(&policy, AuthorizationViewRole::PrimaryReplay, 200, resource),
            json_view(&policy, AuthorizationViewRole::PeerReplay, 403, denied),
        ];
        assert_eq!(
            compare(&policy, &views).outcome(),
            AuthorizationReviewOutcome::PeerDenied
        );

        for resource_with_error_field in [
            json!({"data":{"account":{"id":42,"error":"historical-note"}}}),
            json!({"data":{"account":{"id":42}},"errors":[]}),
        ] {
            let views = quartet(
                &policy,
                resource_with_error_field.clone(),
                resource_with_error_field.clone(),
                resource_with_error_field.clone(),
                resource_with_error_field,
            );
            assert_eq!(
                compare(&policy, &views).outcome(),
                AuthorizationReviewOutcome::StableCrossPrincipalEquivalence
            );
        }
    }

    #[test]
    fn status_equality_without_field_or_resource_equality_is_insufficient() {
        let policy = policy(false, false);
        let primary = json!({"data":{"account":{"id":42}}});
        let peer = json!({"data":{"account":{"other":"value"}}});
        let views = quartet(&policy, primary.clone(), peer.clone(), primary, peer);
        let result = compare(&policy, &views);
        assert_eq!(
            result.outcome(),
            AuthorizationReviewOutcome::CrossResourcesDifferent
        );
        assert!(result.cross_candidate().unwrap().status());
        assert!(!result.cross_candidate().unwrap().fields());
    }

    #[test]
    fn selected_path_must_resolve_and_be_material_in_all_views() {
        let policy = policy(false, false);
        for missing in [json!({"data":{}}), json!({"data":{"account":null}})] {
            let present = json!({"data":{"account":{"id":42}}});
            let views = quartet(
                &policy,
                present.clone(),
                missing.clone(),
                present.clone(),
                missing,
            );
            assert_eq!(
                compare(&policy, &views).outcome(),
                AuthorizationReviewOutcome::SelectedPathMissing
            );
        }
    }

    #[test]
    fn ignored_volatile_field_and_unordered_arrays_use_existing_profile() {
        let ignored = policy(false, true);
        let first = json!({"data":{"account":{"id":42,"updated_at":"first"}}});
        let second = json!({"data":{"account":{"id":42,"updated_at":"second"}}});
        let views = quartet(&ignored, first.clone(), second.clone(), first, second);
        assert_eq!(
            compare(&ignored, &views).outcome(),
            AuthorizationReviewOutcome::StableCrossPrincipalEquivalence
        );

        let unordered = policy(true, false);
        let left = json!({"data":{"account":{"roles":["reader","writer"]}}});
        let right = json!({"data":{"account":{"roles":["writer","reader"]}}});
        let views = quartet(&unordered, left.clone(), right.clone(), left, right);
        assert_eq!(
            compare(&unordered, &views).outcome(),
            AuthorizationReviewOutcome::StableCrossPrincipalEquivalence
        );

        let ordered = policy(false, false);
        let left = json!({"data":{"account":{"roles":["reader","writer"]}}});
        let right = json!({"data":{"account":{"roles":["writer","reader"]}}});
        let views = quartet(&ordered, left.clone(), right.clone(), left, right);
        assert_eq!(
            compare(&ordered, &views).outcome(),
            AuthorizationReviewOutcome::CrossFieldsEquivalentOnly
        );
    }

    #[test]
    fn ignored_only_selected_content_cannot_become_positive() {
        let policy = policy(false, true);
        let first = json!({"data":{"account":{"updated_at":"first"}}});
        let second = json!({"data":{"account":{"updated_at":"second"}}});
        let views = quartet(&policy, first.clone(), second.clone(), first, second);
        assert_eq!(
            compare(&policy, &views).outcome(),
            AuthorizationReviewOutcome::SelectedPathMissing
        );
    }

    #[test]
    fn terminal_states_have_deterministic_fail_closed_precedence() {
        let policy = policy(false, false);
        let body = json!({"data":{"account":{"id":42}}});
        for (state, expected) in [
            (
                AuthorizationReviewBodyState::Cancelled,
                AuthorizationReviewOutcome::Cancelled,
            ),
            (
                AuthorizationReviewBodyState::BudgetExhausted,
                AuthorizationReviewOutcome::BudgetExhausted,
            ),
            (
                AuthorizationReviewBodyState::Truncated,
                AuthorizationReviewOutcome::Truncated,
            ),
            (
                AuthorizationReviewBodyState::Incomplete,
                AuthorizationReviewOutcome::Incomplete,
            ),
            (
                AuthorizationReviewBodyState::Redirect,
                AuthorizationReviewOutcome::RedirectObserved,
            ),
            (
                AuthorizationReviewBodyState::RateLimited,
                AuthorizationReviewOutcome::RateLimited,
            ),
            (
                AuthorizationReviewBodyState::DefensiveInterference,
                AuthorizationReviewOutcome::DefensiveInterference,
            ),
            (
                AuthorizationReviewBodyState::MalformedJson,
                AuthorizationReviewOutcome::MalformedJson,
            ),
            (
                AuthorizationReviewBodyState::UnsupportedMedia,
                AuthorizationReviewOutcome::UnsupportedMedia,
            ),
            (
                AuthorizationReviewBodyState::Html,
                AuthorizationReviewOutcome::UnsupportedMedia,
            ),
            (
                AuthorizationReviewBodyState::ServerError,
                AuthorizationReviewOutcome::Incomplete,
            ),
        ] {
            let status = if matches!(
                state,
                AuthorizationReviewBodyState::Cancelled
                    | AuthorizationReviewBodyState::BudgetExhausted
                    | AuthorizationReviewBodyState::Incomplete
            ) {
                None
            } else {
                Some(500)
            };
            let media = match state {
                AuthorizationReviewBodyState::Html => AuthorizationReviewMediaClass::Html,
                AuthorizationReviewBodyState::UnsupportedMedia => {
                    AuthorizationReviewMediaClass::Other
                },
                AuthorizationReviewBodyState::Cancelled
                | AuthorizationReviewBodyState::BudgetExhausted
                | AuthorizationReviewBodyState::Incomplete => {
                    AuthorizationReviewMediaClass::Missing
                },
                _ => AuthorizationReviewMediaClass::JsonCompatible,
            };
            let mut views = quartet(
                &policy,
                body.clone(),
                body.clone(),
                body.clone(),
                body.clone(),
            );
            views[1] = AuthorizationReviewView::terminal(
                &policy,
                AuthorizationViewRole::PeerCandidate,
                status,
                media,
                state,
                receipt(2),
            )
            .unwrap();
            assert_eq!(compare(&policy, &views).outcome(), expected);
        }
    }

    #[test]
    fn view_construction_requires_real_status_and_consistent_media() {
        let policy = policy(false, false);
        let body = json!({"data":{"account":{"id":42}}});
        for status in [0, 99, 600, u16::MAX] {
            assert_eq!(
                AuthorizationReviewView::capture_json(
                    &policy,
                    AuthorizationViewRole::PrimaryCandidate,
                    status,
                    &body,
                    receipt(1),
                )
                .unwrap_err(),
                AuthorizationReviewViewError::InvalidStatus
            );
        }
        for (status, media, state) in [
            (
                Some(200),
                AuthorizationReviewMediaClass::JsonCompatible,
                AuthorizationReviewBodyState::CompleteJson,
            ),
            (
                Some(200),
                AuthorizationReviewMediaClass::Missing,
                AuthorizationReviewBodyState::Cancelled,
            ),
            (
                None,
                AuthorizationReviewMediaClass::Html,
                AuthorizationReviewBodyState::Html,
            ),
            (
                Some(200),
                AuthorizationReviewMediaClass::JsonCompatible,
                AuthorizationReviewBodyState::Html,
            ),
            (
                Some(200),
                AuthorizationReviewMediaClass::Other,
                AuthorizationReviewBodyState::MalformedJson,
            ),
        ] {
            assert_eq!(
                AuthorizationReviewView::terminal(
                    &policy,
                    AuthorizationViewRole::PrimaryCandidate,
                    status,
                    media,
                    state,
                    receipt(1),
                )
                .unwrap_err(),
                AuthorizationReviewViewError::InvalidTerminalState
            );
        }
        let cancelled = AuthorizationReviewView::terminal(
            &policy,
            AuthorizationViewRole::PrimaryCandidate,
            None,
            AuthorizationReviewMediaClass::Missing,
            AuthorizationReviewBodyState::Cancelled,
            receipt(1),
        )
        .unwrap();
        assert_eq!(cancelled.status(), None);
        assert_eq!(
            cancelled.media_class(),
            AuthorizationReviewMediaClass::Missing
        );
    }

    #[test]
    fn roles_policies_and_receipts_must_reconcile() {
        let policy = policy(false, false);
        let other_policy_source = format!(
            "schema = \"{AUTHORIZATION_REVIEW_POLICY_SCHEMA}\"\nresource = \"/api/accounts/43\"\nresource_handle = \"account-other\"\nexpectation = \"primary-only\"\nmethod = \"GET\"\n[comparison]\nselected_paths = [\"/data/account\"]\nignored_paths = []\nunordered_array_paths = []\nmax_diff_paths = 32\n"
        );
        let other_policy = AuthorizationReviewPolicy::parse_toml(
            &Url::parse("https://api.example.test/").unwrap(),
            other_policy_source.as_bytes(),
        )
        .unwrap();
        let body = json!({"data":{"account":{"id":42}}});
        let mut views = quartet(
            &policy,
            body.clone(),
            body.clone(),
            body.clone(),
            body.clone(),
        );
        views[3] = json_view(&other_policy, AuthorizationViewRole::PeerReplay, 200, body);
        assert_eq!(
            AuthorizationDifferentialResult::compare(
                &policy,
                proof(),
                [&views[0], &views[1], &views[2], &views[3]],
            )
            .unwrap_err(),
            AuthorizationDifferentialError::PolicyMismatch
        );

        let mut role_mismatch = quartet(
            &policy,
            json!({"data":{"account":{"id":42}}}),
            json!({"data":{"account":{"id":42}}}),
            json!({"data":{"account":{"id":42}}}),
            json!({"data":{"account":{"id":42}}}),
        );
        role_mismatch[3].role = AuthorizationViewRole::PeerCandidate;
        assert_eq!(
            AuthorizationDifferentialResult::compare(
                &policy,
                proof(),
                [
                    &role_mismatch[0],
                    &role_mismatch[1],
                    &role_mismatch[2],
                    &role_mismatch[3],
                ],
            )
            .unwrap_err(),
            AuthorizationDifferentialError::RoleSetMismatch
        );

        let body = json!({"data":{"account":{"id":42}}});
        let mut resource_mismatch = quartet(
            &policy,
            body.clone(),
            body.clone(),
            body.clone(),
            body.clone(),
        );
        resource_mismatch[3].resource_scope_id = other_policy.resource_scope_id();
        assert_eq!(
            AuthorizationDifferentialResult::compare(
                &policy,
                proof(),
                [
                    &resource_mismatch[0],
                    &resource_mismatch[1],
                    &resource_mismatch[2],
                    &resource_mismatch[3],
                ],
            )
            .unwrap_err(),
            AuthorizationDifferentialError::ResourceMismatch
        );

        let mut receipt_mismatch = quartet(
            &policy,
            body.clone(),
            body.clone(),
            body.clone(),
            body.clone(),
        );
        receipt_mismatch[3].receipt_id = receipt_mismatch[0].receipt_id;
        assert_eq!(
            AuthorizationDifferentialResult::compare(
                &policy,
                proof(),
                [
                    &receipt_mismatch[0],
                    &receipt_mismatch[1],
                    &receipt_mismatch[2],
                    &receipt_mismatch[3],
                ],
            )
            .unwrap_err(),
            AuthorizationDifferentialError::ReceiptMismatch
        );

        let mut view_mismatch = quartet(&policy, body.clone(), body.clone(), body.clone(), body);
        view_mismatch[0].profiled = None;
        assert_eq!(
            AuthorizationDifferentialResult::compare(
                &policy,
                proof(),
                [
                    &view_mismatch[0],
                    &view_mismatch[1],
                    &view_mismatch[2],
                    &view_mismatch[3],
                ],
            )
            .unwrap_err(),
            AuthorizationDifferentialError::ViewContractMismatch
        );
    }

    #[test]
    fn result_receipt_is_role_ordered_deterministic_and_materially_bound() {
        let policy = policy(false, false);
        let body = json!({"data":{"account":{"id":42}}});
        let views = quartet(&policy, body.clone(), body.clone(), body.clone(), body);
        let first = AuthorizationDifferentialResult::compare(
            &policy,
            proof(),
            [&views[0], &views[1], &views[2], &views[3]],
        )
        .unwrap();
        let reordered = AuthorizationDifferentialResult::compare(
            &policy,
            proof(),
            [&views[3], &views[1], &views[0], &views[2]],
        )
        .unwrap();
        assert_eq!(first.receipt_id(), reordered.receipt_id());

        let mut changed = views;
        changed[3].receipt_id = receipt(99);
        let changed = compare(&policy, &changed);
        assert_ne!(first.receipt_id(), changed.receipt_id());
        let encoded = serde_json::to_value(&first).unwrap();
        assert_eq!(
            encoded["algorithm_version"],
            AUTHORIZATION_REVIEW_ALGORITHM_VERSION
        );
        assert_eq!(encoded["policy_id"], policy.policy_id().to_wire());
        assert_eq!(
            encoded["resource_scope_id"],
            policy.resource_scope_id().to_wire()
        );
    }

    #[test]
    fn view_debug_and_serialized_result_contain_no_raw_values() {
        let policy = policy(false, false);
        let secret = "PRIVATE-RESOURCE-HANDLE-MUST-NOT-LEAK-346E2A";
        let body = json!({"data":{"account":{"token":secret}}});
        let views = quartet(&policy, body.clone(), body.clone(), body.clone(), body);
        for view in &views {
            assert!(!format!("{view:?}").contains(secret));
        }
        let result = compare(&policy, &views);
        assert!(!serde_json::to_string(&result).unwrap().contains(secret));
    }

    #[test]
    fn arbitrary_bounded_json_never_becomes_positive_without_four_stable_views() {
        let policy = policy(false, false);
        for value in [
            json!(null),
            json!({}),
            json!([]),
            json!({"data":{"account":null}}),
            json!({"data":{"account":[]}}),
            json!({"data":{"account":{"id":1}}}),
        ] {
            let other = json!({"data":{"account":{"id":2}}});
            let views = quartet(&policy, value.clone(), other.clone(), value, other);
            assert_ne!(
                compare(&policy, &views).outcome(),
                AuthorizationReviewOutcome::StableCrossPrincipalEquivalence
            );
        }
    }
}
