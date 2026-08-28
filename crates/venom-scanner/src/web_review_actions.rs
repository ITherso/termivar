//! Transport-neutral action identities for native low-risk web review.
//!
//! This catalog defines two opt-in differential actions, but deliberately does
//! not install them into the standard planner, bind an executor, or authorize
//! network I/O. Runtime composition remains responsible for exact-origin
//! authority, shared accounting, and request construction.
//!
//! Every catalog entry has one immutable relationship: a passive control
//! followed by one active candidate. Both entries are knowledge-only, so even
//! a successful action cannot transition a hypothesis into a confirmed state.

use serde::{Deserialize, Serialize};
#[cfg(feature = "scanning")]
use venom_core::KnowledgePredicate;

use crate::planner::{RiskScore, VerificationTarget};

/// Number of actions in the native low-risk web-review catalog.
pub const NATIVE_WEB_REVIEW_ACTION_COUNT: usize = 2;

/// Hard per-case request count declared by every native web-review action.
pub const NATIVE_WEB_REVIEW_REQUESTS_PER_CASE: usize = 2;

/// Hard per-case active-request count declared by every native web-review action.
pub const NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE: usize = 1;

/// Closed evidence namespace emitted only by the sealed native-review observer.
#[cfg(feature = "scanning")]
pub(crate) const NATIVE_WEB_REVIEW_EVIDENCE_NAMESPACE: &str = "web.review.observation";
/// Marker proving that one response reached the bounded review projection.
#[cfg(feature = "scanning")]
pub(crate) const NATIVE_WEB_REVIEW_RESPONSE_MARKER: &str = "response-marker";

/// Returns the exact marker selected by native active pair-completion rules.
#[cfg(feature = "scanning")]
pub(crate) fn native_web_review_response_marker_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new(
        NATIVE_WEB_REVIEW_EVIDENCE_NAMESPACE,
        NATIVE_WEB_REVIEW_RESPONSE_MARKER,
    )
    .expect("the native review marker predicate is a valid static identity")
}

const CONTROL_CANDIDATE_LEGS: [NativeWebReviewRequestLeg; NATIVE_WEB_REVIEW_REQUESTS_PER_CASE] = [
    NativeWebReviewRequestLeg::PassiveControl,
    NativeWebReviewRequestLeg::ActiveCandidate,
];

/// Stable semantic actions available to an explicitly composed web-review host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NativeWebReviewActionKind {
    /// Compare a request without `Origin` to one carrying a case-specific origin.
    CorsPolicyPair,
    /// Compare a query-free request to one carrying a single case-specific query value.
    RedirectReflectionQueryPair,
}

/// The only request surface an action may vary between its matched legs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NativeWebReviewDifferentialInput {
    /// The active candidate adds one bounded `Origin` header.
    OriginHeader,
    /// The active candidate adds one bounded query parameter.
    SingleQueryParameter,
}

/// Ordered request roles for one native web-review case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NativeWebReviewRequestLeg {
    /// Negative/control observation collected without the candidate mutation.
    PassiveControl,
    /// Candidate observation containing exactly the action's declared mutation.
    ActiveCandidate,
}

impl NativeWebReviewRequestLeg {
    /// Returns whether this leg consumes active-verification authority.
    pub const fn is_active(self) -> bool {
        matches!(self, Self::ActiveCandidate)
    }
}

impl NativeWebReviewActionKind {
    /// Returns every native web-review action in stable declaration order.
    pub const fn all() -> [Self; NATIVE_WEB_REVIEW_ACTION_COUNT] {
        [Self::CorsPolicyPair, Self::RedirectReflectionQueryPair]
    }

    /// Returns the stable planner action identity.
    pub const fn action_id(self) -> &'static str {
        match self {
            Self::CorsPolicyPair => "web.review.cors.policy-pair@1",
            Self::RedirectReflectionQueryPair => "web.review.redirect-reflection.query-pair@1",
        }
    }

    /// Returns the stable opaque executor-route identity.
    ///
    /// The catalog does not register or implement the route.
    pub const fn executor_id(self) -> &'static str {
        match self {
            Self::CorsPolicyPair => "web.review.probe.cors-policy-pair@1",
            Self::RedirectReflectionQueryPair => {
                "web.review.probe.redirect-reflection-query-pair@1"
            },
        }
    }

    /// Returns the compact stable name used in derived audit identities.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::CorsPolicyPair => "cors-policy-pair",
            Self::RedirectReflectionQueryPair => "redirect-reflection-query-pair",
        }
    }

    /// Returns the single request surface this action may vary.
    pub const fn differential_input(self) -> NativeWebReviewDifferentialInput {
        match self {
            Self::CorsPolicyPair => NativeWebReviewDifferentialInput::OriginHeader,
            Self::RedirectReflectionQueryPair => {
                NativeWebReviewDifferentialInput::SingleQueryParameter
            },
        }
    }

    /// Returns the complete, fixed request order for one case.
    pub const fn request_legs(
        self,
    ) -> &'static [NativeWebReviewRequestLeg; NATIVE_WEB_REVIEW_REQUESTS_PER_CASE] {
        let _ = self;
        &CONTROL_CANDIDATE_LEGS
    }

    /// Returns the maximum requests this action may issue for one case.
    pub const fn maximum_requests_per_case(self) -> usize {
        self.request_legs().len()
    }

    /// Returns the maximum active requests this action may issue for one case.
    pub const fn maximum_active_requests_per_case(self) -> usize {
        let _ = self;
        NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE
    }

    /// Returns the low operational risk used by future planner composition.
    ///
    /// This score models request-side operational risk, not finding severity.
    pub fn risk(self) -> RiskScore {
        let percent = match self {
            Self::CorsPolicyPair => 5,
            Self::RedirectReflectionQueryPair => 8,
        };
        RiskScore::from_percent(percent).expect("native web-review risk is a valid constant")
    }

    /// Returns the immutable claim policy for this action.
    ///
    /// No catalog entry can target either its motivation hypothesis or a
    /// distinct hypothesis. A later planner profile must copy this value rather
    /// than infer claim authority from a successful execution.
    pub const fn verification_target(self) -> VerificationTarget {
        let _ = self;
        VerificationTarget::KnowledgeOnly
    }
}

#[cfg(test)]
#[path = "web_review_actions_tests.rs"]
mod tests;
