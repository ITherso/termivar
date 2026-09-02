//! Transport-neutral semantic action identities for standard web profiles.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `venom scan`:** yes, through `StandardWebDecisionRuntime`.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Planning, verification, and execution consume this catalog as sibling
//! layers. The catalog defines stable meaning and routing identities but owns
//! no HTTP method, client, executor, or runtime policy.

use serde::{Deserialize, Serialize};

mod native_review;

#[cfg(all(feature = "scanning", feature = "authorization-review"))]
pub(crate) use native_review::authorization_review_phase_terminal_predicate;
#[cfg(feature = "scanning")]
pub(crate) use native_review::{
    native_web_review_response_marker_predicate, NATIVE_WEB_REVIEW_EVIDENCE_NAMESPACE,
    NATIVE_WEB_REVIEW_RESPONSE_MARKER,
};
pub use native_review::{
    NativeWebReviewActionKind, NativeWebReviewDifferentialInput, NativeWebReviewRequestLeg,
    NATIVE_WEB_REVIEW_ACTION_COUNT, NATIVE_WEB_REVIEW_ACTIVE_REQUESTS_PER_CASE,
    NATIVE_WEB_REVIEW_REQUESTS_PER_CASE,
};

/// Number of semantic actions in the standard web catalog.
pub const STANDARD_WEB_ACTION_COUNT: usize = 9;

/// Number of semantic actions supported by the built-in discovery capability.
pub const STANDARD_WEB_DISCOVERY_ACTION_COUNT: usize = 8;

/// Stable semantic action kinds shared by standard web profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StandardWebActionKind {
    /// Inspect nginx-specific configuration and routing behavior.
    NginxConfiguration,
    /// Inspect Apache HTTP Server configuration and routing behavior.
    ApacheConfiguration,
    /// Discover PHP request inputs before deeper testing.
    PhpInputDiscovery,
    /// Enumerate Laravel routes with a low-risk discovery executor.
    LaravelRouteDiscovery,
    /// Analyze inputs discovered on Laravel routes.
    LaravelInputAnalysis,
    /// Enumerate Livewire component boundaries.
    LivewireComponentDiscovery,
    /// Observe a Sanctum-compatible session/CSRF cookie-name convention.
    ///
    /// The cookie convention motivates this action but does not independently
    /// prove that Sanctum authentication is installed or active.
    SanctumAuthBoundary,
    /// Analyze an advertised HTTP Basic authentication boundary.
    HttpBasicAuthBoundary,
    /// Analyze an advertised HTTP Bearer authentication boundary.
    HttpBearerAuthBoundary,
}

impl StandardWebActionKind {
    /// Returns every standard kind in stable declaration order.
    pub const fn all() -> [Self; STANDARD_WEB_ACTION_COUNT] {
        [
            Self::NginxConfiguration,
            Self::ApacheConfiguration,
            Self::PhpInputDiscovery,
            Self::LaravelRouteDiscovery,
            Self::LaravelInputAnalysis,
            Self::LivewireComponentDiscovery,
            Self::SanctumAuthBoundary,
            Self::HttpBasicAuthBoundary,
            Self::HttpBearerAuthBoundary,
        ]
    }

    /// Returns the semantic action subset supported by discovery executors.
    ///
    /// HTTP method selection and executor construction remain in the execution
    /// layer; this list only declares the capability boundary shared with
    /// verification.
    pub const fn discovery() -> [Self; STANDARD_WEB_DISCOVERY_ACTION_COUNT] {
        [
            Self::NginxConfiguration,
            Self::ApacheConfiguration,
            Self::PhpInputDiscovery,
            Self::LaravelRouteDiscovery,
            Self::LivewireComponentDiscovery,
            Self::SanctumAuthBoundary,
            Self::HttpBasicAuthBoundary,
            Self::HttpBearerAuthBoundary,
        ]
    }

    /// Returns the stable planner action identity.
    pub const fn action_id(self) -> &'static str {
        match self {
            Self::NginxConfiguration => "web.action.nginx.configuration",
            Self::ApacheConfiguration => "web.action.apache.configuration",
            Self::PhpInputDiscovery => "web.action.php.input-discovery",
            Self::LaravelRouteDiscovery => "web.action.laravel.route-discovery",
            Self::LaravelInputAnalysis => "web.action.laravel.input-analysis",
            Self::LivewireComponentDiscovery => "web.action.livewire.component-discovery",
            Self::SanctumAuthBoundary => "web.action.sanctum.auth-boundary",
            Self::HttpBasicAuthBoundary => "web.action.http-basic.auth-boundary",
            Self::HttpBearerAuthBoundary => "web.action.http-bearer.auth-boundary",
        }
    }

    /// Returns the stable opaque route identity for an action executor.
    ///
    /// The identity does not select a transport or implementation. Runtime
    /// composition binds it to an executor outside this semantic catalog.
    pub const fn executor_id(self) -> &'static str {
        match self {
            Self::NginxConfiguration => "web.probe.nginx-configuration",
            Self::ApacheConfiguration => "web.probe.apache-configuration",
            Self::PhpInputDiscovery => "web.probe.php-inputs",
            Self::LaravelRouteDiscovery => "web.probe.laravel-routes",
            Self::LaravelInputAnalysis => "web.probe.laravel-inputs",
            Self::LivewireComponentDiscovery => "web.probe.livewire-components",
            Self::SanctumAuthBoundary => "web.probe.sanctum-auth",
            Self::HttpBasicAuthBoundary => "web.probe.http-basic-auth",
            Self::HttpBearerAuthBoundary => "web.probe.http-bearer-auth",
        }
    }

    /// Returns the stable compact name used in derived profile identities.
    ///
    /// This catalog owns the slug so execution and verification layers cannot
    /// drift when new semantic actions are introduced. Existing verification
    /// rule identifiers depend on the discovery-action values and must remain
    /// stable.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::NginxConfiguration => "nginx-configuration",
            Self::ApacheConfiguration => "apache-configuration",
            Self::PhpInputDiscovery => "php-input-discovery",
            Self::LaravelRouteDiscovery => "laravel-route",
            Self::LaravelInputAnalysis => "laravel-input-analysis",
            Self::LivewireComponentDiscovery => "livewire-component",
            Self::SanctumAuthBoundary => "sanctum-auth",
            Self::HttpBasicAuthBoundary => "http-basic-auth",
            Self::HttpBearerAuthBoundary => "http-bearer-auth",
        }
    }
}

/// Stable semantic action subset with built-in discovery support.
pub const STANDARD_WEB_DISCOVERY_ACTIONS: [StandardWebActionKind;
    STANDARD_WEB_DISCOVERY_ACTION_COUNT] = StandardWebActionKind::discovery();

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn discovery_capability_is_a_stable_subset_of_the_catalog() {
        assert_eq!(
            STANDARD_WEB_DISCOVERY_ACTIONS.len(),
            STANDARD_WEB_DISCOVERY_ACTION_COUNT
        );
        for discovery in STANDARD_WEB_DISCOVERY_ACTIONS {
            assert!(StandardWebActionKind::all().contains(&discovery));
        }
    }

    #[test]
    fn every_standard_action_has_a_unique_stable_slug() {
        let slugs = StandardWebActionKind::all()
            .into_iter()
            .map(StandardWebActionKind::slug)
            .collect::<BTreeSet<_>>();

        assert_eq!(slugs.len(), STANDARD_WEB_ACTION_COUNT);
        assert!(slugs.iter().all(|slug| !slug.is_empty()));
        assert_eq!(
            StandardWebActionKind::LaravelRouteDiscovery.slug(),
            "laravel-route"
        );
        assert_eq!(
            StandardWebActionKind::HttpBearerAuthBoundary.slug(),
            "http-bearer-auth"
        );
    }
}
