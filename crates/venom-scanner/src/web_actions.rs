//! Transport-neutral semantic action identities for standard web profiles.
//!
//! Planning, verification, and execution consume this catalog as sibling
//! layers. The catalog defines stable meaning and routing identities but owns
//! no HTTP method, client, executor, or runtime policy.

use serde::{Deserialize, Serialize};

/// Number of semantic actions in the standard web catalog.
pub const STANDARD_WEB_ACTION_COUNT: usize = 9;

/// Number of semantic actions supported by the built-in discovery capability.
pub const STANDARD_WEB_DISCOVERY_ACTION_COUNT: usize = 5;

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
    /// Analyze stateful Sanctum authentication boundaries.
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
}

/// Stable semantic action subset with built-in discovery support.
pub const STANDARD_WEB_DISCOVERY_ACTIONS: [StandardWebActionKind;
    STANDARD_WEB_DISCOVERY_ACTION_COUNT] = StandardWebActionKind::discovery();

#[cfg(test)]
mod tests {
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
}
