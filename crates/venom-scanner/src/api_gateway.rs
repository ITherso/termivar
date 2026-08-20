//! API gateway policy records.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `platform-models`.
//! - **Execution:** host/library records only; no repository runtime caller.
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! These types describe host-supplied routes, rate-limit policies, quotas, and
//! observations. They do not authenticate callers, route requests, enforce a
//! policy, refill a bucket, or reset a quota. A host that consumes these records
//! must supply and enforce those behaviors itself.

use serde::{Deserialize, Serialize};

/// Rate-limit algorithm requested by a host policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitStrategy {
    #[serde(rename = "token_bucket")]
    TokenBucket,
    #[serde(rename = "sliding_window")]
    SlidingWindow,
    #[serde(rename = "fixed_window")]
    FixedWindow,
    #[serde(rename = "leaky_bucket")]
    LeakyBucket,
}

impl RateLimitStrategy {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TokenBucket => "token_bucket",
            Self::SlidingWindow => "sliding_window",
            Self::FixedWindow => "fixed_window",
            Self::LeakyBucket => "leaky_bucket",
        }
    }
}

/// Host-supplied rate-limit policy record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub policy_id: String,
    pub name: String,
    pub strategy: RateLimitStrategy,
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub window_size_secs: u32,
    pub enabled: bool,
}

/// Host-observed rate-limit state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitStatus {
    pub client_id: String,
    pub policy_id: String,
    pub requests_allowed: u32,
    pub requests_used: u32,
    pub requests_remaining: u32,
    pub reset_time_secs: u64,
    pub quota_exceeded: bool,
}

/// Host-supplied quota and usage record.
///
/// The model deliberately has no default constructor: limits, identifiers, and
/// reset timestamps must come from the integrating host rather than from
/// fabricated product tiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiQuota {
    pub quota_id: String,
    pub client_id: String,
    pub requests_per_day: u64,
    pub requests_used_today: u64,
    pub scan_credits: u64,
    pub scan_credits_used: u64,
    pub api_calls_this_hour: u64,
    pub last_reset_time: u64,
}

impl ApiQuota {
    #[must_use]
    pub fn requests_remaining(&self) -> u64 {
        self.requests_per_day
            .saturating_sub(self.requests_used_today)
    }

    #[must_use]
    pub fn credits_remaining(&self) -> u64 {
        self.scan_credits.saturating_sub(self.scan_credits_used)
    }

    #[must_use]
    pub fn quota_exceeded(&self) -> bool {
        self.requests_used_today >= self.requests_per_day
            || self.scan_credits_used >= self.scan_credits
    }
}

/// Route requirements supplied to a separate host implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteConfig {
    pub route_id: String,
    pub path: String,
    pub method: String,
    pub rate_limit_policy_id: Option<String>,
    pub requires_auth: bool,
    pub timeout_secs: u32,
    pub allowed_roles: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explicit_quota() -> ApiQuota {
        ApiQuota {
            quota_id: "host-quota-1".to_owned(),
            client_id: "client-1".to_owned(),
            requests_per_day: 8,
            requests_used_today: 3,
            scan_credits: 5,
            scan_credits_used: 2,
            api_calls_this_hour: 1,
            last_reset_time: 1_700_000_000,
        }
    }

    #[test]
    fn quota_math_saturates_when_host_usage_exceeds_limits() {
        let mut quota = explicit_quota();
        quota.requests_used_today = u64::MAX;
        quota.scan_credits_used = u64::MAX;

        assert_eq!(quota.requests_remaining(), 0);
        assert_eq!(quota.credits_remaining(), 0);
        assert!(quota.quota_exceeded());
    }

    #[test]
    fn route_record_preserves_auth_and_policy_requirements() {
        let route = RouteConfig {
            route_id: "admin".to_owned(),
            path: "/admin".to_owned(),
            method: "POST".to_owned(),
            rate_limit_policy_id: Some("strict".to_owned()),
            requires_auth: true,
            timeout_secs: 30,
            allowed_roles: vec!["admin".to_owned()],
        };

        let encoded = serde_json::to_value(&route).unwrap();
        assert_eq!(encoded["requires_auth"], true);
        assert_eq!(encoded["rate_limit_policy_id"], "strict");
        assert_eq!(encoded["allowed_roles"][0], "admin");
    }

    #[test]
    fn rate_limit_status_is_scoped_to_a_policy() {
        let status = RateLimitStatus {
            client_id: "client-1".to_owned(),
            policy_id: "strict".to_owned(),
            requests_allowed: 10,
            requests_used: 10,
            requests_remaining: 0,
            reset_time_secs: 60,
            quota_exceeded: true,
        };

        assert_eq!(status.policy_id, "strict");
        assert!(status.quota_exceeded);
    }

    #[test]
    fn strategy_names_are_stable_data_values() {
        assert_eq!(RateLimitStrategy::TokenBucket.as_str(), "token_bucket");
        assert_eq!(RateLimitStrategy::SlidingWindow.as_str(), "sliding_window");
        assert_eq!(RateLimitStrategy::FixedWindow.as_str(), "fixed_window");
        assert_eq!(RateLimitStrategy::LeakyBucket.as_str(), "leaky_bucket");
    }
}
