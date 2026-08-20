#![cfg(feature = "platform-models")]

use venom_scanner::{ApiQuota, RateLimitPolicy, RateLimitStatus, RateLimitStrategy, RouteConfig};

#[test]
fn host_supplies_quota_identifiers_limits_and_usage() {
    let quota = ApiQuota {
        quota_id: "quota-from-host".to_owned(),
        client_id: "client-from-host".to_owned(),
        requests_per_day: 20,
        requests_used_today: 7,
        scan_credits: 9,
        scan_credits_used: 4,
        api_calls_this_hour: 3,
        last_reset_time: 123,
    };

    assert_eq!(quota.requests_remaining(), 13);
    assert_eq!(quota.credits_remaining(), 5);
    assert!(!quota.quota_exceeded());
}

#[test]
fn quota_exhaustion_uses_supplied_limits_without_underflow() {
    let quota = ApiQuota {
        quota_id: "quota-from-host".to_owned(),
        client_id: "client-from-host".to_owned(),
        requests_per_day: 2,
        requests_used_today: 3,
        scan_credits: 1,
        scan_credits_used: 8,
        api_calls_this_hour: 3,
        last_reset_time: 123,
    };

    assert_eq!(quota.requests_remaining(), 0);
    assert_eq!(quota.credits_remaining(), 0);
    assert!(quota.quota_exceeded());
}

#[test]
fn route_policy_is_data_and_retains_all_enforcement_requirements() {
    let route = RouteConfig {
        route_id: "create-scan".to_owned(),
        path: "/api/v1/scans".to_owned(),
        method: "POST".to_owned(),
        rate_limit_policy_id: Some("strict".to_owned()),
        requires_auth: true,
        timeout_secs: 30,
        allowed_roles: vec!["admin".to_owned(), "analyst".to_owned()],
    };

    let round_trip: RouteConfig =
        serde_json::from_str(&serde_json::to_string(&route).unwrap()).unwrap();
    assert_eq!(round_trip, route);
    assert!(round_trip.requires_auth);
    assert_eq!(round_trip.rate_limit_policy_id.as_deref(), Some("strict"));
}

#[test]
fn rate_limit_observation_is_policy_scoped() {
    let status = RateLimitStatus {
        client_id: "client".to_owned(),
        policy_id: "policy".to_owned(),
        requests_allowed: 5,
        requests_used: 5,
        requests_remaining: 0,
        reset_time_secs: 60,
        quota_exceeded: true,
    };

    assert_eq!(status.policy_id, "policy");
    assert!(status.quota_exceeded);
}

#[test]
fn policies_round_trip_without_implying_enforcement() {
    let policy = RateLimitPolicy {
        policy_id: "strict".to_owned(),
        name: "Strict host policy".to_owned(),
        strategy: RateLimitStrategy::TokenBucket,
        requests_per_second: 2,
        burst_size: 4,
        window_size_secs: 60,
        enabled: true,
    };

    let round_trip: RateLimitPolicy =
        serde_json::from_str(&serde_json::to_string(&policy).unwrap()).unwrap();
    assert_eq!(round_trip, policy);
    assert_eq!(round_trip.strategy.as_str(), "token_bucket");
}
