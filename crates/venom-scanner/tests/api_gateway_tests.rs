use venom_scanner::{
    ApiGateway, ApiQuota, QuotaManager, RateLimitPolicy, RateLimitStrategy, RateLimiter,
    RouteConfig,
};

#[test]
fn test_rate_limit_policy_creation() {
    let policy = RateLimitPolicy {
        policy_id: "standard".to_string(),
        name: "Standard Rate Limit".to_string(),
        strategy: RateLimitStrategy::TokenBucket,
        requests_per_second: 100,
        burst_size: 500,
        window_size_secs: 60,
        enabled: true,
    };

    assert_eq!(policy.requests_per_second, 100);
    assert_eq!(policy.burst_size, 500);
    assert!(policy.enabled);
}

#[test]
fn test_rate_limiter_policy_registration() {
    let mut limiter = RateLimiter::new();

    for i in 0..3 {
        let policy = RateLimitPolicy {
            policy_id: format!("policy_{}", i),
            name: format!("Policy {}", i),
            strategy: RateLimitStrategy::TokenBucket,
            requests_per_second: 10 + i as u32 * 10,
            burst_size: 50 + i as u32 * 50,
            window_size_secs: 60,
            enabled: true,
        };
        limiter.add_policy(policy);
    }

    assert_eq!(limiter.policy_count(), 3);
}

#[test]
fn test_rate_limit_enforcement() {
    let mut limiter = RateLimiter::new();

    let policy = RateLimitPolicy {
        policy_id: "test_policy".to_string(),
        name: "Test".to_string(),
        strategy: RateLimitStrategy::TokenBucket,
        requests_per_second: 10,
        burst_size: 20,
        window_size_secs: 60,
        enabled: true,
    };

    limiter.add_policy(policy);

    // First request should succeed
    let result = limiter.is_allowed("client1", "test_policy");
    assert!(result);
}

#[test]
fn test_api_quota_creation() {
    let quota = ApiQuota::new("premium_client".to_string());

    assert_eq!(quota.requests_per_day, 10000);
    assert_eq!(quota.scan_credits, 1000);
    assert_eq!(quota.requests_remaining(), 10000);
    assert_eq!(quota.credits_remaining(), 1000);
}

#[test]
fn test_quota_exceeded_detection() {
    let mut quota = ApiQuota::new("client1".to_string());

    quota.requests_used_today = quota.requests_per_day;

    assert!(quota.quota_exceeded());
    assert_eq!(quota.requests_remaining(), 0);
}

#[test]
fn test_quota_manager() {
    let manager = QuotaManager::new();

    let quota1 = manager.create_quota("client1".to_string());
    let quota2 = manager.create_quota("client2".to_string());

    assert_eq!(manager.quota_count(), 2);
    assert!(manager.get_quota(&quota1.quota_id).is_some());
    assert!(manager.get_quota(&quota2.quota_id).is_some());
}

#[test]
fn test_quota_request_recording() {
    let manager = QuotaManager::new();
    let quota = manager.create_quota("client1".to_string());

    for i in 0..5 {
        manager.record_request(&quota.quota_id, 10);
        let current = manager.get_quota(&quota.quota_id).unwrap();
        assert_eq!(current.requests_used_today, i + 1);
        assert_eq!(current.scan_credits_used, 10 * (i + 1) as u64);
    }
}

#[test]
fn test_quota_daily_reset() {
    let manager = QuotaManager::new();
    let quota = manager.create_quota("client1".to_string());

    manager.record_request(&quota.quota_id, 100);

    let before_reset = manager.get_quota(&quota.quota_id).unwrap();
    assert_eq!(before_reset.requests_used_today, 1);

    manager.reset_daily_quota(&quota.quota_id);

    let after_reset = manager.get_quota(&quota.quota_id).unwrap();
    assert_eq!(after_reset.requests_used_today, 0);
}

#[test]
fn test_route_configuration() {
    let route = RouteConfig {
        route_id: "scan_create".to_string(),
        path: "/api/v1/scans".to_string(),
        method: "POST".to_string(),
        rate_limit_policy_id: Some("premium".to_string()),
        requires_auth: true,
        timeout_secs: 30,
        allowed_roles: vec!["Admin".to_string(), "Analyst".to_string()],
    };

    assert_eq!(route.path, "/api/v1/scans");
    assert_eq!(route.method, "POST");
    assert!(route.requires_auth);
    assert_eq!(route.allowed_roles.len(), 2);
}

#[test]
fn test_api_gateway_route_registration() {
    let mut gateway = ApiGateway::new();

    for i in 0..5 {
        let route = RouteConfig {
            route_id: format!("route_{}", i),
            path: format!("/api/v1/endpoint{}", i),
            method: "GET".to_string(),
            rate_limit_policy_id: None,
            requires_auth: i % 2 == 0,
            timeout_secs: 30,
            allowed_roles: vec![],
        };
        gateway.register_route(route);
    }

    assert_eq!(gateway.route_count(), 5);
}

#[test]
fn test_api_gateway_route_lookup() {
    let mut gateway = ApiGateway::new();

    let route = RouteConfig {
        route_id: "lookup_test".to_string(),
        path: "/api/v1/scans".to_string(),
        method: "GET".to_string(),
        rate_limit_policy_id: None,
        requires_auth: false,
        timeout_secs: 30,
        allowed_roles: vec![],
    };

    gateway.register_route(route);

    let found = gateway.get_route("/api/v1/scans", "GET");
    assert!(found.is_some());
    assert_eq!(found.unwrap().route_id, "lookup_test");

    let not_found = gateway.get_route("/api/v1/nonexistent", "POST");
    assert!(not_found.is_none());
}

#[test]
fn test_request_validation_success() {
    let mut gateway = ApiGateway::new();

    let route = RouteConfig {
        route_id: "route1".to_string(),
        path: "/test".to_string(),
        method: "GET".to_string(),
        rate_limit_policy_id: None,
        requires_auth: false,
        timeout_secs: 30,
        allowed_roles: vec![],
    };

    gateway.register_route(route);

    let result = gateway.validate_request("client1", "/test", "GET", "User");
    assert!(result.allowed);
    assert_eq!(result.reason, "OK");
}

#[test]
fn test_request_validation_route_not_found() {
    let gateway = ApiGateway::new();

    let result = gateway.validate_request("client1", "/nonexistent", "GET", "User");
    assert!(!result.allowed);
    assert_eq!(result.reason, "Route not found");
}

#[test]
fn test_request_validation_insufficient_permissions() {
    let mut gateway = ApiGateway::new();

    let route = RouteConfig {
        route_id: "admin_only".to_string(),
        path: "/admin".to_string(),
        method: "GET".to_string(),
        rate_limit_policy_id: None,
        requires_auth: true,
        timeout_secs: 30,
        allowed_roles: vec!["Admin".to_string()],
    };

    gateway.register_route(route);

    let result = gateway.validate_request("client1", "/admin", "GET", "Viewer");
    assert!(!result.allowed);
    assert_eq!(result.reason, "Insufficient permissions");
}

#[test]
fn test_request_validation_with_rate_limit() {
    let mut gateway = ApiGateway::new();

    let policy = RateLimitPolicy {
        policy_id: "strict".to_string(),
        name: "Strict".to_string(),
        strategy: RateLimitStrategy::TokenBucket,
        requests_per_second: 1,
        burst_size: 2,
        window_size_secs: 60,
        enabled: true,
    };

    gateway.rate_limiter.add_policy(policy);

    let route = RouteConfig {
        route_id: "limited".to_string(),
        path: "/limited".to_string(),
        method: "GET".to_string(),
        rate_limit_policy_id: Some("strict".to_string()),
        requires_auth: false,
        timeout_secs: 30,
        allowed_roles: vec![],
    };

    gateway.register_route(route);

    // First request should succeed
    let result1 = gateway.validate_request("client1", "/limited", "GET", "User");
    assert!(result1.allowed);
}

#[test]
fn test_multi_tier_quotas() {
    let _manager = QuotaManager::new();

    // Create tiers with different quotas
    let mut free_quota = ApiQuota::new("free_client".to_string());
    free_quota.requests_per_day = 1000;
    free_quota.scan_credits = 100;

    let mut premium_quota = ApiQuota::new("premium_client".to_string());
    premium_quota.requests_per_day = 100000;
    premium_quota.scan_credits = 10000;

    assert!(free_quota.requests_per_day < premium_quota.requests_per_day);
    assert!(free_quota.scan_credits < premium_quota.scan_credits);
}

#[test]
fn test_rate_limit_strategy_variants() {
    assert_eq!(RateLimitStrategy::TokenBucket.as_str(), "token_bucket");
    assert_eq!(RateLimitStrategy::SlidingWindow.as_str(), "sliding_window");
    assert_eq!(RateLimitStrategy::FixedWindow.as_str(), "fixed_window");
    assert_eq!(RateLimitStrategy::LeakyBucket.as_str(), "leaky_bucket");
}

#[test]
fn test_complex_gateway_scenario() {
    let mut gateway = ApiGateway::new();

    // Add policies
    let policies = vec![
        RateLimitPolicy {
            policy_id: "free".to_string(),
            name: "Free Tier".to_string(),
            strategy: RateLimitStrategy::TokenBucket,
            requests_per_second: 10,
            burst_size: 50,
            window_size_secs: 60,
            enabled: true,
        },
        RateLimitPolicy {
            policy_id: "premium".to_string(),
            name: "Premium Tier".to_string(),
            strategy: RateLimitStrategy::TokenBucket,
            requests_per_second: 1000,
            burst_size: 5000,
            window_size_secs: 60,
            enabled: true,
        },
    ];

    for policy in policies {
        gateway.rate_limiter.add_policy(policy);
    }

    // Add routes
    for i in 0..10 {
        let route = RouteConfig {
            route_id: format!("route_{}", i),
            path: format!("/api/v1/endpoint{}", i),
            method: if i % 2 == 0 { "GET" } else { "POST" }.to_string(),
            rate_limit_policy_id: if i % 3 == 0 {
                Some("free".to_string())
            } else {
                Some("premium".to_string())
            },
            requires_auth: i % 4 == 0,
            timeout_secs: 30,
            allowed_roles: if i % 5 == 0 {
                vec!["Admin".to_string()]
            } else {
                vec![]
            },
        };
        gateway.register_route(route);
    }

    assert_eq!(gateway.route_count(), 10);
    assert_eq!(gateway.rate_limiter.policy_count(), 2);
}
