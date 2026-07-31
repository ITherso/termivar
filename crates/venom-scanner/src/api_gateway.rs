//! API Gateway & Advanced Rate Limiting
//!
//! Request throttling, quota management, and intelligent routing.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Rate limit strategy
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
    pub fn as_str(&self) -> &str {
        match self {
            RateLimitStrategy::TokenBucket => "token_bucket",
            RateLimitStrategy::SlidingWindow => "sliding_window",
            RateLimitStrategy::FixedWindow => "fixed_window",
            RateLimitStrategy::LeakyBucket => "leaky_bucket",
        }
    }
}

/// Rate limit policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub policy_id: String,
    pub name: String,
    pub strategy: RateLimitStrategy,
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub window_size_secs: u32,
    pub enabled: bool,
}

/// Rate limit status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStatus {
    pub client_id: String,
    pub requests_allowed: u32,
    pub requests_used: u32,
    pub requests_remaining: u32,
    pub reset_time_secs: u64,
    pub quota_exceeded: bool,
}

/// API quota for clients
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn new(client_id: String) -> Self {
        Self {
            quota_id: format!("quota_{}", uuid::Uuid::new_v4()),
            client_id,
            requests_per_day: 10000,
            requests_used_today: 0,
            scan_credits: 1000,
            scan_credits_used: 0,
            api_calls_this_hour: 0,
            last_reset_time: current_timestamp(),
        }
    }

    pub fn requests_remaining(&self) -> u64 {
        self.requests_per_day
            .saturating_sub(self.requests_used_today)
    }

    pub fn credits_remaining(&self) -> u64 {
        self.scan_credits.saturating_sub(self.scan_credits_used)
    }

    pub fn quota_exceeded(&self) -> bool {
        self.requests_remaining() == 0 || self.credits_remaining() == 0
    }
}

/// Rate limiter using token bucket algorithm
pub struct RateLimiter {
    policies: HashMap<String, RateLimitPolicy>,
    client_tokens: Arc<DashMap<String, TokenBucket>>,
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
pub struct TokenBucket {
    pub tokens: f32,
    pub capacity: f32,
    pub refill_rate: f32,
    pub last_refill_time: u64,
}

impl TokenBucket {
    pub fn new(capacity: f32, refill_rate: f32) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill_time: current_timestamp(),
        }
    }

    pub fn refill(&mut self) {
        let now = current_timestamp();
        let elapsed = (now - self.last_refill_time) as f32;
        let tokens_to_add = elapsed * self.refill_rate;
        self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
        self.last_refill_time = now;
    }

    pub fn try_consume(&mut self, tokens: f32) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            client_tokens: Arc::new(DashMap::new()),
        }
    }

    /// Registers a rate limit policy
    pub fn add_policy(&mut self, policy: RateLimitPolicy) {
        self.policies.insert(policy.policy_id.clone(), policy);
    }

    /// Checks if request is allowed
    pub fn is_allowed(&self, client_id: &str, policy_id: &str) -> bool {
        if let Some(policy) = self.policies.get(policy_id) {
            if !policy.enabled {
                return true;
            }

            let capacity = policy.burst_size as f32;
            let refill_rate = policy.requests_per_second as f32;

            let mut bucket = self
                .client_tokens
                .entry(client_id.to_string())
                .or_insert_with(|| TokenBucket::new(capacity, refill_rate))
                .clone();

            let allowed = bucket.try_consume(1.0);

            if let Some(mut existing) = self.client_tokens.get_mut(client_id) {
                *existing = bucket;
            }

            allowed
        } else {
            true
        }
    }

    /// Gets remaining tokens for client
    pub fn remaining_tokens(&self, client_id: &str, _policy_id: &str) -> Option<f32> {
        self.client_tokens
            .get(client_id)
            .map(|bucket| bucket.tokens)
    }

    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Quota manager for per-client limits
pub struct QuotaManager {
    quotas: Arc<DashMap<String, ApiQuota>>,
}

impl QuotaManager {
    pub fn new() -> Self {
        Self {
            quotas: Arc::new(DashMap::new()),
        }
    }

    /// Creates quota for client
    pub fn create_quota(&self, client_id: String) -> ApiQuota {
        let quota = ApiQuota::new(client_id.clone());
        self.quotas.insert(quota.quota_id.clone(), quota.clone());
        quota
    }

    /// Gets quota by client ID
    pub fn get_quota(&self, quota_id: &str) -> Option<ApiQuota> {
        self.quotas.get(quota_id).map(|q| q.clone())
    }

    /// Increments request count
    pub fn record_request(&self, quota_id: &str, credits_used: u64) -> bool {
        if let Some(mut quota) = self.quotas.get_mut(quota_id) {
            quota.requests_used_today += 1;
            quota.scan_credits_used += credits_used;
            quota.api_calls_this_hour += 1;
            !quota.quota_exceeded()
        } else {
            false
        }
    }

    /// Resets daily quota
    pub fn reset_daily_quota(&self, quota_id: &str) {
        if let Some(mut quota) = self.quotas.get_mut(quota_id) {
            quota.requests_used_today = 0;
            quota.last_reset_time = current_timestamp();
        }
    }

    pub fn quota_count(&self) -> usize {
        self.quotas.len()
    }
}

impl Default for QuotaManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Route configuration for API gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub route_id: String,
    pub path: String,
    pub method: String,
    pub rate_limit_policy_id: Option<String>,
    pub requires_auth: bool,
    pub timeout_secs: u32,
    pub allowed_roles: Vec<String>,
}

/// API Gateway router
pub struct ApiGateway {
    pub routes: HashMap<String, RouteConfig>,
    pub rate_limiter: RateLimiter,
    pub quota_manager: QuotaManager,
}

impl ApiGateway {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            rate_limiter: RateLimiter::new(),
            quota_manager: QuotaManager::new(),
        }
    }

    /// Registers a route
    pub fn register_route(&mut self, route: RouteConfig) {
        self.routes.insert(route.route_id.clone(), route);
    }

    /// Gets route by path and method
    pub fn get_route(&self, path: &str, method: &str) -> Option<&RouteConfig> {
        self.routes
            .values()
            .find(|r| r.path == path && r.method == method)
    }

    /// Validates incoming request
    pub fn validate_request(
        &self,
        client_id: &str,
        path: &str,
        method: &str,
        user_role: &str,
    ) -> RequestValidationResult {
        // Find route
        let route = match self.get_route(path, method) {
            Some(r) => r,
            None => {
                return RequestValidationResult {
                    allowed: false,
                    reason: "Route not found".to_string(),
                    remaining_quota: 0,
                }
            },
        };

        // Check role
        if !route.allowed_roles.is_empty() && !route.allowed_roles.contains(&user_role.to_string())
        {
            return RequestValidationResult {
                allowed: false,
                reason: "Insufficient permissions".to_string(),
                remaining_quota: 0,
            };
        }

        // Check rate limit
        if let Some(policy_id) = &route.rate_limit_policy_id {
            if !self.rate_limiter.is_allowed(client_id, policy_id) {
                return RequestValidationResult {
                    allowed: false,
                    reason: "Rate limit exceeded".to_string(),
                    remaining_quota: 0,
                };
            }
        }

        RequestValidationResult {
            allowed: true,
            reason: "OK".to_string(),
            remaining_quota: 1000,
        }
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }
}

impl Default for ApiGateway {
    fn default() -> Self {
        Self::new()
    }
}

/// Request validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestValidationResult {
    pub allowed: bool,
    pub reason: String,
    pub remaining_quota: u64,
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_policy() {
        let policy = RateLimitPolicy {
            policy_id: "policy1".to_string(),
            name: "Standard".to_string(),
            strategy: RateLimitStrategy::TokenBucket,
            requests_per_second: 100,
            burst_size: 500,
            window_size_secs: 60,
            enabled: true,
        };

        assert_eq!(policy.strategy, RateLimitStrategy::TokenBucket);
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(100.0, 10.0);
        assert_eq!(bucket.tokens, 100.0);

        let consumed = bucket.try_consume(50.0);
        assert!(consumed);
        assert_eq!(bucket.tokens, 50.0);
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new();
        let policy = RateLimitPolicy {
            policy_id: "policy1".to_string(),
            name: "Test".to_string(),
            strategy: RateLimitStrategy::TokenBucket,
            requests_per_second: 10,
            burst_size: 50,
            window_size_secs: 60,
            enabled: true,
        };

        limiter.add_policy(policy);
        assert_eq!(limiter.policy_count(), 1);
    }

    #[test]
    fn test_api_quota() {
        let quota = ApiQuota::new("client1".to_string());
        assert_eq!(quota.requests_per_day, 10000);
        assert_eq!(quota.requests_remaining(), 10000);
    }

    #[test]
    fn test_quota_manager() {
        let manager = QuotaManager::new();
        let quota = manager.create_quota("client1".to_string());

        assert!(manager.get_quota(&quota.quota_id).is_some());
    }

    #[test]
    fn test_route_config() {
        let route = RouteConfig {
            route_id: "route1".to_string(),
            path: "/api/v1/scans".to_string(),
            method: "POST".to_string(),
            rate_limit_policy_id: Some("policy1".to_string()),
            requires_auth: true,
            timeout_secs: 30,
            allowed_roles: vec!["Admin".to_string(), "Analyst".to_string()],
        };

        assert_eq!(route.path, "/api/v1/scans");
    }

    #[test]
    fn test_api_gateway() {
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
        assert_eq!(gateway.route_count(), 1);
    }

    #[test]
    fn test_rate_limit_strategy() {
        assert_eq!(RateLimitStrategy::TokenBucket.as_str(), "token_bucket");
        assert_eq!(RateLimitStrategy::SlidingWindow.as_str(), "sliding_window");
    }
}
