//! Authentication & Authorization Module
//!
//! User management, API key generation, role-based access control (RBAC).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// User role definitions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "analyst")]
    Analyst,
    #[serde(rename = "viewer")]
    Viewer,
    #[serde(rename = "api_only")]
    ApiOnly,
}

impl UserRole {
    pub fn as_str(&self) -> &str {
        match self {
            UserRole::Admin => "admin",
            UserRole::Analyst => "analyst",
            UserRole::Viewer => "viewer",
            UserRole::ApiOnly => "api_only",
        }
    }

    /// Checks if role has permission
    pub fn has_permission(&self, permission: &str) -> bool {
        match self {
            UserRole::Admin => true, // Admin has all permissions
            UserRole::Analyst => {
                matches!(
                    permission,
                    "view_scans"
                        | "create_scan"
                        | "modify_scan"
                        | "view_findings"
                        | "export_report"
                )
            },
            UserRole::Viewer => {
                matches!(permission, "view_scans" | "view_findings" | "export_report")
            },
            UserRole::ApiOnly => {
                matches!(permission, "api_access")
            },
        }
    }
}

/// User account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub role: UserRole,
    pub api_key: Option<String>,
    pub created_at: u64,
    pub last_login: Option<u64>,
    pub active: bool,
}

impl User {
    /// Creates a new user
    pub fn new(username: String, email: String, role: UserRole) -> Self {
        Self {
            user_id: uuid::Uuid::new_v4().to_string(),
            username,
            email,
            role,
            api_key: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_login: None,
            active: true,
        }
    }

    /// Generates API key
    pub fn generate_api_key(&mut self) -> String {
        let key = format!("venom_{}_{}", self.user_id, uuid::Uuid::new_v4());
        self.api_key = Some(key.clone());
        key
    }

    /// Records login time
    pub fn record_login(&mut self) {
        self.last_login = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    }
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub token: String,
    pub user_id: String,
    pub role: UserRole,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl AuthToken {
    /// Creates a new token
    pub fn new(user_id: String, role: UserRole, ttl_secs: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            token: uuid::Uuid::new_v4().to_string(),
            user_id,
            role,
            issued_at: now,
            expires_at: now + ttl_secs,
        }
    }

    /// Checks if token is expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }

    /// Checks if token has permission
    pub fn has_permission(&self, permission: &str) -> bool {
        !self.is_expired() && self.role.has_permission(permission)
    }
}

/// User credentials for login
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Login response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserInfo,
    pub expires_in: u64,
}

/// Public user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub role: String,
}

/// User manager
pub struct UserManager {
    users: HashMap<String, User>,
    tokens: HashMap<String, AuthToken>,
}

impl UserManager {
    /// Creates a new user manager
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            tokens: HashMap::new(),
        }
    }

    /// Creates a new user
    pub fn create_user(&mut self, username: String, email: String, role: UserRole) -> User {
        let user = User::new(username, email, role);
        self.users.insert(user.user_id.clone(), user.clone());
        user
    }

    /// Gets user by ID
    pub fn get_user(&self, user_id: &str) -> Option<User> {
        self.users.get(user_id).cloned()
    }

    /// Generates auth token for user
    pub fn generate_token(&mut self, user_id: String, ttl_secs: u64) -> Option<AuthToken> {
        if let Some(user) = self.users.get(&user_id) {
            let token = AuthToken::new(user_id, user.role, ttl_secs);
            self.tokens.insert(token.token.clone(), token.clone());
            Some(token)
        } else {
            None
        }
    }

    /// Validates token
    pub fn validate_token(&self, token: &str) -> Option<AuthToken> {
        self.tokens
            .get(token)
            .cloned()
            .filter(|token| !token.is_expired())
    }

    /// Revokes token
    pub fn revoke_token(&mut self, token: &str) -> bool {
        self.tokens.remove(token).is_some()
    }

    /// User count
    pub fn user_count(&self) -> usize {
        self.users.len()
    }
}

impl Default for UserManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_role_permissions() {
        assert!(UserRole::Admin.has_permission("create_scan"));
        assert!(UserRole::Analyst.has_permission("create_scan"));
        assert!(!UserRole::Viewer.has_permission("create_scan"));
    }

    #[test]
    fn test_user_creation() {
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            UserRole::Analyst,
        );
        assert_eq!(user.username, "testuser");
        assert_eq!(user.role, UserRole::Analyst);
        assert!(user.active);
    }

    #[test]
    fn test_api_key_generation() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            UserRole::Analyst,
        );
        let key = user.generate_api_key();
        assert!(key.starts_with("venom_"));
        assert_eq!(user.api_key, Some(key));
    }

    #[test]
    fn test_auth_token_creation() {
        let token = AuthToken::new("user123".to_string(), UserRole::Admin, 3600);
        assert!(!token.is_expired());
        assert!(token.has_permission("create_scan"));
    }

    #[test]
    fn test_expired_token() {
        let mut token = AuthToken::new("user123".to_string(), UserRole::Admin, 3600);
        // Manually set expires_at to the past
        token.expires_at = token.issued_at - 100;
        assert!(token.is_expired());
        assert!(!token.has_permission("create_scan"));
    }

    #[test]
    fn test_user_manager() {
        let mut manager = UserManager::new();
        let user = manager.create_user(
            "testuser".to_string(),
            "test@example.com".to_string(),
            UserRole::Analyst,
        );

        assert_eq!(manager.user_count(), 1);
        assert_eq!(
            manager.get_user(&user.user_id).unwrap().username,
            "testuser"
        );
    }

    #[test]
    fn test_token_generation_and_validation() {
        let mut manager = UserManager::new();
        let user = manager.create_user(
            "testuser".to_string(),
            "test@example.com".to_string(),
            UserRole::Analyst,
        );

        let token = manager.generate_token(user.user_id.clone(), 3600).unwrap();
        let validated = manager.validate_token(&token.token);

        assert!(validated.is_some());
    }

    #[test]
    fn test_token_revocation() {
        let mut manager = UserManager::new();
        let user = manager.create_user(
            "testuser".to_string(),
            "test@example.com".to_string(),
            UserRole::Analyst,
        );
        let token = manager.generate_token(user.user_id, 3600).unwrap();

        assert!(manager.revoke_token(&token.token));
        assert!(manager.validate_token(&token.token).is_none());
    }

    #[test]
    fn test_login_request() {
        let login = LoginRequest {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        assert_eq!(login.username, "user");
    }

    #[test]
    fn test_user_info() {
        let info = UserInfo {
            user_id: "123".to_string(),
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            role: "admin".to_string(),
        };

        assert_eq!(info.role, "admin");
    }
}
