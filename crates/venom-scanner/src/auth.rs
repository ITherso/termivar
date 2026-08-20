//! Identity metadata records.
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
//! This module contains non-secret identity metadata. It deliberately does not
//! accept, issue, store, validate, serialize, or debug-print passwords, API
//! keys, session tokens, or other credentials. Authentication and permission
//! enforcement belong to an integrating host.

use serde::{Deserialize, Serialize};

/// Role label supplied by an integrating host.
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
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Analyst => "analyst",
            Self::Viewer => "viewer",
            Self::ApiOnly => "api_only",
        }
    }
}

/// Non-secret user metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub role: UserRole,
    pub created_at: u64,
    pub last_login: Option<u64>,
    pub active: bool,
}

impl User {
    /// Creates a metadata record with a locally unique identifier.
    #[must_use]
    pub fn new(username: String, email: String, role: UserRole) -> Self {
        Self {
            user_id: uuid::Uuid::new_v4().to_string(),
            username,
            email,
            role,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_login: None,
            active: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn role_names_are_metadata_not_permission_decisions() {
        assert_eq!(UserRole::Admin.as_str(), "admin");
        assert_eq!(UserRole::Analyst.as_str(), "analyst");
        assert_eq!(UserRole::Viewer.as_str(), "viewer");
        assert_eq!(UserRole::ApiOnly.as_str(), "api_only");
    }

    #[test]
    fn user_serialization_contains_no_credential_fields() {
        let user = User::new(
            "analyst".to_owned(),
            "analyst@example.test".to_owned(),
            UserRole::Analyst,
        );

        let encoded = serde_json::to_value(&user).unwrap();
        let object = encoded.as_object().unwrap();
        for forbidden in ["api_key", "password", "token", "secret"] {
            assert!(!object.contains_key(forbidden));
        }

        let debug = format!("{user:?}");
        assert!(!debug.contains("credential-canary"));
    }

    #[test]
    fn legacy_secret_bearing_user_shape_is_rejected() {
        let encoded = json!({
            "user_id": "user-1",
            "username": "analyst",
            "email": "analyst@example.test",
            "role": "analyst",
            "api_key": "credential-canary",
            "created_at": 1,
            "last_login": null,
            "active": true
        });

        assert!(serde_json::from_value::<User>(encoded).is_err());
    }
}
