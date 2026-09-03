//! Experimental HTTP adapter for Termivar.
//!
//! ## Runtime scope
//!
//! - **Build:** separate workspace crate (`termivar-api`).
//! - **Execution:** optional CLI startup hook (`termivar-cli/api-adapter`).
//!   `start_api` fails nonzero and does not bind a listener; `router` exposes only
//!   `GET /health` as a library value.
//! - **Default `termivar scan`:** no.
//! - **Support:** unsupported — no live network listener.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The implemented alpha surface is deliberately small: [`router`] exposes
//! `GET /health`, while [`start_api`] is a startup hook and does not yet bind a
//! network listener.
//!
//! # Example
//!
//! ```rust
//! let app = termivar_api::router();
//! # let _ = app;
//! ```

#![deny(rustdoc::broken_intra_doc_links)]

use std::fmt;

use axum::{routing::get, Router};

/// Error returned by the unsupported listener startup hook.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiError {
    address: String,
}

impl ApiError {
    fn unsupported_listener(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }

    /// Returns the address that was not bound.
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the API listener adapter is unsupported and did not bind {}",
            self.address
        )
    }
}

impl fmt::Debug for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ApiError {}

/// Result returned by the API adapter boundary.
pub type Result<T> = std::result::Result<T, ApiError>;

/// Returns `OK` for process-level health checks.
pub async fn health() -> &'static str {
    "OK"
}

/// Builds the currently implemented Axum router.
///
/// The alpha router contains only `GET /health`.
pub fn router() -> Router {
    Router::new().route("/health", get(health))
}

/// Rejects the unsupported API startup hook.
///
/// This function deliberately returns an error because it does not bind `addr`.
/// Callers that need a live server may serve [`router`] with their own Tokio
/// listener until the transport lifecycle is stabilized.
pub async fn start_api(addr: &str) -> Result<()> {
    Err(ApiError::unsupported_listener(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsupported_startup_fails_closed() {
        let error = start_api("127.0.0.1:8080").await.unwrap_err();
        assert_eq!(error.address(), "127.0.0.1:8080");
        assert!(error.to_string().contains("unsupported"));
        assert!(error.to_string().contains("did not bind"));
        assert_eq!(format!("{error:?}"), error.to_string());
    }
}
