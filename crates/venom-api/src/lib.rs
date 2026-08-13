//! Experimental HTTP adapter for Venom.
//!
//! ## Runtime scope
//!
//! - **Build:** separate workspace crate (`venom-api`).
//! - **Execution:** optional CLI startup hook (`venom-cli/api-adapter`).
//!   `start_api` fails nonzero and does not bind a listener; `router` exposes only
//!   `GET /health` as a library value.
//! - **Default `venom scan`:** no.
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
//! let app = venom_api::router();
//! # let _ = app;
//! ```

#![deny(rustdoc::broken_intra_doc_links)]

use axum::{routing::get, Router};
use venom_core::{Error, Result};

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
    Err(Error::api(format!(
        "the API listener adapter is unsupported and did not bind {addr}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsupported_startup_fails_closed() {
        let error = start_api("127.0.0.1:8080").await.unwrap_err();
        assert_eq!(error.kind(), "API");
        assert!(error.to_string().contains("unsupported"));
        assert!(error.to_string().contains("did not bind"));
    }
}
