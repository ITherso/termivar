//! Experimental HTTP adapter for Venom.
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
use venom_core::Result;

/// Returns `OK` for process-level health checks.
pub async fn health() -> &'static str {
    "OK"
}

/// Builds the currently implemented Axum router.
///
/// The alpha router contains only `GET /health`.
#[must_use]
pub fn router() -> Router {
    Router::new().route("/health", get(health))
}

/// Runs the current API startup hook.
///
/// This function does not bind `addr` yet. Callers that need a live server
/// should serve [`router`] with their own Tokio listener until the transport
/// lifecycle is stabilized.
pub async fn start_api(addr: &str) -> Result<()> {
    println!("API starting on {}", addr);
    Ok(())
}
