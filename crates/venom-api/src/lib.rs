//! Experimental HTTP adapter for Venom.
//!
//! ## Runtime scope
//!
//! - **Build:** separate workspace crate (`venom-api`).
//! - **Execution:** explicit CLI startup hook (`venom api`). `start_api` does not
//!   bind a listener; `router` exposes only `GET /health` as a library value.
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
use venom_core::Result;

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

/// Runs the current API startup hook.
///
/// This function does not bind `addr` yet. Callers that need a live server
/// should serve [`router`] with their own Tokio listener until the transport
/// lifecycle is stabilized.
pub async fn start_api(addr: &str) -> Result<()> {
    println!("API starting on {}", addr);
    Ok(())
}
