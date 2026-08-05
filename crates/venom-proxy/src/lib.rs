//! Experimental HTTP/TLS proxy boundary for Venom.
//!
//! ## Runtime scope
//!
//! - **Build:** separate workspace crate (`venom-proxy`).
//! - **Execution:** explicit CLI adapter (`venom proxy`).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental fixed-upstream bidirectional TCP relay — not a TLS
//!   MITM implementation and not an HTTP interceptor (see [`mitm`]). The
//!   `AsyncMitmProxy` type name is legacy/aspirational.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! [`ProxyServer`] is the process-level adapter around [`AsyncMitmProxy`]. The
//! interception API is unstable during the alpha release line and must only be
//! used for explicitly authorized traffic.

#![deny(rustdoc::broken_intra_doc_links)]

pub mod mitm;

pub use mitm::{AsyncMitmProxy, CertCache};

/// Configures the listening address for the experimental proxy adapter.
pub struct ProxyServer {
    addr: String,
    port: u16,
}

impl ProxyServer {
    /// Creates a proxy server bound to `addr:port` when started.
    #[must_use]
    pub fn new(addr: String, port: u16) -> Self {
        Self { addr, port }
    }

    /// Starts proxying to the current alpha upstream, `127.0.0.1:80`.
    ///
    /// Upstream selection is not yet a stable public configuration contract.
    pub async fn start(&self) -> Result<()> {
        let listen_addr = format!("{}:{}", self.addr, self.port);
        let proxy = AsyncMitmProxy::new(&listen_addr, "127.0.0.1:80".to_string()).await?;
        proxy.start().await
    }
}

type Result<T> = std::io::Result<T>;
