//! Experimental fixed-upstream TCP relay boundary for Termivar.
//!
//! ## Runtime scope
//!
//! - **Build:** separate workspace crate (`termivar-proxy`).
//! - **Execution:** explicit optional CLI adapter (`termivar-cli/proxy-adapter`).
//! - **Default `termivar scan`:** no.
//! - **Support:** experimental fixed-upstream bidirectional TCP relay — not a TLS
//!   MITM implementation and not an HTTP interceptor (see [`relay`]).
//!
//! See `docs/internals/runtime-map.md`.
//!
//! [`ProxyServer`] is the process-level adapter around
//! [`FixedUpstreamTcpRelay`]. Both listener and upstream are explicit typed
//! socket addresses. TLS and HTTP interception are not implemented; use only
//! for explicitly authorized traffic.

#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::net::SocketAddr;

pub mod relay;

pub use relay::FixedUpstreamTcpRelay;

type Result<T> = std::io::Result<T>;

/// Configures the listening address for the experimental proxy adapter.
pub struct ProxyServer {
    listen_addr: SocketAddr,
    upstream_addr: SocketAddr,
}

impl ProxyServer {
    /// Creates a relay server with explicit listener and upstream addresses.
    #[must_use]
    pub fn new(listen_addr: SocketAddr, upstream_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            upstream_addr,
        }
    }

    /// Binds the listener and starts relaying to the configured upstream.
    pub async fn start(&self) -> Result<()> {
        FixedUpstreamTcpRelay::bind(self.listen_addr, self.upstream_addr)
            .await?
            .run()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_preserves_explicit_ipv6_endpoints() {
        let listen_addr = "[::1]:8081".parse().unwrap();
        let upstream_addr = "[::1]:9081".parse().unwrap();
        let server = ProxyServer::new(listen_addr, upstream_addr);
        assert_eq!(server.listen_addr, listen_addr);
        assert_eq!(server.upstream_addr, upstream_addr);
    }
}
