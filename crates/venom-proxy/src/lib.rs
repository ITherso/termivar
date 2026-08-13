//! Experimental fixed-upstream TCP relay boundary for Venom.
//!
//! ## Runtime scope
//!
//! - **Build:** separate workspace crate (`venom-proxy`).
//! - **Execution:** explicit optional CLI adapter (`venom-cli/proxy-adapter`).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental fixed-upstream bidirectional TCP relay — not a TLS
//!   MITM implementation and not an HTTP interceptor (see [`mitm`]). The
//!   `AsyncMitmProxy` type name is legacy/aspirational.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! [`ProxyServer`] is the process-level adapter around the legacy-named
//! [`AsyncMitmProxy`] relay. TLS and HTTP interception are not implemented; use
//! only for explicitly authorized traffic.

#![deny(rustdoc::broken_intra_doc_links)]

use std::net::SocketAddr;

pub mod mitm;

pub use mitm::{AsyncMitmProxy, CertCache};

type Result<T> = std::io::Result<T>;

/// Configures the listening address for the experimental proxy adapter.
pub struct ProxyServer {
    listen_addr: String,
}

impl ProxyServer {
    /// Creates a proxy server bound to `addr:port` when started.
    #[must_use]
    pub fn new(addr: String, port: u16) -> Self {
        let listen_addr = match addr.parse::<std::net::IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, port).to_string(),
            Err(_) => format!("{addr}:{port}"),
        };
        Self { listen_addr }
    }

    /// Creates a proxy server from a validated IPv4 or IPv6 socket address.
    #[must_use]
    pub fn from_socket_addr(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
        }
    }

    /// Starts proxying to the current alpha upstream, `127.0.0.1:80`.
    ///
    /// Upstream selection is not yet a stable public configuration contract.
    pub async fn start(&self) -> Result<()> {
        let proxy = AsyncMitmProxy::new(&self.listen_addr, "127.0.0.1:80".to_string()).await?;
        proxy.start().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_address_constructor_preserves_ipv6_brackets() {
        let server = ProxyServer::from_socket_addr("[::1]:8081".parse().unwrap());
        assert_eq!(server.listen_addr, "[::1]:8081");
    }

    #[test]
    fn legacy_constructor_formats_ip_literals_as_socket_addresses() {
        let server = ProxyServer::new("::1".to_string(), 8081);
        assert_eq!(server.listen_addr, "[::1]:8081");
    }
}
