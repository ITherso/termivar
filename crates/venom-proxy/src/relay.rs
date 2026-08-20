//! Explicit fixed-upstream TCP relay.
//!
//! The relay accepts a TCP connection, opens the configured upstream socket,
//! and copies bytes bidirectionally. It does not parse HTTP `CONNECT`, terminate
//! TLS, generate certificates, or inspect application traffic.

use std::net::SocketAddr;

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
};

/// A bound TCP listener that relays each connection to one explicit upstream.
#[derive(Debug)]
pub struct FixedUpstreamTcpRelay {
    listener: TcpListener,
    upstream_addr: SocketAddr,
}

impl FixedUpstreamTcpRelay {
    /// Binds `listen_addr` and records the explicit fixed upstream.
    pub async fn bind(listen_addr: SocketAddr, upstream_addr: SocketAddr) -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(listen_addr).await?,
            upstream_addr,
        })
    }

    /// Returns the bound listener address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Returns the configured fixed upstream.
    #[must_use]
    pub fn upstream_addr(&self) -> SocketAddr {
        self.upstream_addr
    }

    /// Accepts connections until the listener fails or the task is cancelled.
    pub async fn run(self) -> std::io::Result<()> {
        let listen_addr = self.listener.local_addr()?;
        eprintln!(
            "fixed-upstream TCP relay listening on {listen_addr}, upstream {}",
            self.upstream_addr
        );

        loop {
            let (downstream, _) = self.listener.accept().await?;
            let upstream_addr = self.upstream_addr;
            tokio::spawn(async move {
                if let Err(error) = relay_connection(downstream, upstream_addr).await {
                    eprintln!("TCP relay connection failed: {error}");
                }
            });
        }
    }
}

async fn relay_connection(
    mut downstream: TcpStream,
    upstream_addr: SocketAddr,
) -> std::io::Result<()> {
    let mut upstream = TcpStream::connect(upstream_addr).await?;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn relays_bytes_only_to_the_explicit_loopback_upstream() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let relay = FixedUpstreamTcpRelay::bind("127.0.0.1:0".parse().unwrap(), upstream_addr)
            .await
            .unwrap();
        assert_eq!(relay.upstream_addr(), upstream_addr);
        let relay_addr = relay.local_addr().unwrap();
        let relay_task = tokio::spawn(relay.run());

        let upstream_task = tokio::spawn(async move {
            let (mut connection, _) = upstream_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            connection.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            connection.write_all(b"pong").await.unwrap();
            connection.shutdown().await.unwrap();
        });

        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        upstream_task.await.unwrap();
        relay_task.abort();
    }
}
