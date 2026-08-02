use rcgen::generate_simple_self_signed;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct CachedCert {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

pub struct CertCache {
    certs: RwLock<HashMap<String, CachedCert>>,
}

impl CertCache {
    pub fn new() -> Self {
        Self {
            certs: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get_or_generate(&self, domain: &str) -> CachedCert {
        {
            let certs = self.certs.read().await;
            if let Some(cert) = certs.get(domain) {
                return cert.clone();
            }
        }

        let subject_alt_names = vec![domain.to_string()];
        let cert =
            generate_simple_self_signed(subject_alt_names).expect("Failed to generate certificate");

        let cert_der = cert.serialize_der().expect("Failed to serialize cert");
        let key_der = cert.serialize_private_key_der();

        let cached = CachedCert { cert_der, key_der };

        {
            let mut certs = self.certs.write().await;
            certs.insert(domain.to_string(), cached.clone());
        }

        cached
    }
}

impl Default for CertCache {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AsyncMitmProxy {
    listener: TcpListener,
    cert_cache: Arc<CertCache>,
    upstream_addr: String,
}

impl AsyncMitmProxy {
    pub async fn new(listen_addr: &str, upstream_addr: String) -> tokio::io::Result<Self> {
        let listener = TcpListener::bind(listen_addr).await?;
        let cert_cache = Arc::new(CertCache::new());

        Ok(Self {
            listener,
            cert_cache,
            upstream_addr,
        })
    }

    pub async fn start(self) -> tokio::io::Result<()> {
        println!("MITM Proxy listening on {}", self.listener.local_addr()?);

        loop {
            match self.listener.accept().await {
                Ok((client_socket, client_addr)) => {
                    let upstream = self.upstream_addr.clone();
                    let cert_cache = Arc::clone(&self.cert_cache);

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            client_socket,
                            client_addr,
                            &upstream,
                            &cert_cache,
                        )
                        .await
                        {
                            eprintln!("Connection error: {}", e);
                        }
                    });
                },
                Err(e) => eprintln!("Accept error: {}", e),
            }
        }
    }

    async fn handle_connection(
        mut client_socket: TcpStream,
        _client_addr: SocketAddr,
        upstream_addr: &str,
        _cert_cache: &CertCache,
    ) -> tokio::io::Result<()> {
        let mut upstream_socket = TcpStream::connect(upstream_addr).await?;

        let (mut client_read, mut client_write) = client_socket.split();
        let (mut upstream_read, mut upstream_write) = upstream_socket.split();

        let client_to_upstream = async {
            let mut buffer = vec![0u8; 65536];
            loop {
                match client_read.read(&mut buffer).await? {
                    0 => break,
                    n => {
                        upstream_write.write_all(&buffer[..n]).await?;
                    },
                }
            }
            Ok::<_, tokio::io::Error>(())
        };

        let upstream_to_client = async {
            let mut buffer = vec![0u8; 65536];
            loop {
                match upstream_read.read(&mut buffer).await? {
                    0 => break,
                    n => {
                        client_write.write_all(&buffer[..n]).await?;
                    },
                }
            }
            Ok::<_, tokio::io::Error>(())
        };

        tokio::select! {
            res1 = client_to_upstream => res1,
            res2 = upstream_to_client => res2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cert_cache_generation() {
        let cache = CertCache::new();
        let cert1 = cache.get_or_generate("example.com").await;
        let cert2 = cache.get_or_generate("example.com").await;

        assert_eq!(cert1.cert_der, cert2.cert_der);
        assert_eq!(cert1.key_der, cert2.key_der);
    }

    #[tokio::test]
    async fn test_cert_cache_multiple_domains() {
        let cache = CertCache::new();
        let _cert1 = cache.get_or_generate("domain1.com").await;
        let _cert2 = cache.get_or_generate("domain2.com").await;

        let certs = cache.certs.read().await;
        assert_eq!(certs.len(), 2);
    }

    #[tokio::test]
    async fn test_async_mitm_proxy_creation() {
        let result = AsyncMitmProxy::new("127.0.0.1:9999", "127.0.0.1:80".to_string()).await;
        assert!(result.is_ok());
    }
}
