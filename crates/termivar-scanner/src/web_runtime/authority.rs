//! Shared authority for every subject executed by one bounded web runtime.
//!
//! The authority is intentionally crate-private. Product runtimes may clone its
//! handles, but cannot mint a second request budget, transport broker, knowledge
//! store, cancellation domain, or wall-clock origin for another subject in the
//! same assessment.

use std::sync::{Arc, OnceLock};

use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    http_evidence::HttpRequestBroker, runtime_budget::RequestAccountingBroker, HttpEvidenceError,
    HttpEvidencePolicy, KnowledgeBase, RuntimeBudget,
};

#[cfg(feature = "tls-observation")]
use super::{TlsObservationCollector, WebAssessmentTlsObservationAudit};

#[cfg(feature = "oast-native-provider")]
use crate::native_oast_provider::{
    NativeOastProviderAdapter, NativeOastProviderConfiguration, NativeOastProviderError,
};

#[cfg(feature = "oast-native-provider")]
struct NativeOastProviderMintSeal;

/// Move-only proof that a native-provider adapter was minted by the one
/// shared web-runtime authority.
///
/// The private seal deliberately has no constructor or trait implementations.
/// Sibling scanner modules may name this crate-private type through the
/// `web_runtime` re-export, but only this module can construct it.
#[cfg(feature = "oast-native-provider")]
pub(crate) struct NativeOastProviderMintToken(NativeOastProviderMintSeal);

/// Returns whether credentials may be dispatched to this exact target.
///
/// Authenticated transport requires HTTPS except for numeric-IP loopback HTTP
/// fixtures. Hostname-based localhost and every other cleartext origin fail
/// closed before secret material reaches transport.
pub(crate) fn authenticated_transport_is_allowed(target: &Url) -> bool {
    target.scheme() == "https"
        || (target.scheme() == "http"
            && target.host().is_some_and(|host| {
                matches!(host, url::Host::Ipv4(ip) if ip.is_loopback())
                    || matches!(host, url::Host::Ipv6(ip) if ip.is_loopback())
            }))
}

/// One immutable wall-clock origin and absolute deadline shared by all subjects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SharedWebRuntimeTiming {
    started_at: tokio::time::Instant,
    deadline: Option<tokio::time::Instant>,
}

impl SharedWebRuntimeTiming {
    pub(crate) const fn started_at(self) -> tokio::time::Instant {
        self.started_at
    }

    pub(crate) const fn deadline(self) -> Option<tokio::time::Instant> {
        self.deadline
    }
}

/// Singleton capability bundle for one exact-origin web run.
///
/// Cloning this type clones shared handles only. The request counters, transport
/// audit, knowledge base, cancellation state, and lazily established absolute
/// deadline remain common to every clone.
#[derive(Clone)]
pub(crate) struct SharedWebRuntimeAuthority {
    policy: HttpEvidencePolicy,
    budget: RuntimeBudget,
    knowledge: KnowledgeBase,
    requests: HttpRequestBroker,
    request_accounting: RequestAccountingBroker,
    cancellation: CancellationToken,
    timing: Arc<OnceLock<SharedWebRuntimeTiming>>,
    #[cfg(feature = "tls-observation")]
    tls_observation: Option<TlsObservationCollector>,
    #[cfg(feature = "oast-native-provider")]
    native_oast_provider_minted: Arc<std::sync::Mutex<bool>>,
}

impl SharedWebRuntimeAuthority {
    /// Creates the sole metered transport authority for an exact origin.
    ///
    /// A custom policy may carry broader host authorization for another API, but
    /// this runtime narrows its private broker to `target`'s exact origin after
    /// proving that the supplied policy already authorized that target.
    pub(crate) fn new_exact_origin(
        target: &Url,
        policy: HttpEvidencePolicy,
        budget: RuntimeBudget,
        cancellation: CancellationToken,
    ) -> Result<Self, HttpEvidenceError> {
        Self::new_exact_origin_inner(
            target,
            policy,
            budget,
            cancellation,
            #[cfg(feature = "tls-observation")]
            None,
        )
    }

    /// Creates the exact-origin authority with passive TLS observation selected.
    #[cfg(feature = "tls-observation")]
    pub(crate) fn new_exact_origin_with_tls_observation(
        target: &Url,
        policy: HttpEvidencePolicy,
        budget: RuntimeBudget,
        cancellation: CancellationToken,
    ) -> Result<Self, HttpEvidenceError> {
        Self::new_exact_origin_inner(
            target,
            policy,
            budget,
            cancellation,
            Some(TlsObservationCollector::new(target.scheme())),
        )
    }

    /// Test-only verified trusted-root constructor for one owned TLS fixture.
    #[cfg(all(test, feature = "tls-observation"))]
    fn new_exact_origin_with_tls_observation_and_test_root(
        target: &Url,
        policy: HttpEvidencePolicy,
        budget: RuntimeBudget,
        cancellation: CancellationToken,
        root_certificate_der: &[u8],
        resolved_address: std::net::SocketAddr,
    ) -> Result<Self, HttpEvidenceError> {
        let host = target
            .host_str()
            .ok_or_else(|| HttpEvidenceError::InvalidUrl {
                value: target.as_str().to_owned(),
                source: url::ParseError::EmptyHost,
            })?;
        let policy = policy.restricted_to_exact_origin(target)?;
        let request_accounting = RequestAccountingBroker::new(budget);
        let tls_observation = TlsObservationCollector::new(target.scheme());
        let requests = HttpRequestBroker::new_metered_with_tls_observation_and_test_root(
            policy.clone(),
            request_accounting.clone(),
            tls_observation.clone(),
            root_certificate_der,
            host,
            resolved_address,
        )?;

        Ok(Self {
            policy,
            budget,
            knowledge: KnowledgeBase::new(),
            requests,
            request_accounting,
            cancellation,
            timing: Arc::new(OnceLock::new()),
            tls_observation: Some(tls_observation),
            #[cfg(feature = "oast-native-provider")]
            native_oast_provider_minted: Arc::new(std::sync::Mutex::new(false)),
        })
    }

    fn new_exact_origin_inner(
        target: &Url,
        policy: HttpEvidencePolicy,
        budget: RuntimeBudget,
        cancellation: CancellationToken,
        #[cfg(feature = "tls-observation")] tls_observation: Option<TlsObservationCollector>,
    ) -> Result<Self, HttpEvidenceError> {
        let policy = policy.restricted_to_exact_origin(target)?;
        let request_accounting = RequestAccountingBroker::new(budget);
        #[cfg(feature = "tls-observation")]
        let requests = match tls_observation.as_ref() {
            Some(collector) => HttpRequestBroker::new_metered_with_tls_observation(
                policy.clone(),
                request_accounting.clone(),
                collector.clone(),
            )?,
            None => HttpRequestBroker::new_metered(policy.clone(), request_accounting.clone())?,
        };
        #[cfg(not(feature = "tls-observation"))]
        let requests = HttpRequestBroker::new_metered(policy.clone(), request_accounting.clone())?;

        Ok(Self {
            policy,
            budget,
            knowledge: KnowledgeBase::new(),
            requests,
            request_accounting,
            cancellation,
            timing: Arc::new(OnceLock::new()),
            #[cfg(feature = "tls-observation")]
            tls_observation,
            #[cfg(feature = "oast-native-provider")]
            native_oast_provider_minted: Arc::new(std::sync::Mutex::new(false)),
        })
    }

    /// Fails closed unless `target` belongs to this authority's exact origin.
    pub(crate) fn authorize_target(&self, target: &Url) -> Result<(), HttpEvidenceError> {
        self.policy.require_permitted_target(target)
    }

    pub(crate) const fn budget(&self) -> RuntimeBudget {
        self.budget
    }

    pub(crate) const fn knowledge(&self) -> &KnowledgeBase {
        &self.knowledge
    }

    pub(crate) const fn requests(&self) -> &HttpRequestBroker {
        &self.requests
    }

    pub(crate) const fn request_accounting(&self) -> &RequestAccountingBroker {
        &self.request_accounting
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub(crate) const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    #[cfg(feature = "tls-observation")]
    pub(crate) fn tls_observation_audit(&self) -> Option<WebAssessmentTlsObservationAudit> {
        self.tls_observation
            .as_ref()
            .map(TlsObservationCollector::audit)
    }

    /// Starts the shared monotonic clock once and returns the same timing on replay.
    ///
    /// Lazy start preserves the standalone runtime contract: time between
    /// `build()` and the first execution attempt is not charged. An assessment
    /// starts the authority before discovery, so every later subject inherits
    /// that already-established absolute deadline.
    pub(crate) fn start(&self) -> SharedWebRuntimeTiming {
        *self.timing.get_or_init(|| {
            let started_at = tokio::time::Instant::now();
            SharedWebRuntimeTiming {
                started_at,
                deadline: started_at.checked_add(self.budget.max_wall_time()),
            }
        })
    }

    /// Mints the single narrowing native-provider authority from the same
    /// broker, budget, cancellation domain, exact target origin, and absolute
    /// deadline already owned by this assessment.
    #[cfg(feature = "oast-native-provider")]
    #[cfg_attr(
        all(not(test), not(feature = "ssrf-oast-review")),
        expect(
            dead_code,
            reason = "sealed PR B authority is consumed only by the separately gated ssrf-oast-review capability"
        )
    )]
    pub(crate) fn mint_native_oast_provider(
        &self,
        configuration: NativeOastProviderConfiguration,
    ) -> Result<NativeOastProviderAdapter, NativeOastProviderError> {
        let mut minted = self
            .native_oast_provider_minted
            .lock()
            .map_err(|_| NativeOastProviderError::internal_invariant())?;
        if *minted {
            return Err(NativeOastProviderError::authority_already_minted());
        }
        let target_origin = self
            .policy
            .allowed_origins()
            .iter()
            .next()
            .filter(|_| self.policy.allowed_origins().len() == 1)
            .ok_or_else(NativeOastProviderError::internal_invariant)?;
        let timing = self.start();
        let adapter = NativeOastProviderAdapter::mint(
            NativeOastProviderMintToken(NativeOastProviderMintSeal),
            configuration,
            target_origin,
            self.request_accounting.clone(),
            self.budget,
            self.cancellation.clone(),
            timing.deadline(),
        )?;
        *minted = true;
        Ok(adapter)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "tls-observation")]
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use termivar_core::{
        ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource, EvidenceValue,
        HttpEvidencePredicate,
    };

    use super::*;
    #[cfg(feature = "tls-observation")]
    use crate::{DecisionExecutionLimits, HttpProbe, HttpProbeMethod};
    use crate::{DecisionExecutionStage, RuntimeBudgetDimension, TransportDispatchOutcome};

    #[cfg(feature = "tls-observation")]
    const OWNED_TLS_LEAF: &str = concat!(
        "MIIBszCCAVmgAwIBAgIUUg3keFcU1xXWK8BNVb1KynPulV8wCgYIKoZIzj0EAwIw",
        "JjEkMCIGA1UEAwwbUnVzdGxzIFJvYnVzdCBSb290IC0gUnVuZyAyMCAXDTc1MDEw",
        "MTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAwWjAhMR8wHQYDVQQDDBZyY2dlbiBzZWxm",
        "IHNpZ25lZCBjZXJ0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEud6w4gtZ0xbw",
        "J3E69SSMy5TZfdIifl9L5ZY+hgEe4UiUsBWS32f6Y5NR5Jo8FO1f6o13b3+FvVHR",
        "EHCGdvppL6NoMGYwFQYDVR0RBA4wDIIKZm9vYmFyLmNvbTAdBgNVHSUEFjAUBggr",
        "BgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFELvxbj5tD75n4pYFvJyr+c8qVEi",
        "MA8GA1UdEwEB/wQFMAMBAQAwCgYIKoZIzj0EAwIDSAAwRQIhALxSSdUsrRFnwNMu",
        "/doBqI8i8u5HdohVAheFTDwObkOMAiASSjULUtkWSD15u/7Sr01Wm9J1MpqW1pob",
        "BVqU3CNRlA=="
    );
    #[cfg(feature = "tls-observation")]
    const OWNED_TLS_INTERMEDIATE: &str = concat!(
        "MIIBiTCCATCgAwIBAgIUHWiVYIvMMWoZEFYvSz46COf2FqowCgYIKoZIzj0EAwIw",
        "HTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY",
        "DzQwOTYwMTAxMDAwMDAwWjAmMSQwIgYDVQQDDBtSdXN0bHMgUm9idXN0IFJvb3Qg",
        "LSBSdW5nIDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATAOCcBD7dXjmAZ3te5",
        "D47cCJ9ec93PWv7BKYIL826CJsKfXQOGrBTthLm77hXLhHu6uv8E5QXNLZpfowLQ",
        "Do1ao0MwQTAPBgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRdza76r11Ok9vRmlg6",
        "Nn/wL/N+jTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIFmZrXeK",
        "hnfkahocvkhhNT3cDv1LWf6WBoFaCiBwZXFPAiARaKRiSCMG7PCHmSqFe82TBVmL",
        "odHGogAVax1Dh/aYAA=="
    );
    #[cfg(feature = "tls-observation")]
    const OWNED_TLS_ROOT: &str = concat!(
        "MIIBgDCCASegAwIBAgIUPHDUu9WL36yvTmFeNFZVe/qhClcwCgYIKoZIzj0EAwIw",
        "HTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY",
        "DzQwOTYwMTAxMDAwMDAwWjAdMRswGQYDVQQDDBJSdXN0bHMgUm9idXN0IFJvb3Qw",
        "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASW/VkDFs5iGDQvH8jaXYT4jMx66jo+",
        "5CWKyMt4OlTDdBfKfnmQ9LYeK/PsYfJ8wVizuSlPzXi9je8SnyYejGP3o0MwQTAP",
        "BgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRqY/oMENJbNo7y39iL6GW3tDs0rzAP",
        "BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIEUbrmSUjANju9nNpFop",
        "PAl9Wh8tBxI5IY+BPh466+aUAiA1/9+prypt6s3Doo0GDsnoFGJi1UBivUg1qdik",
        "cy4eNw=="
    );
    #[cfg(feature = "tls-observation")]
    const OWNED_TLS_KEY: &str = concat!(
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTbAQpfjAT46fgF4B",
        "mP15n37woNG5ZNJmwcqsred/7tmhRANCAAS53rDiC1nTFvAncTr1JIzLlNl90iJ+",
        "X0vllj6GAR7hSJSwFZLfZ/pjk1HkmjwU7V/qjXdvf4W9UdEQcIZ2+mkv"
    );

    fn target(path: &str) -> Url {
        Url::parse(&format!("https://example.test{path}")).unwrap()
    }

    #[cfg(feature = "tls-observation")]
    struct OwnedTlsMaterial {
        root_der: Vec<u8>,
        leaf_der: Vec<u8>,
        chain: Vec<Vec<u8>>,
        key_der: Vec<u8>,
    }

    #[cfg(feature = "tls-observation")]
    fn generate_owned_tls_material(
        dns_name: &str,
        not_before_year: i32,
        not_after_year: i32,
        intermediate: bool,
        include_intermediate: bool,
    ) -> OwnedTlsMaterial {
        use rcgen::{
            date_time_ymd, BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose,
            IsCa, KeyPair, KeyUsagePurpose,
        };

        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Termivar owned TLS root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let root_key = KeyPair::generate().unwrap();
        let root = root_params.self_signed(&root_key).unwrap();

        let mut leaf_params = CertificateParams::new(vec![dns_name.to_owned()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, dns_name);
        leaf_params.not_before = date_time_ymd(not_before_year, 1, 1);
        leaf_params.not_after = date_time_ymd(not_after_year, 1, 1);
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let (leaf, intermediate_der) = if intermediate {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params
                .distinguished_name
                .push(DnType::CommonName, "Termivar owned TLS intermediate");
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let key = KeyPair::generate().unwrap();
            let certificate = params.signed_by(&key, &root, &root_key).unwrap();
            let leaf = leaf_params
                .signed_by(&leaf_key, &certificate, &key)
                .unwrap();
            (leaf, Some(certificate.der().to_vec()))
        } else {
            (
                leaf_params.signed_by(&leaf_key, &root, &root_key).unwrap(),
                None,
            )
        };
        let leaf_der = leaf.der().to_vec();
        let mut chain = vec![leaf_der.clone()];
        if include_intermediate {
            chain.extend(intermediate_der);
        }
        OwnedTlsMaterial {
            root_der: root.der().to_vec(),
            leaf_der,
            chain,
            key_der: leaf_key.serialize_der(),
        }
    }

    #[cfg(feature = "tls-observation")]
    async fn serve_tls_once(
        chain: Vec<Vec<u8>>,
        key_der: Vec<u8>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<bool>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::{
            rustls::{
                pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
                ServerConfig,
            },
            TlsAcceptor,
        };

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let certificates = chain.into_iter().map(CertificateDer::from).collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return false;
            };
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() <= 16 * 1024);
            }
            assert!(request.starts_with(b"GET /observed HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
            true
        });
        (address, task)
    }

    #[cfg(feature = "tls-observation")]
    async fn serve_owned_tls_once() -> (std::net::SocketAddr, tokio::task::JoinHandle<bool>) {
        // DER/key material copied from rustls's MIT/Apache-2.0 licensed test
        // corpus (`tests/common/key/ecdsa-p256`). It is public, task-owned test
        // material only and never enters the product or report.
        serve_tls_once(
            vec![
                STANDARD.decode(OWNED_TLS_LEAF).unwrap(),
                STANDARD.decode(OWNED_TLS_INTERMEDIATE).unwrap(),
            ],
            STANDARD.decode(OWNED_TLS_KEY).unwrap(),
        )
        .await
    }

    #[cfg(feature = "tls-observation")]
    async fn serve_plain_http_once() -> (Url, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        (
            Url::parse(&format!("http://{address}/plain")).unwrap(),
            task,
        )
    }

    #[cfg(feature = "tls-observation")]
    #[tokio::test]
    async fn selected_tls_observation_uses_verified_owned_loopback_response_without_extra_dispatch()
    {
        use sha2::{Digest, Sha256};

        let (address, server) = serve_owned_tls_once().await;
        let url = Url::parse(&format!("https://foobar.com:{}/observed", address.port())).unwrap();
        let root = STANDARD.decode(OWNED_TLS_ROOT).unwrap();
        let leaf = STANDARD.decode(OWNED_TLS_LEAF).unwrap();
        let authority =
            SharedWebRuntimeAuthority::new_exact_origin_with_tls_observation_and_test_root(
                &url,
                HttpEvidencePolicy::for_origin(url.clone()).unwrap(),
                RuntimeBudget::default(),
                CancellationToken::new(),
                &root,
                address,
            )
            .unwrap();
        let response = authority
            .requests()
            .collect_for_runtime(
                "tls-observation.owned-loopback",
                DecisionExecutionStage::Passive,
                None,
                DecisionExecutionLimits::default(),
                &HttpProbe::new(url, HttpProbeMethod::Get).unwrap(),
            )
            .await
            .unwrap();
        assert!(server.await.unwrap());

        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"ok");
        let accounting = authority.request_accounting().snapshot();
        assert_eq!(accounting.total_requests(), 1);
        let dispatch = authority.request_accounting().dispatch_audit();
        assert_eq!(dispatch.receipts().len(), 1);
        assert_eq!(
            dispatch.receipts()[0].outcome(),
            TransportDispatchOutcome::Completed
        );
        let audit = authority.tls_observation_audit().unwrap();
        assert_eq!(audit.successful_https_response_count(), 1);
        assert_eq!(audit.plaintext_response_count(), 0);
        assert_eq!(audit.tls_info_unavailable_count(), 0);
        assert_eq!(audit.malformed_certificate_count(), 0);
        assert_eq!(audit.additional_request_count(), 0);
        assert_eq!(audit.leaf_observations().len(), 1);
        assert_eq!(
            audit.leaf_observations()[0].byte_length(),
            leaf.len() as u64
        );
        assert_eq!(
            audit.leaf_observations()[0].sha256(),
            format!("{:x}", Sha256::digest(&leaf))
        );
        assert_eq!(audit.leaf_observations()[0].response_occurrence_count(), 1);
    }

    #[cfg(feature = "tls-observation")]
    async fn assert_tls_validation_failure(
        material: OwnedTlsMaterial,
        trusted_root: Vec<u8>,
        request_host: &str,
    ) {
        let (address, server) = serve_tls_once(material.chain, material.key_der).await;
        let url = Url::parse(&format!(
            "https://{request_host}:{}/observed",
            address.port()
        ))
        .unwrap();
        let authority =
            SharedWebRuntimeAuthority::new_exact_origin_with_tls_observation_and_test_root(
                &url,
                HttpEvidencePolicy::for_origin(url.clone()).unwrap(),
                RuntimeBudget::default(),
                CancellationToken::new(),
                &trusted_root,
                address,
            )
            .unwrap();
        let result = authority
            .requests()
            .collect_for_runtime(
                "tls-observation.validation-failure",
                DecisionExecutionStage::Passive,
                None,
                DecisionExecutionLimits::default(),
                &HttpProbe::new(url, HttpProbeMethod::Get).unwrap(),
            )
            .await;
        assert!(result.is_err());
        assert!(!server.await.unwrap(), "invalid TLS must not reach HTTP");
        assert_eq!(
            authority.request_accounting().snapshot().total_requests(),
            1
        );
        let dispatch = authority.request_accounting().dispatch_audit();
        assert_eq!(dispatch.receipts().len(), 1);
        assert_eq!(
            dispatch.receipts()[0].outcome(),
            TransportDispatchOutcome::TransportFailure
        );
        let audit = authority.tls_observation_audit().unwrap();
        assert_eq!(audit.successful_https_response_count(), 0);
        assert_eq!(audit.tls_info_unavailable_count(), 0);
        assert_eq!(audit.malformed_certificate_count(), 0);
        assert!(audit.leaf_observations().is_empty());
    }

    #[cfg(feature = "tls-observation")]
    #[tokio::test]
    async fn tls_validation_failures_never_create_leaf_observations() {
        let untrusted = generate_owned_tls_material("foobar.com", 2020, 2040, false, false);
        let unrelated_root =
            generate_owned_tls_material("unrelated.test", 2020, 2040, false, false).root_der;
        assert_tls_validation_failure(untrusted, unrelated_root, "foobar.com").await;

        let hostname_mismatch = generate_owned_tls_material("foobar.com", 2020, 2040, false, false);
        let root = hostname_mismatch.root_der.clone();
        assert_tls_validation_failure(hostname_mismatch, root, "wrong.example").await;

        let incomplete_chain = generate_owned_tls_material("foobar.com", 2020, 2040, true, false);
        let root = incomplete_chain.root_der.clone();
        assert_tls_validation_failure(incomplete_chain, root, "foobar.com").await;

        let expired = generate_owned_tls_material("foobar.com", 2000, 2001, false, false);
        let root = expired.root_der.clone();
        assert_tls_validation_failure(expired, root, "foobar.com").await;

        let not_yet_valid = generate_owned_tls_material("foobar.com", 2040, 2041, false, false);
        let root = not_yet_valid.root_der.clone();
        assert_tls_validation_failure(not_yet_valid, root, "foobar.com").await;
    }

    #[cfg(feature = "tls-observation")]
    async fn observe_generated_leaf(
        material: OwnedTlsMaterial,
    ) -> (crate::web_runtime::TlsLeafObservation, String) {
        use sha2::{Digest, Sha256};

        let expected = format!("{:x}", Sha256::digest(&material.leaf_der));
        let root = material.root_der.clone();
        let (address, server) = serve_tls_once(material.chain, material.key_der).await;
        let url = Url::parse(&format!("https://foobar.com:{}/observed", address.port())).unwrap();
        let authority =
            SharedWebRuntimeAuthority::new_exact_origin_with_tls_observation_and_test_root(
                &url,
                HttpEvidencePolicy::for_origin(url.clone()).unwrap(),
                RuntimeBudget::default(),
                CancellationToken::new(),
                &root,
                address,
            )
            .unwrap();
        authority
            .requests()
            .collect_for_runtime(
                "tls-observation.alternate-leaf",
                DecisionExecutionStage::Passive,
                None,
                DecisionExecutionLimits::default(),
                &HttpProbe::new(url, HttpProbeMethod::Get).unwrap(),
            )
            .await
            .unwrap();
        assert!(server.await.unwrap());
        assert_eq!(
            authority.request_accounting().snapshot().total_requests(),
            1
        );
        let audit = authority.tls_observation_audit().unwrap();
        assert_eq!(audit.leaf_observations().len(), 1);
        (audit.leaf_observations()[0].clone(), expected)
    }

    #[cfg(feature = "tls-observation")]
    #[tokio::test]
    async fn alternate_valid_certificates_produce_distinct_exact_leaf_hashes() {
        let first = generate_owned_tls_material("foobar.com", 2000, 2100, false, false);
        let second = generate_owned_tls_material("foobar.com", 2000, 2100, false, false);
        let (first_observed, first_expected) = observe_generated_leaf(first).await;
        let (second_observed, second_expected) = observe_generated_leaf(second).await;
        assert_eq!(first_observed.sha256(), first_expected);
        assert_eq!(second_observed.sha256(), second_expected);
        assert_ne!(first_observed.sha256(), second_observed.sha256());
        for observed in [first_observed, second_observed] {
            assert_eq!(observed.not_before_epoch_seconds(), 946_684_800);
            assert_eq!(observed.not_after_epoch_seconds(), 4_102_444_800);
            assert_eq!(observed.dns_san_count(), 1);
            assert_eq!(observed.ip_san_count(), 0);
            assert_eq!(observed.other_san_count(), 0);
            assert!(!observed.san_count_truncated());
            assert_eq!(
                observed.certificate_time_status(),
                crate::web_runtime::TlsCertificateTimeStatus::ValidAtObservation
            );
            assert!(observed.standard_transport_validation_succeeded());
        }
    }

    #[cfg(feature = "tls-observation")]
    #[tokio::test]
    async fn selected_plain_http_records_not_applicable_without_an_extra_dispatch() {
        let (url, server) = serve_plain_http_once().await;
        let authority = SharedWebRuntimeAuthority::new_exact_origin_with_tls_observation(
            &url,
            HttpEvidencePolicy::for_origin(url.clone()).unwrap(),
            RuntimeBudget::default(),
            CancellationToken::new(),
        )
        .unwrap();
        authority
            .requests()
            .collect_for_runtime(
                "tls-observation.plain-http",
                DecisionExecutionStage::Passive,
                None,
                DecisionExecutionLimits::default(),
                &HttpProbe::new(url, HttpProbeMethod::Get).unwrap(),
            )
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(
            authority.request_accounting().snapshot().total_requests(),
            1
        );
        let audit = authority.tls_observation_audit().unwrap();
        assert_eq!(audit.plaintext_response_count(), 1);
        assert_eq!(audit.successful_https_response_count(), 0);
        assert!(audit.leaf_observations().is_empty());
    }

    #[cfg(feature = "tls-observation")]
    #[test]
    fn option_off_constructor_retains_no_tls_observation_state() {
        let root = target("/root");
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &root,
            HttpEvidencePolicy::for_origin(root.clone()).unwrap(),
            RuntimeBudget::default(),
            CancellationToken::new(),
        )
        .unwrap();
        assert!(authority.tls_observation_audit().is_none());
    }

    #[test]
    fn authority_narrows_a_broader_policy_to_one_exact_origin() {
        let root = target("/root");
        let policy = HttpEvidencePolicy::new(
            [root.clone(), Url::parse("https://other.test/").unwrap()],
            std::time::Duration::from_secs(2),
            1024,
        )
        .unwrap();
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &root,
            policy,
            RuntimeBudget::default(),
            CancellationToken::new(),
        )
        .unwrap();

        assert_eq!(
            authority.requests().policy().allowed_origins(),
            &std::collections::BTreeSet::from(["https://example.test".to_owned()])
        );
        authority.authorize_target(&target("/next")).unwrap();
        assert!(matches!(
            authority.authorize_target(&Url::parse("https://other.test/").unwrap()),
            Err(HttpEvidenceError::TargetOutsidePolicy { .. })
        ));
    }

    #[test]
    fn authority_revalidates_same_origin_credentials_and_unsupported_schemes() {
        let root = target("/root");
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &root,
            HttpEvidencePolicy::for_origin(root.clone()).unwrap(),
            RuntimeBudget::default(),
            CancellationToken::new(),
        )
        .unwrap();

        assert!(matches!(
            authority.authorize_target(
                &Url::parse("https://embedded:secret@example.test/private").unwrap()
            ),
            Err(HttpEvidenceError::EmbeddedCredentials)
        ));
        assert!(matches!(
            authority.authorize_target(&Url::parse("ftp://example.test/archive").unwrap()),
            Err(HttpEvidenceError::UnsupportedScheme { .. })
        ));
    }

    #[test]
    fn clones_share_budget_knowledge_cancellation_and_absolute_deadline() {
        let target = target("/one");
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &target,
            HttpEvidencePolicy::for_origin(target.clone()).unwrap(),
            RuntimeBudget::default().with_max_total_requests(1),
            CancellationToken::new(),
        )
        .unwrap();
        let clone = authority.clone();

        let timing = authority.start();
        assert_eq!(clone.start(), timing);
        assert_eq!(
            timing.deadline(),
            timing
                .started_at()
                .checked_add(RuntimeBudget::default().max_wall_time())
        );

        let subject = EntityId::new(format!("endpoint:{target}")).unwrap();
        let evidence = Evidence::new(
            subject.clone(),
            EvidenceKind::Http,
            HttpEvidencePredicate::RESPONSE_STATUS.into(),
            EvidenceValue::Unsigned(200),
            EvidenceSource::new("authority-test", "status").unwrap(),
            ConfidenceScore::MAX,
        );
        authority.knowledge().insert_evidence(evidence).unwrap();
        assert_eq!(clone.knowledge().evidence_for_subject(&subject).len(), 1);

        let mut lease = authority
            .request_accounting()
            .try_begin("action.one", DecisionExecutionStage::Passive, None)
            .unwrap();
        lease.finish(TransportDispatchOutcome::Completed);
        drop(lease);
        let limit = clone
            .request_accounting()
            .try_begin("action.two", DecisionExecutionStage::Passive, None)
            .unwrap_err();
        assert_eq!(limit.dimension(), RuntimeBudgetDimension::TotalRequests);

        clone.cancellation_token().cancel();
        assert!(authority.cancellation().is_cancelled());
    }

    #[cfg(feature = "oast-native-provider")]
    #[test]
    fn native_oast_mint_narrows_the_shared_broker_and_separates_provider_from_target() {
        use crate::native_oast_provider::{
            NativeOastProviderConfiguration, NativeOastProviderErrorKind,
            NativeOastProviderLifecycle, NativeOastProviderLimits,
        };

        let root = target("/root");
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &root,
            HttpEvidencePolicy::for_origin(root.clone()).unwrap(),
            RuntimeBudget::default(),
            CancellationToken::new(),
        )
        .unwrap();
        let clone = authority.clone();
        let limits = NativeOastProviderLimits::new(1, 1, 4, 1, 16_384, 65_536, 5_000).unwrap();

        let overlap = clone
            .mint_native_oast_provider(
                NativeOastProviderConfiguration::new(
                    "https://example.test/",
                    "assessment:native-oast-overlap",
                    [72; 32],
                    b"NATIVE-OAST-OVERLAP-MUST-NOT-LEAK-83B4".to_vec(),
                    limits,
                )
                .unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            overlap.kind(),
            NativeOastProviderErrorKind::ProviderTargetOriginOverlap
        );

        let adapter = authority
            .mint_native_oast_provider(
                NativeOastProviderConfiguration::new(
                    "https://oast.example.test/",
                    "assessment:native-oast-authority",
                    [71; 32],
                    b"NATIVE-OAST-AUTHORITY-MUST-NOT-LEAK-91A7".to_vec(),
                    limits,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(adapter.lifecycle(), NativeOastProviderLifecycle::Configured);
        assert!(authority
            .authorize_target(&Url::parse("https://oast.example.test/v1/sessions").unwrap())
            .is_err());

        let second = clone
            .mint_native_oast_provider(
                NativeOastProviderConfiguration::new(
                    "https://other-oast.example.test/",
                    "assessment:native-oast-second",
                    [73; 32],
                    b"NATIVE-OAST-SECOND-MUST-NOT-LEAK-68C2".to_vec(),
                    limits,
                )
                .unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            second.kind(),
            NativeOastProviderErrorKind::AuthorityAlreadyMinted
        );
        assert_eq!(
            second.to_string(),
            "native OAST provider authority was already minted"
        );
    }
}
