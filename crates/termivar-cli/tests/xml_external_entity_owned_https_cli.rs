//! Actual-process owned-HTTPS acceptance for controlled XML review.
//!
//! The fixture keeps ordinary hostname and certificate-chain validation. The
//! closed compile profile maps two fixed `.test` identities onto two distinct
//! loopback addresses; it does not expose caller-selected trust or DNS input.

#![cfg(feature = "xml-external-entity-owned-https-test-profile")]

use std::{
    collections::BTreeSet,
    env, fs, io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Output, Stdio},
    sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use termivar_oast::{
    serve_provider_on_listener_with_request_ledger, AdminToken, LoopbackBind, ProviderConfig,
    ProviderLimits, ProviderState, ProviderTestRequestLedger, ProviderTestRequestSnapshot,
    PublicOrigin,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};
use url::Url;

const TARGET_HOST: &str = "xml-target.termivar.test";
const PROVIDER_HOST: &str = "oast-provider.termivar.test";
const PROVIDER_ORIGIN: &str = "https://oast-provider.termivar.test/";
const ADMIN_SECRET: &[u8] = b"OWNED-XML-OAST-ADMIN-MUST-NOT-LEAK-91A7D4E2";
const JSON_NAME: &str = "assessment.json";
const MAX_FIXTURE_REQUEST_BYTES: usize = 96 * 1_024;
const MAX_PARSER_OUTPUT_BYTES: usize = 4 * 1_024;
const MAX_TERMIVAR_OUTPUT_BYTES: usize = 2 * 1_024 * 1_024;
const PARSER_TIMEOUT: Duration = Duration::from_secs(5);
const TERMIVAR_TIMEOUT: Duration = Duration::from_secs(45);
const XML_MEDIA_TYPE: &str = "application/xml; charset=utf-8";
const POST_RESPONSE_SENTINEL: &[u8] = b"OWNED_XML_POST_RESPONSE_MUST_NOT_LEAK_5E3A91C7";
const GET_RESPONSE_SENTINEL: &[u8] = b"OWNED_XML_GET_RESPONSE_MUST_NOT_LEAK_2D8B64F0";
const EXPAT_HELPER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/xml_expat_owned_https.py"
);

// Public test root SHA-256:
// 8a838ab89d539252df6bafc16eb489aebb42cbd350b941f3d708fecc7041d409
// Its private key is deliberately not retained in the repository.
const ROOT_CERTIFICATE_DER_BASE64: &str = concat!(
    "MIIBjTCCATOgAwIBAgIJAJLYjoWViQgyMAoGCCqGSM49BAMCMCkxJzAlBgNVBAMT",
    "HlRlcm1pdmFyIE93bmVkIEhUVFBTIFRlc3QgUm9vdDAgFw0yNjA4MzAwMDAwMDBa",
    "GA8yMDk5MTIzMTIzNTk1OVowKTEnMCUGA1UEAxMeVGVybWl2YXIgT3duZWQgSFRU",
    "UFMgVGVzdCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEIQz45V50Pyx",
    "2eBYt1RA6bImh/m+1+tFfrE3o4dEwLpyfTYF314TD9K/HFknQlmO2//jzCYCXAWJ",
    "JkBnmP5qRqNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYD",
    "VR0OBBYEFBd0YfXO+Bxp1hr5F4pYDhecrqA3MAoGCCqGSM49BAMCA0gAMEUCIEYh",
    "m8rw77JIp6N6ZYDJT6Vvh37VamQZZJpzCuSNKLwzAiEAzsZJR6xAfZPCEjF1SSi9",
    "QZHP7IZerxPUSmqzKFPCGsM=",
);

// Harmless fixture-only leaf certificate. SHA-256:
// 59f309b27977c182fd780ef141f94933870fccd0203a0490fce513d088f0fde2
const TARGET_CERTIFICATE_DER_BASE64: &str = concat!(
    "MIIBzDCCAXKgAwIBAgIRALhsqz1EJuw7B+km1k2o0I4wCgYIKoZIzj0EAwIwKTEn",
    "MCUGA1UEAxMeVGVybWl2YXIgT3duZWQgSFRUUFMgVGVzdCBSb290MCAXDTI2MDgz",
    "MDAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5WjAjMSEwHwYDVQQDExh4bWwtdGFyZ2V0",
    "LnRlcm1pdmFyLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARXB7l88Pqf",
    "JZRSxjIyvjmoJB5zJeNmVW5yFOV5YIME4lln5RA1OCN+LmtDg1KnFODCI8x4iJmS",
    "krhM8FDTsTfwo38wfTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAWBgNV",
    "HSUBAf8EDDAKBggrBgEFBQcDATAmBgNVHREBAf8EHDAaghh4bWwtdGFyZ2V0LnRl",
    "cm1pdmFyLnRlc3QwHQYDVR0OBBYEFISgirl45m9mugolOLxEyZqD1ORrMAoGCCqG",
    "SM49BAMCA0gAMEUCIQDeD1Ki5rvbmuJOmhrIo9JYp27Rkb2TXJcuPTgZBYqVfQIg",
    "PlaNXprli3miCepASnh8eHx73IMxRTBL4Jj673kXGhQ=",
);
const TARGET_PRIVATE_KEY_PKCS8_BASE64: &str = concat!(
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDFqndX0ICI09OnWp",
    "FeblzCo3QLV20Awz6QxTU/wmTBOhRANCAARXB7l88PqfJZRSxjIyvjmoJB5zJeNm",
    "VW5yFOV5YIME4lln5RA1OCN+LmtDg1KnFODCI8x4iJmSkrhM8FDTsTfw",
);

// Harmless fixture-only leaf certificate. SHA-256:
// 49668ee55df7177bd3276b73cb0a59ce6c26862222189127093b9bf44556ca01
const PROVIDER_CERTIFICATE_DER_BASE64: &str = concat!(
    "MIIB1DCCAXqgAwIBAgIRAJ2VCRSvAPiG6sgAwVd7ZtcwCgYIKoZIzj0EAwIwKTEn",
    "MCUGA1UEAxMeVGVybWl2YXIgT3duZWQgSFRUUFMgVGVzdCBSb290MCAXDTI2MDgz",
    "MDAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5WjAmMSQwIgYDVQQDExtvYXN0LXByb3Zp",
    "ZGVyLnRlcm1pdmFyLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASZbDAL",
    "2nexLDOQP3Z3/dGvMTqug3UxQo8KZO3pheeuYwnuNyia0ucrlbFwBmTk01N9Ub1Q",
    "vbmYvpPLsukZZKhCo4GDMIGAMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA",
    "MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMBMCkGA1UdEQEB/wQfMB2CG29hc3QtcHJv",
    "dmlkZXIudGVybWl2YXIudGVzdDAdBgNVHQ4EFgQUG0tNOY9y20ce3HakZVADlK63",
    "1GQwCgYIKoZIzj0EAwIDSAAwRQIgIr9Gb/i05tdaM/Ms1BSJa9ztYMRIj7/Zrxsg",
    "ct1ho5QCIQDa6sE+A/Hw5ZIHiC+ytyLIgdgDBvqAA/fmDmamyz8x7w==",
);
const PROVIDER_PRIVATE_KEY_PKCS8_BASE64: &str = concat!(
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguMlws94WzulnlRZ+",
    "BbWg2z9ehMlYDcUUQgU7yy0xUcChRANCAASZbDAL2nexLDOQP3Z3/dGvMTqug3Ux",
    "Qo8KZO3pheeuYwnuNyia0ucrlbFwBmTk01N9Ub1QvbmYvpPLsukZZKhC",
);

#[derive(Clone, Debug, PartialEq, Eq)]
struct TargetRequestFact {
    method: String,
    path: String,
    body_len: usize,
    parser_mode: ParserMode,
    parser_external_entity_count: usize,
    content_type: ContentTypeClass,
    host: HostClass,
    envelope_role: XmlEnvelopeRole,
    private_callback_sentinels: Vec<PrivateFixtureSentinel>,
    administrator_secret_present: bool,
    authorization_header_present: bool,
    cookie_header_present: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContentTypeClass {
    ExactXml,
    Missing,
    OtherOrDuplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostClass {
    Exact,
    Missing,
    OtherOrDuplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XmlEnvelopeRole {
    Control,
    Candidate,
    Replay,
    Invalid,
}

#[derive(Clone, PartialEq, Eq)]
struct PrivateFixtureSentinel(Vec<u8>);

impl std::fmt::Debug for PrivateFixtureSentinel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivateFixtureSentinel(<redacted>)")
    }
}

impl PrivateFixtureSentinel {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum ParserMode {
    Safe = 0,
    External = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderCertificate {
    Correct,
    WrongHostname,
    InvalidChain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetCertificate {
    Correct,
    WrongHostname,
    InvalidChain,
}

impl ParserMode {
    const fn argument(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::External => "external",
        }
    }

    fn from_atomic(value: u8) -> Self {
        match value {
            0 => Self::Safe,
            1 => Self::External,
            _ => panic!("fixture parser mode invariant"),
        }
    }
}

struct OwnedHttpsFixture {
    target_url: String,
    target_requests: Arc<Mutex<Vec<TargetRequestFact>>>,
    parser_mode: Arc<AtomicU8>,
    parser_resolutions: Arc<AtomicUsize>,
    target_connections: Arc<AtomicUsize>,
    target_connections_finished: Arc<AtomicUsize>,
    target_tls_rejections: Arc<AtomicUsize>,
    provider_connections: Arc<AtomicUsize>,
    provider_connections_finished: Arc<AtomicUsize>,
    provider_tls_rejections: Arc<AtomicUsize>,
    provider_request_ledger: ProviderTestRequestLedger,
    fixture_errors: Arc<Mutex<Vec<&'static str>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl OwnedHttpsFixture {
    fn select_parser_mode(&self, mode: ParserMode) {
        self.parser_mode.store(mode as u8, Ordering::SeqCst);
    }

    fn provider_requests(&self) -> ProviderTestRequestSnapshot {
        self.provider_request_ledger.snapshot()
    }

    fn private_callback_sentinels(&self) -> Vec<PrivateFixtureSentinel> {
        let mut sentinels = self
            .provider_request_ledger
            .private_identity_sentinels()
            .into_iter()
            .map(PrivateFixtureSentinel)
            .collect::<Vec<_>>();
        for request in self.target_requests.lock().unwrap().iter() {
            for sentinel in &request.private_callback_sentinels {
                if !sentinels.contains(sentinel) {
                    sentinels.push(sentinel.clone());
                }
            }
        }
        sentinels
    }

    async fn shutdown(self) -> FixtureSnapshot {
        let quiescent = async {
            loop {
                if self.target_connections.load(Ordering::SeqCst)
                    == self.target_connections_finished.load(Ordering::SeqCst)
                    && self.provider_connections.load(Ordering::SeqCst)
                        == self.provider_connections_finished.load(Ordering::SeqCst)
                {
                    break;
                }
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        if timeout(Duration::from_secs(2), quiescent).await.is_err() {
            self.fixture_errors
                .lock()
                .unwrap()
                .push("fixture_connections_not_quiescent");
        }
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
        FixtureSnapshot {
            target_requests: self.target_requests.lock().unwrap().clone(),
            parser_resolutions: self.parser_resolutions.load(Ordering::SeqCst),
            target_connections: self.target_connections.load(Ordering::SeqCst),
            target_tls_rejections: self.target_tls_rejections.load(Ordering::SeqCst),
            provider_connections: self.provider_connections.load(Ordering::SeqCst),
            provider_tls_rejections: self.provider_tls_rejections.load(Ordering::SeqCst),
            provider_requests: self.provider_request_ledger.snapshot(),
            fixture_errors: self.fixture_errors.lock().unwrap().clone(),
        }
    }
}

#[derive(Debug)]
struct FixtureSnapshot {
    target_requests: Vec<TargetRequestFact>,
    parser_resolutions: usize,
    target_connections: usize,
    target_tls_rejections: usize,
    provider_connections: usize,
    provider_tls_rejections: usize,
    provider_requests: ProviderTestRequestSnapshot,
    fixture_errors: Vec<&'static str>,
}

fn termivar() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_termivar"));
    command.stdin(Stdio::null());
    command.kill_on_drop(true);
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(key);
    }
    command.env_remove("SSL_CERT_FILE");
    command.env_remove("SSL_CERT_DIR");
    command
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: status={:?}, stdout_bytes={}, stderr_bytes={}",
        output.status.code(),
        output.stdout.len(),
        output.stderr.len(),
    );
}

async fn run_termivar(mut command: Command, operation: &str) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("{operation} could not start: {error}"));
    let stdout = child.stdout.take().expect("termivar stdout pipe");
    let stderr = child.stderr.take().expect("termivar stderr pipe");
    let execution = async {
        let (status, stdout, stderr) = tokio::try_join!(
            child.wait(),
            read_bounded_pipe(stdout, MAX_TERMIVAR_OUTPUT_BYTES),
            read_bounded_pipe(stderr, MAX_TERMIVAR_OUTPUT_BYTES),
        )?;
        Ok::<_, io::Error>(Output {
            status,
            stdout,
            stderr,
        })
    };
    match timeout(TERMIVAR_TIMEOUT, execution).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => panic!("{operation} failed while collecting bounded output: {error}"),
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            panic!("{operation} exceeded its fixture timeout");
        },
    }
}

fn assert_no_private_sentinels(bytes: &[u8], source: &str) {
    for (label, sentinel) in [
        ("administrator_secret", ADMIN_SECRET),
        ("provider_host", PROVIDER_HOST.as_bytes()),
        ("endpoint_path", b"xml-parser".as_slice()),
        ("raw_doctype", b"<!ENTITY".as_slice()),
        ("raw_entity_name", b"termivar_external".as_slice()),
        ("post_response", POST_RESPONSE_SENTINEL),
        ("get_response", GET_RESPONSE_SENTINEL),
        ("policy_path", b"owned-xml-policy-".as_slice()),
        ("secret_path", b"owned-provider-".as_slice()),
    ] {
        assert!(
            !bytes
                .windows(sentinel.len())
                .any(|window| window == sentinel),
            "{source} leaked {label}"
        );
    }
}

fn assert_no_dynamic_sentinels(bytes: &[u8], source: &str, sentinels: &[PrivateFixtureSentinel]) {
    for sentinel in sentinels {
        let sentinel = sentinel.as_slice();
        assert!(
            sentinel.len() >= 16,
            "private fixture sentinel was not distinctive"
        );
        assert!(
            !bytes
                .windows(sentinel.len())
                .any(|window| window == sentinel),
            "{source} leaked a private callback identity"
        );
    }
}

fn assert_output_has_no_private_sentinels(output: &Output, operation: &str) {
    assert_no_private_sentinels(&output.stdout, operation);
    assert_no_private_sentinels(&output.stderr, operation);
}

fn assert_output_has_no_dynamic_sentinels(
    output: &Output,
    operation: &str,
    sentinels: &[PrivateFixtureSentinel],
) {
    assert_no_dynamic_sentinels(&output.stdout, operation, sentinels);
    assert_no_dynamic_sentinels(&output.stderr, operation, sentinels);
}

fn decode(source: &str) -> Vec<u8> {
    STANDARD.decode(source).expect("fixed base64 must decode")
}

fn tls_acceptor(certificate: &str, private_key: &str) -> TlsAcceptor {
    let certificates = vec![CertificateDer::from(decode(certificate))];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(decode(private_key)));
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .expect("fixed fixture certificate and key must agree");
    TlsAcceptor::from(Arc::new(server))
}

fn tls_acceptor_with_invalid_signature(certificate: &str, private_key: &str) -> TlsAcceptor {
    let mut certificate = decode(certificate);
    let signature_byte = certificate.last_mut().expect("fixture certificate bytes");
    *signature_byte ^= 1;
    let certificates = vec![CertificateDer::from(certificate)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(decode(private_key)));
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .expect("corrupted-signature certificate retains the fixture public key");
    TlsAcceptor::from(Arc::new(server))
}

async fn bind_distinct_frontends() -> (TcpListener, TcpListener, u16) {
    for _ in 0..32 {
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind owned target TLS listener");
        let port = target.local_addr().unwrap().port();
        if let Ok(provider) = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 2), port)).await {
            return (target, provider, port);
        }
    }
    panic!("could not bind distinct owned target/provider loopback identities");
}

async fn start_fixture(provider_certificate: ProviderCertificate) -> OwnedHttpsFixture {
    start_fixture_with_certificates(TargetCertificate::Correct, provider_certificate).await
}

async fn start_fixture_with_certificates(
    target_certificate: TargetCertificate,
    provider_certificate: ProviderCertificate,
) -> OwnedHttpsFixture {
    let (target_listener, provider_tls_listener, port) = bind_distinct_frontends().await;
    let provider_backend_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind native-provider backend");
    let provider_backend = provider_backend_listener.local_addr().unwrap();

    let provider_limits =
        ProviderLimits::new(1, 3, 3, 8, 3, 30_000, 16).expect("fixture provider limits");
    let public_origin: PublicOrigin = PROVIDER_ORIGIN.parse().expect("fixed provider origin");
    let provider = ProviderState::new(
        ProviderConfig::new(
            LoopbackBind::new(provider_backend).unwrap(),
            public_origin,
            provider_limits,
        ),
        AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
    )
    .expect("construct provider state");

    let fixture_errors = Arc::new(Mutex::new(Vec::new()));
    let target_requests = Arc::new(Mutex::new(Vec::new()));
    let parser_mode = Arc::new(AtomicU8::new(ParserMode::Safe as u8));
    let parser_resolutions = Arc::new(AtomicUsize::new(0));
    let target_connections = Arc::new(AtomicUsize::new(0));
    let target_connections_finished = Arc::new(AtomicUsize::new(0));
    let target_tls_rejections = Arc::new(AtomicUsize::new(0));
    let provider_connections = Arc::new(AtomicUsize::new(0));
    let provider_connections_finished = Arc::new(AtomicUsize::new(0));
    let provider_tls_rejections = Arc::new(AtomicUsize::new(0));
    let provider_request_ledger = ProviderTestRequestLedger::new();

    let backend_ledger = provider_request_ledger.clone();
    let backend_errors = fixture_errors.clone();
    let backend_task = tokio::spawn(async move {
        if serve_provider_on_listener_with_request_ledger(
            provider_backend_listener,
            provider,
            backend_ledger,
        )
        .await
        .is_err()
        {
            backend_errors
                .lock()
                .unwrap()
                .push("provider_backend_failed");
        }
    });
    let proxy_task = tokio::spawn(run_tls_proxy(
        provider_tls_listener,
        match provider_certificate {
            ProviderCertificate::Correct => tls_acceptor(
                PROVIDER_CERTIFICATE_DER_BASE64,
                PROVIDER_PRIVATE_KEY_PKCS8_BASE64,
            ),
            ProviderCertificate::WrongHostname => tls_acceptor(
                TARGET_CERTIFICATE_DER_BASE64,
                TARGET_PRIVATE_KEY_PKCS8_BASE64,
            ),
            ProviderCertificate::InvalidChain => tls_acceptor_with_invalid_signature(
                PROVIDER_CERTIFICATE_DER_BASE64,
                PROVIDER_PRIVATE_KEY_PKCS8_BASE64,
            ),
        },
        provider_backend,
        provider_connections.clone(),
        provider_connections_finished.clone(),
        provider_tls_rejections.clone(),
        provider_certificate != ProviderCertificate::Correct,
        fixture_errors.clone(),
    ));
    let target_task = tokio::spawn(run_target_server(
        target_listener,
        match target_certificate {
            TargetCertificate::Correct => tls_acceptor(
                TARGET_CERTIFICATE_DER_BASE64,
                TARGET_PRIVATE_KEY_PKCS8_BASE64,
            ),
            TargetCertificate::WrongHostname => tls_acceptor(
                PROVIDER_CERTIFICATE_DER_BASE64,
                PROVIDER_PRIVATE_KEY_PKCS8_BASE64,
            ),
            TargetCertificate::InvalidChain => tls_acceptor_with_invalid_signature(
                TARGET_CERTIFICATE_DER_BASE64,
                TARGET_PRIVATE_KEY_PKCS8_BASE64,
            ),
        },
        port,
        target_requests.clone(),
        parser_mode.clone(),
        parser_resolutions.clone(),
        target_connections.clone(),
        target_connections_finished.clone(),
        target_tls_rejections.clone(),
        target_certificate != TargetCertificate::Correct,
        fixture_errors.clone(),
    ));

    OwnedHttpsFixture {
        target_url: format!("https://{TARGET_HOST}:{port}/application/"),
        target_requests,
        parser_mode,
        parser_resolutions,
        target_connections,
        target_connections_finished,
        target_tls_rejections,
        provider_connections,
        provider_connections_finished,
        provider_tls_rejections,
        provider_request_ledger,
        fixture_errors,
        tasks: vec![target_task, proxy_task, backend_task],
    }
}

async fn run_tls_proxy(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    backend: SocketAddr,
    connections: Arc<AtomicUsize>,
    connections_finished: Arc<AtomicUsize>,
    tls_rejections: Arc<AtomicUsize>,
    expect_tls_rejection: bool,
    errors: Arc<Mutex<Vec<&'static str>>>,
) {
    let mut active = JoinSet::new();
    loop {
        let accepted = listener.accept().await;
        let Ok((stream, _)) = accepted else {
            errors.lock().unwrap().push("provider_tls_accept_failed");
            return;
        };
        connections.fetch_add(1, Ordering::SeqCst);
        let acceptor = acceptor.clone();
        let connections_finished = connections_finished.clone();
        let tls_rejections = tls_rejections.clone();
        let errors = errors.clone();
        active.spawn(async move {
            let mut frontend = match acceptor.accept(stream).await {
                Ok(frontend) => {
                    if expect_tls_rejection {
                        errors
                            .lock()
                            .unwrap()
                            .push("provider_tls_unexpected_accept");
                        connections_finished.fetch_add(1, Ordering::SeqCst);
                        return;
                    }
                    frontend
                },
                Err(_) => {
                    if expect_tls_rejection {
                        tls_rejections.fetch_add(1, Ordering::SeqCst);
                    } else {
                        errors.lock().unwrap().push("provider_tls_handshake_failed");
                    }
                    connections_finished.fetch_add(1, Ordering::SeqCst);
                    return;
                },
            };
            let result = async {
                let mut backend = TcpStream::connect(backend).await?;
                tokio::io::copy_bidirectional(&mut frontend, &mut backend).await?;
                Ok::<(), io::Error>(())
            }
            .await;
            if result.is_err() {
                errors.lock().unwrap().push("provider_tls_proxy_failed");
            }
            connections_finished.fetch_add(1, Ordering::SeqCst);
        });
        while active.try_join_next().is_some() {}
    }
}

async fn run_target_server(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    provider_port: u16,
    requests: Arc<Mutex<Vec<TargetRequestFact>>>,
    parser_mode: Arc<AtomicU8>,
    parser_resolutions: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    connections_finished: Arc<AtomicUsize>,
    tls_rejections: Arc<AtomicUsize>,
    expect_tls_rejection: bool,
    errors: Arc<Mutex<Vec<&'static str>>>,
) {
    let mut active = JoinSet::new();
    loop {
        let accepted = listener.accept().await;
        let Ok((stream, _)) = accepted else {
            errors.lock().unwrap().push("target_tls_accept_failed");
            return;
        };
        connections.fetch_add(1, Ordering::SeqCst);
        let acceptor = acceptor.clone();
        let requests = requests.clone();
        let parser_mode = parser_mode.clone();
        let parser_resolutions = parser_resolutions.clone();
        let connections_finished = connections_finished.clone();
        let tls_rejections = tls_rejections.clone();
        let errors = errors.clone();
        active.spawn(async move {
            let frontend = match acceptor.accept(stream).await {
                Ok(frontend) => {
                    if expect_tls_rejection {
                        errors.lock().unwrap().push("target_tls_unexpected_accept");
                        connections_finished.fetch_add(1, Ordering::SeqCst);
                        return;
                    }
                    frontend
                },
                Err(_) => {
                    if expect_tls_rejection {
                        tls_rejections.fetch_add(1, Ordering::SeqCst);
                    } else {
                        errors.lock().unwrap().push("target_tls_handshake_failed");
                    }
                    connections_finished.fetch_add(1, Ordering::SeqCst);
                    return;
                },
            };
            let result = handle_target_connection(
                frontend,
                provider_port,
                requests,
                parser_mode,
                parser_resolutions,
            )
            .await;
            if result.is_err() {
                errors.lock().unwrap().push("target_connection_failed");
            }
            connections_finished.fetch_add(1, Ordering::SeqCst);
        });
        while active.try_join_next().is_some() {}
    }
}

struct FixtureRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    content_type: ContentTypeClass,
    host: HostClass,
    administrator_secret_present: bool,
    authorization_header_present: bool,
    cookie_header_present: bool,
}

async fn handle_target_connection<S>(
    mut stream: S,
    provider_port: u16,
    requests: Arc<Mutex<Vec<TargetRequestFact>>>,
    parser_mode: Arc<AtomicU8>,
    parser_resolutions: Arc<AtomicUsize>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_request(&mut stream, provider_port).await?;
    let mode = ParserMode::from_atomic(parser_mode.load(Ordering::SeqCst));
    let (envelope_role, private_callback_sentinels) = if request.method == "POST" {
        classify_xml_envelope(&request.body)
    } else {
        (XmlEnvelopeRole::Invalid, Vec::new())
    };
    let external_entity_count = if request.method == "POST" {
        run_expat_parser(&request.body, mode, provider_port).await?
    } else {
        0
    };
    requests.lock().unwrap().push(TargetRequestFact {
        method: request.method.clone(),
        path: request.path.clone(),
        body_len: request.body.len(),
        parser_mode: mode,
        parser_external_entity_count: external_entity_count,
        content_type: request.content_type,
        host: request.host,
        envelope_role,
        private_callback_sentinels,
        administrator_secret_present: request.administrator_secret_present,
        authorization_header_present: request.authorization_header_present,
        cookie_header_present: request.cookie_header_present,
    });
    parser_resolutions.fetch_add(external_entity_count, Ordering::SeqCst);

    let (content_type, body) = if request.method == "POST" {
        (
            "application/xml; charset=utf-8",
            b"<accepted marker=\"OWNED_XML_POST_RESPONSE_MUST_NOT_LEAK_5E3A91C7\"/>".as_slice(),
        )
    } else {
        (
            "text/html; charset=utf-8",
            b"<!doctype html><html><body><main>OWNED_XML_GET_RESPONSE_MUST_NOT_LEAK_2D8B64F0</main></body></html>".as_slice(),
        )
    };
    write_response(&mut stream, content_type, body).await
}

async fn read_request<S>(stream: &mut S, target_port: u16) -> io::Result<FixtureRequest>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let header_end = loop {
        if bytes.len() >= MAX_FIXTURE_REQUEST_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request bound"));
        }
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request head"));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request head utf8"))?;
    let mut lines = head.split("\r\n");
    let mut start = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request line"))?
        .split_whitespace();
    let method = start.next().unwrap_or_default().to_owned();
    let path = start.next().unwrap_or_default().to_owned();
    if method.is_empty() || path.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "request line"));
    }
    let authorization_header_present =
        lines_from_head(head).any(|line| header_name_is(line, "authorization"));
    let cookie_header_present = lines_from_head(head).any(|line| header_name_is(line, "cookie"));
    let content_type = classify_content_type(head);
    let host = classify_host(head, target_port);
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "content length"))?
        .unwrap_or(0);
    if header_end.saturating_add(content_length) > MAX_FIXTURE_REQUEST_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "request bound"));
    }
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request body"));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let administrator_secret_present = bytes[..header_end + content_length]
        .windows(ADMIN_SECRET.len())
        .any(|window| window == ADMIN_SECRET);
    Ok(FixtureRequest {
        method,
        path,
        body: bytes[header_end..header_end + content_length].to_vec(),
        content_type,
        host,
        administrator_secret_present,
        authorization_header_present,
        cookie_header_present,
    })
}

fn classify_host(head: &str, target_port: u16) -> HostClass {
    let mut values = lines_from_head(head).filter_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.trim())
    });
    let expected = format!("{TARGET_HOST}:{target_port}");
    match (values.next(), values.next()) {
        (Some(value), None) if value == expected => HostClass::Exact,
        (None, None) => HostClass::Missing,
        _ => HostClass::OtherOrDuplicate,
    }
}

fn classify_content_type(head: &str) -> ContentTypeClass {
    let mut values = lines_from_head(head).filter_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.trim())
    });
    match (values.next(), values.next()) {
        (Some(value), None) if value == XML_MEDIA_TYPE => ContentTypeClass::ExactXml,
        (None, None) => ContentTypeClass::Missing,
        _ => ContentTypeClass::OtherOrDuplicate,
    }
}

fn classify_xml_envelope(body: &[u8]) -> (XmlEnvelopeRole, Vec<PrivateFixtureSentinel>) {
    const PREFIX: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE termivar-review [<!ENTITY termivar_external SYSTEM \"";
    const SEPARATOR: &str = "\">]>\n<termivar-review role=\"";

    let Ok(document) = std::str::from_utf8(body) else {
        return (XmlEnvelopeRole::Invalid, Vec::new());
    };
    let Some(remainder) = document.strip_prefix(PREFIX) else {
        return (XmlEnvelopeRole::Invalid, Vec::new());
    };
    let Some((callback, tail)) = remainder.split_once(SEPARATOR) else {
        return (XmlEnvelopeRole::Invalid, Vec::new());
    };
    let role = match tail {
        "control\">control</termivar-review>\n" => XmlEnvelopeRole::Control,
        "candidate\">&termivar_external;</termivar-review>\n" => XmlEnvelopeRole::Candidate,
        "replay\">&termivar_external;</termivar-review>\n" => XmlEnvelopeRole::Replay,
        _ => return (XmlEnvelopeRole::Invalid, Vec::new()),
    };
    let raw_callback = callback;
    let Ok(callback) = Url::parse(raw_callback) else {
        return (XmlEnvelopeRole::Invalid, Vec::new());
    };
    if callback.scheme() != "https"
        || callback.host_str() != Some(PROVIDER_HOST)
        || callback.port().is_some()
        || !callback.username().is_empty()
        || callback.password().is_some()
        || callback.query().is_some()
        || callback.fragment().is_some()
    {
        return (XmlEnvelopeRole::Invalid, Vec::new());
    }
    let Some(mut segments) = callback.path_segments() else {
        return (XmlEnvelopeRole::Invalid, Vec::new());
    };
    let (Some(prefix), Some(session), Some(correlation), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return (XmlEnvelopeRole::Invalid, Vec::new());
    };
    if prefix != "c"
        || !valid_opaque_route_segment(session)
        || !valid_opaque_route_segment(correlation)
        || raw_callback != format!("https://{PROVIDER_HOST}/c/{session}/{correlation}")
    {
        return (XmlEnvelopeRole::Invalid, Vec::new());
    }
    (
        role,
        vec![
            PrivateFixtureSentinel(session.as_bytes().to_vec()),
            PrivateFixtureSentinel(correlation.as_bytes().to_vec()),
        ],
    )
}

fn valid_opaque_route_segment(segment: &str) -> bool {
    segment.len() == 22
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn lines_from_head(head: &str) -> impl Iterator<Item = &str> {
    head.split("\r\n").skip(1)
}

fn header_name_is(line: &str, expected: &str) -> bool {
    line.split_once(':')
        .is_some_and(|(name, _)| name.eq_ignore_ascii_case(expected))
}

fn python_interpreters() -> Vec<PathBuf> {
    if let Some(selected) = env::var_os("TERMIVAR_TEST_PYTHON").filter(|value| !value.is_empty()) {
        return vec![PathBuf::from(selected)];
    }
    if cfg!(windows) {
        vec![PathBuf::from("python"), PathBuf::from("python3")]
    } else {
        vec![PathBuf::from("python3"), PathBuf::from("python")]
    }
}

async fn read_bounded_pipe<R>(reader: R, limit: usize) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(limit.saturating_add(1)).unwrap())
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "child output bound",
        ));
    }
    Ok(bytes)
}

async fn run_expat_with_interpreter(
    interpreter: &Path,
    body: &[u8],
    mode: ParserMode,
    provider_port: u16,
) -> io::Result<usize> {
    let mut child = Command::new(interpreter);
    child
        .args(["-I", EXPAT_HELPER, "--mode", mode.argument()])
        .arg("--provider-port")
        .arg(provider_port.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ] {
        child.env_remove(key);
    }
    let mut child = child.spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "parser stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "parser stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "parser stderr"))?;

    let execution = async {
        stdin.write_all(body).await?;
        stdin.shutdown().await?;
        let (status, stdout, stderr) = tokio::try_join!(
            child.wait(),
            read_bounded_pipe(stdout, MAX_PARSER_OUTPUT_BYTES),
            read_bounded_pipe(stderr, MAX_PARSER_OUTPUT_BYTES),
        )?;
        Ok::<_, io::Error>((status, stdout, stderr))
    };
    let (status, stdout, stderr) = match timeout(PARSER_TIMEOUT, execution).await {
        Ok(result) => result?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(io::Error::new(io::ErrorKind::TimedOut, "parser timeout"));
        },
    };
    if !status.success() || !stderr.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "parser rejected document",
        ));
    }
    let document: Value = serde_json::from_slice(&stdout)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "parser result"))?;
    let object = document
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "parser result"))?;
    let expected_keys = ["external_entity_count", "mode", "runtime", "schema"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_keys
        || document["schema"] != "termivar-test.xml-expat-result/v1"
        || document["runtime"] != "cpython-3.12"
        || document["mode"] != mode.argument()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "parser result contract",
        ));
    }
    let count = document["external_entity_count"]
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "parser result count"))?;
    if count > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "parser result count",
        ));
    }
    Ok(count)
}

async fn run_expat_parser(body: &[u8], mode: ParserMode, provider_port: u16) -> io::Result<usize> {
    let mut missing = None;
    for interpreter in python_interpreters() {
        match run_expat_with_interpreter(&interpreter, body, mode, provider_port).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => missing = Some(error),
            result => return result,
        }
    }
    Err(missing.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "CPython 3.12")))
}

async fn write_response<S>(stream: &mut S, content_type: &str, body: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

fn policy(target_url: &str) -> String {
    format!(
        "schema = \"security.xml-external-entity-review-policy/v1\"\n\
endpoint = \"{target_url}xml-parser\"\n\
provider_origin = \"{PROVIDER_ORIGIN}\"\n\
method = \"POST\"\n\
media_type = \"application/xml; charset=utf-8\"\n\
acknowledge_xml_post = true\n\
acknowledge_external_interaction = true\n\
acknowledge_disposable_test_endpoint = true\n\
polls_per_leg = 1\n\
poll_interval_ms = 250\n\
lifetime_ms = 10000\n"
    )
}

fn bundle_bytes(directory: &Path, sentinels: &[PrivateFixtureSentinel]) -> Vec<u8> {
    let mut names = fs::read_dir(directory)
        .expect("read report bundle")
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["assessment.html", JSON_NAME, "manifest.json"]);
    names
        .into_iter()
        .flat_map(|name| {
            let bytes = fs::read(directory.join(&name)).unwrap();
            assert_no_private_sentinels(&bytes, &format!("bundle file {name}"));
            assert_no_dynamic_sentinels(&bytes, &format!("bundle file {name}"), sentinels);
            bytes
        })
        .collect()
}

fn private_path(parent: &Path, name: &str) -> PathBuf {
    parent.join(name)
}

fn provider_request_delta(
    after: ProviderTestRequestSnapshot,
    before: ProviderTestRequestSnapshot,
) -> ProviderTestRequestSnapshot {
    ProviderTestRequestSnapshot {
        register: after.register.checked_sub(before.register).unwrap(),
        allocate: after.allocate.checked_sub(before.allocate).unwrap(),
        poll: after.poll.checked_sub(before.poll).unwrap(),
        cleanup: after.cleanup.checked_sub(before.cleanup).unwrap(),
        callback: after.callback.checked_sub(before.callback).unwrap(),
        other: after.other.checked_sub(before.other).unwrap(),
    }
}

fn expected_provider_requests(callback: usize) -> ProviderTestRequestSnapshot {
    ProviderTestRequestSnapshot {
        register: 1,
        allocate: 3,
        poll: 4,
        cleanup: 1,
        callback,
        other: 0,
    }
}

struct CompletedScan {
    report_dir: PathBuf,
    assessment: Value,
    private_sentinels: Vec<PrivateFixtureSentinel>,
}

async fn run_actual_scan(
    temporary: &Path,
    fixture: &OwnedHttpsFixture,
    mode: ParserMode,
    label: &str,
) -> CompletedScan {
    fixture.select_parser_mode(mode);
    let policy_path = private_path(temporary, &format!("owned-xml-policy-{label}.toml"));
    let secret_path = private_path(temporary, &format!("owned-provider-{label}.secret"));
    let report_dir = private_path(temporary, &format!("assessment-{label}"));
    fs::write(&policy_path, policy(&fixture.target_url)).expect("write policy");
    fs::write(&secret_path, ADMIN_SECRET).expect("write administrator token");
    let private_path_sentinels = [&policy_path, &secret_path]
        .map(|path| PrivateFixtureSentinel(path.to_string_lossy().as_bytes().to_vec()));

    let mut command = termivar();
    command
        .arg("scan")
        .arg(&fixture.target_url)
        .args(["--profile", "web-review", "--xml-external-entity-review"])
        .arg("--xml-external-entity-policy")
        .arg(&policy_path)
        .arg("--oast-admin-token-file")
        .arg(&secret_path)
        .arg("--report-dir")
        .arg(&report_dir);
    let scan = run_termivar(command, label).await;
    let policy_cleanup = fs::remove_file(&policy_path);
    let secret_cleanup = fs::remove_file(&secret_path);
    assert_success(&scan, label);
    assert!(scan.stdout.is_empty());
    assert_output_has_no_private_sentinels(&scan, label);
    let mut private_sentinels = fixture.private_callback_sentinels();
    private_sentinels.extend(private_path_sentinels);
    assert_output_has_no_dynamic_sentinels(&scan, label, &private_sentinels);
    policy_cleanup.expect("remove consumed XML policy before offline checks");
    secret_cleanup.expect("remove consumed provider secret before offline checks");
    assert!(!policy_path.exists());
    assert!(!secret_path.exists());

    let assessment_bytes = fs::read(report_dir.join(JSON_NAME)).expect("read assessment JSON");
    assert_no_private_sentinels(&assessment_bytes, label);
    assert_no_dynamic_sentinels(&assessment_bytes, label, &private_sentinels);
    let assessment: Value =
        serde_json::from_slice(&assessment_bytes).expect("parse assessment JSON");
    CompletedScan {
        report_dir,
        assessment,
        private_sentinels,
    }
}

async fn run_incomplete_scan(
    temporary: &Path,
    fixture: &OwnedHttpsFixture,
    mode: ParserMode,
    label: &str,
) -> Value {
    fixture.select_parser_mode(mode);
    let policy_path = private_path(temporary, &format!("owned-xml-policy-{label}.toml"));
    let secret_path = private_path(temporary, &format!("owned-provider-{label}.secret"));
    let report_dir = private_path(temporary, &format!("assessment-{label}"));
    fs::write(&policy_path, policy(&fixture.target_url)).expect("write policy");
    fs::write(&secret_path, ADMIN_SECRET).expect("write administrator token");
    let private_path_sentinels = [&policy_path, &secret_path]
        .map(|path| PrivateFixtureSentinel(path.to_string_lossy().as_bytes().to_vec()));

    let mut command = termivar();
    command
        .arg("scan")
        .arg(&fixture.target_url)
        .args([
            "--profile",
            "web-review",
            "--xml-external-entity-review",
            "--format",
            "json",
        ])
        .arg("--xml-external-entity-policy")
        .arg(&policy_path)
        .arg("--oast-admin-token-file")
        .arg(&secret_path)
        .arg("--report-dir")
        .arg(&report_dir);
    let scan = run_termivar(command, label).await;
    let policy_cleanup = fs::remove_file(&policy_path);
    let secret_cleanup = fs::remove_file(&secret_path);

    assert!(!scan.status.success(), "{label} unexpectedly completed");
    assert!(!scan.stdout.is_empty(), "{label} omitted its diagnostic");
    assert_output_has_no_private_sentinels(&scan, label);
    let mut private_sentinels = fixture.private_callback_sentinels();
    private_sentinels.extend(private_path_sentinels);
    assert_output_has_no_dynamic_sentinels(&scan, label, &private_sentinels);
    assert!(
        !report_dir.exists(),
        "{label} published a reusable bundle for an incomplete assessment"
    );
    let diagnostic: Value = serde_json::from_slice(&scan.stdout).expect("parse scan diagnostic");
    assert_eq!(diagnostic["schema_version"], "web-assessment/v2");
    assert!(diagnostic["incomplete_reasons"]
        .as_array()
        .is_some_and(|reasons| reasons
            .iter()
            .any(|reason| reason == "xml_external_entity_review_incomplete")));
    policy_cleanup.expect("remove consumed XML policy after diagnostic assertions");
    secret_cleanup.expect("remove consumed provider secret after diagnostic assertions");
    assert!(!policy_path.exists());
    assert!(!secret_path.exists());
    diagnostic
}

fn assert_common_audit(audit: &Value) {
    assert_eq!(
        audit["schema"],
        "security.xml-external-entity-review-audit/v1"
    );
    assert_eq!(audit["policy"]["execution_mode"], "production");
    assert_eq!(audit["target"]["request_count"], 3);
    assert_eq!(audit["target"]["complete"], true);
    assert_eq!(audit["target"]["accounting_complete"], true);
    assert_eq!(audit["provider"]["request_count"], 9);
    assert_eq!(audit["provider"]["active_verification_count"], 1);
    assert_eq!(audit["provider"]["preflight_clean"], true);
    assert_eq!(audit["provider"]["control_callback_observed"], false);
    assert_eq!(audit["provider"]["callback_targets_distinct"], true);
    assert_eq!(audit["provider"]["cleanup_verified"], true);
    assert_eq!(audit["provider"]["complete"], true);
    assert_eq!(audit["semantic_effect"], "not_performed");
    assert_eq!(audit["impact_validation"], "not_performed");
}

fn xml_items(assessment: &Value) -> Vec<&Value> {
    assessment["items"]
        .as_array()
        .expect("assessment items")
        .iter()
        .filter(|item| {
            item["capability_id"] == "xml.external-entity.repeated-outbound-interaction@1"
        })
        .collect()
}

async fn verify_and_self_compare(scan: &CompletedScan, label: &str) {
    let before_offline = bundle_bytes(&scan.report_dir, &scan.private_sentinels);
    let mut verify_command = termivar();
    verify_command
        .args(["report", "verify", "--dir"])
        .arg(&scan.report_dir)
        .args(["--format", "json"]);
    let verify = run_termivar(verify_command, &format!("{label} Verify")).await;
    assert_success(&verify, &format!("{label} Verify"));
    assert_output_has_no_private_sentinels(&verify, &format!("{label} Verify"));
    assert_output_has_no_dynamic_sentinels(
        &verify,
        &format!("{label} Verify"),
        &scan.private_sentinels,
    );
    let verification: Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verification["status"], "integrity_match");

    let assessment_path = scan.report_dir.join(JSON_NAME);
    let mut compare_command = termivar();
    compare_command
        .args(["report", "compare", "--before"])
        .arg(&assessment_path)
        .arg("--after")
        .arg(&assessment_path)
        .args(["--same-scope", "--format", "json"]);
    let compare = run_termivar(compare_command, &format!("{label} self-Compare")).await;
    assert_success(&compare, &format!("{label} self-Compare"));
    assert_output_has_no_private_sentinels(&compare, &format!("{label} self-Compare"));
    assert_output_has_no_dynamic_sentinels(
        &compare,
        &format!("{label} self-Compare"),
        &scan.private_sentinels,
    );
    let comparison: Value = serde_json::from_slice(&compare.stdout).unwrap();
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert_eq!(comparison[group], json!([]));
    }
    assert_eq!(
        comparison["unchanged"].as_array().map(Vec::len),
        scan.assessment["items"].as_array().map(Vec::len)
    );
    let xml_comparison = &comparison["xml_external_entity_review_comparison"];
    assert_eq!(xml_comparison["status"], "compared");
    for facet in ["methodology", "coverage", "outcome"] {
        assert_eq!(xml_comparison[facet]["status"], "unchanged");
    }
    assert_eq!(
        bundle_bytes(&scan.report_dir, &scan.private_sentinels),
        before_offline
    );
}

#[test]
fn fixture_wire_classifier_requires_the_exact_media_type_and_xml_envelope() {
    let callback = format!(
        "https://{PROVIDER_HOST}/c/{}/{}",
        "B".repeat(22),
        "C".repeat(22)
    );
    let candidate = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE termivar-review [<!ENTITY termivar_external SYSTEM \"{callback}\">]>\n\
<termivar-review role=\"candidate\">&termivar_external;</termivar-review>\n"
    );
    let (role, sentinels) = classify_xml_envelope(candidate.as_bytes());
    assert_eq!(role, XmlEnvelopeRole::Candidate);
    assert_eq!(sentinels.len(), 2);
    assert_eq!(sentinels[0].as_slice(), "B".repeat(22).as_bytes());
    assert_eq!(sentinels[1].as_slice(), "C".repeat(22).as_bytes());

    for invalid in [
        candidate.replace("role=\"candidate\"", "role=\"control\""),
        candidate.replace(PROVIDER_HOST, "other-provider.termivar.test"),
        candidate.replace("/c/", "/c/%42/"),
        candidate.replace("</termivar-review>", "</termivar-review><extra/>"),
        candidate.replace(&callback, &format!("{callback}?ignored=true")),
        candidate.replace(
            &callback,
            &callback.replacen(PROVIDER_HOST, &format!("{PROVIDER_HOST}:443"), 1),
        ),
    ] {
        assert_eq!(
            classify_xml_envelope(invalid.as_bytes()).0,
            XmlEnvelopeRole::Invalid
        );
    }

    assert_eq!(
        classify_content_type(
            "POST /application/xml-parser HTTP/1.1\r\nContent-Type: application/xml; charset=utf-8\r\n\r\n"
        ),
        ContentTypeClass::ExactXml
    );
    assert_eq!(
        classify_content_type("POST /application/xml-parser HTTP/1.1\r\n\r\n"),
        ContentTypeClass::Missing
    );
    assert_eq!(
        classify_content_type(
            "POST /application/xml-parser HTTP/1.1\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Type: application/xml; charset=utf-8\r\n\r\n"
        ),
        ContentTypeClass::OtherOrDuplicate
    );
    assert_eq!(
        classify_host(
            &format!("POST /application/xml-parser HTTP/1.1\r\nHost: {TARGET_HOST}:8443\r\n\r\n"),
            8443
        ),
        HostClass::Exact
    );
    assert_eq!(
        classify_host("POST /application/xml-parser HTTP/1.1\r\n\r\n", 8443),
        HostClass::Missing
    );
    assert_eq!(
        classify_host(
            &format!(
                "POST /application/xml-parser HTTP/1.1\r\nHost: {TARGET_HOST}:8443\r\nHost: {TARGET_HOST}:8443\r\n\r\n"
            ),
            8443
        ),
        HostClass::OtherOrDuplicate
    );
}

#[test]
fn expat_oracle_consumes_its_single_resolution_before_network_work() {
    let source = fs::read_to_string(EXPAT_HELPER).expect("read pinned Expat helper");
    let guard = source
        .find("if resolutions != 0:")
        .expect("resolution guard");
    let consumption = source
        .find("resolutions += 1")
        .expect("resolution consumption");
    let fetch = source
        .find("payload = _fetch_external_entity(system_id, provider_port)")
        .expect("external fetch");
    assert!(guard < consumption && consumption < fetch);
    assert_eq!(
        source
            .matches("payload = _fetch_external_entity(system_id, provider_port)")
            .count(),
        1
    );
}

async fn run_provider_tls_rejection_case(
    temporary: &Path,
    certificate: ProviderCertificate,
    label: &str,
) {
    let fixture = start_fixture(certificate).await;
    let diagnostic = run_incomplete_scan(temporary, &fixture, ParserMode::External, label).await;
    assert_eq!(diagnostic["disposition"], "incomplete");
    assert_eq!(
        diagnostic["assessment"]["report"]["assessment_items"]["projection_status"],
        "unavailable"
    );

    let snapshot = fixture.shutdown().await;
    assert!(snapshot.fixture_errors.is_empty(), "{snapshot:?}");
    assert_eq!(
        snapshot.provider_requests,
        ProviderTestRequestSnapshot::default(),
        "{snapshot:?}"
    );
    assert_eq!(snapshot.provider_connections, 1, "{snapshot:?}");
    assert_eq!(snapshot.provider_tls_rejections, 1, "{snapshot:?}");
    assert_eq!(snapshot.parser_resolutions, 0, "{snapshot:?}");
    assert_eq!(snapshot.target_connections, 3, "{snapshot:?}");
    assert_eq!(snapshot.target_tls_rejections, 0, "{snapshot:?}");
    assert_eq!(snapshot.target_requests.len(), 3, "{snapshot:?}");
    assert!(snapshot.target_requests.iter().all(|request| {
        request.method == "GET"
            && request.path == "/application/"
            && request.body_len == 0
            && request.parser_external_entity_count == 0
            && request.content_type == ContentTypeClass::Missing
            && request.host == HostClass::Exact
            && request.envelope_role == XmlEnvelopeRole::Invalid
            && request.private_callback_sentinels.is_empty()
            && !request.administrator_secret_present
            && !request.authorization_header_present
            && !request.cookie_header_present
    }));
}

async fn run_target_tls_rejection_case(
    temporary: &Path,
    certificate: TargetCertificate,
    label: &str,
) {
    let fixture = start_fixture_with_certificates(certificate, ProviderCertificate::Correct).await;
    let diagnostic = run_incomplete_scan(temporary, &fixture, ParserMode::External, label).await;
    assert_eq!(fixture.private_callback_sentinels().len(), 4);
    assert_eq!(diagnostic["disposition"], "failed");
    assert!(diagnostic["incomplete_reasons"]
        .as_array()
        .is_some_and(|reasons| reasons
            .iter()
            .any(|reason| reason == "started_runtime_failure")));
    assert_eq!(
        diagnostic["assessment"]["report"]["assessment_items"]["projection_status"],
        "unavailable"
    );

    let snapshot = fixture.shutdown().await;
    assert!(snapshot.fixture_errors.is_empty(), "{snapshot:?}");
    assert_eq!(
        snapshot.provider_requests,
        ProviderTestRequestSnapshot {
            register: 1,
            allocate: 3,
            poll: 1,
            cleanup: 1,
            callback: 0,
            other: 0,
        },
        "{snapshot:?}"
    );
    assert_eq!(snapshot.parser_resolutions, 0, "{snapshot:?}");
    assert_eq!(snapshot.target_connections, 2, "{snapshot:?}");
    assert_eq!(snapshot.target_tls_rejections, 2, "{snapshot:?}");
    assert!(snapshot.target_requests.is_empty(), "{snapshot:?}");
    assert_eq!(snapshot.provider_tls_rejections, 0, "{snapshot:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs only in the pinned four-platform Runtime Smoke acceptance"]
async fn owned_https_profile_runs_actual_cli_and_offline_bundle_commands() {
    assert_eq!(
        format!("{:x}", Sha256::digest(decode(ROOT_CERTIFICATE_DER_BASE64))),
        "8a838ab89d539252df6bafc16eb489aebb42cbd350b941f3d708fecc7041d409"
    );
    let temporary = tempfile::tempdir().expect("create private fixture directory");
    let mut capability_command = termivar();
    capability_command.args(["capabilities", "--format", "json"]);
    let capabilities = run_termivar(capability_command, "owned HTTPS profile capabilities").await;
    assert_success(&capabilities, "owned HTTPS profile capabilities");
    assert_output_has_no_private_sentinels(&capabilities, "owned HTTPS profile capabilities");
    let capability_document: Value =
        serde_json::from_slice(&capabilities.stdout).expect("parse capabilities JSON");
    let feature_inventory = capability_document["cli_package_features"]
        .as_array()
        .expect("feature inventory");
    assert_eq!(feature_inventory.len(), 23);
    let feature_names = feature_inventory
        .iter()
        .map(|row| row["name"].as_str().expect("feature name"))
        .collect::<BTreeSet<_>>();
    assert_eq!(feature_names.len(), feature_inventory.len());
    let compiled = feature_inventory
        .iter()
        .filter(|row| row["build_state"] == "compiled")
        .map(|row| row["name"].as_str().expect("feature name"))
        .collect::<BTreeSet<_>>();
    for required in [
        "xml-external-entity-owned-https-test-profile",
        "xml-external-entity-review",
    ] {
        assert!(compiled.contains(required), "{required} was not compiled");
    }
    assert!(capability_document["surfaces"]
        .as_array()
        .expect("surface inventory")
        .iter()
        .all(
            |surface| surface["compile_feature"] != "xml-external-entity-owned-https-test-profile"
        ));

    let fixture = start_fixture(ProviderCertificate::Correct).await;
    let safe = run_actual_scan(temporary.path(), &fixture, ParserMode::Safe, "safe").await;
    let safe_audit = &safe.assessment["xml_external_entity_review"];
    assert_common_audit(safe_audit);
    assert_eq!(safe_audit["outcome"], "no_callback");
    assert_eq!(safe_audit["provider"]["candidate_callback_observed"], false);
    assert_eq!(safe_audit["provider"]["replay_callback_observed"], false);
    assert_eq!(safe_audit["provider"]["event_identities_distinct"], false);
    assert_eq!(safe_audit["item_projected"], false);
    assert!(xml_items(&safe.assessment).is_empty());
    bundle_bytes(&safe.report_dir, &safe.private_sentinels);
    let provider_after_safe = fixture.provider_requests();
    assert_eq!(provider_after_safe, expected_provider_requests(0));

    let enabled =
        run_actual_scan(temporary.path(), &fixture, ParserMode::External, "enabled").await;
    let enabled_audit = &enabled.assessment["xml_external_entity_review"];
    assert_common_audit(enabled_audit);
    assert_eq!(
        enabled_audit["outcome"],
        "repeated_external_entity_resolution_observed"
    );
    assert_eq!(
        enabled_audit["provider"]["candidate_callback_observed"],
        true
    );
    assert_eq!(enabled_audit["provider"]["replay_callback_observed"], true);
    assert_eq!(enabled_audit["provider"]["event_identities_distinct"], true);
    assert_eq!(enabled_audit["item_projected"], true);
    let enabled_items = xml_items(&enabled.assessment);
    assert_eq!(enabled_items.len(), 1);
    assert_eq!(enabled_items[0]["disposition"], "needs_review");
    assert_eq!(enabled_items[0]["claim_basis"], "differential");
    assert_eq!(enabled_items[0]["severity"], Value::Null);
    bundle_bytes(&enabled.report_dir, &enabled.private_sentinels);
    let provider_after_enabled = fixture.provider_requests();
    assert_eq!(fixture.private_callback_sentinels().len(), 4);
    assert_eq!(
        provider_request_delta(provider_after_enabled, provider_after_safe),
        expected_provider_requests(2)
    );

    let snapshot = fixture.shutdown().await;
    assert!(snapshot.fixture_errors.is_empty(), "{snapshot:?}");
    for (mode, expected) in [
        (ParserMode::Safe, [0, 0, 0]),
        (ParserMode::External, [0, 1, 1]),
    ] {
        let xml_requests = snapshot
            .target_requests
            .iter()
            .filter(|request| {
                request.parser_mode == mode
                    && request.method == "POST"
                    && request.path == "/application/xml-parser"
            })
            .collect::<Vec<_>>();
        assert_eq!(xml_requests.len(), 3, "{snapshot:?}");
        assert_eq!(
            xml_requests
                .iter()
                .map(|request| request.parser_external_entity_count)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            xml_requests
                .iter()
                .map(|request| request.envelope_role)
                .collect::<Vec<_>>(),
            [
                XmlEnvelopeRole::Control,
                XmlEnvelopeRole::Candidate,
                XmlEnvelopeRole::Replay,
            ]
        );
        assert!(xml_requests.iter().all(|request| {
            request.body_len > 0
                && request.content_type == ContentTypeClass::ExactXml
                && request.host == HostClass::Exact
                && request.private_callback_sentinels.len() == 2
        }));
        assert!(
            xml_requests[1].private_callback_sentinels[0]
                == xml_requests[0].private_callback_sentinels[0]
        );
        assert!(
            xml_requests[2].private_callback_sentinels[0]
                == xml_requests[0].private_callback_sentinels[0]
        );
        assert!(
            xml_requests[0].private_callback_sentinels[1]
                != xml_requests[1].private_callback_sentinels[1]
        );
        assert!(
            xml_requests[0].private_callback_sentinels[1]
                != xml_requests[2].private_callback_sentinels[1]
        );
        assert!(
            xml_requests[1].private_callback_sentinels[1]
                != xml_requests[2].private_callback_sentinels[1]
        );
        let ordinary_requests = snapshot
            .target_requests
            .iter()
            .filter(|request| {
                request.parser_mode == mode
                    && !(request.method == "POST" && request.path == "/application/xml-parser")
            })
            .collect::<Vec<_>>();
        assert_eq!(ordinary_requests.len(), 3, "{snapshot:?}");
        assert!(ordinary_requests.iter().all(|request| {
            request.method == "GET"
                && request.path == "/application/"
                && request.body_len == 0
                && request.parser_external_entity_count == 0
                && request.content_type == ContentTypeClass::Missing
                && request.host == HostClass::Exact
                && request.envelope_role == XmlEnvelopeRole::Invalid
                && request.private_callback_sentinels.is_empty()
        }));
    }
    assert_eq!(snapshot.target_requests.len(), 12, "{snapshot:?}");
    assert!(snapshot.target_requests.iter().all(|request| {
        !request.administrator_secret_present
            && !request.authorization_header_present
            && !request.cookie_header_present
    }));
    assert_eq!(snapshot.parser_resolutions, 2, "{snapshot:?}");
    assert_eq!(snapshot.target_connections, 12, "{snapshot:?}");
    assert_eq!(snapshot.target_tls_rejections, 0, "{snapshot:?}");
    assert!(snapshot.provider_connections >= 2, "{snapshot:?}");
    assert_eq!(snapshot.provider_tls_rejections, 0, "{snapshot:?}");
    assert_eq!(snapshot.provider_requests, provider_after_enabled);

    verify_and_self_compare(&safe, "safe").await;
    verify_and_self_compare(&enabled, "enabled").await;
    run_provider_tls_rejection_case(
        temporary.path(),
        ProviderCertificate::WrongHostname,
        "wrong-provider-hostname",
    )
    .await;
    run_target_tls_rejection_case(
        temporary.path(),
        TargetCertificate::WrongHostname,
        "wrong-target-hostname",
    )
    .await;
    run_target_tls_rejection_case(
        temporary.path(),
        TargetCertificate::InvalidChain,
        "invalid-target-chain",
    )
    .await;
    run_provider_tls_rejection_case(
        temporary.path(),
        ProviderCertificate::InvalidChain,
        "invalid-provider-chain",
    )
    .await;

    let mut controlled_command = termivar();
    controlled_command
        .args(["report", "compare", "--before"])
        .arg(safe.report_dir.join(JSON_NAME))
        .arg("--after")
        .arg(enabled.report_dir.join(JSON_NAME))
        .args(["--same-scope", "--format", "json"]);
    let controlled = run_termivar(controlled_command, "safe-to-enabled Compare").await;
    assert_success(&controlled, "safe-to-enabled Compare");
    assert_output_has_no_private_sentinels(&controlled, "safe-to-enabled Compare");
    let mut controlled_sentinels = safe.private_sentinels.clone();
    for sentinel in &enabled.private_sentinels {
        if !controlled_sentinels.contains(sentinel) {
            controlled_sentinels.push(sentinel.clone());
        }
    }
    assert_output_has_no_dynamic_sentinels(
        &controlled,
        "safe-to-enabled Compare",
        &controlled_sentinels,
    );
    let comparison: Value = serde_json::from_slice(&controlled.stdout).unwrap();
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    assert_eq!(comparison["only_in_before"], json!([]));
    assert_eq!(comparison["changed"], json!([]));
    let added = comparison["only_in_after"].as_array().expect("added items");
    assert_eq!(added.len(), 1);
    assert_eq!(
        added[0]["capability_id"],
        "xml.external-entity.repeated-outbound-interaction@1"
    );
    assert_eq!(
        comparison["unchanged"].as_array().map(Vec::len),
        safe.assessment["items"].as_array().map(Vec::len)
    );
    let xml_comparison = &comparison["xml_external_entity_review_comparison"];
    assert_eq!(xml_comparison["status"], "compared");
    assert_eq!(xml_comparison["methodology"]["status"], "unchanged");
    assert_eq!(xml_comparison["coverage"]["status"], "changed");
    assert_eq!(xml_comparison["outcome"]["status"], "changed");
}
