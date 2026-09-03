//! # Phase 4: bounded differential parameter discovery
//!
//! Each candidate is compared with a baseline and a randomized unknown-query
//! control, then repeated as the exact same candidate request. A reproducible difference is an
//! endpoint observation only; reflection or status alone is not a vulnerability
//! claim.

use std::collections::BTreeSet;

use async_trait::async_trait;
use url::Url;
use uuid::Uuid;

use super::phase3_fuzzer::ResponseSignature;
use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
    http_evidence::HttpProbeMethod,
    legacy_discovery::{BoundedHttpResponse, DiscoveryDelta},
};

const PARAMETER_ACTION_ID: &str = "legacy.discovery.parameter";
const MAX_PARAMETER_NAME_BYTES: usize = 64;
const MAX_PARAMETER_CANDIDATES: usize = 256;
const CANDIDATE_MARKER_PREFIX: &str = "venom-candidate-";

/// Differential query-parameter discovery.
#[derive(Debug)]
pub struct ParameterDiscoverer {
    param_wordlist: Vec<String>,
    candidate_input_within_limits: bool,
}

impl ParameterDiscoverer {
    /// Creates a discoverer from a bounded set of candidate parameter names.
    /// Probes execute in canonical endpoint/parameter order. The compatibility
    /// concurrency argument now selects only whether authority exists: zero
    /// preserves the historical no-dispatch boundary, while every positive
    /// value is conservatively narrowed to sequential execution so request
    /// selection and budget exhaustion remain deterministic.
    pub fn new(param_wordlist: Vec<String>, concurrency_limit: usize) -> Self {
        if concurrency_limit == 0 {
            Self {
                param_wordlist: Vec::new(),
                candidate_input_within_limits: true,
            }
        } else {
            Self::sequential(param_wordlist)
        }
    }

    /// Creates the deterministic sequential form without a compatibility
    /// concurrency argument.
    pub fn sequential(param_wordlist: Vec<String>) -> Self {
        let candidate_input_within_limits = param_wordlist.len() <= MAX_PARAMETER_CANDIDATES;
        let param_wordlist = param_wordlist
            .into_iter()
            .filter(|name| valid_parameter_name(name))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Self {
            param_wordlist,
            candidate_input_within_limits,
        }
    }

    /// Uses a conservative set of ordinary navigation/query parameters.
    pub fn with_default_wordlist(concurrency_limit: usize) -> Self {
        if concurrency_limit == 0 {
            Self {
                param_wordlist: Vec::new(),
                candidate_input_within_limits: true,
            }
        } else {
            Self::with_default_wordlist_sequential()
        }
    }

    /// Uses the conservative default set with deterministic sequential
    /// dispatch.
    pub fn with_default_wordlist_sequential() -> Self {
        Self::sequential(
            [
                "id", "lang", "limit", "page", "q", "query", "search", "sort",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        )
    }
}

fn valid_parameter_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_PARAMETER_NAME_BYTES
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'[' | b']')
        })
}

#[async_trait]
impl ScanPhase for ParameterDiscoverer {
    fn phase_number(&self) -> u8 {
        4
    }

    fn name(&self) -> &'static str {
        // Retained as the stable phase/action identity for existing reports.
        "Hidden Parameter Miner"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        if !self.candidate_input_within_limits {
            return Err(ScannerError::DiscoveryStateLimitExceeded);
        }
        ctx.log("Phase 4: bounded differential parameter discovery initiated".to_owned());
        let snapshot = ctx.discovery_snapshot();
        let mut delta = DiscoveryDelta::new();
        let mut findings = Vec::new();

        for (endpoint, existing_parameters) in snapshot.endpoints() {
            let endpoint = ctx.canonicalize_discovery_url(&Url::parse(endpoint)?)?;
            let endpoint_query_names = endpoint
                .query_pairs()
                .map(|(name, _)| name.into_owned())
                .collect::<BTreeSet<_>>();
            let mut observed_parameters = BTreeSet::new();
            for parameter in &self.param_wordlist {
                if existing_parameters.contains(parameter)
                    || endpoint_query_names.contains(parameter)
                {
                    continue;
                }
                if parameter_is_observable(ctx, &endpoint, parameter).await? {
                    observed_parameters.insert(parameter.clone());
                    findings.push(ScanFinding {
                        phase: self.phase_number(),
                        module_name: self.name().to_owned(),
                        severity: "INFO".to_owned(),
                        description: "A query parameter produced a reproducible response differential from both the baseline and randomized unknown-parameter control."
                            .to_owned(),
                        evidence: format!(
                            "Parameter observation: '{}' on {}",
                            parameter,
                            endpoint_subject(&endpoint)
                        ),
                    });
                }
            }
            if !observed_parameters.is_empty() {
                let mut all_parameters = existing_parameters.clone();
                all_parameters.extend(observed_parameters);
                delta.record_endpoint(endpoint, all_parameters);
            }
        }

        // No discovery mutation is visible unless every requested comparison
        // completed successfully within the shared transport/body budget.
        ctx.commit_discovery(PARAMETER_ACTION_ID, delta)?;
        ctx.log(format!(
            "Phase 4: differential parameter discovery completed with {} observations",
            findings.len()
        ));
        Ok(findings)
    }
}

async fn parameter_is_observable(
    ctx: &ScanContext,
    endpoint: &Url,
    parameter: &str,
) -> Result<bool, ScannerError> {
    let control_nonce = Uuid::new_v4().simple().to_string();
    let candidate_nonce = Uuid::new_v4().simple().to_string();
    let control_name = format!("_venom_control_{control_nonce}");
    // Keep the negative and candidate values structurally identical so a
    // generic rule reacting to the marker shape cannot be mistaken for a
    // parameter-name differential.
    let control_marker = format!("{CANDIDATE_MARKER_PREFIX}{control_nonce}");
    let candidate_marker = format!("{CANDIDATE_MARKER_PREFIX}{candidate_nonce}");

    let baseline = ctx
        .request(PARAMETER_ACTION_ID, HttpProbeMethod::Get, endpoint.clone())
        .await?;
    let negative_url = append_query_parameter(endpoint, &control_name, &control_marker);
    let negative = ctx
        .request(PARAMETER_ACTION_ID, HttpProbeMethod::Get, negative_url)
        .await?;
    let candidate_url = append_query_parameter(endpoint, parameter, &candidate_marker);
    let candidate = ctx
        .request(
            PARAMETER_ACTION_ID,
            HttpProbeMethod::Get,
            candidate_url.clone(),
        )
        .await?;
    let reproduction = ctx
        .request(PARAMETER_ACTION_ID, HttpProbeMethod::Get, candidate_url)
        .await?;

    let dynamic_values = DynamicProbeValues {
        parameter,
        control_nonce: &control_nonce,
        candidate_nonce: &candidate_nonce,
        control_name: &control_name,
        control_marker: &control_marker,
        candidate_marker: &candidate_marker,
    };
    Ok(parameter_differential(
        &baseline,
        &negative,
        &candidate,
        &reproduction,
        dynamic_values,
    ))
}

#[derive(Debug, Clone, Copy)]
struct DynamicProbeValues<'a> {
    parameter: &'a str,
    control_nonce: &'a str,
    candidate_nonce: &'a str,
    control_name: &'a str,
    control_marker: &'a str,
    candidate_marker: &'a str,
}

fn parameter_differential(
    baseline: &BoundedHttpResponse,
    negative: &BoundedHttpResponse,
    candidate: &BoundedHttpResponse,
    reproduction: &BoundedHttpResponse,
    values: DynamicProbeValues<'_>,
) -> bool {
    let any_truncated = [baseline, negative, candidate, reproduction]
        .into_iter()
        .any(|response| response.body_truncated());

    // A pre-existing occurrence cannot be correlated to this attempt. This is
    // practically unlikely with UUID markers but is a required fail-closed
    // boundary and keeps deterministic fixtures honest.
    let marker_preexisting = body_contains(baseline.body(), CANDIDATE_MARKER_PREFIX)
        || body_contains(negative.body(), CANDIDATE_MARKER_PREFIX);

    // Normalize every leg with the same value universe. Using asymmetric
    // scrubbers would itself manufacture a differential when an ordinary page
    // happened to contain a short candidate name such as `q`.
    let raw_values = [
        values.parameter,
        values.control_nonce,
        values.candidate_nonce,
        values.control_name,
        values.control_marker,
        values.candidate_marker,
    ];
    let scrubbed_values =
        symmetric_scrub_values([baseline, negative, candidate, reproduction], &raw_values);
    let scrubbed_refs = scrubbed_values
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let baseline_signature = ResponseSignature::capture(baseline, &scrubbed_refs);
    let negative_signature = ResponseSignature::capture(negative, &scrubbed_refs);
    let candidate_signature = ResponseSignature::capture(candidate, &scrubbed_refs);
    let reproduction_signature = ResponseSignature::capture(reproduction, &scrubbed_refs);

    profiles_support_observation(
        &baseline_signature,
        &negative_signature,
        &candidate_signature,
        &reproduction_signature,
        any_truncated,
        marker_preexisting,
    )
}

fn symmetric_scrub_values(
    responses: [&BoundedHttpResponse; 4],
    dynamic_values: &[&str],
) -> Vec<String> {
    let mut values = Vec::new();
    for value in dynamic_values {
        add_scrub_variants(&mut values, value);
    }
    for response in responses {
        let request_url = response.request_url();
        add_scrub_variants(&mut values, request_url.as_str());
        add_scrub_variants(&mut values, request_url.path());
        if let Some(query) = request_url.query() {
            add_scrub_variants(&mut values, query);
            add_scrub_variants(&mut values, &format!("{}?{query}", request_url.path()));
        }
    }
    values.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    values.dedup();
    values
}

fn add_scrub_variants(values: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        return;
    }
    values.push(value.to_owned());
    let encoded = percent_encode_non_alphanumeric(value.as_bytes());
    values.push(encoded.clone());
    values.push(normalize_percent_escape_case(
        &encoded,
        u8::to_ascii_lowercase,
    ));
    values.push(normalize_percent_escape_case(value, u8::to_ascii_lowercase));
    values.push(normalize_percent_escape_case(value, u8::to_ascii_uppercase));
}

fn normalize_percent_escape_case(value: &str, map: fn(&u8) -> u8) -> String {
    let mut bytes = value.as_bytes().to_vec();
    let mut index = 0;
    while index + 2 < bytes.len() {
        if bytes[index] == b'%' {
            bytes[index + 1] = map(&bytes[index + 1]);
            bytes[index + 2] = map(&bytes[index + 2]);
            index += 3;
        } else {
            index += 1;
        }
    }
    String::from_utf8(bytes).expect("changing ASCII percent escapes preserves UTF-8")
}

fn percent_encode_non_alphanumeric(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len().saturating_mul(3));
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn profiles_support_observation(
    baseline: &ResponseSignature,
    negative: &ResponseSignature,
    candidate: &ResponseSignature,
    reproduction: &ResponseSignature,
    any_truncated: bool,
    marker_preexisting: bool,
) -> bool {
    !any_truncated
        && !marker_preexisting
        && candidate == reproduction
        && candidate != baseline
        && candidate != negative
}

fn append_query_parameter(endpoint: &Url, name: &str, value: &str) -> Url {
    let mut mutated = endpoint.clone();
    mutated.query_pairs_mut().append_pair(name, value);
    mutated
}

fn body_contains(body: &[u8], needle: &str) -> bool {
    !needle.is_empty()
        && body
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
}

fn endpoint_subject(endpoint: &Url) -> String {
    let mut subject = endpoint.clone();
    subject.set_query(None);
    subject.set_fragment(None);
    subject.to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use super::*;
    use crate::legacy_discovery::DiscoveryLimits;

    struct LocalFixture {
        target: Url,
        requests: Arc<AtomicUsize>,
        targets: Arc<Mutex<Vec<String>>>,
        task: JoinHandle<()>,
    }

    impl Drop for LocalFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve_fixture(
        max_requests: usize,
        handler: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> LocalFixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed_requests = Arc::clone(&requests);
        let targets = Arc::new(Mutex::new(Vec::new()));
        let observed_targets = Arc::clone(&targets);
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            for _ in 0..max_requests {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1_024];
                    let read = stream.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                    assert!(request.len() <= 16 * 1_024, "fixture request too large");
                }
                observed_requests.fetch_add(1, Ordering::SeqCst);
                let target = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap()
                    .to_owned();
                observed_targets
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(target.clone());
                let body = handler(&target);
                let wire = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(wire.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        LocalFixture {
            target: Url::parse(&format!("http://{address}/search")).unwrap(),
            requests,
            targets,
            task,
        }
    }

    fn scan_context(target: Url) -> ScanContext {
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let context = ScanContext::new(target.clone(), reqwest::Client::new(), telemetry);
        let mut delta = DiscoveryDelta::new();
        delta.record_endpoint(target, ["existing".to_owned()]);
        context
            .commit_discovery(PARAMETER_ACTION_ID, delta)
            .unwrap();
        context
    }

    #[test]
    fn phase_identity_and_default_bounds_are_stable() {
        let discoverer = ParameterDiscoverer::with_default_wordlist_sequential();
        assert_eq!(discoverer.phase_number(), 4);
        assert_eq!(discoverer.name(), "Hidden Parameter Miner");
        assert_eq!(discoverer.param_wordlist.len(), 8);
    }

    #[test]
    fn candidates_are_bounded_deduplicated_and_deterministic() {
        let discoverer = ParameterDiscoverer::sequential(vec![
            "z".to_owned(),
            "a".to_owned(),
            "z".to_owned(),
            String::new(),
            "x".repeat(MAX_PARAMETER_NAME_BYTES + 1),
            "line\nbreak".to_owned(),
        ]);
        assert_eq!(discoverer.param_wordlist, vec!["a", "z"]);
    }

    #[test]
    fn oversized_candidate_input_is_rejected_before_execution() {
        let discoverer = ParameterDiscoverer::sequential(
            (0..=MAX_PARAMETER_CANDIDATES)
                .map(|index| format!("p{index}"))
                .collect(),
        );
        assert!(!discoverer.candidate_input_within_limits);
        assert!(discoverer.param_wordlist.len() > MAX_PARAMETER_CANDIDATES);
    }

    #[test]
    fn url_mutation_preserves_and_encodes_existing_query() {
        let endpoint = Url::parse("https://example.test/search?scope=docs%20and%20api").unwrap();
        let mutated = append_query_parameter(&endpoint, "new name", "a&b=c");
        assert_eq!(
            mutated.as_str(),
            "https://example.test/search?scope=docs%20and%20api&new+name=a%26b%3Dc"
        );
        assert_eq!(endpoint.query(), Some("scope=docs%20and%20api"));
    }

    #[test]
    fn public_subject_omits_query_values() {
        let endpoint = Url::parse("https://example.test/search?token=secret#part").unwrap();
        assert_eq!(endpoint_subject(&endpoint), "https://example.test/search");
    }

    #[test]
    fn byte_search_handles_empty_and_binary_bodies() {
        assert!(!body_contains(b"prefix\0marker", ""));
        assert!(body_contains(b"prefix\0marker", "marker"));
        assert!(!body_contains(b"prefix\0marker", "other"));
    }

    fn signature(status: u16, body: &str) -> ResponseSignature {
        ResponseSignature::from_parts(status, None, body)
    }

    #[test]
    fn invariant_200_application_produces_no_observation() {
        let same = signature(200, "unchanged application response");
        assert!(!profiles_support_observation(
            &same, &same, &same, &same, false, false
        ));
    }

    #[test]
    fn positive_differential_must_be_distinct_and_reproducible() {
        let baseline = signature(200, "ordinary response");
        let negative = signature(200, "unknown parameter ignored");
        let recognized = signature(200, "recognized parameter response");
        assert!(profiles_support_observation(
            &baseline,
            &negative,
            &recognized,
            &recognized,
            false,
            false,
        ));

        let non_reproduction = signature(200, "one-off response");
        assert!(!profiles_support_observation(
            &baseline,
            &negative,
            &recognized,
            &non_reproduction,
            false,
            false,
        ));
    }

    #[test]
    fn negative_control_equivalence_and_preexisting_marker_fail_closed() {
        let baseline = signature(200, "ordinary response");
        let generic_query_response = signature(200, "query echoed");
        assert!(!profiles_support_observation(
            &baseline,
            &generic_query_response,
            &generic_query_response,
            &generic_query_response,
            false,
            false,
        ));

        let recognized = signature(200, "recognized parameter response");
        assert!(!profiles_support_observation(
            &baseline,
            &generic_query_response,
            &recognized,
            &recognized,
            false,
            true,
        ));
        assert!(!profiles_support_observation(
            &baseline,
            &generic_query_response,
            &recognized,
            &recognized,
            true,
            false,
        ));
    }

    #[tokio::test]
    async fn ignored_unknown_parameters_with_invariant_200_produce_zero_observations() {
        let fixture = serve_fixture(4, |_| "ordinary application page".to_owned()).await;
        let context = scan_context(fixture.target.clone());
        let findings = ParameterDiscoverer::sequential(vec!["q".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
        assert_eq!(
            context
                .discovery_snapshot()
                .endpoints()
                .get(fixture.target.as_str())
                .unwrap(),
            &BTreeSet::from(["existing".to_owned()])
        );
    }

    #[tokio::test]
    async fn generic_query_key_echo_produces_zero_observations() {
        let fixture = serve_fixture(4, |target| {
            let parsed = Url::parse(&format!("http://fixture.test{target}")).unwrap();
            let names = parsed
                .query_pairs()
                .map(|(name, _)| name.into_owned())
                .collect::<Vec<_>>()
                .join(",");
            format!("query keys: {names}")
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = ParameterDiscoverer::sequential(vec!["q".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn bare_random_nonce_echo_produces_zero_observations() {
        let fixture = serve_fixture(4, |target| {
            let parsed = Url::parse(&format!("http://fixture.test{target}")).unwrap();
            parsed
                .query_pairs()
                .next()
                .map(|(_, value)| {
                    value
                        .strip_prefix(CANDIDATE_MARKER_PREFIX)
                        .unwrap_or(&value)
                        .to_owned()
                })
                .unwrap_or_else(|| "ordinary application page".to_owned())
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = ParameterDiscoverer::sequential(vec!["q".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn preexisting_marker_namespace_suppresses_an_apparent_differential() {
        let fixture = serve_fixture(4, |target| {
            if target.contains("q=") {
                "recognized candidate response".to_owned()
            } else {
                "documentation example venom-candidate-already-present".to_owned()
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());
        let findings = ParameterDiscoverer::sequential(vec!["q".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn reproducible_candidate_differential_records_one_info_observation() {
        let fixture = serve_fixture(4, |target| {
            if target.contains("q=") {
                "recognized query behavior".to_owned()
            } else {
                "ordinary application page".to_owned()
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());
        let findings = ParameterDiscoverer::sequential(vec!["q".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "INFO");
        let public_text = format!("{} {}", findings[0].description, findings[0].evidence);
        assert!(!public_text.contains("venom-candidate-"));
        assert!(!public_text.to_lowercase().contains("vulnerab"));
        assert!(!public_text.to_lowercase().contains("confirm"));
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
        let targets = fixture
            .targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(targets[0], "/search");
        assert!(targets[1].contains("_venom_control_"));
        assert!(targets[1].contains("venom-candidate-"));
        assert_eq!(targets[2], targets[3]);
        assert!(targets[2].contains("q=venom-candidate-"));
        assert_eq!(
            context
                .discovery_snapshot()
                .endpoints()
                .get(fixture.target.as_str())
                .unwrap(),
            &BTreeSet::from(["existing".to_owned(), "q".to_owned()])
        );
    }

    #[tokio::test]
    async fn marker_shape_reaction_is_not_a_parameter_name_observation() {
        let fixture = serve_fixture(4, |target| {
            if target.contains("venom-candidate-") {
                "generic marker-shaped value response".to_owned()
            } else {
                "ordinary application page".to_owned()
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = ParameterDiscoverer::sequential(vec!["q".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn percent_encoded_query_key_echo_produces_zero_observations() {
        let fixture = serve_fixture(4, |target| {
            let key = target
                .split_once('?')
                .and_then(|(_, query)| query.rsplit('&').next())
                .and_then(|pair| pair.split_once('=').map(|(name, _)| name))
                .unwrap_or("none");
            format!("wire query key: {key}")
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = ParameterDiscoverer::sequential(vec!["filters[id]".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn an_already_known_parameter_is_not_probed_again() {
        let fixture = serve_fixture(0, |_| unreachable!()).await;
        let context = scan_context(fixture.target.clone());
        let findings = ParameterDiscoverer::sequential(vec!["existing".to_owned()])
            .execute(&context)
            .await
            .unwrap();
        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn compatibility_zero_concurrency_preserves_no_request_authority() {
        let fixture = serve_fixture(0, |_| unreachable!()).await;
        let context = scan_context(fixture.target.clone());

        let explicit = ParameterDiscoverer::new(vec!["q".to_owned()], 0)
            .execute(&context)
            .await
            .unwrap();
        let defaults = ParameterDiscoverer::with_default_wordlist(0)
            .execute(&context)
            .await
            .unwrap();

        assert!(explicit.is_empty());
        assert!(defaults.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn root_query_parameter_is_known_without_running_the_crawler() {
        let fixture = serve_fixture(0, |_| unreachable!()).await;
        let mut target = fixture.target.clone();
        target.set_query(Some("q=known"));
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let context = ScanContext::new(target, reqwest::Client::new(), telemetry);

        let findings = ParameterDiscoverer::sequential(vec!["q".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn query_name_beyond_retained_state_sample_is_still_never_probed() {
        let fixture = serve_fixture(0, |_| unreachable!()).await;
        let mut target = fixture.target.clone();
        {
            let mut query = target.query_pairs_mut();
            for index in 0..256 {
                query.append_pair(&format!("a{index:03}"), "known");
            }
            query.append_pair("q", "known");
        }
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let context = ScanContext::new(target, reqwest::Client::new(), telemetry);

        let findings = ParameterDiscoverer::sequential(vec!["q".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn public_host_seed_query_parameter_is_not_probed_again() {
        let fixture = serve_fixture(0, |_| unreachable!()).await;
        let mut target = fixture.target.clone();
        target.set_query(Some("seeded=root"));
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let context = ScanContext::new(target, reqwest::Client::new(), telemetry);
        context.add_endpoint("/other?seeded=known".to_owned(), Vec::new());

        let findings = ParameterDiscoverer::sequential(vec!["seeded".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancelled_empty_candidate_phase_cannot_commit_success() {
        let fixture = serve_fixture(0, |_| unreachable!()).await;
        let cancellation = tokio_util::sync::CancellationToken::new();
        cancellation.cancel();
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let context = ScanContext::with_cancellation(
            fixture.target.clone(),
            reqwest::Client::new(),
            telemetry,
            30,
            cancellation,
        );

        let error = ParameterDiscoverer::new(Vec::new(), 0)
            .execute(&context)
            .await
            .unwrap_err();

        assert!(matches!(error, ScannerError::Cancelled));
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fourth_leg_budget_denial_is_typed_and_does_not_partially_commit() {
        let fixture = serve_fixture(3, |target| {
            if target.contains("q=") {
                "recognized query behavior".to_owned()
            } else {
                "ordinary application page".to_owned()
            }
        })
        .await;
        let limits = DiscoveryLimits::new()
            .with_max_depth(1)
            .with_max_pages(1)
            .unwrap()
            .with_max_requests(3)
            .with_request_timeout(Duration::from_secs(1))
            .unwrap()
            .with_max_wall_time(Duration::from_secs(10))
            .unwrap()
            .with_body_limits(128 * 1_024, 64 * 1_024)
            .unwrap();
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let context = ScanContext::new_with_discovery_limits(
            fixture.target.clone(),
            reqwest::Client::new(),
            telemetry,
            limits,
        );
        let mut seed = DiscoveryDelta::new();
        seed.record_endpoint(fixture.target.clone(), ["existing".to_owned()]);
        context.commit_discovery(PARAMETER_ACTION_ID, seed).unwrap();
        let before = context.discovery_snapshot();

        let error = ParameterDiscoverer::sequential(vec!["q".to_owned()])
            .execute(&context)
            .await
            .unwrap_err();
        assert!(matches!(error, ScannerError::BudgetExceeded(_)));
        assert_eq!(context.discovery_snapshot(), before);
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
    }
}
