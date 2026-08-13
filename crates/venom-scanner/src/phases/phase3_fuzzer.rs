//! # Phase 3: controlled directory discovery
//!
//! The opt-in legacy directory phase compares each candidate with randomized
//! nonexistent-path controls through the run-scoped discovery broker. It
//! records endpoint observations only; no status code is a vulnerability claim.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
    http_evidence::HttpProbeMethod,
    legacy_discovery::{BoundedHttpResponse, DiscoveryDelta},
};

const DIRECTORY_ACTION_ID: &str = "legacy.discovery.directory";
const MAX_DIRECTORY_CANDIDATES: usize = 256;
const MAX_DIRECTORY_CANDIDATE_BYTES: usize = 8_192;
const MAX_DIRECTORY_CONTROL_SHAPES: usize = 16;
const MAX_DIRECTORY_SHAPE_DEPTH: usize = 16;
const MAX_DIRECTORY_EXTENSION_BYTES: usize = 32;
/// Directory discovery with a bounded candidate wordlist.
#[derive(Debug)]
pub struct DirectoryFuzzer {
    wordlist: Vec<String>,
    candidate_input_within_limits: bool,
}

impl DirectoryFuzzer {
    /// Creates a directory discoverer while retaining the pre-1.0 constructor
    /// shape used by legacy hosts.
    ///
    /// The compatibility concurrency argument no longer changes execution:
    /// bounded discovery deliberately dispatches sequentially so request
    /// selection and budget exhaustion remain deterministic.
    pub fn new(wordlist: Vec<String>, _concurrency_limit: usize) -> Self {
        Self::sequential(wordlist)
    }

    /// Creates the deterministic sequential form without a compatibility
    /// concurrency argument.
    pub fn sequential(wordlist: Vec<String>) -> Self {
        let candidate_input_within_limits = wordlist.len() <= MAX_DIRECTORY_CANDIDATES
            && wordlist
                .iter()
                .all(|candidate| candidate.len() <= MAX_DIRECTORY_CANDIDATE_BYTES);
        Self {
            wordlist,
            candidate_input_within_limits,
        }
    }

    /// Uses a conservative list of common application endpoints while
    /// retaining the legacy constructor shape.
    pub fn with_default_wordlist(_concurrency_limit: usize) -> Self {
        Self::with_default_wordlist_sequential()
    }

    /// Uses the conservative endpoint set with deterministic sequential
    /// dispatch.
    pub fn with_default_wordlist_sequential() -> Self {
        Self::sequential(
            [
                "/admin",
                "/api",
                "/api/v1",
                "/docs",
                "/swagger",
                "/swagger.json",
                "/graphql",
                "/health",
                "/status",
                "/uploads",
                "/files",
                "/backup",
                "/debug",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        )
    }

    fn candidates(&self, context: &ScanContext) -> Result<Vec<Url>, ScannerError> {
        if !self.candidate_input_within_limits {
            return Err(ScannerError::DiscoveryStateLimitExceeded);
        }
        let mut candidates = BTreeSet::new();
        for word in &self.wordlist {
            let joined = context.target.join(word)?;
            candidates.insert(context.canonicalize_discovery_url(&joined)?.to_string());
        }
        candidates
            .into_iter()
            .map(|value| Url::parse(&value).map_err(ScannerError::from))
            .collect()
    }
}

#[async_trait]
impl ScanPhase for DirectoryFuzzer {
    fn phase_number(&self) -> u8 {
        3
    }

    fn name(&self) -> &'static str {
        // Retained as the stable phase/action identity for existing reports.
        "Directory & Endpoint Fuzzer"
    }

    async fn execute(&self, context: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        context.log("Phase 3: controlled directory discovery initiated.".to_owned());
        let candidates = self.candidates(context)?;
        if candidates.is_empty() {
            context.commit_discovery(DIRECTORY_ACTION_ID, DiscoveryDelta::new())?;
            context.log(
                "Phase 3: controlled directory discovery completed with 0 endpoint observations."
                    .to_owned(),
            );
            return Ok(Vec::new());
        }
        let candidate_groups = group_candidates_by_shape(candidates)?;
        if candidate_groups.is_empty() {
            context.commit_discovery(DIRECTORY_ACTION_ID, DiscoveryDelta::new())?;
            context.log(
                "Phase 3: no conservatively calibratable endpoint candidates remained.".to_owned(),
            );
            return Ok(Vec::new());
        }

        let discovery_before = context.discovery_snapshot();
        let mut calibrations = BTreeMap::new();
        for shape in candidate_groups.keys() {
            let calibration = ControlCalibration::collect(context, shape).await?;
            if !calibration.is_stable() {
                context.commit_discovery(DIRECTORY_ACTION_ID, DiscoveryDelta::new())?;
                context.log(
                    "Phase 3: nonexistent-path controls were unusable or unstable; candidate dispatch was skipped."
                        .to_owned(),
                );
                return Ok(Vec::new());
            }
            calibrations.insert(shape.clone(), calibration);
        }

        let mut delta = DiscoveryDelta::new();
        let mut findings = Vec::new();
        for (shape, candidates) in candidate_groups {
            for candidate in candidates {
                let response = context
                    .request(DIRECTORY_ACTION_ID, HttpProbeMethod::Get, candidate.clone())
                    .await?;
                let calibration = calibrations
                    .get(&shape)
                    .ok_or(ScannerError::DiscoveryStateLimitExceeded)?;
                let (control, signature) = calibration.compare(&candidate, &response);
                if candidate_is_observable(&control, &signature) {
                    let existing_parameters = discovery_before
                        .endpoints()
                        .get(candidate.as_str())
                        .cloned()
                        .unwrap_or_default();
                    delta.record_endpoint(candidate.clone(), existing_parameters);
                    findings.push(ScanFinding {
                        phase: self.phase_number(),
                        module_name: self.name().to_owned(),
                        severity: "INFO".to_owned(),
                        description:
                            "A path produced a response distinct from calibrated nonexistent-path controls."
                                .to_owned(),
                        evidence: format!(
                            "Endpoint observation: {} (HTTP {})",
                            endpoint_subject(&candidate),
                            response.status()
                        ),
                    });
                }
            }
        }

        // A failed probe returns before this single commit, so a partial batch
        // can never escape into later phases.
        context.commit_discovery(DIRECTORY_ACTION_ID, delta)?;
        context.log(format!(
            "Phase 3: controlled directory discovery completed with {} endpoint observations.",
            findings.len()
        ));
        Ok(findings)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DirectoryShape {
    parent_segments: Vec<String>,
    trailing_slash: bool,
    extension: Option<String>,
}

impl DirectoryShape {
    fn from_candidate(candidate: &Url) -> Result<Option<Self>, ScannerError> {
        if candidate.query().is_some() {
            // Replaying supplied query values on randomized control paths would
            // expand the host's authority and could duplicate sensitive data.
            return Ok(None);
        }
        if candidate.path().contains('%') || candidate.path().contains("//") {
            // Percent-encoded and empty-segment paths can change shape after
            // intermediary decoding or normalization. Do not guess at their
            // equivalence class.
            return Ok(None);
        }
        let segments = candidate
            .path()
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        if segments.is_empty() {
            return Ok(None);
        }
        if segments
            .iter()
            .take(segments.len().saturating_sub(1))
            .any(|segment| !is_safe_path_component(segment))
        {
            return Ok(None);
        }
        if segments.len() > MAX_DIRECTORY_SHAPE_DEPTH {
            return Err(ScannerError::DiscoveryStateLimitExceeded);
        }
        let Some(last_segment) = segments.last() else {
            return Ok(None);
        };
        let extension = match last_segment.split_once('.') {
            Some((stem, extension))
                if !extension.contains('.')
                    && is_safe_path_component(stem)
                    && is_safe_path_component(extension)
                    && extension.len() <= MAX_DIRECTORY_EXTENSION_BYTES =>
            {
                Some(extension.to_owned())
            },
            Some(_) => return Ok(None),
            None if is_safe_path_component(last_segment) => None,
            None => return Ok(None),
        };
        if segments.iter().any(|segment| segment.starts_with('.')) {
            // A generic dot-path policy cannot be safely calibrated without
            // probing a special namespace, so fail closed for these candidates.
            return Ok(None);
        }
        Ok(Some(Self {
            parent_segments: segments[..segments.len().saturating_sub(1)]
                .iter()
                .map(|segment| (*segment).to_owned())
                .collect(),
            trailing_slash: candidate.path().ends_with('/'),
            extension,
        }))
    }

    fn control_url(&self, context: &ScanContext, nonce: &str) -> Result<Url, ScannerError> {
        let mut path = String::new();
        for segment in &self.parent_segments {
            path.push('/');
            path.push_str(segment);
        }
        path.push('/');
        path.push_str(nonce);
        if let Some(extension) = &self.extension {
            path.push('.');
            path.push_str(extension);
        }
        if self.trailing_slash {
            path.push('/');
        }
        let control = context.target.join(&path)?;
        context.canonicalize_discovery_url(&control)
    }
}

fn is_safe_path_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn group_candidates_by_shape(
    candidates: Vec<Url>,
) -> Result<BTreeMap<DirectoryShape, Vec<Url>>, ScannerError> {
    let mut groups = BTreeMap::<DirectoryShape, Vec<Url>>::new();
    for candidate in candidates {
        if let Some(shape) = DirectoryShape::from_candidate(&candidate)? {
            groups.entry(shape).or_default().push(candidate);
        }
    }
    if groups.len() > MAX_DIRECTORY_CONTROL_SHAPES {
        return Err(ScannerError::DiscoveryStateLimitExceeded);
    }
    Ok(groups)
}

struct ControlCalibration {
    urls: [Url; 2],
    nonces: [String; 2],
    responses: [BoundedHttpResponse; 2],
}

impl ControlCalibration {
    async fn collect(context: &ScanContext, shape: &DirectoryShape) -> Result<Self, ScannerError> {
        let first_nonce = Uuid::new_v4().simple().to_string();
        let mut second_nonce = Uuid::new_v4().simple().to_string();
        while second_nonce == first_nonce {
            second_nonce = Uuid::new_v4().simple().to_string();
        }
        let nonces = [first_nonce, second_nonce];
        let urls = [
            shape.control_url(context, &nonces[0])?,
            shape.control_url(context, &nonces[1])?,
        ];
        let first = context
            .request(DIRECTORY_ACTION_ID, HttpProbeMethod::Get, urls[0].clone())
            .await?;
        let second = context
            .request(DIRECTORY_ACTION_ID, HttpProbeMethod::Get, urls[1].clone())
            .await?;
        Ok(Self {
            urls,
            nonces,
            responses: [first, second],
        })
    }

    fn scrubber(&self, candidate: Option<&Url>) -> ResponseScrubber {
        let mut urls = vec![&self.urls[0], &self.urls[1]];
        if let Some(candidate) = candidate {
            urls.push(candidate);
        }
        ResponseScrubber::from_requests(&urls, &[self.nonces[0].as_str(), self.nonces[1].as_str()])
    }

    fn is_stable(&self) -> bool {
        if self.responses.iter().any(control_is_unusable) {
            return false;
        }
        let scrubber = self.scrubber(None);
        ResponseSignature::capture_with_scrubber(&self.responses[0], &scrubber)
            == ResponseSignature::capture_with_scrubber(&self.responses[1], &scrubber)
    }

    fn compare(
        &self,
        candidate_url: &Url,
        candidate_response: &BoundedHttpResponse,
    ) -> (ResponseSignature, ResponseSignature) {
        let scrubber = self.scrubber(Some(candidate_url));
        (
            ResponseSignature::capture_with_scrubber(&self.responses[0], &scrubber),
            ResponseSignature::capture_with_scrubber(candidate_response, &scrubber),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResponseSignature {
    status: u16,
    content_type: Option<String>,
    location: Option<String>,
    cache_control: Option<String>,
    www_authenticate: Option<String>,
    body_digest: [u8; 32],
    body_length: usize,
    body_truncated: bool,
}

impl ResponseSignature {
    pub(super) fn capture(response: &BoundedHttpResponse, scrubbed_values: &[&str]) -> Self {
        let scrubber = ResponseScrubber::new(response.request_url(), scrubbed_values);
        Self::capture_with_scrubber(response, &scrubber)
    }

    fn capture_with_scrubber(response: &BoundedHttpResponse, scrubber: &ResponseScrubber) -> Self {
        let normalized_body = scrubber.body(response.body());
        Self {
            status: response.status(),
            content_type: response
                .content_type()
                .map(|value| scrubber.header(value).to_ascii_lowercase()),
            location: response
                .location()
                .map(|value| normalize_location(response.request_url(), value, scrubber)),
            cache_control: response
                .header("cache-control")
                .map(|value| scrubber.header(value).to_ascii_lowercase()),
            www_authenticate: response
                .header("www-authenticate")
                .map(|value| scrubber.header(value).to_ascii_lowercase()),
            body_digest: Sha256::digest(&normalized_body).into(),
            body_length: normalized_body.len(),
            body_truncated: response.body_truncated(),
        }
    }

    #[cfg(test)]
    pub(super) fn from_parts(status: u16, location: Option<&str>, body: &str) -> Self {
        let normalized = normalize_text(body, &[]).into_bytes();
        Self {
            status,
            content_type: Some("text/html".to_owned()),
            location: location.map(str::to_owned),
            cache_control: None,
            www_authenticate: None,
            body_digest: Sha256::digest(&normalized).into(),
            body_length: normalized.len(),
            body_truncated: false,
        }
    }
}

fn control_is_unusable(response: &BoundedHttpResponse) -> bool {
    response.body_truncated() || response.status() == 429 || matches!(response.status(), 500..=599)
}

fn candidate_is_observable(control: &ResponseSignature, candidate: &ResponseSignature) -> bool {
    // 401 and 403 are endpoint observations when they differ from the control;
    // they still produce INFO output rather than a security finding. A bounded
    // prefix is not enough to distinguish either response, so truncation fails
    // closed instead of manufacturing a route observation.
    !control.body_truncated
        && !candidate.body_truncated
        && matches!(candidate.status, 200..=399 | 401 | 403)
        && candidate != control
}

struct ResponseScrubber {
    values: Vec<String>,
}

impl ResponseScrubber {
    fn new(request_url: &Url, extra_values: &[&str]) -> Self {
        Self::from_requests(&[request_url], extra_values)
    }

    fn from_requests(request_urls: &[&Url], extra_values: &[&str]) -> Self {
        let mut values = extra_values
            .iter()
            .filter(|value| !value.is_empty())
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();

        // Soft-404 implementations commonly echo the requested target. Remove
        // every compared request's incidental values from every leg. A shared
        // universe avoids manufacturing a difference when a control template
        // happens to contain the static candidate path (for example, a nav
        // link to `/admin`).
        for request_url in request_urls {
            let mut request_target = request_url.path().to_owned();
            if let Some(query) = request_url.query() {
                request_target.push('?');
                request_target.push_str(query);
                add_scrub_variants(&mut values, query);
            }
            add_scrub_variants(&mut values, request_url.path());
            if let Some(terminal) = request_url
                .path()
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .filter(|terminal| !terminal.is_empty())
            {
                // Some wildcard routers echo only the requested basename. It
                // is incidental request data just like a full path and must
                // not manufacture a candidate/control distinction.
                add_scrub_variants(&mut values, terminal);
            }
            add_scrub_variants(&mut values, &request_target);
            add_scrub_variants(&mut values, request_url.as_str());
        }
        values.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
        values.dedup();
        Self { values }
    }

    fn body(&self, body: &[u8]) -> Vec<u8> {
        normalize_text(&String::from_utf8_lossy(body), &self.values).into_bytes()
    }

    fn header(&self, value: &str) -> String {
        normalize_text(value, &self.values)
    }
}

fn add_scrub_variants(values: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        return;
    }
    values.push(value.to_owned());
    let encoded = percent_encode_non_alphanumeric(value.as_bytes());
    values.push(encoded.clone());
    values.push(lowercase_percent_escapes(&encoded));
    values.push(uppercase_percent_escapes(value));
    values.push(lowercase_percent_escapes(value));
}

fn lowercase_percent_escapes(value: &str) -> String {
    normalize_percent_escape_case(value, u8::to_ascii_lowercase)
}

fn uppercase_percent_escapes(value: &str) -> String {
    normalize_percent_escape_case(value, u8::to_ascii_uppercase)
}

fn normalize_percent_escape_case(value: &str, map: fn(&u8) -> u8) -> String {
    let mut bytes = value.as_bytes().to_vec();
    let mut index = 0;
    while index + 2 < bytes.len() {
        if bytes[index] == b'%'
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            bytes[index + 1] = map(&bytes[index + 1]);
            bytes[index + 2] = map(&bytes[index + 2]);
            index += 3;
        } else {
            index += 1;
        }
    }
    match String::from_utf8(bytes) {
        Ok(normalized) => normalized,
        Err(_) => value.to_owned(),
    }
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

fn normalize_location(request_url: &Url, location: &str, scrubber: &ResponseScrubber) -> String {
    let Ok(mut destination) = request_url.join(location.trim()) else {
        return "[invalid-location]".to_owned();
    };
    if !matches!(destination.scheme(), "http" | "https") {
        return "[non-http-location]".to_owned();
    }
    if destination.origin() != request_url.origin() {
        return "[cross-origin-location]".to_owned();
    }
    destination.set_fragment(None);
    let pairs = destination
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        destination.set_query(None);
    } else {
        let mut names = std::collections::HashSet::with_capacity(pairs.len());
        if pairs.iter().all(|(name, _)| names.insert(name.clone())) {
            let mut sorted = pairs;
            sorted.sort();
            destination.query_pairs_mut().clear().extend_pairs(sorted);
        }
    }
    scrubber.header(destination.as_str())
}

fn normalize_text(text: &str, scrubbed_values: &[String]) -> String {
    // The replacement must not contain any character allowed in dynamic URL
    // components. Otherwise a later short value (for example parameter `q`)
    // can rewrite an earlier replacement and manufacture unequal signatures.
    const SCRUB_SENTINEL: &str = "\u{1f}";
    let mut normalized = uppercase_percent_escapes(text);
    for value in scrubbed_values {
        if !value.is_empty() {
            normalized = normalized.replace(&uppercase_percent_escapes(value), SCRUB_SENTINEL);
        }
    }
    normalized.split_whitespace().collect::<Vec<_>>().join(" ")
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

    struct FixtureResponse {
        status: &'static str,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl FixtureResponse {
        fn html(status: &'static str, body: impl Into<String>) -> Self {
            Self {
                status,
                headers: vec![("Content-Type".to_owned(), "text/html".to_owned())],
                body: body.into(),
            }
        }

        fn redirect(location: impl Into<String>, body: impl Into<String>) -> Self {
            Self {
                status: "302 Found",
                headers: vec![
                    ("Content-Type".to_owned(), "text/html".to_owned()),
                    ("Location".to_owned(), location.into()),
                ],
                body: body.into(),
            }
        }
    }

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
        handler: impl Fn(&str) -> FixtureResponse + Send + Sync + 'static,
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
                let response = handler(&target);
                let mut wire = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    response.body.len()
                );
                for (name, value) in response.headers {
                    wire.push_str(&format!("{name}: {value}\r\n"));
                }
                wire.push_str("\r\n");
                wire.push_str(&response.body);
                stream.write_all(wire.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        LocalFixture {
            target: Url::parse(&format!("http://{address}/")).unwrap(),
            requests,
            targets,
            task,
        }
    }

    fn scan_context(target: Url) -> ScanContext {
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        ScanContext::new(target, reqwest::Client::new(), telemetry)
    }

    fn signature(status: u16, location: Option<&str>, body: &str) -> ResponseSignature {
        ResponseSignature::from_parts(status, location, body)
    }

    fn control_nonce_from_target(target: &str) -> Option<&str> {
        let path = target.split('?').next()?.trim_end_matches('/');
        let terminal = path.rsplit('/').next()?;
        let nonce = terminal.split_once('.').map_or(terminal, |(stem, _)| stem);
        (nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(nonce)
    }

    fn is_control_target(target: &str) -> bool {
        control_nonce_from_target(target).is_some()
    }

    #[test]
    fn phase_identity_is_stable() {
        let fuzzer = DirectoryFuzzer::with_default_wordlist_sequential();
        assert_eq!(fuzzer.phase_number(), 3);
        assert_eq!(fuzzer.name(), "Directory & Endpoint Fuzzer");
        assert_eq!(fuzzer.wordlist.len(), 13);
    }

    #[test]
    fn oversized_candidate_input_fails_before_transport() {
        let context = scan_context(Url::parse("https://example.test/").unwrap());
        let fuzzer = DirectoryFuzzer::sequential(
            (0..=MAX_DIRECTORY_CANDIDATES)
                .map(|index| format!("/path-{index}"))
                .collect(),
        );

        assert!(matches!(
            fuzzer.candidates(&context),
            Err(ScannerError::DiscoveryStateLimitExceeded)
        ));
    }

    #[test]
    fn wildcard_200_and_custom_soft_404_are_suppressed() {
        let control = signature(200, None, "not found: [nonce]");
        let wildcard = signature(200, None, "not found: [nonce]");
        assert!(!candidate_is_observable(&control, &wildcard));

        let custom_control = signature(404, None, "Our custom missing page");
        let custom_candidate = signature(404, None, "Our custom missing page");
        assert!(!candidate_is_observable(&custom_control, &custom_candidate));
    }

    #[test]
    fn stable_selected_header_difference_is_observable() {
        let control = signature(200, None, "same body");
        let mut candidate = control.clone();
        candidate.cache_control = Some("private".to_owned());
        assert!(candidate_is_observable(&control, &candidate));
    }

    #[test]
    fn redirect_all_is_suppressed_but_distinct_redirect_is_observed() {
        let control = signature(302, Some("/login"), "redirecting");
        assert!(!candidate_is_observable(
            &control,
            &signature(302, Some("/login"), "redirecting")
        ));
        assert!(candidate_is_observable(
            &control,
            &signature(302, Some("/admin/login"), "redirecting")
        ));
    }

    #[test]
    fn protected_status_is_only_observable_when_distinct_from_control() {
        let control = signature(404, None, "missing");
        assert!(candidate_is_observable(
            &control,
            &signature(403, None, "forbidden")
        ));
        let wildcard = signature(403, None, "forbidden");
        assert!(!candidate_is_observable(
            &wildcard,
            &signature(403, None, "forbidden")
        ));
    }

    #[test]
    fn explicit_missing_and_server_error_statuses_are_not_endpoints() {
        let control = signature(200, None, "wildcard");
        assert!(!candidate_is_observable(
            &control,
            &signature(404, None, "distinct missing page")
        ));
        assert!(!candidate_is_observable(
            &control,
            &signature(500, None, "server failure")
        ));
    }

    #[test]
    fn truncated_bodies_never_establish_a_distinct_endpoint() {
        let control = signature(404, None, "missing");
        let mut candidate = signature(200, None, "bounded prefix");
        candidate.body_truncated = true;
        assert!(!candidate_is_observable(&control, &candidate));

        let mut truncated_control = control;
        truncated_control.body_truncated = true;
        assert!(!candidate_is_observable(
            &truncated_control,
            &signature(200, None, "complete")
        ));
    }

    #[test]
    fn nonce_scrubbing_makes_equivalent_control_pages_equal() {
        assert_eq!(
            normalize_text("missing path alpha-123", &["alpha-123".to_owned()]),
            normalize_text("missing path beta-456", &["beta-456".to_owned()]),
        );
    }

    #[test]
    fn request_target_echoes_are_scrubbed() {
        let first_url = Url::parse("https://example.test/resource-123").unwrap();
        let second_url = Url::parse("https://example.test/admin").unwrap();
        let scrubber = ResponseScrubber::from_requests(&[&first_url, &second_url], &["123"]);
        let first = scrubber.body(b"no route: /resource-123; nav /admin");
        let second = scrubber.body(b"no route: /admin; nav /admin");
        assert_eq!(first, second);
    }

    #[test]
    fn encoded_request_target_echoes_are_scrubbed() {
        let first_url = Url::parse("https://example.test/resource-123").unwrap();
        let second_url = Url::parse("https://example.test/admin").unwrap();
        let scrubber = ResponseScrubber::from_requests(&[&first_url, &second_url], &["123"]);
        let first = scrubber.body(b"no route: %2Fresource-123");
        let second = scrubber.body(b"no route: %2fadmin");
        assert_eq!(first, second);
    }

    #[test]
    fn redirect_destination_is_resolved_and_request_target_is_scrubbed() {
        let control_url = Url::parse("https://example.test/resource-123?source=control").unwrap();
        let candidate_url = Url::parse("https://example.test/admin?source=candidate").unwrap();
        let scrubber = ResponseScrubber::from_requests(&[&control_url, &candidate_url], &["123"]);

        assert_eq!(
            normalize_location(&control_url, "/login?next=/resource-123", &scrubber,),
            normalize_location(&candidate_url, "/login?next=/admin", &scrubber),
        );
        assert_eq!(
            normalize_location(&control_url, "https://other.test/a", &scrubber),
            "[cross-origin-location]",
        );
        assert_eq!(
            normalize_location(&control_url, "mailto:ops@example.test", &scrubber),
            "[non-http-location]",
        );
    }

    #[test]
    fn redirect_destination_canonicalizes_only_safe_query_ordering() {
        let request = Url::parse("https://example.test/source").unwrap();
        let scrubber = ResponseScrubber::new(&request, &[]);
        assert_eq!(
            normalize_location(&request, "/login?b=2&a=1#one", &scrubber),
            normalize_location(&request, "/login?a=1&b=2#two", &scrubber),
        );
        assert_ne!(
            normalize_location(&request, "/login?a=1&a=2", &scrubber),
            normalize_location(&request, "/login?a=2&a=1", &scrubber),
            "repeated-name value order can carry application semantics"
        );
    }

    #[test]
    fn endpoint_subject_never_discloses_query_values() {
        let endpoint = Url::parse("https://example.test/path?token=secret#part").unwrap();
        assert_eq!(endpoint_subject(&endpoint), "https://example.test/path");
    }

    #[test]
    fn candidate_construction_is_canonical_deduplicated_and_same_origin() {
        let context = scan_context(Url::parse("https://example.test/root").unwrap());
        let fuzzer = DirectoryFuzzer::sequential(vec![
            "/a#first".to_owned(),
            "/a#second".to_owned(),
            "/b?z=2&a=1".to_owned(),
        ]);
        assert_eq!(
            fuzzer
                .candidates(&context)
                .unwrap()
                .into_iter()
                .map(|url| url.to_string())
                .collect::<Vec<_>>(),
            vec!["https://example.test/a", "https://example.test/b?a=1&z=2"]
        );
        assert!(
            DirectoryFuzzer::sequential(vec!["https://outside.test/a".to_owned()])
                .candidates(&context)
                .is_err()
        );
    }

    #[test]
    fn candidate_shapes_separate_depth_trailing_slash_and_extension() {
        let candidates = [
            "https://example.test/a",
            "https://example.test/a/",
            "https://example.test/a/b",
            "https://example.test/a.json",
            "https://example.test/a?view=one",
        ]
        .into_iter()
        .map(|candidate| Url::parse(candidate).unwrap())
        .collect();

        assert_eq!(group_candidates_by_shape(candidates).unwrap().len(), 4);
        assert!(DirectoryShape::from_candidate(
            &Url::parse("https://example.test/.hidden").unwrap()
        )
        .unwrap()
        .is_none());
        assert!(DirectoryShape::from_candidate(
            &Url::parse("https://example.test/admin?token=secret").unwrap()
        )
        .unwrap()
        .is_none());
        for unsafe_candidate in [
            "https://example.test/admin%2fsettings",
            "https://example.test/admin;mode=one",
            "https://example.test/admin.json.bak",
            "https://example.test/a.b/admin",
        ] {
            assert!(
                DirectoryShape::from_candidate(&Url::parse(unsafe_candidate).unwrap())
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn wildcard_200_with_request_echo_produces_no_observation() {
        let fixture = serve_fixture(4, |target| {
            FixtureResponse::html("200 OK", format!("no route {target}; nav /admin"))
        })
        .await;
        let context = scan_context(fixture.target.clone());
        let findings = DirectoryFuzzer::sequential(vec!["/api".to_owned(), "/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(
            context
                .discovery_snapshot()
                .endpoints()
                .keys()
                .collect::<Vec<_>>(),
            vec![&fixture.target.to_string()]
        );
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 4);
        let targets = fixture
            .targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(is_control_target(&targets[0]));
        assert!(is_control_target(&targets[1]));
        assert_eq!(
            targets[2..].iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["/admin", "/api"]
        );
    }

    #[tokio::test]
    async fn dynamic_soft_404_control_signatures_prevent_candidate_dispatch() {
        let sequence = Arc::new(AtomicUsize::new(0));
        let handler_sequence = Arc::clone(&sequence);
        let fixture = serve_fixture(2, move |_| {
            let request_id = handler_sequence.fetch_add(1, Ordering::SeqCst);
            FixtureResponse {
                status: "200 OK",
                headers: vec![
                    ("Content-Type".to_owned(), "text/html".to_owned()),
                    (
                        "Cache-Control".to_owned(),
                        format!("private, request-id={request_id}"),
                    ),
                ],
                body: "custom application missing page".to_owned(),
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = DirectoryFuzzer::sequential(vec!["/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unusable_first_or_second_control_prevents_candidate_dispatch() {
        let first_sequence = Arc::new(AtomicUsize::new(0));
        let handler_sequence = Arc::clone(&first_sequence);
        let first_unusable = serve_fixture(2, move |_| {
            if handler_sequence.fetch_add(1, Ordering::SeqCst) == 0 {
                FixtureResponse::html("500 Internal Server Error", "temporary failure")
            } else {
                FixtureResponse::html("200 OK", "wildcard")
            }
        })
        .await;
        let context = scan_context(first_unusable.target.clone());
        let findings = DirectoryFuzzer::sequential(vec!["/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap();
        assert!(findings.is_empty());
        assert_eq!(first_unusable.requests.load(Ordering::SeqCst), 2);

        let second_sequence = Arc::new(AtomicUsize::new(0));
        let handler_sequence = Arc::clone(&second_sequence);
        let second_unusable = serve_fixture(2, move |_| {
            if handler_sequence.fetch_add(1, Ordering::SeqCst) == 1 {
                FixtureResponse::html("429 Too Many Requests", "rate limited")
            } else {
                FixtureResponse::html("200 OK", "wildcard")
            }
        })
        .await;
        let context = scan_context(second_unusable.target.clone());
        let findings = DirectoryFuzzer::sequential(vec!["/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap();
        assert!(findings.is_empty());
        assert_eq!(second_unusable.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn lowercase_percent_encoded_request_echo_is_suppressed() {
        let fixture = serve_fixture(3, |target| {
            let encoded = percent_encode_non_alphanumeric(target.as_bytes()).to_ascii_lowercase();
            FixtureResponse::html("200 OK", format!("no route {encoded}"))
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = DirectoryFuzzer::sequential(vec!["/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn selected_headers_location_and_body_share_the_scrub_universe() {
        let fixture = serve_fixture(3, |target| {
            let encoded = percent_encode_non_alphanumeric(target.as_bytes());
            FixtureResponse {
                status: "302 Found",
                headers: vec![
                    (
                        "Content-Type".to_owned(),
                        format!("text/html; profile={encoded}"),
                    ),
                    (
                        "Location".to_owned(),
                        format!("/login?next={encoded}&b=2&a=1"),
                    ),
                    (
                        "Cache-Control".to_owned(),
                        format!("private, target={encoded}"),
                    ),
                    (
                        "WWW-Authenticate".to_owned(),
                        format!("Basic realm={encoded}"),
                    ),
                ],
                body: format!("redirecting from {target}"),
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = DirectoryFuzzer::sequential(vec!["/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn ordinary_controls_do_not_turn_dot_path_policy_into_an_observation() {
        let fixture = serve_fixture(3, |target| {
            if target.starts_with("/.") {
                FixtureResponse::html("403 Forbidden", "dot paths forbidden")
            } else {
                FixtureResponse::html("200 OK", format!("wildcard {target}"))
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = DirectoryFuzzer::sequential(vec!["/.git".to_owned(), "/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        let targets = fixture
            .targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(targets.len(), 3);
        assert!(targets.iter().all(|target| !target.starts_with("/.")));
    }

    #[tokio::test]
    async fn extension_specific_wildcard_is_calibrated_with_matching_controls() {
        let fixture = serve_fixture(3, |target| {
            if target.split('?').next().unwrap().ends_with(".json") {
                FixtureResponse::html("200 OK", format!(r#"{{"missing":"{target}"}}"#))
            } else {
                FixtureResponse::html("404 Not Found", "missing")
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = DirectoryFuzzer::sequential(vec!["/swagger.json".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
        let targets = fixture
            .targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(targets[0].ends_with(".json"));
        assert!(targets[1].ends_with(".json"));
        assert_eq!(targets[2], "/swagger.json");
    }

    #[tokio::test]
    async fn parent_scoped_wildcard_is_calibrated_inside_the_same_namespace() {
        let fixture = serve_fixture(3, |target| {
            if target.starts_with("/api/") {
                FixtureResponse::html("200 OK", format!("api wildcard {target}"))
            } else {
                FixtureResponse::html("404 Not Found", "missing")
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = DirectoryFuzzer::sequential(vec!["/api/v1".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
        let targets = fixture
            .targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(targets[0].starts_with("/api/"));
        assert!(targets[1].starts_with("/api/"));
        assert_eq!(targets[2], "/api/v1");
    }

    #[tokio::test]
    async fn terminal_segment_only_echo_is_not_an_endpoint_observation() {
        let fixture = serve_fixture(6, |target| {
            let terminal = target
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or_default();
            FixtureResponse::html("200 OK", format!("missing resource {terminal}"))
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings =
            DirectoryFuzzer::sequential(vec!["/admin".to_owned(), "/config.json".to_owned()])
                .execute(&context)
                .await
                .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 6);
    }

    #[tokio::test]
    async fn empty_candidate_set_performs_zero_requests() {
        let fixture = serve_fixture(0, |_| unreachable!()).await;
        let context = scan_context(fixture.target.clone());

        let findings = DirectoryFuzzer::sequential(Vec::new())
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn query_values_are_never_replayed_to_control_paths() {
        let fixture = serve_fixture(0, |_| unreachable!()).await;
        let context = scan_context(fixture.target.clone());

        let findings = DirectoryFuzzer::sequential(vec!["/admin?token=secret".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
        assert!(fixture
            .targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty());
    }

    #[tokio::test]
    async fn truncated_control_prevents_candidate_dispatch() {
        let fixture =
            serve_fixture(2, |_| FixtureResponse::html("200 OK", "x".repeat(1_024))).await;
        let limits = DiscoveryLimits::new()
            .with_max_requests(2)
            .with_body_limits(4 * 1_024, 64)
            .unwrap();
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let context = ScanContext::new_with_discovery_limits(
            fixture.target.clone(),
            reqwest::Client::new(),
            telemetry,
            limits,
        );

        let findings = DirectoryFuzzer::sequential(vec!["/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn prior_control_nonce_echo_does_not_change_classification() {
        let remembered_nonce = Arc::new(Mutex::new(None::<String>));
        let handler_nonce = Arc::clone(&remembered_nonce);
        let fixture = serve_fixture(3, move |target| {
            let nonce = if let Some(value) = control_nonce_from_target(target) {
                *handler_nonce
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(value.to_owned());
                value.to_owned()
            } else {
                handler_nonce
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
                    .unwrap()
            };
            FixtureResponse::html("200 OK", format!("missing nonce {nonce}"))
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let findings = DirectoryFuzzer::sequential(vec!["/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap();

        assert!(findings.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn custom_soft_404_and_redirect_all_produce_no_observation() {
        let soft_404 = serve_fixture(3, |_| {
            FixtureResponse::html("200 OK", "custom application missing page")
        })
        .await;
        let context = scan_context(soft_404.target.clone());
        let findings = DirectoryFuzzer::sequential(vec!["/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap();
        assert!(findings.is_empty());

        let redirect_all = serve_fixture(3, |target| {
            let path = target.split('?').next().unwrap();
            let encoded = percent_encode_non_alphanumeric(path.as_bytes());
            let location = if path == "/admin" {
                format!("/login?a=1&next={encoded}&b=2")
            } else {
                format!("/login?b=2&next={encoded}&a=1")
            };
            FixtureResponse::redirect(location, format!("redirecting from {path}"))
        })
        .await;
        let context = scan_context(redirect_all.target.clone());
        let findings = DirectoryFuzzer::sequential(vec!["/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap();
        assert!(findings.is_empty());
        assert_eq!(
            context
                .discovery_snapshot()
                .endpoints()
                .keys()
                .collect::<Vec<_>>(),
            vec![&redirect_all.target.to_string()]
        );
    }

    #[tokio::test]
    async fn distinct_endpoint_and_protected_route_are_info_observations() {
        let fixture = serve_fixture(4, |target| {
            if target == "/admin" {
                FixtureResponse::html("200 OK", "admin endpoint")
            } else if target == "/protected" {
                FixtureResponse::html("403 Forbidden", "access boundary")
            } else {
                FixtureResponse::html("404 Not Found", "missing")
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());
        let findings =
            DirectoryFuzzer::sequential(vec!["/protected".to_owned(), "/admin".to_owned()])
                .execute(&context)
                .await
                .unwrap();

        assert_eq!(findings.len(), 2);
        assert!(findings[0].evidence.contains("/admin"));
        assert!(findings[1].evidence.contains("/protected"));
        assert!(findings.iter().all(|finding| finding.severity == "INFO"));
        assert!(findings.iter().all(|finding| {
            let text = format!("{} {}", finding.description, finding.evidence).to_lowercase();
            !text.contains("vulnerab")
                && !text.contains("confirm")
                && !text.contains(".venom-nonexistent")
        }));
        let snapshot = context.discovery_snapshot();
        assert!(snapshot
            .endpoints()
            .contains_key(fixture.target.join("/admin").unwrap().as_str()));
        assert!(snapshot
            .endpoints()
            .contains_key(fixture.target.join("/protected").unwrap().as_str()));
    }

    #[tokio::test]
    async fn budget_denial_after_control_leaves_discovery_state_uncommitted() {
        let fixture = serve_fixture(1, |_| {
            FixtureResponse::html("404 Not Found", "missing control")
        })
        .await;
        let limits = DiscoveryLimits::new()
            .with_max_depth(1)
            .with_max_pages(1)
            .unwrap()
            .with_max_requests(1)
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
        let existing = fixture.target.join("/existing").unwrap();
        seed.record_endpoint(existing.clone(), ["kept".to_owned()]);
        context.commit_discovery(DIRECTORY_ACTION_ID, seed).unwrap();

        let before = context.discovery_snapshot();
        let error = DirectoryFuzzer::sequential(vec!["/admin".to_owned()])
            .execute(&context)
            .await
            .unwrap_err();
        assert!(matches!(error, ScannerError::BudgetExceeded(_)));
        assert_eq!(context.discovery_snapshot(), before);
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
        assert_eq!(
            context.discovery_snapshot().endpoints()[existing.as_str()],
            BTreeSet::from(["kept".to_owned()])
        );
    }
}
