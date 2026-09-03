//! Bounded transport and typed state for the opt-in legacy scanner.
//!
//! This is a migration boundary, not a second scanner runtime. Discovery
//! phases two through four share one passive authority and verification phases
//! five through nine share a distinct active authority. The two finite
//! envelopes cannot consume or reset each other. Phase one and custom phases
//! may still use the explicitly unmetered legacy client.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use url::Url;

use crate::{
    error::ScannerError,
    http_evidence::{
        HttpEvidencePolicy, HttpProbe, HttpProbeMethod, HttpRequestBroker, HttpRequestBrokerError,
        MAX_HTTP_BODY_LIMIT,
    },
    runtime_budget::RequestAccountingBroker,
    DecisionExecutionLimits, DecisionExecutionStage, RuntimeBudget, RuntimeBudgetDimension,
    RuntimeLimitExceeded,
};

const DEFAULT_MAX_DEPTH: usize = 4;
const DEFAULT_MAX_PAGES: usize = 64;
const DEFAULT_MAX_REQUESTS: u32 = 64;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_WALL_TIME: Duration = Duration::from_secs(120);
const DEFAULT_MAX_CUMULATIVE_BODY_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_VERIFICATION_REQUESTS: u32 = 96;
const DEFAULT_VERIFICATION_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_VERIFICATION_WALL_TIME: Duration = Duration::from_secs(120);
const DEFAULT_MAX_VERIFICATION_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_MAX_VERIFICATION_RESPONSE_BODY_BYTES: usize = 64 * 1024;
const MAX_VERIFICATION_REQUESTS: u32 = 4_096;
const MAX_DISCOVERY_ENDPOINTS: usize = 4_096;
const MAX_DISCOVERY_FORMS: usize = 4_096;
const MAX_DISCOVERY_URL_BYTES: usize = 8_192;
const MAX_DISCOVERY_PARAMETERS_PER_ENDPOINT: usize = 256;
const MAX_DISCOVERY_TOTAL_PARAMETERS: usize = 16_384;
const MAX_DISCOVERY_CONTROLS_PER_FORM: usize = 256;
const MAX_DISCOVERY_TOTAL_FORM_CONTROLS: usize = 16_384;
const MAX_DISCOVERY_NAME_BYTES: usize = 1_024;

/// Host-configurable resource envelope for legacy discovery phases two to four.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryLimits {
    max_depth: usize,
    max_pages: usize,
    max_requests: u32,
    request_timeout: Duration,
    max_wall_time: Duration,
    max_cumulative_body_bytes: u64,
    max_response_body_bytes: usize,
}

impl DiscoveryLimits {
    /// Creates the default finite discovery envelope.
    pub const fn new() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_pages: DEFAULT_MAX_PAGES,
            max_requests: DEFAULT_MAX_REQUESTS,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_wall_time: DEFAULT_MAX_WALL_TIME,
            max_cumulative_body_bytes: DEFAULT_MAX_CUMULATIVE_BODY_BYTES,
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
        }
    }

    /// Replaces the link-depth bound.
    pub const fn with_max_depth(mut self, limit: usize) -> Self {
        self.max_depth = limit;
        self
    }

    /// Replaces the page bound, rejecting values beyond retained state.
    pub fn with_max_pages(mut self, limit: usize) -> Result<Self, ScannerError> {
        if limit > MAX_DISCOVERY_ENDPOINTS {
            return Err(ScannerError::InvalidDiscoveryLimits);
        }
        self.max_pages = limit;
        Ok(self)
    }

    /// Replaces the shared dispatch bound. Zero denies every request.
    pub const fn with_max_requests(mut self, limit: u32) -> Self {
        self.max_requests = limit;
        self
    }

    /// Replaces the timeout for one request at millisecond precision.
    pub fn with_request_timeout(mut self, limit: Duration) -> Result<Self, ScannerError> {
        if limit < Duration::from_millis(1) {
            return Err(ScannerError::InvalidDiscoveryLimits);
        }
        self.request_timeout = limit;
        Ok(self)
    }

    /// Replaces the shared monotonic wall-clock bound at millisecond precision.
    pub fn with_max_wall_time(mut self, limit: Duration) -> Result<Self, ScannerError> {
        if limit < Duration::from_millis(1) {
            return Err(ScannerError::InvalidDiscoveryLimits);
        }
        self.max_wall_time = limit;
        Ok(self)
    }

    /// Replaces cumulative and per-response body ceilings together.
    pub fn with_body_limits(
        mut self,
        cumulative: u64,
        per_response: usize,
    ) -> Result<Self, ScannerError> {
        let per_response_u64 =
            u64::try_from(per_response).map_err(|_| ScannerError::InvalidDiscoveryLimits)?;
        if cumulative == 0
            || per_response == 0
            || per_response > MAX_HTTP_BODY_LIMIT
            || per_response_u64 > cumulative
        {
            return Err(ScannerError::InvalidDiscoveryLimits);
        }
        self.max_cumulative_body_bytes = cumulative;
        self.max_response_body_bytes = per_response;
        Ok(self)
    }

    /// Returns the maximum link depth, where the root is depth zero.
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }

    /// Returns the maximum number of crawler pages scheduled.
    pub const fn max_pages(self) -> usize {
        self.max_pages
    }

    /// Returns the maximum shared HTTP dispatch count.
    pub const fn max_requests(self) -> u32 {
        self.max_requests
    }

    /// Returns the timeout applied to one request and its bounded body read.
    pub const fn request_timeout(self) -> Duration {
        self.request_timeout
    }

    /// Returns the shared monotonic wall-clock allowance.
    pub const fn max_wall_time(self) -> Duration {
        self.max_wall_time
    }

    /// Returns the cumulative delivered response-body allowance.
    pub const fn max_cumulative_body_bytes(self) -> u64 {
        self.max_cumulative_body_bytes
    }

    /// Returns the retained body ceiling for one response.
    pub const fn max_response_body_bytes(self) -> usize {
        self.max_response_body_bytes
    }
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Host-configurable resource envelope shared by legacy phases five to nine.
///
/// The authority permits only bodyless, exact-origin requests through the
/// redirect- and retry-disabled broker. It does not grant verifier transition
/// authority: a completed request is still only a probe receipt or bounded
/// observation until an existing verifier contract evaluates its evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationLimits {
    max_requests: u32,
    request_timeout: Duration,
    max_wall_time: Duration,
    max_cumulative_body_bytes: u64,
    max_response_body_bytes: usize,
}

impl VerificationLimits {
    /// Creates the default finite legacy-verification envelope.
    pub const fn new() -> Self {
        Self {
            max_requests: DEFAULT_MAX_VERIFICATION_REQUESTS,
            request_timeout: DEFAULT_VERIFICATION_REQUEST_TIMEOUT,
            max_wall_time: DEFAULT_MAX_VERIFICATION_WALL_TIME,
            max_cumulative_body_bytes: DEFAULT_MAX_VERIFICATION_RESPONSE_BYTES,
            max_response_body_bytes: DEFAULT_MAX_VERIFICATION_RESPONSE_BODY_BYTES,
        }
    }

    /// Replaces the shared dispatch bound. Zero denies every request.
    pub fn with_max_requests(mut self, limit: u32) -> Result<Self, ScannerError> {
        if limit > MAX_VERIFICATION_REQUESTS {
            return Err(ScannerError::InvalidVerificationLimits);
        }
        self.max_requests = limit;
        Ok(self)
    }

    /// Replaces the timeout for one request at millisecond precision.
    pub fn with_request_timeout(mut self, limit: Duration) -> Result<Self, ScannerError> {
        if limit < Duration::from_millis(1) {
            return Err(ScannerError::InvalidVerificationLimits);
        }
        self.request_timeout = limit;
        Ok(self)
    }

    /// Replaces the shared monotonic wall-clock bound at millisecond precision.
    pub fn with_max_wall_time(mut self, limit: Duration) -> Result<Self, ScannerError> {
        if limit < Duration::from_millis(1) {
            return Err(ScannerError::InvalidVerificationLimits);
        }
        self.max_wall_time = limit;
        Ok(self)
    }

    /// Replaces cumulative and per-response body ceilings together.
    pub fn with_body_limits(
        mut self,
        cumulative: u64,
        per_response: usize,
    ) -> Result<Self, ScannerError> {
        let per_response_u64 =
            u64::try_from(per_response).map_err(|_| ScannerError::InvalidVerificationLimits)?;
        if cumulative == 0
            || per_response == 0
            || per_response > MAX_HTTP_BODY_LIMIT
            || per_response_u64 > cumulative
        {
            return Err(ScannerError::InvalidVerificationLimits);
        }
        self.max_cumulative_body_bytes = cumulative;
        self.max_response_body_bytes = per_response;
        Ok(self)
    }

    /// Returns the maximum shared active-verification dispatch count.
    pub const fn max_requests(self) -> u32 {
        self.max_requests
    }

    /// Returns the timeout applied to one request and bounded body read.
    pub const fn request_timeout(self) -> Duration {
        self.request_timeout
    }

    /// Returns the shared monotonic wall-clock allowance.
    pub const fn max_wall_time(self) -> Duration {
        self.max_wall_time
    }

    /// Returns the cumulative delivered response-body allowance.
    pub const fn max_cumulative_body_bytes(self) -> u64 {
        self.max_cumulative_body_bytes
    }

    /// Returns the retained body ceiling for one response.
    pub const fn max_response_body_bytes(self) -> usize {
        self.max_response_body_bytes
    }
}

impl Default for VerificationLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Method semantics retained for one parser-tree-descendant HTML form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DiscoveryFormMethod {
    /// Missing, invalid, or explicitly GET form method.
    Get,
    /// Explicit POST form method. It is recorded but never converted to GET.
    Post,
    /// HTML dialog form method. It is recorded but never sent as HTTP.
    Dialog,
}

/// Bounded parser-tree-descendant form observation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveryForm {
    action: Url,
    method: DiscoveryFormMethod,
    controls: BTreeSet<String>,
}

impl DiscoveryForm {
    /// Creates a typed form observation after applying collection bounds.
    pub(crate) fn new(
        action: Url,
        method: DiscoveryFormMethod,
        controls: impl IntoIterator<Item = String>,
    ) -> Result<Self, ScannerError> {
        let controls = controls.into_iter().collect::<BTreeSet<_>>();
        if action.as_str().len() > MAX_DISCOVERY_URL_BYTES
            || controls.len() > MAX_DISCOVERY_CONTROLS_PER_FORM
            || controls
                .iter()
                .any(|name| name.is_empty() || name.len() > MAX_DISCOVERY_NAME_BYTES)
        {
            return Err(ScannerError::DiscoveryStateLimitExceeded);
        }
        Ok(Self {
            action,
            method,
            controls,
        })
    }

    /// Returns the canonical action URL.
    pub fn action(&self) -> &Url {
        &self.action
    }

    /// Returns the observed form method semantics.
    pub const fn method(&self) -> DiscoveryFormMethod {
        self.method
    }

    /// Returns sorted, unique named controls.
    pub const fn controls(&self) -> &BTreeSet<String> {
        &self.controls
    }
}

/// Candidate discovery writes committed as one state transition.
#[derive(Debug, Default)]
pub(crate) struct DiscoveryDelta {
    endpoints: BTreeMap<String, BTreeSet<String>>,
    visited: BTreeSet<String>,
    forms: BTreeSet<DiscoveryForm>,
}

impl DiscoveryDelta {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record_endpoint(
        &mut self,
        url: Url,
        parameters: impl IntoIterator<Item = String>,
    ) {
        self.endpoints
            .entry(url.to_string())
            .or_default()
            .extend(parameters);
    }

    pub(crate) fn record_visited(&mut self, url: Url) {
        self.visited.insert(url.to_string());
    }

    pub(crate) fn record_form(&mut self, form: DiscoveryForm) {
        self.forms.insert(form);
    }
}

/// Deterministic read snapshot used by later discovery phases.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DiscoverySnapshot {
    endpoints: BTreeMap<String, BTreeSet<String>>,
    visited: BTreeSet<String>,
    forms: BTreeSet<DiscoveryForm>,
}

impl DiscoverySnapshot {
    pub(crate) const fn endpoints(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.endpoints
    }

    pub(crate) const fn visited(&self) -> &BTreeSet<String> {
        &self.visited
    }

    pub(crate) const fn forms(&self) -> &BTreeSet<DiscoveryForm> {
        &self.forms
    }

    pub(crate) fn merge_endpoint(
        &mut self,
        url: Url,
        parameters: impl IntoIterator<Item = String>,
    ) {
        if self.endpoints.len() >= MAX_DISCOVERY_ENDPOINTS
            && !self.endpoints.contains_key(url.as_str())
        {
            return;
        }
        if url.as_str().len() > MAX_DISCOVERY_URL_BYTES {
            return;
        }
        let total_before = self.endpoints.values().map(BTreeSet::len).sum::<usize>();
        let entry = self.endpoints.entry(url.to_string()).or_default();
        let global_room = MAX_DISCOVERY_TOTAL_PARAMETERS.saturating_sub(total_before);
        let endpoint_room = MAX_DISCOVERY_PARAMETERS_PER_ENDPOINT.saturating_sub(entry.len());
        let mut merged = parameters.into_iter().collect::<BTreeSet<_>>();
        merged.extend(url.query_pairs().filter_map(|(name, _)| {
            (!name.is_empty() && name.len() <= MAX_DISCOVERY_NAME_BYTES).then(|| name.into_owned())
        }));
        for name in merged
            .into_iter()
            .filter(|name| !name.is_empty() && name.len() <= MAX_DISCOVERY_NAME_BYTES)
            .take(global_room.min(endpoint_room))
        {
            entry.insert(name);
        }
    }

    pub(crate) fn merge_visited(&mut self, url: Url) {
        if url.as_str().len() <= MAX_DISCOVERY_URL_BYTES
            && (self.visited.len() < MAX_DISCOVERY_ENDPOINTS || self.visited.contains(url.as_str()))
        {
            self.visited.insert(url.to_string());
        }
    }
}

#[derive(Debug, Default)]
struct DiscoveryState {
    snapshot: DiscoverySnapshot,
    started: Option<Instant>,
}

#[derive(Debug, Default)]
struct VerificationState {
    started: Option<Instant>,
}

/// Bounded response exposed to discovery semantics, not raw reqwest state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundedHttpResponse {
    request_url: Url,
    final_url: Url,
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    body_truncated: bool,
}

impl BoundedHttpResponse {
    pub(crate) const fn request_url(&self) -> &Url {
        &self.request_url
    }

    pub(crate) const fn final_url(&self) -> &Url {
        &self.final_url
    }

    pub(crate) const fn status(&self) -> u16 {
        self.status
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub(crate) fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    pub(crate) fn location(&self) -> Option<&str> {
        self.header("location")
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) const fn body_truncated(&self) -> bool {
        self.body_truncated
    }
}

#[derive(Clone)]
pub(crate) struct LegacyDiscoveryAuthority {
    limits: DiscoveryLimits,
    authorized_origin: url::Origin,
    broker: Option<HttpRequestBroker>,
    cancellation: tokio_util::sync::CancellationToken,
    state: Arc<Mutex<DiscoveryState>>,
}

/// Shared active-transport authority for corrected or quarantined legacy
/// verification phases. It owns no claim state and cannot confirm findings.
#[derive(Clone)]
pub(crate) struct LegacyVerificationAuthority {
    limits: VerificationLimits,
    authorized_origin: url::Origin,
    broker: Option<HttpRequestBroker>,
    #[cfg(test)]
    accounting: RequestAccountingBroker,
    cancellation: tokio_util::sync::CancellationToken,
    state: Arc<Mutex<VerificationState>>,
}

impl LegacyVerificationAuthority {
    pub(crate) fn new(
        target: &Url,
        limits: VerificationLimits,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Self {
        let active_limit = u16::try_from(limits.max_requests).unwrap_or(u16::MAX);
        let budget = RuntimeBudget::default()
            .with_max_total_requests(limits.max_requests)
            .with_max_active_verifications(active_limit)
            .with_max_wall_time(limits.max_wall_time)
            .with_max_response_bytes(limits.max_cumulative_body_bytes)
            .with_max_request_body_bytes(0);
        let accounting = RequestAccountingBroker::new(budget);
        let policy = HttpEvidencePolicy::new(
            [target.clone()],
            limits.request_timeout,
            limits.max_response_body_bytes,
        );
        let broker = policy
            .and_then(|policy| HttpRequestBroker::new_metered(policy, accounting.clone()))
            .ok();
        Self {
            limits,
            authorized_origin: target.origin(),
            broker,
            #[cfg(test)]
            accounting,
            cancellation,
            state: Arc::new(Mutex::new(VerificationState::default())),
        }
    }

    pub(crate) const fn limits(&self) -> VerificationLimits {
        self.limits
    }

    pub(crate) async fn request(
        &self,
        action_id: &str,
        method: HttpProbeMethod,
        url: Url,
    ) -> Result<BoundedHttpResponse, ScannerError> {
        if self.cancellation.is_cancelled() {
            return Err(ScannerError::Cancelled);
        }
        let request_url = canonicalize_exact_origin(&url, &self.authorized_origin)?;
        let remaining = self.remaining_wall_time(action_id)?;
        let broker = self.broker.as_ref().ok_or(ScannerError::InvalidTarget)?;
        let probe =
            HttpProbe::new(request_url.clone(), method).map_err(|_| ScannerError::InvalidTarget)?;
        let collect = broker.collect_for_runtime(
            action_id,
            DecisionExecutionStage::Active,
            None,
            DecisionExecutionLimits::new().with_max_response_body_bytes(
                u64::try_from(self.limits.max_response_body_bytes).unwrap_or(u64::MAX),
            ),
            &probe,
        );
        let collected = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => return Err(ScannerError::Cancelled),
            result = tokio::time::timeout(remaining, collect) => match result {
                Ok(result) => result,
                Err(_) => return Err(self.wall_limit(action_id, self.verification_elapsed())),
            },
        }
        .map_err(map_broker_error)?;

        bounded_response(request_url, collected)
    }

    pub(crate) fn ensure_commit_allowed(&self, action_id: &str) -> Result<(), ScannerError> {
        if self.cancellation.is_cancelled() {
            return Err(ScannerError::Cancelled);
        }
        self.remaining_wall_time(action_id).map(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn accounting_snapshot(&self) -> crate::runtime_budget::RequestAccountingSnapshot {
        self.accounting.snapshot()
    }

    fn wall_limit(&self, action_id: &str, elapsed: Duration) -> ScannerError {
        ScannerError::BudgetExceeded(RuntimeLimitExceeded::new(
            RuntimeBudgetDimension::WallTime,
            u64::try_from(self.limits.max_wall_time.as_millis()).unwrap_or(u64::MAX),
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            Some(action_id.to_owned()),
        ))
    }

    fn remaining_wall_time(&self, action_id: &str) -> Result<Duration, ScannerError> {
        let elapsed = {
            let mut state = self.lock_state();
            state.started.get_or_insert_with(Instant::now).elapsed()
        };
        if elapsed >= self.limits.max_wall_time {
            return Err(self.wall_limit(action_id, elapsed));
        }
        Ok(self.limits.max_wall_time.saturating_sub(elapsed))
    }

    fn verification_elapsed(&self) -> Duration {
        self.lock_state()
            .started
            .map_or(Duration::ZERO, |started| started.elapsed())
    }

    fn lock_state(&self) -> MutexGuard<'_, VerificationState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl LegacyDiscoveryAuthority {
    pub(crate) fn new(
        target: &Url,
        limits: DiscoveryLimits,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Self {
        let budget = RuntimeBudget::default()
            .with_max_total_requests(limits.max_requests)
            .with_max_wall_time(limits.max_wall_time)
            .with_max_response_bytes(limits.max_cumulative_body_bytes)
            .with_max_request_body_bytes(0);
        let accounting = RequestAccountingBroker::new(budget);
        let policy = HttpEvidencePolicy::new(
            [target.clone()],
            limits.request_timeout,
            limits.max_response_body_bytes,
        );
        let broker = policy
            .and_then(|policy| HttpRequestBroker::new_metered(policy, accounting.clone()))
            .ok();
        let authority = Self {
            limits,
            authorized_origin: target.origin(),
            broker,
            cancellation,
            state: Arc::new(Mutex::new(DiscoveryState::default())),
        };
        let mut root = DiscoveryDelta::new();
        root.record_endpoint(
            target.clone(),
            target
                .query_pairs()
                .filter_map(|(name, _)| {
                    (!name.is_empty() && name.len() <= MAX_DISCOVERY_NAME_BYTES)
                        .then(|| name.into_owned())
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .take(MAX_DISCOVERY_PARAMETERS_PER_ENDPOINT),
        );
        let _ = authority.commit_initial(root);
        authority
    }

    pub(crate) const fn limits(&self) -> DiscoveryLimits {
        self.limits
    }

    pub(crate) fn canonicalize(&self, url: &Url) -> Result<Url, ScannerError> {
        canonicalize_exact_origin(url, &self.authorized_origin)
    }

    pub(crate) async fn request(
        &self,
        action_id: &str,
        method: HttpProbeMethod,
        url: Url,
    ) -> Result<BoundedHttpResponse, ScannerError> {
        if self.cancellation.is_cancelled() {
            return Err(ScannerError::Cancelled);
        }
        let request_url = self.canonicalize(&url)?;
        let remaining = self.remaining_wall_time(action_id)?;
        let broker = self.broker.as_ref().ok_or(ScannerError::InvalidTarget)?;
        let probe =
            HttpProbe::new(request_url.clone(), method).map_err(|_| ScannerError::InvalidTarget)?;
        let collect = broker.collect_for_runtime(
            action_id,
            DecisionExecutionStage::Passive,
            None,
            DecisionExecutionLimits::new().with_max_response_body_bytes(
                u64::try_from(self.limits.max_response_body_bytes).unwrap_or(u64::MAX),
            ),
            &probe,
        );
        let collected = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => return Err(ScannerError::Cancelled),
            result = tokio::time::timeout(remaining, collect) => match result {
                Ok(result) => result,
                Err(_) => return Err(self.wall_limit(action_id, self.discovery_elapsed())),
            },
        }
        .map_err(map_broker_error)?;

        bounded_response(request_url, collected)
    }

    pub(crate) fn snapshot(&self) -> DiscoverySnapshot {
        self.lock_state().snapshot.clone()
    }

    pub(crate) fn commit(
        &self,
        action_id: &str,
        delta: DiscoveryDelta,
    ) -> Result<DiscoverySnapshot, ScannerError> {
        self.commit_inner(Some(action_id), delta)
    }

    fn commit_initial(&self, delta: DiscoveryDelta) -> Result<DiscoverySnapshot, ScannerError> {
        self.commit_inner(None, delta)
    }

    fn commit_inner(
        &self,
        action_id: Option<&str>,
        delta: DiscoveryDelta,
    ) -> Result<DiscoverySnapshot, ScannerError> {
        let mut state = self.lock_state();
        let mut candidate = state.snapshot.clone();
        for (raw_url, parameters) in delta.endpoints {
            let url = self.canonicalize(&Url::parse(&raw_url)?)?;
            let mut parameters = parameters;
            if parameters.len() > MAX_DISCOVERY_PARAMETERS_PER_ENDPOINT
                || parameters
                    .iter()
                    .any(|name| name.is_empty() || name.len() > MAX_DISCOVERY_NAME_BYTES)
            {
                return Err(ScannerError::DiscoveryStateLimitExceeded);
            }
            // URL-derived names are observations from the endpoint itself, not
            // an unbounded caller batch. Retain their canonical lexical prefix
            // within the per-endpoint ceiling so even a query-heavy root is
            // still registered rather than disappearing on initialization.
            for name in url
                .query_pairs()
                .filter_map(|(name, _)| {
                    (!name.is_empty() && name.len() <= MAX_DISCOVERY_NAME_BYTES)
                        .then(|| name.into_owned())
                })
                .collect::<BTreeSet<_>>()
            {
                if parameters.len() >= MAX_DISCOVERY_PARAMETERS_PER_ENDPOINT {
                    break;
                }
                parameters.insert(name);
            }
            candidate
                .endpoints
                .entry(url.to_string())
                .or_default()
                .extend(parameters);
        }
        for raw_url in delta.visited {
            let url = self.canonicalize(&Url::parse(&raw_url)?)?;
            candidate.visited.insert(url.to_string());
        }
        for mut form in delta.forms {
            form.action = self.canonicalize(&form.action)?;
            candidate.forms.insert(form);
        }
        if candidate.endpoints.len() > MAX_DISCOVERY_ENDPOINTS
            || candidate.visited.len() > MAX_DISCOVERY_ENDPOINTS
            || candidate.forms.len() > MAX_DISCOVERY_FORMS
            || candidate
                .endpoints
                .values()
                .any(|parameters| parameters.len() > MAX_DISCOVERY_PARAMETERS_PER_ENDPOINT)
            || candidate
                .endpoints
                .values()
                .map(BTreeSet::len)
                .sum::<usize>()
                > MAX_DISCOVERY_TOTAL_PARAMETERS
            || candidate
                .forms
                .iter()
                .map(|form| form.controls.len())
                .sum::<usize>()
                > MAX_DISCOVERY_TOTAL_FORM_CONTROLS
        {
            return Err(ScannerError::DiscoveryStateLimitExceeded);
        }
        if let (Some(action_id), Some(started)) = (action_id, state.started) {
            let elapsed = started.elapsed();
            if elapsed >= self.limits.max_wall_time {
                return Err(self.wall_limit(action_id, elapsed));
            }
        }
        if action_id.is_some() && self.cancellation.is_cancelled() {
            return Err(ScannerError::Cancelled);
        }
        state.snapshot = candidate.clone();
        Ok(candidate)
    }

    fn wall_limit(&self, action_id: &str, elapsed: Duration) -> ScannerError {
        ScannerError::BudgetExceeded(RuntimeLimitExceeded::new(
            RuntimeBudgetDimension::WallTime,
            u64::try_from(self.limits.max_wall_time.as_millis()).unwrap_or(u64::MAX),
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            Some(action_id.to_owned()),
        ))
    }

    fn remaining_wall_time(&self, action_id: &str) -> Result<Duration, ScannerError> {
        let elapsed = {
            let mut state = self.lock_state();
            state.started.get_or_insert_with(Instant::now).elapsed()
        };
        if elapsed >= self.limits.max_wall_time {
            return Err(self.wall_limit(action_id, elapsed));
        }
        Ok(self.limits.max_wall_time.saturating_sub(elapsed))
    }

    fn discovery_elapsed(&self) -> Duration {
        self.lock_state()
            .started
            .map_or(Duration::ZERO, |started| started.elapsed())
    }

    fn lock_state(&self) -> MutexGuard<'_, DiscoveryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn canonicalize_exact_origin(
    url: &Url,
    authorized_origin: &url::Origin,
) -> Result<Url, ScannerError> {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || &url.origin() != authorized_origin
    {
        return Err(ScannerError::InvalidTarget);
    }
    let mut canonical = url.clone();
    canonical.set_fragment(None);
    if canonical.path().is_empty() {
        canonical.set_path("/");
    }
    let pairs = canonical
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        canonical.set_query(None);
    } else {
        let mut names = HashSet::with_capacity(pairs.len());
        if pairs.iter().all(|(name, _)| names.insert(name.clone())) {
            let mut sorted = pairs;
            sorted.sort();
            canonical.query_pairs_mut().clear().extend_pairs(sorted);
        }
    }
    if canonical.as_str().len() > MAX_DISCOVERY_URL_BYTES {
        return Err(ScannerError::DiscoveryStateLimitExceeded);
    }
    Ok(canonical)
}

fn bounded_response(
    request_url: Url,
    collected: crate::http_evidence::CollectedHttpResponse,
) -> Result<BoundedHttpResponse, ScannerError> {
    let mut headers = BTreeMap::new();
    for name in [
        "content-type",
        "location",
        "cache-control",
        "www-authenticate",
    ] {
        if let Some(value) = collected.header(name) {
            headers.insert(name.to_owned(), value.to_owned());
        }
    }
    Ok(BoundedHttpResponse {
        request_url,
        final_url: collected.final_url().clone(),
        status: collected.status(),
        headers,
        body: collected.body().to_vec(),
        body_truncated: collected.body_truncated(),
    })
}

fn map_broker_error(error: HttpRequestBrokerError) -> ScannerError {
    match error {
        HttpRequestBrokerError::RuntimeLimit(limit) => ScannerError::BudgetExceeded(limit),
        HttpRequestBrokerError::Http(_) => ScannerError::NetworkError(
            "bounded legacy transport failed without accepting a result".to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    #[test]
    fn defaults_are_finite_and_coherent() {
        let limits = DiscoveryLimits::default();
        assert_eq!(limits.max_depth(), 4);
        assert_eq!(limits.max_pages(), 64);
        assert_eq!(limits.max_requests(), 64);
        assert!(limits.max_response_body_bytes() as u64 <= limits.max_cumulative_body_bytes());
        assert!(limits.request_timeout() <= limits.max_wall_time());
    }

    #[test]
    fn invalid_limits_fail_closed() {
        assert!(DiscoveryLimits::new()
            .with_request_timeout(Duration::ZERO)
            .is_err());
        assert!(DiscoveryLimits::new()
            .with_request_timeout(Duration::from_micros(999))
            .is_err());
        assert!(DiscoveryLimits::new()
            .with_max_wall_time(Duration::from_micros(999))
            .is_err());
        assert!(DiscoveryLimits::new().with_body_limits(1, 2).is_err());
    }

    #[test]
    fn verification_defaults_are_finite_and_coherent() {
        let limits = VerificationLimits::default();
        assert_eq!(limits.max_requests(), 96);
        assert!(limits.max_response_body_bytes() as u64 <= limits.max_cumulative_body_bytes());
        assert!(limits.request_timeout() <= limits.max_wall_time());
        assert!(limits.max_requests() <= MAX_VERIFICATION_REQUESTS);
    }

    #[test]
    fn invalid_verification_limits_fail_closed() {
        assert!(VerificationLimits::new()
            .with_max_requests(MAX_VERIFICATION_REQUESTS + 1)
            .is_err());
        assert!(VerificationLimits::new()
            .with_request_timeout(Duration::ZERO)
            .is_err());
        assert!(VerificationLimits::new()
            .with_request_timeout(Duration::from_micros(999))
            .is_err());
        assert!(VerificationLimits::new()
            .with_max_wall_time(Duration::from_micros(999))
            .is_err());
        assert!(VerificationLimits::new().with_body_limits(1, 2).is_err());
    }

    #[test]
    fn verification_wall_clock_starts_on_first_request_preflight() {
        let target = Url::parse("https://example.test/").unwrap();
        let limits = VerificationLimits::new()
            .with_max_wall_time(Duration::from_secs(1))
            .unwrap();
        let authority = LegacyVerificationAuthority::new(
            &target,
            limits,
            tokio_util::sync::CancellationToken::new(),
        );

        std::thread::sleep(Duration::from_millis(10));

        let remaining = authority
            .remaining_wall_time("legacy.verification.test")
            .unwrap();
        assert!(remaining > Duration::from_millis(900));
    }

    #[test]
    fn verification_commit_guard_rechecks_cancellation() {
        let target = Url::parse("https://example.test/").unwrap();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let authority = LegacyVerificationAuthority::new(
            &target,
            VerificationLimits::default(),
            cancellation.clone(),
        );
        authority
            .remaining_wall_time("legacy.verification.test")
            .unwrap();
        cancellation.cancel();

        assert!(matches!(
            authority.ensure_commit_allowed("legacy.verification.test"),
            Err(ScannerError::Cancelled)
        ));
    }

    #[test]
    fn verification_commit_guard_rechecks_wall_deadline() {
        let target = Url::parse("https://example.test/").unwrap();
        let authority = LegacyVerificationAuthority::new(
            &target,
            VerificationLimits::new()
                .with_max_wall_time(Duration::from_millis(1))
                .unwrap(),
            tokio_util::sync::CancellationToken::new(),
        );
        authority
            .remaining_wall_time("legacy.verification.test")
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));

        assert!(matches!(
            authority.ensure_commit_allowed("legacy.verification.test"),
            Err(ScannerError::BudgetExceeded(limit))
                if limit.dimension() == RuntimeBudgetDimension::WallTime
        ));
    }

    #[tokio::test]
    async fn verification_scope_rejection_precedes_transport() {
        let target = Url::parse("https://example.test/").unwrap();
        let authority = LegacyVerificationAuthority::new(
            &target,
            VerificationLimits::default(),
            tokio_util::sync::CancellationToken::new(),
        );

        for rejected in [
            Url::parse("https://other.test/").unwrap(),
            Url::parse("https://user:secret@example.test/").unwrap(),
            Url::parse("file:///tmp/not-http").unwrap(),
        ] {
            let error = authority
                .request("legacy.verification.test", HttpProbeMethod::Get, rejected)
                .await
                .unwrap_err();
            assert!(matches!(error, ScannerError::InvalidTarget));
        }
    }

    #[tokio::test]
    async fn zero_verification_request_budget_denies_before_transport() {
        let target = Url::parse("http://127.0.0.1:9/").unwrap();
        let authority = LegacyVerificationAuthority::new(
            &target,
            VerificationLimits::new().with_max_requests(0).unwrap(),
            tokio_util::sync::CancellationToken::new(),
        );

        let error = authority
            .request("legacy.verification.test", HttpProbeMethod::Get, target)
            .await
            .unwrap_err();

        assert!(matches!(error, ScannerError::BudgetExceeded(_)));
    }

    #[tokio::test]
    async fn verification_dispatch_is_accounted_as_active_not_passive() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let authority = LegacyVerificationAuthority::new(
            &target,
            VerificationLimits::default(),
            tokio_util::sync::CancellationToken::new(),
        );

        authority
            .request("legacy.verification.test", HttpProbeMethod::Get, target)
            .await
            .unwrap();
        server.await.unwrap();

        let accounting = authority.accounting_snapshot();
        assert_eq!(accounting.total_requests(), 1);
        assert_eq!(accounting.active_verifications(), 1);
        assert_eq!(accounting.passive_requests(), 0);
    }

    #[test]
    fn discovery_wall_clock_starts_on_first_discovery_request_preflight() {
        let target = Url::parse("https://example.test/").unwrap();
        let limits = DiscoveryLimits::new()
            .with_max_wall_time(Duration::from_secs(1))
            .unwrap();
        let authority = LegacyDiscoveryAuthority::new(
            &target,
            limits,
            tokio_util::sync::CancellationToken::new(),
        );

        std::thread::sleep(Duration::from_millis(10));

        let remaining = authority
            .remaining_wall_time("legacy.discovery.test")
            .unwrap();
        assert!(remaining > Duration::from_millis(900));
    }

    #[test]
    fn discovery_wall_deadline_is_rechecked_before_state_commit() {
        let target = Url::parse("https://example.test/").unwrap();
        let limits = DiscoveryLimits::new()
            .with_max_wall_time(Duration::from_millis(1))
            .unwrap();
        let authority = LegacyDiscoveryAuthority::new(
            &target,
            limits,
            tokio_util::sync::CancellationToken::new(),
        );
        let before = authority.snapshot();
        let _ = authority
            .remaining_wall_time("legacy.discovery.test")
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let mut delta = DiscoveryDelta::new();
        delta.record_endpoint(
            Url::parse("https://example.test/after-deadline").unwrap(),
            std::iter::empty(),
        );

        let error = authority
            .commit("legacy.discovery.test", delta)
            .unwrap_err();

        assert!(matches!(error, ScannerError::BudgetExceeded(_)));
        assert_eq!(authority.snapshot(), before);
    }

    #[test]
    fn oversized_parameter_batch_fails_atomically() {
        let target = Url::parse("https://example.test/").unwrap();
        let authority = LegacyDiscoveryAuthority::new(
            &target,
            DiscoveryLimits::default(),
            tokio_util::sync::CancellationToken::new(),
        );
        let before = authority.snapshot();
        let mut delta = DiscoveryDelta::new();
        delta.record_endpoint(
            Url::parse("https://example.test/bounded").unwrap(),
            (0..=MAX_DISCOVERY_PARAMETERS_PER_ENDPOINT).map(|index| format!("p{index}")),
        );

        let error = authority
            .commit("legacy.discovery.test", delta)
            .unwrap_err();

        assert!(matches!(error, ScannerError::DiscoveryStateLimitExceeded));
        assert_eq!(authority.snapshot(), before);
    }

    #[test]
    fn root_query_names_are_registered_with_the_authority() {
        let target = Url::parse("https://example.test/?known=1&mode=safe").unwrap();
        let authority = LegacyDiscoveryAuthority::new(
            &target,
            DiscoveryLimits::default(),
            tokio_util::sync::CancellationToken::new(),
        );

        assert_eq!(
            authority.snapshot().endpoints()[target.as_str()],
            BTreeSet::from(["known".to_owned(), "mode".to_owned()])
        );
    }

    #[test]
    fn query_heavy_root_is_registered_with_a_deterministic_bounded_name_sample() {
        let mut target = Url::parse("https://example.test/").unwrap();
        {
            let mut query = target.query_pairs_mut();
            for index in 0..=MAX_DISCOVERY_PARAMETERS_PER_ENDPOINT {
                query.append_pair(&format!("p{index:03}"), "value");
            }
        }
        let authority = LegacyDiscoveryAuthority::new(
            &target,
            DiscoveryLimits::default(),
            tokio_util::sync::CancellationToken::new(),
        );

        let snapshot = authority.snapshot();
        let parameters = snapshot
            .endpoints()
            .get(target.as_str())
            .expect("the root endpoint remains registered");
        assert_eq!(parameters.len(), MAX_DISCOVERY_PARAMETERS_PER_ENDPOINT);
        assert!(parameters.contains("p000"));
        assert!(parameters.contains("p255"));
        assert!(!parameters.contains("p256"));
    }

    #[test]
    fn cancellation_before_commit_is_atomic() {
        let target = Url::parse("https://example.test/").unwrap();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let authority = LegacyDiscoveryAuthority::new(
            &target,
            DiscoveryLimits::default(),
            cancellation.clone(),
        );
        let before = authority.snapshot();
        let mut delta = DiscoveryDelta::new();
        delta.record_endpoint(
            Url::parse("https://example.test/not-committed").unwrap(),
            std::iter::empty(),
        );
        cancellation.cancel();

        let error = authority
            .commit("legacy.discovery.test", delta)
            .unwrap_err();

        assert!(matches!(error, ScannerError::Cancelled));
        assert_eq!(authority.snapshot(), before);
    }

    #[test]
    fn endpoint_query_names_are_derived_at_the_commit_boundary() {
        let target = Url::parse("https://example.test/").unwrap();
        let authority = LegacyDiscoveryAuthority::new(
            &target,
            DiscoveryLimits::default(),
            tokio_util::sync::CancellationToken::new(),
        );
        let endpoint = Url::parse("https://example.test/search?known=1").unwrap();
        let mut delta = DiscoveryDelta::new();
        delta.record_endpoint(endpoint.clone(), std::iter::empty());

        let snapshot = authority.commit("legacy.discovery.test", delta).unwrap();

        assert_eq!(
            snapshot.endpoints()[endpoint.as_str()],
            BTreeSet::from(["known".to_owned()])
        );
    }
}
