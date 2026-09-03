use serde::Serialize;
use std::{
    fmt,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use termivar_core::{ConfidenceScore, EntityId, Evidence, EvidenceSource};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{
    limits::{
        ensure_input_budget, invalid_config, validate_identifier, PluginBudget,
        MAX_PLUGIN_CASE_ID_BYTES, MAX_PLUGIN_URL_BYTES,
    },
    recorder::{
        evidence_value_bytes, redact_value, sanitize_error_safely, PluginObservation,
        PluginRedactionPolicy, SecretRedactionPolicy,
    },
    transport::{
        origin_string, validate_authorized_origin, validate_scoped_url, PluginHttpMethod,
        PluginHttpRequest, PluginHttpResponse, PluginRequestBroker,
    },
    PluginError,
};

pub struct PluginExecutionRequest {
    subject: EntityId,
    authorized_origin: Url,
    case_id: String,
    input: Vec<u8>,
    budget: PluginBudget,
    cancellation: CancellationToken,
    broker: Arc<dyn PluginRequestBroker>,
    redaction: Arc<dyn PluginRedactionPolicy>,
    reliability: ConfidenceScore,
}

impl PluginExecutionRequest {
    /// Creates a request with finite defaults, empty input, no confidence, and
    /// the default secret redaction policy.
    pub fn new(
        subject: EntityId,
        authorized_origin: Url,
        case_id: impl Into<String>,
        broker: Arc<dyn PluginRequestBroker>,
    ) -> Result<Self, PluginError> {
        validate_authorized_origin(&authorized_origin)?;
        let case_id = case_id.into();
        validate_identifier(&case_id, "plugin case id", MAX_PLUGIN_CASE_ID_BYTES)?;
        Ok(Self {
            subject,
            authorized_origin,
            case_id,
            input: Vec::new(),
            budget: PluginBudget::default(),
            cancellation: CancellationToken::new(),
            broker,
            redaction: Arc::new(SecretRedactionPolicy::default()),
            reliability: ConfidenceScore::NONE,
        })
    }

    /// Sets opaque bounded invocation input.
    pub fn with_input(mut self, input: Vec<u8>) -> Result<Self, PluginError> {
        ensure_input_budget(&input, &self.budget)?;
        self.input = input;
        Ok(self)
    }

    /// Replaces the immutable budget snapshot.
    pub fn with_budget(mut self, budget: PluginBudget) -> Result<Self, PluginError> {
        ensure_input_budget(&self.input, &budget)?;
        self.budget = budget;
        Ok(self)
    }

    /// Narrows response capture to a host execution allowance.
    ///
    /// This operation can only reduce both the per-response and cumulative
    /// ceilings already selected by the request provider.
    pub fn restrict_response_body_bytes(mut self, maximum: u64) -> Self {
        self.budget.max_response_body_bytes = self.budget.max_response_body_bytes.min(maximum);
        self.budget.max_cumulative_body_bytes = self.budget.max_cumulative_body_bytes.min(maximum);
        self
    }

    /// Uses a host-owned cancellation token; the invocation receives a child.
    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Replaces the host redaction policy.
    pub fn with_redaction(mut self, redaction: Arc<dyn PluginRedactionPolicy>) -> Self {
        self.redaction = redaction;
        self
    }

    /// Sets host-assessed source reliability without granting claim authority.
    pub fn with_reliability(mut self, reliability: ConfidenceScore) -> Self {
        self.reliability = reliability;
        self
    }

    /// Authorized evidence subject selected by the host.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Exact authorized HTTP(S) origin selected by the host.
    pub fn authorized_origin(&self) -> &Url {
        &self.authorized_origin
    }

    /// Host verification/correlation identity.
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Opaque bounded input bytes.
    pub fn input(&self) -> &[u8] {
        &self.input
    }
}

impl fmt::Debug for PluginExecutionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginExecutionRequest")
            .field("subject", &"[redacted]")
            .field("authorized_origin", &origin_string(&self.authorized_origin))
            .field("case_id", &"[redacted]")
            .field("input_bytes", &self.input.len())
            .field("budget", &self.budget)
            .field("reliability", &self.reliability)
            .finish_non_exhaustive()
    }
}

/// Usage receipt for one completed plugin invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PluginUsage {
    requests: u64,
    response_body_bytes: u64,
    observations: u64,
    observation_bytes: u64,
}

impl PluginUsage {
    /// Broker dispatch attempts charged to the invocation.
    pub const fn requests(self) -> u64 {
        self.requests
    }

    /// Delivered response bytes charged to the invocation.
    pub const fn response_body_bytes(self) -> u64 {
        self.response_body_bytes
    }

    /// Evidence observations retained at successful completion.
    pub const fn observations(self) -> u64 {
        self.observations
    }

    /// Bounded observation-value representation bytes charged by the host.
    pub const fn observation_bytes(self) -> u64 {
        self.observation_bytes
    }
}

/// Successful execution receipt. Failures are returned as [`PluginError`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginExecutionResult {
    pub(super) plugin_id: String,
    pub(super) observations: Vec<Evidence>,
    pub(super) usage: PluginUsage,
    pub(super) elapsed_ms: u64,
}

impl PluginExecutionResult {
    /// Registered plugin identity.
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Host-normalized evidence observations.
    pub fn observations(&self) -> &[Evidence] {
        &self.observations
    }

    /// Consumes the receipt and returns normalized observations.
    pub fn into_observations(self) -> Vec<Evidence> {
        self.observations
    }

    /// Bounded usage receipt.
    pub const fn usage(&self) -> PluginUsage {
        self.usage
    }

    /// Host-observed elapsed milliseconds.
    pub const fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }
}

struct PluginContextState {
    sealed: bool,
    failure: Option<PluginError>,
    requests: u64,
    response_body_bytes: u64,
    reserved_response_body_bytes: u64,
    observation_bytes: u64,
    observations: Vec<Evidence>,
}

/// Borrowed capability boundary for one plugin invocation.
///
/// The type intentionally does not implement `Clone`: request and recorder
/// authority remain structurally tied to the invocation future.
pub struct PluginContext {
    plugin_id: String,
    subject: EntityId,
    authorized_origin: Url,
    case_id: String,
    input: Vec<u8>,
    budget: PluginBudget,
    pub(super) cancellation: CancellationToken,
    broker: Arc<dyn PluginRequestBroker>,
    pub(super) redaction: Arc<dyn PluginRedactionPolicy>,
    reliability: ConfidenceScore,
    pub(super) deadline: tokio::time::Instant,
    state: Mutex<PluginContextState>,
}

struct PluginRequestReservation<'a> {
    context: &'a PluginContext,
    capture_limit: u64,
    cancellation: CancellationToken,
    active: bool,
}

impl PluginRequestReservation<'_> {
    fn commit(mut self, delivered_body_bytes: u64) -> Result<(), PluginError> {
        {
            let mut state = self.context.lock_state()?;
            ensure_state_active(&state)?;
            let Some(reserved) = state
                .reserved_response_body_bytes
                .checked_sub(self.capture_limit)
            else {
                state.failure = Some(PluginError::HostStateUnavailable);
                return Err(PluginError::HostStateUnavailable);
            };
            if self.context.cancellation.is_cancelled() {
                return Err(PluginError::Cancelled);
            }
            if tokio::time::Instant::now() >= self.context.deadline {
                state.failure = Some(PluginError::WallTimeExceeded);
                return Err(PluginError::WallTimeExceeded);
            }
            let Some(cumulative) = state.response_body_bytes.checked_add(delivered_body_bytes)
            else {
                let error = PluginError::CumulativeBodyBudgetExceeded;
                state.failure = Some(error.clone());
                return Err(error);
            };
            if cumulative > self.context.budget.max_cumulative_body_bytes {
                let error = PluginError::CumulativeBodyBudgetExceeded;
                state.failure = Some(error.clone());
                return Err(error);
            }
            state.reserved_response_body_bytes = reserved;
            state.response_body_bytes = cumulative;
        }
        self.active = false;
        self.cancellation.cancel();
        Ok(())
    }
}

impl Drop for PluginRequestReservation<'_> {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if !self.active {
            return;
        }
        if let Ok(mut state) = self.context.state.lock() {
            match state
                .reserved_response_body_bytes
                .checked_sub(self.capture_limit)
            {
                Some(reserved) => state.reserved_response_body_bytes = reserved,
                None => state.failure = Some(PluginError::HostStateUnavailable),
            }
            if !state.sealed && state.failure.is_none() {
                state.failure = Some(PluginError::RequestAbandoned);
            }
        }
    }
}

impl PluginContext {
    pub(super) fn from_request(
        plugin_id: String,
        request: PluginExecutionRequest,
    ) -> Result<Self, PluginError> {
        ensure_input_budget(&request.input, &request.budget)?;
        let now = tokio::time::Instant::now();
        let deadline = now
            .checked_add(request.budget.max_wall_time())
            .ok_or_else(|| invalid_config("plugin wall budget exceeds runtime clock range"))?;
        Ok(Self {
            plugin_id,
            subject: request.subject,
            authorized_origin: request.authorized_origin,
            case_id: request.case_id,
            input: request.input,
            budget: request.budget,
            cancellation: request.cancellation.child_token(),
            broker: request.broker,
            redaction: request.redaction,
            reliability: request.reliability,
            deadline,
            state: Mutex::new(PluginContextState {
                sealed: false,
                failure: None,
                requests: 0,
                response_body_bytes: 0,
                reserved_response_body_bytes: 0,
                observation_bytes: 0,
                observations: Vec::new(),
            }),
        })
    }

    /// Authorized evidence subject.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Exact authorized HTTP(S) origin.
    pub fn authorized_origin(&self) -> &Url {
        &self.authorized_origin
    }

    /// Host verification/correlation identity.
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Opaque host input bounded before plugin code is polled.
    pub fn input(&self) -> &[u8] {
        &self.input
    }

    /// Immutable resource budget.
    pub const fn budget(&self) -> &PluginBudget {
        &self.budget
    }

    /// Returns whether the host has cancelled this invocation.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Waits until the host cancels this invocation.
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    /// Records one observation; host provenance and redaction are mandatory.
    pub fn record(&self, observation: PluginObservation) -> Result<(), PluginError> {
        self.ensure_active()?;
        let raw_bytes = evidence_value_bytes(&observation.value);
        let redacted_value = match std::panic::catch_unwind(AssertUnwindSafe(|| {
            redact_value(self.redaction.as_ref(), observation.value)
        })) {
            Ok(value) => value,
            Err(_) => return self.fail(PluginError::HostCallbackPanicked),
        };
        let redacted_bytes = evidence_value_bytes(&redacted_value);
        if raw_bytes > self.budget.max_observation_bytes
            || redacted_bytes > self.budget.max_observation_bytes
        {
            return self.fail(PluginError::ObservationBytesBudgetExceeded);
        }
        let charged_bytes = raw_bytes.max(redacted_bytes);

        let source = EvidenceSource::new(self.plugin_id.clone(), observation.method)
            .and_then(|source| source.with_correlation_id(self.case_id.clone()))
            .map_err(|_| invalid_config("plugin observation provenance is invalid"))?;
        let evidence = Evidence::new(
            self.subject.clone(),
            observation.kind,
            observation.predicate,
            redacted_value,
            source,
            self.reliability,
        );

        let mut state = self.lock_state()?;
        ensure_state_active(&state)?;
        if state.observations.len() as u64 >= self.budget.max_observations {
            let error = PluginError::ObservationBudgetExceeded;
            state.failure = Some(error.clone());
            return Err(error);
        }
        let Some(next_bytes) = state.observation_bytes.checked_add(charged_bytes) else {
            let error = PluginError::ObservationBytesBudgetExceeded;
            state.failure = Some(error.clone());
            return Err(error);
        };
        if next_bytes > self.budget.max_observation_bytes {
            let error = PluginError::ObservationBytesBudgetExceeded;
            state.failure = Some(error.clone());
            return Err(error);
        }
        state.observation_bytes = next_bytes;
        state.observations.push(evidence);
        Ok(())
    }

    /// Dispatches one bodyless request through the host-owned bounded broker.
    pub async fn request(
        &self,
        method: PluginHttpMethod,
        url: Url,
    ) -> Result<PluginHttpResponse, PluginError> {
        if validate_scoped_url(&self.authorized_origin, &url).is_err() {
            return self.fail(PluginError::ScopeViolation);
        }
        if url.as_str().len() > MAX_PLUGIN_URL_BYTES {
            return self.fail(PluginError::ScopeViolation);
        }

        let capture_limit = {
            let mut state = self.lock_state()?;
            ensure_state_active(&state)?;
            if self.cancellation.is_cancelled() {
                return Err(PluginError::Cancelled);
            }
            if tokio::time::Instant::now() >= self.deadline {
                state.failure = Some(PluginError::WallTimeExceeded);
                return Err(PluginError::WallTimeExceeded);
            }
            if state.requests >= self.budget.max_requests {
                state.failure = Some(PluginError::RequestBudgetExceeded);
                return Err(PluginError::RequestBudgetExceeded);
            }
            let Some(committed_and_reserved) = state
                .response_body_bytes
                .checked_add(state.reserved_response_body_bytes)
            else {
                state.failure = Some(PluginError::CumulativeBodyBudgetExceeded);
                return Err(PluginError::CumulativeBodyBudgetExceeded);
            };
            let Some(remaining_cumulative) = self
                .budget
                .max_cumulative_body_bytes
                .checked_sub(committed_and_reserved)
            else {
                state.failure = Some(PluginError::CumulativeBodyBudgetExceeded);
                return Err(PluginError::CumulativeBodyBudgetExceeded);
            };
            if remaining_cumulative == 0 {
                state.failure = Some(PluginError::CumulativeBodyBudgetExceeded);
                return Err(PluginError::CumulativeBodyBudgetExceeded);
            }
            if self.budget.max_response_body_bytes == 0 {
                let error = PluginError::ResponseBodyBudgetUnavailable;
                state.failure = Some(error.clone());
                return Err(error);
            }
            let capture_limit = self
                .budget
                .max_response_body_bytes
                .min(remaining_cumulative);
            state.requests += 1;
            let Some(reserved) = state
                .reserved_response_body_bytes
                .checked_add(capture_limit)
            else {
                state.failure = Some(PluginError::CumulativeBodyBudgetExceeded);
                return Err(PluginError::CumulativeBodyBudgetExceeded);
            };
            state.reserved_response_body_bytes = reserved;
            capture_limit
        };

        let request_cancellation = self.cancellation.child_token();
        let reservation = PluginRequestReservation {
            context: self,
            capture_limit,
            cancellation: request_cancellation.clone(),
            active: true,
        };
        let request_timeout = self.budget.request_timeout();
        if request_timeout.is_zero() {
            return self.fail(PluginError::RequestTimeout);
        }
        let remaining = self
            .deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return self.fail(PluginError::WallTimeExceeded);
        }
        let timeout = request_timeout.min(remaining);
        let broker_request = PluginHttpRequest {
            method,
            url,
            max_response_body_bytes: capture_limit,
            cancellation: request_cancellation.clone(),
        };
        let broker = self.broker.execute(broker_request);
        tokio::pin!(broker);
        let sleep = tokio::time::sleep(timeout);
        tokio::pin!(sleep);

        let response = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => {
                request_cancellation.cancel();
                return self.fail(PluginError::Cancelled);
            }
            () = &mut sleep => {
                request_cancellation.cancel();
                let error = if tokio::time::Instant::now() >= self.deadline {
                    PluginError::WallTimeExceeded
                } else {
                    PluginError::RequestTimeout
                };
                return self.fail(error);
            }
            result = &mut broker => match result {
                Ok(response) => response,
                Err(error) => {
                    let error = sanitize_error_safely(self.redaction.as_ref(), error)
                        .unwrap_or(PluginError::HostCallbackPanicked);
                    return self.fail(error);
                },
            },
        };

        if validate_scoped_url(&self.authorized_origin, response.final_url()).is_err()
            || response.final_url().as_str().len() > MAX_PLUGIN_URL_BYTES
        {
            return self.fail(PluginError::ScopeViolation);
        }
        if response.delivered_body_bytes > capture_limit {
            return self.fail(PluginError::ResponseBodyBudgetExceeded {
                actual: response.delivered_body_bytes,
                maximum: capture_limit,
            });
        }

        reservation.commit(response.delivered_body_bytes)?;
        Ok(response)
    }

    pub(super) fn ensure_active(&self) -> Result<(), PluginError> {
        if self.cancellation.is_cancelled() {
            return Err(PluginError::Cancelled);
        }
        if tokio::time::Instant::now() >= self.deadline {
            return self.fail(PluginError::WallTimeExceeded);
        }
        let state = self.lock_state()?;
        ensure_state_active(&state)
    }

    fn fail<T>(&self, error: PluginError) -> Result<T, PluginError> {
        if let Ok(mut state) = self.state.lock() {
            if state.failure.is_none() {
                state.failure = Some(error.clone());
            }
        }
        Err(error)
    }

    pub(super) fn discard(&self) {
        self.cancellation.cancel();
        if let Ok(mut state) = self.state.lock() {
            state.sealed = true;
            state.observations.clear();
        }
    }

    pub(super) fn finish(&self) -> Result<(Vec<Evidence>, PluginUsage), PluginError> {
        let mut state = self.lock_state()?;
        ensure_state_active(&state)?;
        if self.cancellation.is_cancelled() {
            return Err(PluginError::Cancelled);
        }
        if tokio::time::Instant::now() >= self.deadline {
            return Err(PluginError::WallTimeExceeded);
        }
        if state.reserved_response_body_bytes != 0 {
            return Err(PluginError::RequestAbandoned);
        }
        state.sealed = true;
        let observations = std::mem::take(&mut state.observations);
        let usage = PluginUsage {
            requests: state.requests,
            response_body_bytes: state.response_body_bytes,
            observations: observations.len() as u64,
            observation_bytes: state.observation_bytes,
        };
        Ok((observations, usage))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, PluginContextState>, PluginError> {
        self.state
            .lock()
            .map_err(|_| PluginError::HostStateUnavailable)
    }
}

impl fmt::Debug for PluginContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let usage = self.state.lock().ok().map(|state| PluginUsage {
            requests: state.requests,
            response_body_bytes: state.response_body_bytes,
            observations: state.observations.len() as u64,
            observation_bytes: state.observation_bytes,
        });
        formatter
            .debug_struct("PluginContext")
            .field("plugin_id", &self.plugin_id)
            .field("subject", &"[redacted]")
            .field("authorized_origin", &origin_string(&self.authorized_origin))
            .field("case_id", &"[redacted]")
            .field("input_bytes", &self.input.len())
            .field("budget", &self.budget)
            .field("usage", &usage)
            .finish_non_exhaustive()
    }
}

fn ensure_state_active(state: &PluginContextState) -> Result<(), PluginError> {
    if state.sealed {
        return Err(PluginError::ContextSealed);
    }
    if let Some(error) = &state.failure {
        return Err(error.clone());
    }
    Ok(())
}
