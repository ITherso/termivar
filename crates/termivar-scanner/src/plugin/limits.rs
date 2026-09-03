use serde::Serialize;
use std::time::Duration;

use super::PluginError;

pub(super) const MAX_PLUGIN_ID_BYTES: usize = 128;
pub(super) const MAX_PLUGIN_TEXT_BYTES: usize = 1024;
pub(super) const MAX_PLUGIN_CASE_ID_BYTES: usize = 256;
pub(super) const MAX_PLUGIN_REDACTION_LITERAL_COUNT: usize = 64;
pub(super) const MAX_PLUGIN_REDACTION_LITERAL_BYTES: usize = 4096;
pub(super) const MAX_PLUGIN_URL_BYTES: usize = 8192;
pub(super) const MAX_PLUGIN_HEADERS: usize = 64;
pub(super) const MAX_PLUGIN_HEADER_NAME_BYTES: usize = 128;
pub(super) const MAX_PLUGIN_HEADER_VALUE_BYTES: usize = 4096;
pub(super) const HARD_MAX_PLUGIN_INPUT_BYTES: usize = 1024 * 1024;
pub(super) const HARD_MAX_PLUGIN_REQUESTS: u64 = 64;
pub(super) const HARD_MAX_PLUGIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
pub(super) const HARD_MAX_PLUGIN_WALL_TIME: Duration = Duration::from_secs(300);
pub(super) const HARD_MAX_PLUGIN_RESPONSE_BODY_BYTES: u64 = 1024 * 1024;
pub(super) const HARD_MAX_PLUGIN_CUMULATIVE_BODY_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const HARD_MAX_PLUGIN_OBSERVATIONS: u64 = 256;
pub(super) const HARD_MAX_PLUGIN_OBSERVATION_BYTES: u64 = 1024 * 1024;
pub(super) const HARD_MAX_PLUGIN_TEXT_LIST_ITEMS: usize = 256;
/// Immutable invocation limits enforced by [`crate::PluginContext`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginBudget {
    pub(super) max_input_bytes: usize,
    pub(super) max_requests: u64,
    pub(super) request_timeout_ms: u64,
    pub(super) max_wall_time_ms: u64,
    pub(super) max_response_body_bytes: u64,
    pub(super) max_cumulative_body_bytes: u64,
    pub(super) max_observations: u64,
    pub(super) max_observation_bytes: u64,
}

impl Default for PluginBudget {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_requests: 16,
            request_timeout_ms: 5_000,
            max_wall_time_ms: 30_000,
            max_response_body_bytes: 64 * 1024,
            max_cumulative_body_bytes: 256 * 1024,
            max_observations: 64,
            max_observation_bytes: 64 * 1024,
        }
    }
}

impl PluginBudget {
    /// Sets the input-byte ceiling. Zero allows only empty input.
    pub fn with_max_input_bytes(mut self, value: usize) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_INPUT_BYTES {
            return Err(invalid_config(
                "plugin input budget exceeds the hard maximum",
            ));
        }
        self.max_input_bytes = value;
        Ok(self)
    }

    /// Sets the request ceiling. Zero grants no transport authority.
    pub fn with_max_requests(mut self, value: u64) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_REQUESTS {
            return Err(invalid_config(
                "plugin request budget exceeds the hard maximum",
            ));
        }
        self.max_requests = value;
        Ok(self)
    }

    /// Sets the per-request timeout. Zero denies request dispatch.
    pub fn with_request_timeout(mut self, value: Duration) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_REQUEST_TIMEOUT {
            return Err(invalid_config(
                "plugin request timeout exceeds the hard maximum",
            ));
        }
        self.request_timeout_ms = duration_ms(value)?;
        Ok(self)
    }

    /// Sets the invocation wall budget. Zero denies plugin execution.
    pub fn with_max_wall_time(mut self, value: Duration) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_WALL_TIME {
            return Err(invalid_config(
                "plugin wall budget exceeds the hard maximum",
            ));
        }
        self.max_wall_time_ms = duration_ms(value)?;
        Ok(self)
    }

    /// Sets the delivered-body ceiling for one response.
    pub fn with_max_response_body_bytes(mut self, value: u64) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_RESPONSE_BODY_BYTES {
            return Err(invalid_config(
                "plugin response body budget exceeds the hard maximum",
            ));
        }
        self.max_response_body_bytes = value;
        Ok(self)
    }

    /// Sets the invocation-wide delivered response body ceiling.
    pub fn with_max_cumulative_body_bytes(mut self, value: u64) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_CUMULATIVE_BODY_BYTES {
            return Err(invalid_config(
                "plugin cumulative body budget exceeds the hard maximum",
            ));
        }
        self.max_cumulative_body_bytes = value;
        Ok(self)
    }

    /// Sets the maximum number of recorded observations.
    pub fn with_max_observations(mut self, value: u64) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_OBSERVATIONS {
            return Err(invalid_config(
                "plugin observation count exceeds the hard maximum",
            ));
        }
        self.max_observations = value;
        Ok(self)
    }

    /// Sets the aggregate raw observation-value byte ceiling.
    pub fn with_max_observation_bytes(mut self, value: u64) -> Result<Self, PluginError> {
        if value > HARD_MAX_PLUGIN_OBSERVATION_BYTES {
            return Err(invalid_config(
                "plugin observation byte budget exceeds the hard maximum",
            ));
        }
        self.max_observation_bytes = value;
        Ok(self)
    }

    /// Maximum input bytes.
    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    /// Maximum broker dispatches.
    pub const fn max_requests(&self) -> u64 {
        self.max_requests
    }

    /// Per-request timeout.
    pub const fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    /// Invocation wall budget.
    pub const fn max_wall_time(&self) -> Duration {
        Duration::from_millis(self.max_wall_time_ms)
    }

    /// Maximum delivered bytes for one response.
    pub const fn max_response_body_bytes(&self) -> u64 {
        self.max_response_body_bytes
    }

    /// Maximum invocation-wide delivered response bytes.
    pub const fn max_cumulative_body_bytes(&self) -> u64 {
        self.max_cumulative_body_bytes
    }

    /// Maximum observation count.
    pub const fn max_observations(&self) -> u64 {
        self.max_observations
    }

    /// Maximum raw observation-value bytes.
    pub const fn max_observation_bytes(&self) -> u64 {
        self.max_observation_bytes
    }
}

/// Host-owned registration configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginConfig {
    pub(super) enabled: bool,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl PluginConfig {
    /// Creates host policy with the requested enable state.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Returns whether host policy enables the plugin.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

pub(super) fn validate_identifier(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), PluginError> {
    if value.is_empty()
        || value.len() > max
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
    {
        return Err(invalid_config(field));
    }
    Ok(())
}

pub(super) fn validate_text(value: &str, field: &'static str) -> Result<(), PluginError> {
    if value.trim().is_empty() || value.len() > MAX_PLUGIN_TEXT_BYTES {
        return Err(invalid_config(field));
    }
    Ok(())
}

pub(super) fn ensure_input_budget(input: &[u8], budget: &PluginBudget) -> Result<(), PluginError> {
    if input.len() > budget.max_input_bytes {
        return Err(PluginError::InputBudgetExceeded {
            actual: input.len(),
            maximum: budget.max_input_bytes,
        });
    }
    Ok(())
}

fn duration_ms(duration: Duration) -> Result<u64, PluginError> {
    let milliseconds = u64::try_from(duration.as_millis())
        .map_err(|_| invalid_config("plugin duration exceeds supported milliseconds"))?;
    if !duration.is_zero() && milliseconds == 0 {
        return Err(invalid_config(
            "sub-millisecond plugin durations are unsupported",
        ));
    }
    Ok(milliseconds)
}

pub(super) fn invalid_config(detail: &'static str) -> PluginError {
    PluginError::InvalidConfig(detail.to_owned())
}
