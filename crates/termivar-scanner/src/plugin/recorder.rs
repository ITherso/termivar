use regex::Regex;
use std::{fmt, panic::AssertUnwindSafe, sync::LazyLock};
use termivar_core::{EvidenceKind, EvidenceValue, KnowledgePredicate};

use super::{
    limits::{
        invalid_config, validate_identifier, HARD_MAX_PLUGIN_OBSERVATION_BYTES,
        HARD_MAX_PLUGIN_TEXT_LIST_ITEMS, MAX_PLUGIN_ID_BYTES, MAX_PLUGIN_REDACTION_LITERAL_BYTES,
        MAX_PLUGIN_REDACTION_LITERAL_COUNT, MAX_PLUGIN_TEXT_BYTES,
    },
    PluginError, PLUGIN_API_VERSION,
};

/// Host redaction policy applied before any plugin observation becomes evidence.
pub trait PluginRedactionPolicy: Send + Sync {
    /// Returns a redacted replacement for untrusted observation text.
    fn redact(&self, value: &str) -> String;
}

/// Conservative redactor for common secret assignments plus host literals.
#[derive(Clone, Default)]
pub struct SecretRedactionPolicy {
    literals: Vec<String>,
}

impl SecretRedactionPolicy {
    /// Creates a policy with bounded, non-empty literal secrets to remove.
    pub fn new(literals: impl IntoIterator<Item = String>) -> Result<Self, PluginError> {
        let mut retained = Vec::new();
        for literal in literals {
            if literal.is_empty() || literal.len() > MAX_PLUGIN_REDACTION_LITERAL_BYTES {
                return Err(invalid_config("redaction literal is empty or too long"));
            }
            if retained.len() >= MAX_PLUGIN_REDACTION_LITERAL_COUNT {
                return Err(invalid_config("too many redaction literals"));
            }
            if !retained.contains(&literal) {
                retained.push(literal);
            }
        }
        retained.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
        Ok(Self { literals: retained })
    }
}

impl fmt::Debug for SecretRedactionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRedactionPolicy")
            .field("literal_count", &self.literals.len())
            .finish()
    }
}

impl PluginRedactionPolicy for SecretRedactionPolicy {
    fn redact(&self, value: &str) -> String {
        static ASSIGNMENTS: LazyLock<Option<Regex>> = LazyLock::new(|| {
            Regex::new(
                r"(?im)(authorization|proxy-authorization|cookie|set-cookie|api[-_]?key|token|password|secret)\s*[:=]\s*[^\r\n]*",
            )
            .ok()
        });

        let redacted = match ASSIGNMENTS.as_ref() {
            Some(pattern) => pattern.replace_all(value, "$1=[REDACTED]").into_owned(),
            None => "[REDACTED]".to_owned(),
        };
        redact_literals_once(&redacted, &self.literals)
    }
}

fn redact_literals_once(value: &str, literals: &[String]) -> String {
    const REDACTED: &str = "[REDACTED]";
    if literals.is_empty() {
        return value.to_owned();
    }

    // A byte mask keeps transient memory proportional to the already-bounded
    // input. Collecting every match range lets dense, overlapping literals
    // multiply memory before the recorder can enforce its retained-byte cap.
    let mut masked = vec![false; value.len()];
    for pattern in std::iter::once(REDACTED).chain(literals.iter().map(String::as_str)) {
        for (start, matched) in value.match_indices(pattern) {
            masked[start..start + matched.len()].fill(true);
        }
    }
    if !masked.iter().any(|is_masked| *is_masked) {
        return value.to_owned();
    }

    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while cursor < masked.len() {
        let start = cursor;
        let is_masked = masked[cursor];
        while cursor < masked.len() && masked[cursor] == is_masked {
            cursor += 1;
        }
        if is_masked {
            output.push_str(REDACTED);
        } else {
            output.push_str(&value[start..cursor]);
        }
    }
    output
}

/// Untrusted observation draft accepted by the host recorder.
pub struct PluginObservation {
    pub(super) kind: EvidenceKind,
    pub(super) predicate: KnowledgePredicate,
    pub(super) value: EvidenceValue,
    pub(super) method: String,
}

impl PluginObservation {
    /// Creates a bounded observation draft without subject or claim authority.
    pub fn new(
        kind: EvidenceKind,
        predicate: KnowledgePredicate,
        value: EvidenceValue,
        method: impl Into<String>,
    ) -> Result<Self, PluginError> {
        let method = method.into();
        validate_identifier(&method, "plugin observation method", MAX_PLUGIN_ID_BYTES)?;
        validate_identifier(
            predicate.namespace(),
            "plugin observation predicate namespace",
            MAX_PLUGIN_ID_BYTES,
        )?;
        validate_identifier(
            predicate.name(),
            "plugin observation predicate name",
            MAX_PLUGIN_ID_BYTES,
        )?;
        if let EvidenceKind::Custom(name) = &kind {
            validate_identifier(name, "plugin observation kind", MAX_PLUGIN_ID_BYTES)?;
        }
        validate_observation_value(&value)?;
        Ok(Self {
            kind,
            predicate,
            value,
            method,
        })
    }
}

impl fmt::Debug for PluginObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginObservation")
            .field("kind", &self.kind)
            .field("predicate", &self.predicate)
            .field("value", &"[redacted]")
            .field("method", &self.method)
            .finish()
    }
}

pub(super) fn validate_observation_value(value: &EvidenceValue) -> Result<(), PluginError> {
    match value {
        EvidenceValue::Text(text) => {
            if text.len() as u64 > HARD_MAX_PLUGIN_OBSERVATION_BYTES {
                return Err(PluginError::ObservationBytesBudgetExceeded);
            }
        },
        EvidenceValue::TextList(items) => {
            if items.len() > HARD_MAX_PLUGIN_TEXT_LIST_ITEMS
                || evidence_value_bytes(value) > HARD_MAX_PLUGIN_OBSERVATION_BYTES
            {
                return Err(PluginError::ObservationBytesBudgetExceeded);
            }
        },
        EvidenceValue::Boolean(_) | EvidenceValue::Signed(_) | EvidenceValue::Unsigned(_) => {},
        _ => return Err(PluginError::ObservationBytesBudgetExceeded),
    }
    Ok(())
}

pub(super) fn evidence_value_bytes(value: &EvidenceValue) -> u64 {
    match value {
        EvidenceValue::Boolean(_) => 1,
        EvidenceValue::Signed(_) | EvidenceValue::Unsigned(_) => 8,
        EvidenceValue::Text(text) => {
            8_u64.saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX))
        },
        EvidenceValue::TextList(items) => items.iter().fold(8_u64, |total, item| {
            total
                .saturating_add(8)
                .saturating_add(u64::try_from(item.len()).unwrap_or(u64::MAX))
        }),
        _ => u64::MAX,
    }
}

pub(super) fn redact_value(
    policy: &dyn PluginRedactionPolicy,
    value: EvidenceValue,
) -> EvidenceValue {
    match value {
        EvidenceValue::Text(text) => EvidenceValue::Text(policy.redact(&text)),
        EvidenceValue::TextList(items) => {
            EvidenceValue::TextList(items.into_iter().map(|item| policy.redact(&item)).collect())
        },
        other => other,
    }
}

pub(super) fn sanitize_error(
    policy: &dyn PluginRedactionPolicy,
    error: PluginError,
) -> PluginError {
    match error {
        PluginError::InvalidConfig(_) => PluginError::InvalidConfig(redact_host_detail(
            policy,
            "plugin rejected its configuration",
        )),
        PluginError::ExecutionFailed(_) => {
            PluginError::ExecutionFailed(redact_host_detail(policy, "plugin execution failed"))
        },
        PluginError::BrokerFailure(_) => PluginError::BrokerFailure(redact_host_detail(
            policy,
            "host plugin request broker failed",
        )),
        PluginError::IncompatibleApiVersion { .. } => PluginError::IncompatibleApiVersion {
            expected: PLUGIN_API_VERSION.to_owned(),
            actual: "[invalid]".to_owned(),
        },
        other => other,
    }
}

pub(super) fn sanitize_error_safely(
    policy: &dyn PluginRedactionPolicy,
    error: PluginError,
) -> Result<PluginError, PluginError> {
    std::panic::catch_unwind(AssertUnwindSafe(|| sanitize_error(policy, error)))
        .map_err(|_| PluginError::HostCallbackPanicked)
}

fn redact_host_detail(policy: &dyn PluginRedactionPolicy, value: &'static str) -> String {
    bounded_detail(&policy.redact(value))
}

fn bounded_detail(value: &str) -> String {
    let mut end = value.len().min(MAX_PLUGIN_TEXT_BYTES);
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_owned()
}
