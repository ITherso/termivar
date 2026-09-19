//! Bounded, value-free detection of secret-shaped material in complete text bodies.
//!
//! This module deliberately owns no transport or report authority. Callers must
//! establish that a response is complete, uncoded, committed, and otherwise
//! eligible before passing its bytes here. The detector never retains a matched
//! value, a fragment of one, or a digest derived from one.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt, str,
    sync::{Arc, Mutex},
};

use termivar_core::{
    DerivationAlgorithm, EntityId, Evidence, EvidenceDerivation, EvidenceId, EvidenceKind,
    EvidenceOrigin, EvidenceSource, EvidenceValue, HttpEvidencePredicate, KnowledgePredicate,
    PredicateDescriptor,
};

use crate::{
    DecisionEvidenceReceipt, DecisionExecutionStage, HttpEvidenceError, HttpProbeMethod,
    KnowledgeBase, KnowledgeWrite, HTTP_EVIDENCE_EXECUTOR_ID,
};

use super::{
    assessment_item::{
        AssessmentCapabilityDescriptor, AssessmentItemProjectionError, AssessmentItemTarget,
        AssessmentProjectionContext,
    },
    WebAssessmentSubject, BOOTSTRAP_ACTION_ID, BOOTSTRAP_CASE_ID, BOOTSTRAP_HYPOTHESIS_ID,
};

/// Largest complete textual response accepted by this detector.
pub const MAX_SECRET_EXPOSURE_BODY_BYTES: usize = 128 * 1024;
/// Maximum response bytes admitted to detector work across one assessment.
pub const MAX_SECRET_EXPOSURE_TOTAL_BODY_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum value-free matched subject/class observations retained per run.
pub const MAX_SECRET_EXPOSURE_RETAINED_OBSERVATIONS: usize = 32;
/// Maximum committed response outcomes accepted from the parent assessment.
pub const MAX_SECRET_EXPOSURE_RESPONSES: usize = 1_024;
/// Largest encoded payload accepted inside one PEM private-key block.
pub(crate) const MAX_SECRET_EXPOSURE_PEM_PAYLOAD_BYTES: usize = 64 * 1024;
/// Largest bearer value considered by the explicit authorization detector.
pub(crate) const MAX_SECRET_EXPOSURE_TOKEN_BYTES: usize = 512;
/// Maximum byte distance between the two members of an AWS credential pair.
pub(crate) const MAX_SECRET_EXPOSURE_PAIR_WINDOW_BYTES: usize = 4 * 1024;
/// Maximum line-number distance between the two members of an AWS pair.
pub(crate) const MAX_SECRET_EXPOSURE_PAIR_WINDOW_LINES: usize = 16;
/// Maximum total matched occurrences retained as value-free counters.
pub const MAX_SECRET_EXPOSURE_OCCURRENCES: u16 = 64;

pub const SECRET_EXPOSURE_AUDIT_SCHEMA: &str = "security.passive-secret-exposure-audit/v1";
pub const SECRET_EXPOSURE_POLICY_ID: &str = "termivar.passive-secret-exposure/v1";
pub const SECRET_EXPOSURE_CATALOGUE_ID: &str = "termivar.high-specificity-secret-detectors";
pub const SECRET_EXPOSURE_CATALOGUE_REVISION: &str = "v1";
pub const SECRET_EXPOSURE_REPRESENTATION: &str = "complete-uncoded-response-body/v1";
pub(crate) const SECRET_EXPOSURE_NAMESPACE: &str = "web.secret-exposure";
const SECRET_EXPOSURE_CATEGORY: &str = "passive-secret-exposure";
const SECRET_EXPOSURE_SOURCE_METHOD: &str = "bounded-value-free-secret-detection";
const SECRET_EXPOSURE_ALGORITHM: &str = "web.secret-exposure.fixed-catalogue";
const SECRET_EXPOSURE_ALGORITHM_VERSION: u32 = 1;
const ACTIVE_REVIEW_PRIVACY_SOURCE_METHOD: &str = "active-review-body-digest-privacy-guard";
const ACTIVE_REVIEW_PRIVACY_ALGORITHM: &str =
    "web.secret-exposure.active-review-body-digest-privacy-guard";
const ACTIVE_REVIEW_PRIVACY_ALGORITHM_VERSION: u32 = 1;

const RESPONSE_SEQUENCE: &str = "response_sequence";
const RESPONSE_OUTCOME: &str = "response_outcome";
pub(crate) const RESPONSE_BODY_LINEAGE: &str = "response_body_lineage";
pub(crate) const ACTIVE_REVIEW_BODY_LINEAGE: &str = "active_review_body_lineage";
const INSPECTED_BODY_BYTES: &str = "inspected_body_bytes";
const MATCH_OCCURRENCE_COUNT: &str = "match_occurrence_count";
const OMITTED_OBSERVATION_COUNT: &str = "omitted_observation_count";
const BODY_DERIVED_PROJECTION_SUPPRESSED: &str = "body_derived_projection_suppressed";

const MIN_PEM_PAYLOAD_BYTES: usize = 64;
const MIN_STRIPE_PAYLOAD_BYTES: usize = 16;
const MAX_STRIPE_PAYLOAD_BYTES: usize = 128;
const MIN_BEARER_TOKEN_BYTES: usize = 24;

const AWS_ACCESS_KEY_ID_NAMES: [&[u8]; 2] = [b"AWS_ACCESS_KEY_ID", b"aws_access_key_id"];
const AWS_SECRET_ACCESS_KEY_NAMES: [&[u8]; 2] =
    [b"AWS_SECRET_ACCESS_KEY", b"aws_secret_access_key"];

/// Closed public meaning of a detector match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SecretExposureDetectorClass {
    PemPrivateKeyBlock,
    AwsAccessKeyPair,
    StripeLiveSecret,
    AuthorizationBearerAssignment,
}

impl SecretExposureDetectorClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PemPrivateKeyBlock => "pem_private_key_block",
            Self::AwsAccessKeyPair => "aws_access_key_pair",
            Self::StripeLiveSecret => "stripe_live_secret",
            Self::AuthorizationBearerAssignment => "authorization_bearer_assignment",
        }
    }

    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::PemPrivateKeyBlock => "exposure.response-private-key-material@1",
            Self::AwsAccessKeyPair => "exposure.response-aws-access-key-pair@1",
            Self::StripeLiveSecret => "exposure.response-stripe-live-secret@1",
            Self::AuthorizationBearerAssignment => "exposure.response-bearer-authorization@1",
        }
    }

    const fn predicate_name(self) -> &'static str {
        match self {
            Self::PemPrivateKeyBlock => "pem_private_key_block_count",
            Self::AwsAccessKeyPair => "aws_access_key_pair_count",
            Self::StripeLiveSecret => "stripe_live_secret_count",
            Self::AuthorizationBearerAssignment => "bearer_authorization_assignment_count",
        }
    }

    fn parse_predicate_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|class| class.predicate_name() == value)
    }

    const ALL: [Self; 4] = [
        Self::PemPrivateKeyBlock,
        Self::AwsAccessKeyPair,
        Self::StripeLiveSecret,
        Self::AuthorizationBearerAssignment,
    ];

    const fn capability(self) -> &'static AssessmentCapabilityDescriptor {
        match self {
            Self::PemPrivateKeyBlock => &PRIVATE_KEY_CAPABILITY,
            Self::AwsAccessKeyPair => &AWS_ACCESS_KEY_PAIR_CAPABILITY,
            Self::StripeLiveSecret => &STRIPE_LIVE_SECRET_CAPABILITY,
            Self::AuthorizationBearerAssignment => &BEARER_AUTHORIZATION_CAPABILITY,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::PemPrivateKeyBlock => 0,
            Self::AwsAccessKeyPair => 1,
            Self::StripeLiveSecret => 2,
            Self::AuthorizationBearerAssignment => 3,
        }
    }

    const fn from_index(index: usize) -> Self {
        match index {
            0 => Self::PemPrivateKeyBlock,
            1 => Self::AwsAccessKeyPair,
            2 => Self::StripeLiveSecret,
            3 => Self::AuthorizationBearerAssignment,
            _ => unreachable!(),
        }
    }
}

/// One class and its bounded occurrence count. No matched value is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecretExposureClassCount {
    class: SecretExposureDetectorClass,
    occurrence_count: u16,
}

impl SecretExposureClassCount {
    pub(crate) const fn class(self) -> SecretExposureDetectorClass {
        self.class
    }

    pub(crate) const fn occurrence_count(self) -> u16 {
        self.occurrence_count
    }
}

/// Complete value-free result for one accepted textual body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretExposureScan {
    inspected_body_bytes: usize,
    occurrence_count: u16,
    class_counts: Vec<SecretExposureClassCount>,
}

impl SecretExposureScan {
    pub(crate) const fn inspected_body_bytes(&self) -> usize {
        self.inspected_body_bytes
    }

    pub(crate) const fn occurrence_count(&self) -> u16 {
        self.occurrence_count
    }

    pub(crate) fn class_counts(&self) -> &[SecretExposureClassCount] {
        &self.class_counts
    }

    #[cfg(test)]
    pub(crate) fn count_for(&self, class: SecretExposureDetectorClass) -> u16 {
        self.class_counts
            .iter()
            .find(|entry| entry.class == class)
            .map_or(0, |entry| entry.occurrence_count)
    }
}

/// Value-free refusal from the bounded detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretExposureScanError {
    BodyLimitExceeded {
        body_bytes: usize,
        max_body_bytes: usize,
    },
    InvalidUtf8 {
        body_bytes: usize,
    },
    PemPayloadLimitExceeded {
        body_bytes: usize,
        max_payload_bytes: usize,
    },
    TokenLimitExceeded {
        body_bytes: usize,
        max_token_bytes: usize,
    },
    OccurrenceLimitExceeded {
        body_bytes: usize,
        max_occurrences: u16,
    },
}

impl fmt::Display for SecretExposureScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BodyLimitExceeded {
                body_bytes,
                max_body_bytes,
            } => write!(
                formatter,
                "secret-exposure body byte count {body_bytes} exceeds limit {max_body_bytes}"
            ),
            Self::InvalidUtf8 { body_bytes } => write!(
                formatter,
                "secret-exposure body with {body_bytes} bytes is not valid UTF-8"
            ),
            Self::PemPayloadLimitExceeded {
                body_bytes,
                max_payload_bytes,
            } => write!(
                formatter,
                "secret-exposure PEM candidate in {body_bytes}-byte body exceeds payload limit {max_payload_bytes}"
            ),
            Self::TokenLimitExceeded {
                body_bytes,
                max_token_bytes,
            } => write!(
                formatter,
                "secret-exposure token candidate in {body_bytes}-byte body exceeds token limit {max_token_bytes}"
            ),
            Self::OccurrenceLimitExceeded {
                body_bytes,
                max_occurrences,
            } => write!(
                formatter,
                "secret-exposure body with {body_bytes} bytes exceeds occurrence limit {max_occurrences}"
            ),
        }
    }
}

impl Error for SecretExposureScanError {}

/// Inspects one already-qualified complete textual body.
///
/// Successful output contains only byte and occurrence counts. A refusal never
/// includes input bytes, candidate fragments, or a digest of either.
pub(crate) fn scan_complete_text_body(
    body: &[u8],
) -> Result<SecretExposureScan, SecretExposureScanError> {
    if body.len() > MAX_SECRET_EXPOSURE_BODY_BYTES {
        return Err(SecretExposureScanError::BodyLimitExceeded {
            body_bytes: body.len(),
            max_body_bytes: MAX_SECRET_EXPOSURE_BODY_BYTES,
        });
    }
    if str::from_utf8(body).is_err() {
        return Err(SecretExposureScanError::InvalidUtf8 {
            body_bytes: body.len(),
        });
    }

    let mut counts = MatchCounts::new(body.len());
    scan_pem_private_keys(body, &mut counts)?;
    scan_aws_pairs(body, &mut counts)?;
    scan_stripe_live_secrets(body, &mut counts)?;
    scan_authorization_bearer_assignments(body, &mut counts)?;
    Ok(counts.finish())
}

struct MatchCounts {
    body_bytes: usize,
    total: u16,
    by_class: [u16; 4],
}

impl MatchCounts {
    const fn new(body_bytes: usize) -> Self {
        Self {
            body_bytes,
            total: 0,
            by_class: [0; 4],
        }
    }

    fn record(
        &mut self,
        class: SecretExposureDetectorClass,
    ) -> Result<(), SecretExposureScanError> {
        if self.total >= MAX_SECRET_EXPOSURE_OCCURRENCES {
            return Err(SecretExposureScanError::OccurrenceLimitExceeded {
                body_bytes: self.body_bytes,
                max_occurrences: MAX_SECRET_EXPOSURE_OCCURRENCES,
            });
        }
        self.total += 1;
        self.by_class[class.index()] += 1;
        Ok(())
    }

    fn finish(self) -> SecretExposureScan {
        let class_counts = self
            .by_class
            .into_iter()
            .enumerate()
            .filter_map(|(index, occurrence_count)| {
                (occurrence_count != 0).then_some(SecretExposureClassCount {
                    class: SecretExposureDetectorClass::from_index(index),
                    occurrence_count,
                })
            })
            .collect();
        SecretExposureScan {
            inspected_body_bytes: self.body_bytes,
            occurrence_count: self.total,
            class_counts,
        }
    }
}

#[derive(Clone, Copy)]
enum PemLabel {
    Pkcs8,
    Rsa,
    Ec,
    OpenSsh,
}

impl PemLabel {
    const ALL: [Self; 4] = [Self::Pkcs8, Self::Rsa, Self::Ec, Self::OpenSsh];

    const fn begin(self) -> &'static [u8] {
        match self {
            Self::Pkcs8 => b"-----BEGIN PRIVATE KEY-----",
            Self::Rsa => b"-----BEGIN RSA PRIVATE KEY-----",
            Self::Ec => b"-----BEGIN EC PRIVATE KEY-----",
            Self::OpenSsh => b"-----BEGIN OPENSSH PRIVATE KEY-----",
        }
    }

    const fn end(self) -> &'static [u8] {
        match self {
            Self::Pkcs8 => b"-----END PRIVATE KEY-----",
            Self::Rsa => b"-----END RSA PRIVATE KEY-----",
            Self::Ec => b"-----END EC PRIVATE KEY-----",
            Self::OpenSsh => b"-----END OPENSSH PRIVATE KEY-----",
        }
    }

    fn prefix_is_plausible(self, payload_prefix: &[u8]) -> bool {
        match self {
            // DER private-key encodings begin with an ASN.1 SEQUENCE (0x30),
            // whose base64 representation begins with `M`.
            Self::Pkcs8 | Self::Rsa | Self::Ec => payload_prefix.first() == Some(&b'M'),
            // Base64 for the OpenSSH binary magic `openssh-key-v1`.
            Self::OpenSsh => payload_prefix.starts_with(b"b3BlbnNzaC1rZXktdjE"),
        }
    }
}

fn scan_pem_private_keys(
    body: &[u8],
    counts: &mut MatchCounts,
) -> Result<(), SecretExposureScanError> {
    let mut cursor = 0;
    while let Some((line, next)) = next_line(body, cursor) {
        let trimmed = trim_ascii_horizontal(line);
        let Some(label) = PemLabel::ALL
            .into_iter()
            .find(|label| trimmed == label.begin())
        else {
            cursor = next;
            continue;
        };

        let mut payload_bytes = 0usize;
        let mut payload_prefix = [0u8; 24];
        let mut prefix_len = 0usize;
        let mut padding_started = false;
        let mut padding_bytes = 0usize;
        let mut valid = true;
        let mut block_cursor = next;
        let mut closed_at = None;

        while let Some((candidate_line, candidate_next)) = next_line(body, block_cursor) {
            let candidate = trim_ascii_horizontal(candidate_line);
            if candidate == label.end() {
                closed_at = Some(candidate_next);
                break;
            }
            if PemLabel::ALL
                .into_iter()
                .any(|other| candidate == other.begin() || candidate == other.end())
                || candidate.is_empty()
            {
                valid = false;
                break;
            }
            for &byte in candidate {
                if payload_bytes >= MAX_SECRET_EXPOSURE_PEM_PAYLOAD_BYTES {
                    return Err(SecretExposureScanError::PemPayloadLimitExceeded {
                        body_bytes: body.len(),
                        max_payload_bytes: MAX_SECRET_EXPOSURE_PEM_PAYLOAD_BYTES,
                    });
                }
                if byte == b'=' {
                    padding_started = true;
                    padding_bytes += 1;
                    if padding_bytes > 2 {
                        valid = false;
                        break;
                    }
                } else if is_base64_byte(byte) && !padding_started {
                    if prefix_len < payload_prefix.len() {
                        payload_prefix[prefix_len] = byte;
                        prefix_len += 1;
                    }
                } else {
                    valid = false;
                    break;
                }
                payload_bytes += 1;
            }
            if !valid {
                break;
            }
            block_cursor = candidate_next;
        }

        if valid
            && closed_at.is_some()
            && payload_bytes >= MIN_PEM_PAYLOAD_BYTES
            && payload_bytes % 4 == 0
            && label.prefix_is_plausible(&payload_prefix[..prefix_len])
        {
            counts.record(SecretExposureDetectorClass::PemPrivateKeyBlock)?;
            cursor = closed_at.expect("checked PEM close remains present");
        } else {
            cursor = next;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AssignmentLocation {
    byte_offset: usize,
    line_number: usize,
}

fn scan_aws_pairs(body: &[u8], counts: &mut MatchCounts) -> Result<(), SecretExposureScanError> {
    let mut unmatched_ids = Vec::<AssignmentLocation>::new();
    let mut unmatched_secrets = Vec::<AssignmentLocation>::new();
    let mut cursor = 0;
    let mut line_number = 0;

    while let Some((line, next)) = next_line(body, cursor) {
        let mut events = Vec::<(usize, bool)>::new();
        for name in AWS_ACCESS_KEY_ID_NAMES {
            for_each_assignment_value(line, name, |position, value| {
                if valid_aws_access_key_id(value) {
                    events.push((position, true));
                }
            });
        }
        for name in AWS_SECRET_ACCESS_KEY_NAMES {
            for_each_assignment_value(line, name, |position, value| {
                if valid_aws_secret_access_key(value) {
                    events.push((position, false));
                }
            });
        }
        events.sort_unstable_by_key(|event| event.0);

        for (position, is_id) in events {
            let location = AssignmentLocation {
                byte_offset: cursor.saturating_add(position),
                line_number,
            };
            discard_out_of_window(&mut unmatched_ids, location);
            discard_out_of_window(&mut unmatched_secrets, location);
            let counterparts = if is_id {
                &mut unmatched_secrets
            } else {
                &mut unmatched_ids
            };
            if let Some(index) = counterparts
                .iter()
                .position(|other| locations_share_pair_window(*other, location))
            {
                counterparts.remove(index);
                counts.record(SecretExposureDetectorClass::AwsAccessKeyPair)?;
            } else if is_id {
                unmatched_ids.push(location);
            } else {
                unmatched_secrets.push(location);
            }
        }

        cursor = next;
        line_number = line_number.saturating_add(1);
    }
    Ok(())
}

fn discard_out_of_window(locations: &mut Vec<AssignmentLocation>, current: AssignmentLocation) {
    locations.retain(|candidate| locations_share_pair_window(*candidate, current));
}

fn locations_share_pair_window(left: AssignmentLocation, right: AssignmentLocation) -> bool {
    left.byte_offset.abs_diff(right.byte_offset) <= MAX_SECRET_EXPOSURE_PAIR_WINDOW_BYTES
        && left.line_number.abs_diff(right.line_number) <= MAX_SECRET_EXPOSURE_PAIR_WINDOW_LINES
}

fn valid_aws_access_key_id(value: &[u8]) -> bool {
    value.len() == 20
        && (value.starts_with(b"AKIA") || value.starts_with(b"ASIA"))
        && value
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && !equals_ascii_case_insensitive(value, b"AKIAIOSFODNN7EXAMPLE")
        && !looks_like_placeholder(value)
        && has_minimum_byte_variety(value)
}

fn valid_aws_secret_access_key(value: &[u8]) -> bool {
    value.len() == 40
        && value
            .iter()
            .all(|byte| is_base64_byte(*byte) || *byte == b'=')
        && !looks_like_placeholder(value)
        && has_minimum_byte_variety(value)
}

fn scan_stripe_live_secrets(
    body: &[u8],
    counts: &mut MatchCounts,
) -> Result<(), SecretExposureScanError> {
    for prefix in [b"sk_live_".as_slice(), b"rk_live_".as_slice()] {
        let mut cursor = 0;
        while let Some(relative) = find_subslice(&body[cursor..], prefix) {
            let start = cursor + relative;
            if !has_token_boundary_before(body, start, is_stripe_token_byte) {
                cursor = start.saturating_add(1);
                continue;
            }
            let payload_start = start + prefix.len();
            let mut end = payload_start;
            while end < body.len() && is_stripe_token_byte(body[end]) {
                end += 1;
            }
            let payload = &body[payload_start..end];
            if has_token_boundary_after(body, end, is_stripe_token_byte)
                && (MIN_STRIPE_PAYLOAD_BYTES..=MAX_STRIPE_PAYLOAD_BYTES).contains(&payload.len())
                && !looks_like_placeholder(payload)
                && has_minimum_byte_variety(payload)
            {
                counts.record(SecretExposureDetectorClass::StripeLiveSecret)?;
            }
            // A token-byte run cannot contain a second boundary-qualified
            // Stripe candidate. Consume it once so repeated `sk_live_` text
            // inside a single long token cannot rescan the suffix quadratically.
            cursor = end.max(start.saturating_add(1));
        }
    }
    Ok(())
}

fn scan_authorization_bearer_assignments(
    body: &[u8],
    counts: &mut MatchCounts,
) -> Result<(), SecretExposureScanError> {
    let mut cursor = 0;
    while let Some((line, next)) = next_line(body, cursor) {
        for_each_assignment_value_case_insensitive(line, b"authorization", |_, value| {
            let value = trim_ascii_horizontal(value);
            let Some(after_scheme) = strip_ascii_case_insensitive_prefix(value, b"Bearer") else {
                return Ok(());
            };
            if after_scheme
                .first()
                .is_none_or(|byte| !byte.is_ascii_whitespace())
            {
                return Ok(());
            }
            let token = trim_ascii_horizontal(after_scheme);
            if token.len() > MAX_SECRET_EXPOSURE_TOKEN_BYTES {
                return Err(SecretExposureScanError::TokenLimitExceeded {
                    body_bytes: body.len(),
                    max_token_bytes: MAX_SECRET_EXPOSURE_TOKEN_BYTES,
                });
            }
            if token.len() >= MIN_BEARER_TOKEN_BYTES
                && valid_token68(token)
                && !looks_like_placeholder(token)
                && has_minimum_byte_variety(token)
            {
                counts.record(SecretExposureDetectorClass::AuthorizationBearerAssignment)?;
            }
            Ok(())
        })?;
        cursor = next;
    }
    Ok(())
}

fn next_line(body: &[u8], cursor: usize) -> Option<(&[u8], usize)> {
    if cursor >= body.len() {
        return None;
    }
    let relative_end = body[cursor..]
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(body.len() - cursor);
    let end = cursor + relative_end;
    let next = if end < body.len() { end + 1 } else { end };
    Some((&body[cursor..end], next))
}

fn trim_ascii_horizontal(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

#[derive(Default)]
struct AssignmentEndCursor {
    cached: Option<usize>,
    search_from: usize,
    exhausted: bool,
    inspected_bytes: usize,
}

impl AssignmentEndCursor {
    fn next_at_or_after(
        &mut self,
        line: &[u8],
        start: usize,
        matches: impl Fn(u8) -> bool,
    ) -> Option<usize> {
        if self.cached.is_some_and(|index| index >= start) {
            return self.cached;
        }
        if self.exhausted {
            return None;
        }
        let from = self.search_from.max(start);
        for (relative, byte) in line[from..].iter().copied().enumerate() {
            self.inspected_bytes = self.inspected_bytes.saturating_add(1);
            if matches(byte) {
                let index = from + relative;
                self.cached = Some(index);
                self.search_from = index.saturating_add(1);
                return Some(index);
            }
        }
        self.cached = None;
        self.search_from = line.len();
        self.exhausted = true;
        None
    }
}

#[derive(Default)]
struct AssignmentValueEndCursors {
    single_quote: AssignmentEndCursor,
    double_quote: AssignmentEndCursor,
    spaced: AssignmentEndCursor,
    compact: AssignmentEndCursor,
}

impl AssignmentValueEndCursors {
    fn quoted(&mut self, line: &[u8], start: usize, quote: u8) -> Option<usize> {
        let cursor = if quote == b'\'' {
            &mut self.single_quote
        } else {
            &mut self.double_quote
        };
        cursor.next_at_or_after(line, start, |byte| byte == quote)
    }

    fn unquoted(&mut self, line: &[u8], start: usize, retain_spaces: bool) -> usize {
        let cursor = if retain_spaces {
            &mut self.spaced
        } else {
            &mut self.compact
        };
        cursor
            .next_at_or_after(line, start, |byte| {
                if retain_spaces {
                    matches!(byte, b';' | b'#')
                } else {
                    matches!(byte, b' ' | b'\t' | b',' | b';' | b'#' | b'}')
                }
            })
            .unwrap_or(line.len())
    }

    fn inspected_bytes(&self) -> usize {
        self.single_quote
            .inspected_bytes
            .saturating_add(self.double_quote.inspected_bytes)
            .saturating_add(self.spaced.inspected_bytes)
            .saturating_add(self.compact.inspected_bytes)
    }
}

fn for_each_assignment_value(line: &[u8], name: &[u8], mut visit: impl FnMut(usize, &[u8])) {
    let mut cursor = 0;
    let mut ends = AssignmentValueEndCursors::default();
    while let Some(relative) = find_subslice(&line[cursor..], name) {
        let position = cursor + relative;
        if let Some(value) = parse_assignment_value(line, position, name.len(), false, &mut ends) {
            visit(position, value);
        }
        cursor = position.saturating_add(1);
    }
}

fn for_each_assignment_value_case_insensitive<E>(
    line: &[u8],
    name: &[u8],
    mut visit: impl FnMut(usize, &[u8]) -> Result<(), E>,
) -> Result<usize, E> {
    let mut cursor = 0;
    let mut ends = AssignmentValueEndCursors::default();
    while cursor + name.len() <= line.len() {
        if equals_ascii_case_insensitive(&line[cursor..cursor + name.len()], name) {
            if let Some(value) = parse_assignment_value(line, cursor, name.len(), true, &mut ends) {
                visit(cursor, value)?;
            }
        }
        cursor += 1;
    }
    Ok(ends.inspected_bytes())
}

fn parse_assignment_value<'a>(
    line: &'a [u8],
    name_start: usize,
    name_len: usize,
    retain_unquoted_spaces: bool,
    ends: &mut AssignmentValueEndCursors,
) -> Option<&'a [u8]> {
    let name_end = name_start.checked_add(name_len)?;
    let before = name_start.checked_sub(1).and_then(|index| line.get(index));
    if before.is_some_and(|byte| !is_assignment_boundary(*byte)) {
        return None;
    }

    let opening_name_quote = before.copied().filter(|byte| matches!(byte, b'\'' | b'"'));
    let mut cursor = name_end;
    if let Some(quote) = opening_name_quote {
        if line.get(cursor) != Some(&quote) {
            return None;
        }
        cursor += 1;
    } else if line
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return None;
    }
    while line
        .get(cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        cursor += 1;
    }
    if !line
        .get(cursor)
        .is_some_and(|byte| matches!(byte, b':' | b'='))
    {
        return None;
    }
    cursor += 1;
    while line
        .get(cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        cursor += 1;
    }

    let value_quote = line
        .get(cursor)
        .copied()
        .filter(|byte| matches!(byte, b'\'' | b'"'));
    if value_quote.is_some() {
        cursor += 1;
    }
    let value_start = cursor;
    let value_end = if let Some(quote) = value_quote {
        ends.quoted(line, value_start, quote)?
    } else {
        ends.unquoted(line, value_start, retain_unquoted_spaces)
    };
    let value = trim_ascii_horizontal(&line[value_start..value_end]);
    if value.is_empty() {
        return None;
    }
    Some(value)
}

fn is_assignment_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'{' | b'[' | b',' | b';' | b'\'' | b'"')
}

fn valid_token68(token: &[u8]) -> bool {
    let mut padding = false;
    let mut padding_bytes = 0;
    for byte in token {
        if *byte == b'=' {
            padding = true;
            padding_bytes += 1;
            if padding_bytes > 2 {
                return false;
            }
        } else if padding || !is_token68_byte(*byte) {
            return false;
        }
    }
    true
}

fn is_token68_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

fn is_stripe_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

fn has_token_boundary_before(body: &[u8], start: usize, member: fn(u8) -> bool) -> bool {
    start == 0 || !member(body[start - 1])
}

fn has_token_boundary_after(body: &[u8], end: usize, member: fn(u8) -> bool) -> bool {
    end == body.len() || !member(body[end])
}

fn has_minimum_byte_variety(value: &[u8]) -> bool {
    let mut distinct = [0u8; 4];
    let mut count = 0usize;
    for byte in value {
        if !distinct[..count].contains(byte) {
            distinct[count] = *byte;
            count += 1;
            if count == distinct.len() {
                return true;
            }
        }
    }
    false
}

const PRIVATE_KEY_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "exposure.response-private-key-material@1",
        "Private-key material shape was returned",
        "passive-secret-exposure",
        "A complete eligible response contained a structurally plausible private-key block; validity, ownership, and usability were not tested.",
        950_000,
        "exposure.remediation.remove-private-key-material@1",
        "Remove private-key material from served content, rotate affected keys through the responsible operator, and verify the authorized response no longer contains it.",
    );
const AWS_ACCESS_KEY_PAIR_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "exposure.response-aws-access-key-pair@1",
        "Paired AWS credential assignments were returned",
        "passive-secret-exposure",
        "A complete eligible response contained nearby access-key-ID and secret-access-key assignment shapes; provider validity and permissions were not tested.",
        900_000,
        "exposure.remediation.remove-aws-credential-pair@1",
        "Remove credential assignments from served content, review and rotate them through the responsible operator, and verify the authorized response no longer contains them.",
    );
const STRIPE_LIVE_SECRET_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "exposure.response-stripe-live-secret@1",
        "Stripe live secret-key shape was returned",
        "passive-secret-exposure",
        "A complete eligible response contained a Stripe live secret or restricted-key shape; provider validity, account ownership, and permissions were not tested.",
        900_000,
        "exposure.remediation.remove-stripe-live-secret@1",
        "Remove live secret-key material from served content, review and rotate it through the responsible operator, and verify the authorized response no longer contains it.",
    );
const BEARER_AUTHORIZATION_CAPABILITY: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::informational(
        "exposure.response-bearer-authorization@1",
        "Bearer authorization assignment was returned",
        "passive-secret-exposure",
        "A complete eligible response contained an explicit Authorization Bearer assignment; token validity, intended audience, and permissions were not tested.",
        850_000,
        "exposure.remediation.remove-bearer-authorization@1",
        "Remove bearer authorization material from served content, invalidate it where appropriate, and verify the authorized response no longer contains it.",
    );

/// Closed reason one selected response was or was not evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SecretExposureResponseOutcome {
    Evaluated,
    MethodNotGet,
    StatusNot200,
    IncompleteBody,
    RequestContextIneligible,
    ContentCoded,
    ContentLengthInconsistent,
    UnsupportedMediaType,
    InvalidUtf8,
    ResponseByteLimitExceeded,
    TotalByteLimitExceeded,
    DetectorLimitExceeded,
}

impl SecretExposureResponseOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evaluated => "evaluated",
            Self::MethodNotGet => "method_not_get",
            Self::StatusNot200 => "status_not_200",
            Self::IncompleteBody => "incomplete_body",
            Self::RequestContextIneligible => "request_context_ineligible",
            Self::ContentCoded => "content_coded",
            Self::ContentLengthInconsistent => "content_length_inconsistent",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::ResponseByteLimitExceeded => "response_byte_limit_exceeded",
            Self::TotalByteLimitExceeded => "total_byte_limit_exceeded",
            Self::DetectorLimitExceeded => "detector_limit_exceeded",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|item| item.as_str() == value)
    }

    const ALL: [Self; 12] = [
        Self::Evaluated,
        Self::MethodNotGet,
        Self::StatusNot200,
        Self::IncompleteBody,
        Self::RequestContextIneligible,
        Self::ContentCoded,
        Self::ContentLengthInconsistent,
        Self::UnsupportedMediaType,
        Self::InvalidUtf8,
        Self::ResponseByteLimitExceeded,
        Self::TotalByteLimitExceeded,
        Self::DetectorLimitExceeded,
    ];
}

/// One aggregate outcome row retained by the selected audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretExposureOutcomeCount {
    outcome: SecretExposureResponseOutcome,
    count: u32,
}

impl SecretExposureOutcomeCount {
    pub const fn outcome(self) -> SecretExposureResponseOutcome {
        self.outcome
    }

    pub const fn count(self) -> u32 {
        self.count
    }
}

/// One value-free committed subject/class observation.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretExposureObservation {
    subject: EntityId,
    detector_class: SecretExposureDetectorClass,
    occurrence_count: u16,
    evidence_ids: Vec<EvidenceId>,
}

impl fmt::Debug for SecretExposureObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretExposureObservation")
            .field("detector_class", &self.detector_class)
            .field("occurrence_count", &self.occurrence_count)
            .field("evidence_count", &self.evidence_ids.len())
            .finish()
    }
}

impl SecretExposureObservation {
    pub const fn detector_class(&self) -> SecretExposureDetectorClass {
        self.detector_class
    }

    pub const fn occurrence_count(&self) -> u16 {
        self.occurrence_count
    }

    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }
}

/// Complete selected-run audit. It intentionally contains no matched bytes,
/// fragments, reversible encoding, or digest of secret material.
#[derive(Clone, PartialEq, Eq)]
pub struct WebAssessmentSecretExposureAudit {
    outcomes: Vec<SecretExposureOutcomeCount>,
    observations: Vec<SecretExposureObservation>,
    response_count: u32,
    evaluated_response_count: u32,
    interpreted_byte_count: u64,
    body_derived_projection_suppressed_response_count: u32,
    omitted_observation_count: u32,
    match_occurrence_count: u64,
}

impl fmt::Debug for WebAssessmentSecretExposureAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentSecretExposureAudit")
            .field("outcomes", &self.outcomes)
            .field("response_count", &self.response_count)
            .field("evaluated_response_count", &self.evaluated_response_count)
            .field("interpreted_byte_count", &self.interpreted_byte_count)
            .field(
                "body_derived_projection_suppressed_response_count",
                &self.body_derived_projection_suppressed_response_count,
            )
            .field("observation_count", &self.observations.len())
            .field("omitted_observation_count", &self.omitted_observation_count)
            .field("match_occurrence_count", &self.match_occurrence_count)
            .finish()
    }
}

impl WebAssessmentSecretExposureAudit {
    pub fn outcomes(&self) -> &[SecretExposureOutcomeCount] {
        &self.outcomes
    }

    pub fn observations(&self) -> &[SecretExposureObservation] {
        &self.observations
    }

    pub const fn response_count(&self) -> u32 {
        self.response_count
    }

    pub const fn evaluated_response_count(&self) -> u32 {
        self.evaluated_response_count
    }

    pub const fn not_evaluated_response_count(&self) -> u32 {
        self.response_count - self.evaluated_response_count
    }

    pub const fn interpreted_byte_count(&self) -> u64 {
        self.interpreted_byte_count
    }

    pub const fn body_derived_projection_suppressed_response_count(&self) -> u32 {
        self.body_derived_projection_suppressed_response_count
    }

    pub const fn observation_count(&self) -> usize {
        self.observations.len()
    }

    pub const fn omitted_observation_count(&self) -> u32 {
        self.omitted_observation_count
    }

    pub const fn match_occurrence_count(&self) -> u64 {
        self.match_occurrence_count
    }
}

#[derive(Default)]
struct SecretExposureCollectorState {
    response_count: u32,
    admitted_inspection_byte_count: u64,
    interpreted_byte_count: u64,
    retained_observation_count: usize,
}

/// Assessment-owned shared admission state for the sealed ordinary-response
/// observer. The state reserves bounds only; report truth is reconstructed from
/// committed receipt evidence by `CommittedSecretExposureLedger`.
#[derive(Clone, Default)]
pub(crate) struct SecretExposureCollector {
    state: Arc<Mutex<SecretExposureCollectorState>>,
}

impl fmt::Debug for SecretExposureCollector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretExposureCollector")
            .finish_non_exhaustive()
    }
}

impl SecretExposureCollector {
    pub(crate) fn observe(
        &self,
        observation: &crate::http_evidence::CompleteHttpResponseObservation<'_>,
        parents: Vec<EvidenceId>,
    ) -> Result<Vec<Evidence>, HttpEvidenceError> {
        let mut state =
            self.state
                .lock()
                .map_err(|_| HttpEvidenceError::AssessmentObserverInvariant {
                    invariant: "secret-exposure collector lock",
                })?;
        if usize::try_from(state.response_count).unwrap_or(usize::MAX)
            >= MAX_SECRET_EXPOSURE_RESPONSES
        {
            return Err(HttpEvidenceError::AssessmentObserverInvariant {
                invariant: "secret-exposure response limit",
            });
        }
        state.response_count = state.response_count.saturating_add(1);
        let response_sequence = state.response_count;

        let mut scan = None;
        let mut inspected_body_bytes = 0_u64;
        let outcome = if observation.method() != HttpProbeMethod::Get {
            SecretExposureResponseOutcome::MethodNotGet
        } else if observation.status() != 200 {
            SecretExposureResponseOutcome::StatusNot200
        } else if observation.complete_body().is_none() {
            SecretExposureResponseOutcome::IncompleteBody
        } else if !observation.request_headers_empty()
            || !observation.response_final_url_matches_request()
        {
            SecretExposureResponseOutcome::RequestContextIneligible
        } else if !observation.response_content_encoding_absent() {
            SecretExposureResponseOutcome::ContentCoded
        } else if !observation.response_content_length_consistent() {
            SecretExposureResponseOutcome::ContentLengthInconsistent
        } else if !supported_media_type(observation.media_type()) {
            SecretExposureResponseOutcome::UnsupportedMediaType
        } else {
            let body = observation.complete_body().expect("checked complete body");
            if u64::try_from(body.len()).unwrap_or(u64::MAX) != observation.response_body_bytes() {
                SecretExposureResponseOutcome::ContentLengthInconsistent
            } else if body.len() > MAX_SECRET_EXPOSURE_BODY_BYTES {
                SecretExposureResponseOutcome::ResponseByteLimitExceeded
            } else {
                let admitted_bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
                match state
                    .admitted_inspection_byte_count
                    .checked_add(admitted_bytes)
                    .filter(|total| *total <= MAX_SECRET_EXPOSURE_TOTAL_BODY_BYTES)
                {
                    None => SecretExposureResponseOutcome::TotalByteLimitExceeded,
                    Some(total) => {
                        // Reserve detector work before UTF-8 and detector parsing. A
                        // repeatedly malformed or over-complex body must not obtain a
                        // fresh 4 MiB allowance merely because interpretation refused it.
                        // The public audit continues to report only bytes that were
                        // successfully interpreted, not this private admission counter.
                        state.admitted_inspection_byte_count = total;
                        match scan_complete_text_body(body) {
                            Ok(result) => {
                                inspected_body_bytes = result.inspected_body_bytes() as u64;
                                state.interpreted_byte_count = state
                                    .interpreted_byte_count
                                    .checked_add(inspected_body_bytes)
                                    .expect("admitted detector bytes bound interpreted bytes");
                                scan = Some(result);
                                SecretExposureResponseOutcome::Evaluated
                            },
                            Err(SecretExposureScanError::InvalidUtf8 { .. }) => {
                                SecretExposureResponseOutcome::InvalidUtf8
                            },
                            Err(SecretExposureScanError::BodyLimitExceeded { .. }) => {
                                SecretExposureResponseOutcome::ResponseByteLimitExceeded
                            },
                            Err(
                                SecretExposureScanError::PemPayloadLimitExceeded { .. }
                                | SecretExposureScanError::TokenLimitExceeded { .. }
                                | SecretExposureScanError::OccurrenceLimitExceeded { .. },
                            ) => SecretExposureResponseOutcome::DetectorLimitExceeded,
                        }
                    },
                }
            }
        };

        let mut retained = Vec::new();
        let mut omitted = 0_u64;
        if let Some(result) = scan.as_ref() {
            for row in result.class_counts() {
                if state.retained_observation_count < MAX_SECRET_EXPOSURE_RETAINED_OBSERVATIONS {
                    state.retained_observation_count += 1;
                    retained.push(*row);
                } else {
                    omitted = omitted.saturating_add(1);
                }
            }
        }
        drop(state);

        let occurrence_count = scan
            .as_ref()
            .map_or(0, SecretExposureScan::occurrence_count);
        // The fixed detector catalogue is intentionally finite. A zero-match
        // result therefore cannot prove that the complete body contains no
        // other low-entropy secret. Every selected response uses value-free
        // lineage instead of the ordinary public whole-body digest and body-
        // derived projection, so the digest cannot become a dictionary oracle.
        let suppress_public_body_digest = true;
        let mut records = vec![
            (
                RESPONSE_SEQUENCE,
                EvidenceValue::Unsigned(u64::from(response_sequence)),
            ),
            (
                RESPONSE_OUTCOME,
                EvidenceValue::Text(outcome.as_str().to_owned()),
            ),
            (
                INSPECTED_BODY_BYTES,
                EvidenceValue::Unsigned(inspected_body_bytes),
            ),
            (
                MATCH_OCCURRENCE_COUNT,
                EvidenceValue::Unsigned(u64::from(occurrence_count)),
            ),
            (OMITTED_OBSERVATION_COUNT, EvidenceValue::Unsigned(omitted)),
            (
                BODY_DERIVED_PROJECTION_SUPPRESSED,
                EvidenceValue::Boolean(suppress_public_body_digest),
            ),
        ];
        records.extend(retained.iter().map(|row| {
            (
                row.class().predicate_name(),
                EvidenceValue::Unsigned(u64::from(row.occurrence_count())),
            )
        }));
        if suppress_public_body_digest {
            records.push((
                RESPONSE_BODY_LINEAGE,
                EvidenceValue::Text(outcome.as_str().to_owned()),
            ));
        }
        let derivation = EvidenceDerivation::new(
            parents,
            DerivationAlgorithm::new(SECRET_EXPOSURE_ALGORITHM, SECRET_EXPOSURE_ALGORITHM_VERSION)?,
        )?;
        let source = EvidenceSource::new(HTTP_EVIDENCE_EXECUTOR_ID, SECRET_EXPOSURE_SOURCE_METHOD)?
            .with_correlation_id(observation.case_id())?;
        records
            .into_iter()
            .map(|(name, value)| {
                Ok(Evidence::new(
                    observation.subject().clone(),
                    EvidenceKind::Custom(SECRET_EXPOSURE_CATEGORY.to_owned()),
                    KnowledgePredicate::new(SECRET_EXPOSURE_NAMESPACE, name)?,
                    value,
                    source.clone(),
                    observation.reliability(),
                )
                .derived_from(derivation.clone()))
            })
            .collect()
    }
}

fn supported_media_type(media_type: Option<&str>) -> bool {
    let Some(media_type) = media_type else {
        return false;
    };
    media_type.starts_with("text/")
        || matches!(
            media_type,
            "application/json"
                | "application/ld+json"
                | "application/javascript"
                | "application/x-javascript"
                | "application/xml"
                | "application/xhtml+xml"
                | "application/x-www-form-urlencoded"
                | "image/svg+xml"
        )
        || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
}

/// Validates the value-free per-response record used as replacement lineage
/// when the ordinary unkeyed body digest is deliberately suppressed.
pub(crate) fn is_secret_exposure_response_lineage(
    evidence: &Evidence,
    expected_subject: &EntityId,
    expected_correlation_id: &str,
    expected_parent_ids: &[EvidenceId],
) -> bool {
    let EvidenceValue::Text(outcome) = evidence.value() else {
        return false;
    };
    let Some(derivation) = evidence.origin().derivation() else {
        return false;
    };
    let mut actual_parents = derivation.parents().to_vec();
    actual_parents.sort();
    let mut expected_parents = expected_parent_ids.to_vec();
    expected_parents.sort();
    evidence.subject() == expected_subject
        && evidence.kind() == &EvidenceKind::Custom(SECRET_EXPOSURE_CATEGORY.to_owned())
        && evidence.predicate().namespace() == SECRET_EXPOSURE_NAMESPACE
        && evidence.predicate().name() == RESPONSE_BODY_LINEAGE
        && evidence.source().component() == HTTP_EVIDENCE_EXECUTOR_ID
        && evidence.source().method() == SECRET_EXPOSURE_SOURCE_METHOD
        && evidence.source().correlation_id() == Some(expected_correlation_id)
        && SecretExposureResponseOutcome::parse(outcome).is_some()
        && derivation.algorithm().name() == SECRET_EXPOSURE_ALGORITHM
        && derivation.algorithm().version() == SECRET_EXPOSURE_ALGORITHM_VERSION
        && !expected_parents.is_empty()
        && !expected_parents.windows(2).any(|pair| pair[0] == pair[1])
        && actual_parents == expected_parents
}

pub(crate) fn secret_exposure_response_lineage_id(
    evidence: &[Evidence],
    expected_subject: &EntityId,
    expected_correlation_id: &str,
    expected_parent_ids: &[EvidenceId],
) -> Option<EvidenceId> {
    let mut matching = evidence.iter().filter(|item| {
        is_secret_exposure_response_lineage(
            item,
            expected_subject,
            expected_correlation_id,
            expected_parent_ids,
        )
    });
    let id = matching.next()?.id().clone();
    matching.next().is_none().then_some(id)
}

/// Projects one value-free body identity for an already planned active-review
/// response. Selecting S04 suppresses the ordinary unkeyed body digest for
/// these responses without treating probe/reflection material as a detector
/// finding or changing the active review's semantic projection.
pub(crate) fn project_active_review_body_privacy_lineage(
    observation: &crate::http_evidence::CompleteHttpResponseObservation<'_>,
) -> Result<Evidence, HttpEvidenceError> {
    let parents = secret_exposure_observation_parent_ids(observation)?;
    let derivation = EvidenceDerivation::new(
        parents,
        DerivationAlgorithm::new(
            ACTIVE_REVIEW_PRIVACY_ALGORITHM,
            ACTIVE_REVIEW_PRIVACY_ALGORITHM_VERSION,
        )?,
    )?;
    let source = EvidenceSource::new(
        observation.executor_id(),
        ACTIVE_REVIEW_PRIVACY_SOURCE_METHOD,
    )?
    .with_correlation_id(observation.case_id())?;
    Ok(Evidence::new(
        observation.subject().clone(),
        EvidenceKind::Custom(SECRET_EXPOSURE_CATEGORY.to_owned()),
        KnowledgePredicate::new(SECRET_EXPOSURE_NAMESPACE, ACTIVE_REVIEW_BODY_LINEAGE)?,
        EvidenceValue::Boolean(true),
        source,
        observation.reliability(),
    )
    .derived_from(derivation))
}

pub(crate) fn is_active_review_body_privacy_lineage(
    evidence: &Evidence,
    expected_subject: &EntityId,
    expected_correlation_id: &str,
    expected_executor_id: &str,
    expected_parent_ids: &[EvidenceId],
) -> bool {
    let Some(derivation) = evidence.origin().derivation() else {
        return false;
    };
    let mut actual_parents = derivation.parents().to_vec();
    actual_parents.sort();
    let mut expected_parents = expected_parent_ids.to_vec();
    expected_parents.sort();
    evidence.subject() == expected_subject
        && evidence.kind() == &EvidenceKind::Custom(SECRET_EXPOSURE_CATEGORY.to_owned())
        && evidence.predicate().namespace() == SECRET_EXPOSURE_NAMESPACE
        && evidence.predicate().name() == ACTIVE_REVIEW_BODY_LINEAGE
        && evidence.value() == &EvidenceValue::Boolean(true)
        && evidence.source().component() == expected_executor_id
        && evidence.source().method() == ACTIVE_REVIEW_PRIVACY_SOURCE_METHOD
        && evidence.source().correlation_id() == Some(expected_correlation_id)
        && derivation.algorithm().name() == ACTIVE_REVIEW_PRIVACY_ALGORITHM
        && derivation.algorithm().version() == ACTIVE_REVIEW_PRIVACY_ALGORITHM_VERSION
        && !expected_parents.is_empty()
        && !expected_parents.windows(2).any(|pair| pair[0] == pair[1])
        && actual_parents == expected_parents
}

pub(crate) fn secret_exposure_observation_parent_ids(
    observation: &crate::http_evidence::CompleteHttpResponseObservation<'_>,
) -> Result<Vec<EvidenceId>, HttpEvidenceError> {
    let mut parents = [
        (
            observation.request_method_evidence_id(),
            "secret-exposure-request-method-evidence",
        ),
        (
            observation.request_url_evidence_id(),
            "secret-exposure-request-url-evidence",
        ),
        (
            observation.response_status_evidence_id(),
            "secret-exposure-response-status-evidence",
        ),
        (
            observation.response_final_url_evidence_id(),
            "secret-exposure-response-final-url-evidence",
        ),
        (
            observation.response_body_bytes_evidence_id(),
            "secret-exposure-response-body-byte-count-evidence",
        ),
        (
            observation.response_body_truncated_evidence_id(),
            "secret-exposure-response-body-truncated-evidence",
        ),
    ]
    .into_iter()
    .map(|(id, invariant)| {
        id.cloned()
            .ok_or(HttpEvidenceError::AssessmentObserverInvariant { invariant })
    })
    .collect::<Result<Vec<_>, _>>()?;
    if let Some(media) = observation.response_media_type_evidence_id() {
        parents.push(media.clone());
    }
    Ok(parents)
}

/// Reconstructs the exact direct response facts that may authorize the
/// value-free replacement lineage. This deliberately excludes other receipt
/// evidence, including rate-limit and semantic projections.
pub(crate) fn secret_exposure_response_parent_ids(
    evidence: &[Evidence],
    expected_subject: &EntityId,
    expected_correlation_id: &str,
) -> Option<Vec<EvidenceId>> {
    secret_exposure_response_parent_ids_for_executor(
        evidence,
        expected_subject,
        expected_correlation_id,
        HTTP_EVIDENCE_EXECUTOR_ID,
    )
}

pub(crate) fn secret_exposure_response_parent_ids_for_executor(
    evidence: &[Evidence],
    expected_subject: &EntityId,
    expected_correlation_id: &str,
    expected_executor_id: &str,
) -> Option<Vec<EvidenceId>> {
    let required = [
        (
            HttpEvidencePredicate::REQUEST_METHOD,
            EvidenceKind::Http,
            "request-method",
        ),
        (
            HttpEvidencePredicate::REQUEST_URL,
            EvidenceKind::Http,
            "request-url",
        ),
        (
            HttpEvidencePredicate::RESPONSE_STATUS,
            EvidenceKind::Http,
            "response-status",
        ),
        (
            HttpEvidencePredicate::RESPONSE_FINAL_URL,
            EvidenceKind::Http,
            "response-final-url",
        ),
        (
            HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED,
            EvidenceKind::Content,
            "response-body-size",
        ),
        (
            HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED,
            EvidenceKind::Content,
            "response-body-truncation",
        ),
    ];
    let mut parent_ids = Vec::with_capacity(required.len() + 1);
    for (descriptor, kind, source_method) in required {
        let predicate = descriptor.into_knowledge();
        let mut matches = evidence
            .iter()
            .filter(|item| item.predicate() == &predicate);
        let item = matches.next()?;
        if matches.next().is_some()
            || !valid_secret_exposure_response_parent(
                item,
                descriptor,
                &kind,
                source_method,
                expected_subject,
                expected_correlation_id,
                expected_executor_id,
            )
        {
            return None;
        }
        parent_ids.push(item.id().clone());
    }

    let media_predicate = HttpEvidencePredicate::RESPONSE_MEDIA_TYPE.into_knowledge();
    let mut media = evidence
        .iter()
        .filter(|item| item.predicate() == &media_predicate);
    if let Some(item) = media.next() {
        if media.next().is_some()
            || !valid_secret_exposure_response_parent(
                item,
                HttpEvidencePredicate::RESPONSE_MEDIA_TYPE,
                &EvidenceKind::Http,
                "response-media-type",
                expected_subject,
                expected_correlation_id,
                expected_executor_id,
            )
        {
            return None;
        }
        parent_ids.push(item.id().clone());
    }
    parent_ids.sort();
    (!parent_ids.windows(2).any(|pair| pair[0] == pair[1])).then_some(parent_ids)
}

fn valid_secret_exposure_response_parent(
    evidence: &Evidence,
    descriptor: PredicateDescriptor,
    expected_kind: &EvidenceKind,
    expected_source_method: &str,
    expected_subject: &EntityId,
    expected_correlation_id: &str,
    expected_executor_id: &str,
) -> bool {
    if evidence.subject() != expected_subject
        || evidence.kind() != expected_kind
        || evidence.source().component() != expected_executor_id
        || evidence.source().method() != expected_source_method
        || evidence.source().correlation_id() != Some(expected_correlation_id)
        || !matches!(evidence.origin(), EvidenceOrigin::Direct)
    {
        return false;
    }
    match descriptor {
        HttpEvidencePredicate::REQUEST_METHOD => {
            matches!(evidence.value(), EvidenceValue::Text(value) if matches!(value.as_str(), "GET" | "HEAD"))
        },
        HttpEvidencePredicate::REQUEST_URL | HttpEvidencePredicate::RESPONSE_FINAL_URL => {
            matches!(evidence.value(), EvidenceValue::Text(value) if !value.is_empty())
        },
        HttpEvidencePredicate::RESPONSE_STATUS => {
            matches!(evidence.value(), EvidenceValue::Unsigned(value) if (100..=599).contains(value))
        },
        HttpEvidencePredicate::RESPONSE_BODY_BYTES_OBSERVED => {
            matches!(evidence.value(), EvidenceValue::Unsigned(_))
        },
        HttpEvidencePredicate::RESPONSE_BODY_TRUNCATED => {
            matches!(evidence.value(), EvidenceValue::Boolean(_))
        },
        HttpEvidencePredicate::RESPONSE_MEDIA_TYPE => {
            matches!(evidence.value(), EvidenceValue::Text(value) if !value.is_empty())
        },
        _ => false,
    }
}

#[derive(Default, PartialEq, Eq)]
pub(crate) struct CommittedSecretExposureLedger {
    receipts: BTreeMap<(EntityId, String, DecisionExecutionStage), Vec<EvidenceId>>,
    outcomes: BTreeMap<SecretExposureResponseOutcome, u32>,
    observations: Vec<SecretExposureObservation>,
    response_count: u32,
    interpreted_byte_count: u64,
    body_derived_projection_suppressed_response_count: u32,
    omitted_observation_count: u32,
    match_occurrence_count: u64,
}

impl fmt::Debug for CommittedSecretExposureLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedSecretExposureLedger")
            .field("response_count", &self.response_count)
            .field("observation_count", &self.observations.len())
            .finish()
    }
}

impl CommittedSecretExposureLedger {
    pub(crate) fn ingest_receipt(
        &mut self,
        receipt: &DecisionEvidenceReceipt,
        knowledge: &KnowledgeBase,
        expected_subject: &WebAssessmentSubject,
    ) -> Result<(), ()> {
        if receipt.executor_id() != HTTP_EVIDENCE_EXECUTOR_ID
            || receipt.stage() != DecisionExecutionStage::Passive
            || receipt.case().id() != BOOTSTRAP_CASE_ID
            || receipt.case().action_id() != BOOTSTRAP_ACTION_ID
            || receipt.case().hypothesis_id() != BOOTSTRAP_HYPOTHESIS_ID
            || receipt.case().payload_strategy().is_some()
            || !receipt.case().applies_hypothesis_transition()
            || receipt.case().subject().as_str() != format!("endpoint:{}", expected_subject.url())
            || receipt.evidence().len() != receipt.writes().len()
        {
            return Err(());
        }
        for (evidence, write) in receipt.write_set() {
            if !matches!(write, KnowledgeWrite::Inserted | KnowledgeWrite::Unchanged)
                || evidence.subject() != receipt.case().subject()
                || knowledge.evidence(evidence.id()).as_ref() != Some(evidence)
            {
                return Err(());
            }
        }
        let secret = receipt
            .evidence()
            .iter()
            .filter(|item| item.predicate().namespace() == SECRET_EXPOSURE_NAMESPACE)
            .collect::<Vec<_>>();
        if secret.len() < 6 || secret.len() > 11 {
            return Err(());
        }
        let lineage = secret
            .iter()
            .copied()
            .filter(|item| item.predicate().name() == RESPONSE_BODY_LINEAGE)
            .collect::<Vec<_>>();
        if lineage.len() > 1 {
            return Err(());
        }
        let detail = secret
            .iter()
            .copied()
            .filter(|item| item.predicate().name() != RESPONSE_BODY_LINEAGE)
            .collect::<Vec<_>>();
        if detail.len() < 6 || detail.len() > 10 {
            return Err(());
        }
        let key = (
            receipt.case().subject().clone(),
            receipt.case().id().to_owned(),
            receipt.stage(),
        );
        let evidence_ids = secret
            .iter()
            .map(|item| item.id().clone())
            .collect::<Vec<_>>();
        if let Some(existing) = self.receipts.get(&key) {
            return if existing == &evidence_ids {
                Ok(())
            } else {
                Err(())
            };
        }

        let expected_parents = secret_exposure_response_parent_ids(
            receipt.evidence(),
            receipt.case().subject(),
            receipt.case().id(),
        )
        .ok_or(())?;
        let first = *detail.first().ok_or(())?;
        let EvidenceOrigin::Derived(first_derivation) = first.origin() else {
            return Err(());
        };
        let mut canonical_parents = first_derivation.parents().to_vec();
        canonical_parents.sort();
        if canonical_parents != expected_parents
            || first_derivation.algorithm().name() != SECRET_EXPOSURE_ALGORITHM
            || first_derivation.algorithm().version() != SECRET_EXPOSURE_ALGORITHM_VERSION
        {
            return Err(());
        }
        for item in &secret {
            let EvidenceOrigin::Derived(derivation) = item.origin() else {
                return Err(());
            };
            if item.subject() != receipt.case().subject()
                || item.kind() != &EvidenceKind::Custom(SECRET_EXPOSURE_CATEGORY.to_owned())
                || item.source().component() != HTTP_EVIDENCE_EXECUTOR_ID
                || item.source().method() != SECRET_EXPOSURE_SOURCE_METHOD
                || item.source().correlation_id() != Some(receipt.case().id())
                || derivation.algorithm().name() != SECRET_EXPOSURE_ALGORITHM
                || derivation.algorithm().version() != SECRET_EXPOSURE_ALGORITHM_VERSION
                || {
                    let mut parents = derivation.parents().to_vec();
                    parents.sort();
                    parents != canonical_parents
                }
            {
                return Err(());
            }
        }

        let sequence = expect_unsigned(detail[0], RESPONSE_SEQUENCE)?;
        if sequence != u64::from(self.response_count.saturating_add(1)) {
            return Err(());
        }
        let outcome = expect_text(detail[1], RESPONSE_OUTCOME)
            .and_then(SecretExposureResponseOutcome::parse)
            .ok_or(())?;
        let interpreted = expect_unsigned(detail[2], INSPECTED_BODY_BYTES)?;
        let occurrences = expect_unsigned(detail[3], MATCH_OCCURRENCE_COUNT)?;
        let omitted = expect_unsigned(detail[4], OMITTED_OBSERVATION_COUNT)?;
        let suppression_declared = expect_boolean(detail[5], BODY_DERIVED_PROJECTION_SUPPRESSED)?;
        if occurrences > u64::from(MAX_SECRET_EXPOSURE_OCCURRENCES)
            || omitted > 4
            || (outcome == SecretExposureResponseOutcome::Evaluated
                && interpreted > MAX_SECRET_EXPOSURE_BODY_BYTES as u64)
            || (outcome != SecretExposureResponseOutcome::Evaluated && interpreted != 0)
        {
            return Err(());
        }
        let mut class_occurrences = 0_u64;
        let mut seen_classes = BTreeMap::new();
        let mut pending_observations = Vec::new();
        for item in &detail[6..] {
            let class = SecretExposureDetectorClass::parse_predicate_name(item.predicate().name())
                .ok_or(())?;
            let count = expect_unsigned(item, class.predicate_name())?;
            if count == 0 || count > u64::from(MAX_SECRET_EXPOSURE_OCCURRENCES) {
                return Err(());
            }
            if seen_classes.insert(class, ()).is_some() {
                return Err(());
            }
            class_occurrences = class_occurrences.checked_add(count).ok_or(())?;
            pending_observations.push(SecretExposureObservation {
                subject: receipt.case().subject().clone(),
                detector_class: class,
                occurrence_count: u16::try_from(count).map_err(|_| ())?,
                evidence_ids: vec![item.id().clone()],
            });
        }
        if outcome != SecretExposureResponseOutcome::Evaluated
            && (occurrences != 0 || omitted != 0 || !pending_observations.is_empty())
        {
            return Err(());
        }
        if !suppression_declared {
            return Err(());
        }
        match lineage.as_slice() {
            [item]
                if is_secret_exposure_response_lineage(
                    item,
                    receipt.case().subject(),
                    receipt.case().id(),
                    &expected_parents,
                ) => {},
            _ => return Err(()),
        }
        if omitted == 0 && class_occurrences != occurrences {
            return Err(());
        }
        if omitted != 0 && class_occurrences >= occurrences {
            return Err(());
        }
        let next_interpreted = self
            .interpreted_byte_count
            .checked_add(interpreted)
            .filter(|total| *total <= MAX_SECRET_EXPOSURE_TOTAL_BODY_BYTES)
            .ok_or(())?;
        if self
            .observations
            .len()
            .checked_add(pending_observations.len())
            .is_none_or(|count| count > MAX_SECRET_EXPOSURE_RETAINED_OBSERVATIONS)
        {
            return Err(());
        }
        let next_omitted = self
            .omitted_observation_count
            .checked_add(u32::try_from(omitted).map_err(|_| ())?)
            .ok_or(())?;
        let next_occurrences = self
            .match_occurrence_count
            .checked_add(occurrences)
            .ok_or(())?;
        let next_suppressed = self
            .body_derived_projection_suppressed_response_count
            .checked_add(1)
            .ok_or(())?;

        self.response_count = self.response_count.saturating_add(1);
        self.interpreted_byte_count = next_interpreted;
        self.body_derived_projection_suppressed_response_count = next_suppressed;
        self.omitted_observation_count = next_omitted;
        self.match_occurrence_count = next_occurrences;
        *self.outcomes.entry(outcome).or_default() += 1;
        self.observations.extend(pending_observations);
        self.receipts.insert(key, evidence_ids);
        Ok(())
    }

    pub(crate) fn audit(&self) -> WebAssessmentSecretExposureAudit {
        let outcomes = SecretExposureResponseOutcome::ALL
            .into_iter()
            .filter_map(|outcome| {
                self.outcomes
                    .get(&outcome)
                    .copied()
                    .map(|count| SecretExposureOutcomeCount { outcome, count })
            })
            .collect();
        WebAssessmentSecretExposureAudit {
            outcomes,
            observations: self.observations.clone(),
            response_count: self.response_count,
            evaluated_response_count: self
                .outcomes
                .get(&SecretExposureResponseOutcome::Evaluated)
                .copied()
                .unwrap_or(0),
            interpreted_byte_count: self.interpreted_byte_count,
            body_derived_projection_suppressed_response_count: self
                .body_derived_projection_suppressed_response_count,
            omitted_observation_count: self.omitted_observation_count,
            match_occurrence_count: self.match_occurrence_count,
        }
    }
}

fn expect_boolean(item: &Evidence, name: &str) -> Result<bool, ()> {
    if item.predicate().name() != name {
        return Err(());
    }
    match item.value() {
        EvidenceValue::Boolean(value) => Ok(*value),
        _ => Err(()),
    }
}

fn expect_unsigned(item: &Evidence, name: &str) -> Result<u64, ()> {
    if item.predicate().name() != name {
        return Err(());
    }
    match item.value() {
        EvidenceValue::Unsigned(value) => Ok(*value),
        _ => Err(()),
    }
}

fn expect_text<'a>(item: &'a Evidence, name: &str) -> Option<&'a str> {
    if item.predicate().name() != name {
        return None;
    }
    match item.value() {
        EvidenceValue::Text(value) => Some(value),
        _ => None,
    }
}

pub(crate) fn project_secret_exposure_items(
    context: &mut AssessmentProjectionContext,
    knowledge: &KnowledgeBase,
    ledger: &CommittedSecretExposureLedger,
) -> Result<(), AssessmentItemProjectionError> {
    let target = AssessmentItemTarget::subject();
    for observation in &ledger.observations {
        for evidence_id in &observation.evidence_ids {
            context.register_evidence(knowledge, evidence_id)?;
        }
        context.project_observation(
            observation.detector_class.capability(),
            knowledge,
            &observation.subject,
            &target,
            &observation.evidence_ids,
        )?;
    }
    Ok(())
}

fn looks_like_placeholder(value: &[u8]) -> bool {
    [
        b"example".as_slice(),
        b"placeholder".as_slice(),
        b"redacted".as_slice(),
        b"changeme".as_slice(),
        b"replace_me".as_slice(),
        b"replace-me".as_slice(),
        b"your_".as_slice(),
        b"your-".as_slice(),
        b"sample".as_slice(),
    ]
    .into_iter()
    .any(|needle| contains_ascii_case_insensitive(value, needle))
}

fn strip_ascii_case_insensitive_prefix<'a>(value: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    (value.len() >= prefix.len() && equals_ascii_case_insensitive(&value[..prefix.len()], prefix))
        .then_some(&value[prefix.len()..])
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|candidate| equals_ascii_case_insensitive(candidate, needle))
}

fn equals_ascii_case_insensitive(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty() && needle.len() <= haystack.len())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_evidence::{
        complete_http_response_observation_for_test, passive_response_projection_for_test,
        CompleteHttpResponseObservationTestInput,
    };
    use termivar_core::ConfidenceScore;
    use url::Url;

    const AWS_ID: &str = "AKIAZ9Y8X7W6V5U4T3S2";
    const AWS_SECRET: &str = "aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5bC7d";
    const STRIPE_PAYLOAD: &str = "Ab3dEf5hIj7kLm9nPq2rSt4v";
    const BEARER_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.AbCdEfGhIjKlMnOp.QrStUvWxYz12";

    fn count(body: &[u8], class: SecretExposureDetectorClass) -> u16 {
        scan_complete_text_body(body)
            .expect("synthetic text body should scan")
            .count_for(class)
    }

    fn observe_body(
        collector: &SecretExposureCollector,
        subject: &EntityId,
        url: &Url,
        body: &[u8],
    ) -> Vec<Evidence> {
        let passive = passive_response_projection_for_test(&[]);
        let parents = (0..6).map(|_| EvidenceId::new()).collect::<Vec<_>>();
        let observation =
            complete_http_response_observation_for_test(CompleteHttpResponseObservationTestInput {
                case_id: BOOTSTRAP_CASE_ID,
                action_id: BOOTSTRAP_ACTION_ID,
                executor_id: HTTP_EVIDENCE_EXECUTOR_ID,
                hypothesis_id: BOOTSTRAP_HYPOTHESIS_ID,
                has_payload_strategy: false,
                payload_strategy: None,
                applies_hypothesis_transition: true,
                stage: DecisionExecutionStage::Passive,
                subject,
                method: HttpProbeMethod::Get,
                requested_url: url,
                status: 200,
                media_type: Some("text/plain"),
                reliability: ConfidenceScore::MAX,
                complete_body: Some(body),
                request_method_evidence_id: Some(&parents[0]),
                request_url_evidence_id: Some(&parents[1]),
                response_status_evidence_id: Some(&parents[2]),
                response_final_url_evidence_id: Some(&parents[3]),
                response_media_type_evidence_id: Some(&parents[4]),
                response_body_truncated_evidence_id: Some(&parents[5]),
                response_body_digest_evidence_id: None,
                passive_response_projection: &passive,
                review_response_projection: None,
            });
        collector
            .observe(&observation, parents.clone())
            .expect("bounded synthetic response should project")
    }

    fn projected_outcome(evidence: &[Evidence]) -> &str {
        let row = evidence
            .iter()
            .find(|item| item.predicate().name() == RESPONSE_OUTCOME)
            .expect("projection contains response outcome");
        let EvidenceValue::Text(outcome) = row.value() else {
            panic!("response outcome must be text")
        };
        outcome
    }

    fn pem(label: PemLabel, payload: &str) -> String {
        format!(
            "{}\n{}\n{}\n",
            str::from_utf8(label.begin()).expect("fixed marker is UTF-8"),
            payload,
            str::from_utf8(label.end()).expect("fixed marker is UTF-8")
        )
    }

    #[test]
    fn detector_class_tokens_and_output_order_are_stable() {
        let body = format!(
            "Authorization: Bearer {BEARER_TOKEN}\nstripe=sk_live_{STRIPE_PAYLOAD}\nAWS_ACCESS_KEY_ID={AWS_ID}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\n{}",
            pem(PemLabel::Pkcs8, &format!("M{}", "A".repeat(63)))
        );
        let scan = scan_complete_text_body(body.as_bytes()).expect("fixture should scan");
        let actual = scan
            .class_counts()
            .iter()
            .map(|entry| (entry.class().as_str(), entry.occurrence_count()))
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![
                ("pem_private_key_block", 1),
                ("aws_access_key_pair", 1),
                ("stripe_live_secret", 1),
                ("authorization_bearer_assignment", 1),
            ]
        );
        assert_eq!(scan.occurrence_count(), 4);
        assert_eq!(scan.inspected_body_bytes(), body.len());
    }

    #[test]
    fn body_limit_accepts_limit_and_rejects_limit_plus_one() {
        let accepted = vec![b' '; MAX_SECRET_EXPOSURE_BODY_BYTES];
        let scan = scan_complete_text_body(&accepted).expect("exact body limit should scan");
        assert_eq!(scan.inspected_body_bytes(), accepted.len());
        assert_eq!(scan.occurrence_count(), 0);

        let rejected = vec![b' '; MAX_SECRET_EXPOSURE_BODY_BYTES + 1];
        assert_eq!(
            scan_complete_text_body(&rejected),
            Err(SecretExposureScanError::BodyLimitExceeded {
                body_bytes: rejected.len(),
                max_body_bytes: MAX_SECRET_EXPOSURE_BODY_BYTES,
            })
        );
    }

    #[test]
    fn invalid_utf8_is_value_free_refusal() {
        let body = b"private-canary-\xff";
        let error = scan_complete_text_body(body).expect_err("invalid UTF-8 must be refused");
        assert_eq!(
            error,
            SecretExposureScanError::InvalidUtf8 {
                body_bytes: body.len()
            }
        );
        assert!(!format!("{error:?} {error}").contains("private-canary"));
    }

    #[test]
    fn admitted_refusals_share_the_four_mib_detector_work_ceiling() {
        let collector = SecretExposureCollector::default();
        let url = Url::parse("https://example.test/").unwrap();
        let subject = EntityId::new("endpoint:https://example.test/").unwrap();

        let mut invalid_utf8 = vec![b' '; MAX_SECRET_EXPOSURE_BODY_BYTES];
        *invalid_utf8.last_mut().unwrap() = 0xff;
        let mut detector_limited = format!(
            "Authorization: Bearer {}",
            "A".repeat(MAX_SECRET_EXPOSURE_TOKEN_BYTES + 1)
        )
        .into_bytes();
        detector_limited.resize(MAX_SECRET_EXPOSURE_BODY_BYTES, b' ');

        for _ in 0..16 {
            assert_eq!(
                projected_outcome(&observe_body(&collector, &subject, &url, &invalid_utf8)),
                SecretExposureResponseOutcome::InvalidUtf8.as_str()
            );
        }
        for _ in 0..16 {
            assert_eq!(
                projected_outcome(&observe_body(&collector, &subject, &url, &detector_limited)),
                SecretExposureResponseOutcome::DetectorLimitExceeded.as_str()
            );
        }

        let state = collector.state.lock().unwrap();
        assert_eq!(
            state.admitted_inspection_byte_count,
            MAX_SECRET_EXPOSURE_TOTAL_BODY_BYTES
        );
        assert_eq!(state.interpreted_byte_count, 0);
        drop(state);

        assert_eq!(
            projected_outcome(&observe_body(&collector, &subject, &url, b"safe")),
            SecretExposureResponseOutcome::TotalByteLimitExceeded.as_str()
        );
        let state = collector.state.lock().unwrap();
        assert_eq!(
            state.admitted_inspection_byte_count,
            MAX_SECRET_EXPOSURE_TOTAL_BODY_BYTES
        );
        assert_eq!(state.interpreted_byte_count, 0);
    }

    #[test]
    fn pem_private_key_labels_require_matched_structural_blocks() {
        let fixtures = [
            (PemLabel::Pkcs8, format!("M{}", "A1b".repeat(21))),
            (PemLabel::Rsa, format!("M{}", "C3d".repeat(21))),
            (PemLabel::Ec, format!("M{}", "E5f".repeat(21))),
            (
                PemLabel::OpenSsh,
                format!("b3BlbnNzaC1rZXktdjE{}", "G7h".repeat(15)),
            ),
        ];
        for (label, payload) in fixtures {
            assert_eq!(
                count(
                    pem(label, &payload).as_bytes(),
                    SecretExposureDetectorClass::PemPrivateKeyBlock
                ),
                1
            );
        }

        let near_misses = [
            "-----BEGIN PUBLIC KEY-----\nM".to_owned()
                + &"A".repeat(63)
                + "\n-----END PUBLIC KEY-----\n",
            "-----BEGIN PRIVATE KEY-----\nM".to_owned() + &"A".repeat(63),
            pem(PemLabel::Pkcs8, &format!("A{}", "B".repeat(63))),
            "-----BEGIN PRIVATE KEY-----\nMIIA!not-base64\n-----END PRIVATE KEY-----\n".to_owned(),
            "-----BEGIN PRIVATE KEY-----\nMIIA\n-----END RSA PRIVATE KEY-----\n".to_owned(),
        ];
        for body in near_misses {
            assert_eq!(
                count(
                    body.as_bytes(),
                    SecretExposureDetectorClass::PemPrivateKeyBlock
                ),
                0,
                "near miss must abstain"
            );
        }
    }

    #[test]
    fn pem_payload_limit_accepts_limit_and_rejects_limit_plus_one() {
        let accepted_payload =
            format!("M{}", "A".repeat(MAX_SECRET_EXPOSURE_PEM_PAYLOAD_BYTES - 1));
        assert_eq!(
            count(
                pem(PemLabel::Pkcs8, &accepted_payload).as_bytes(),
                SecretExposureDetectorClass::PemPrivateKeyBlock
            ),
            1
        );

        let rejected_payload = format!("M{}", "A".repeat(MAX_SECRET_EXPOSURE_PEM_PAYLOAD_BYTES));
        let body = pem(PemLabel::Pkcs8, &rejected_payload);
        assert_eq!(
            scan_complete_text_body(body.as_bytes()),
            Err(SecretExposureScanError::PemPayloadLimitExceeded {
                body_bytes: body.len(),
                max_payload_bytes: MAX_SECRET_EXPOSURE_PEM_PAYLOAD_BYTES,
            })
        );
    }

    #[test]
    fn aws_requires_one_to_one_paired_assignments() {
        let forward = format!("AWS_ACCESS_KEY_ID={AWS_ID}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\n");
        let reverse =
            format!("aws_secret_access_key: '{AWS_SECRET}'\naws_access_key_id: '{AWS_ID}'\n");
        let same_line = format!(
            "{{\"aws_access_key_id\":\"{AWS_ID}\",\"aws_secret_access_key\":\"{AWS_SECRET}\"}}"
        );
        for body in [forward, reverse, same_line] {
            assert_eq!(
                count(
                    body.as_bytes(),
                    SecretExposureDetectorClass::AwsAccessKeyPair
                ),
                1
            );
        }

        assert_eq!(
            count(
                format!("AWS_ACCESS_KEY_ID={AWS_ID}").as_bytes(),
                SecretExposureDetectorClass::AwsAccessKeyPair
            ),
            0
        );
        assert_eq!(
            count(
                format!("AWS_SECRET_ACCESS_KEY={AWS_SECRET}").as_bytes(),
                SecretExposureDetectorClass::AwsAccessKeyPair
            ),
            0
        );
    }

    #[test]
    fn aws_rejects_documentation_placeholders_and_malformed_values() {
        let documentation = concat!(
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        );
        let placeholder = concat!(
            "AWS_ACCESS_KEY_ID=AKIAYOURACCESSKEY12\n",
            "AWS_SECRET_ACCESS_KEY=YOUR_SECRET_ACCESS_KEY_PLACEHOLDER_12345\n"
        );
        let low_variety = concat!(
            "AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA\n",
            "AWS_SECRET_ACCESS_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        );
        for body in [documentation, placeholder, low_variety] {
            assert_eq!(
                count(
                    body.as_bytes(),
                    SecretExposureDetectorClass::AwsAccessKeyPair
                ),
                0
            );
        }
    }

    #[test]
    fn aws_pair_window_has_byte_and_line_limit_plus_one_boundaries() {
        let first = format!("AWS_ACCESS_KEY_ID={AWS_ID}\n");
        let second = format!("AWS_SECRET_ACCESS_KEY={AWS_SECRET}");
        let id_position = 0usize;
        let exact_padding = MAX_SECRET_EXPOSURE_PAIR_WINDOW_BYTES - first.len() - 1;
        let exact = format!("{first}{}\n{second}", " ".repeat(exact_padding));
        let secret_position = first.len() + exact_padding + 1;
        assert_eq!(
            secret_position.abs_diff(id_position),
            MAX_SECRET_EXPOSURE_PAIR_WINDOW_BYTES
        );
        assert_eq!(
            count(
                exact.as_bytes(),
                SecretExposureDetectorClass::AwsAccessKeyPair
            ),
            1
        );

        let over = format!("{first}{}\n{second}", " ".repeat(exact_padding + 1));
        assert_eq!(
            count(
                over.as_bytes(),
                SecretExposureDetectorClass::AwsAccessKeyPair
            ),
            0
        );

        let at_line_limit = format!(
            "AWS_ACCESS_KEY_ID={AWS_ID}\n{}AWS_SECRET_ACCESS_KEY={AWS_SECRET}",
            "\n".repeat(MAX_SECRET_EXPOSURE_PAIR_WINDOW_LINES - 1)
        );
        assert_eq!(
            count(
                at_line_limit.as_bytes(),
                SecretExposureDetectorClass::AwsAccessKeyPair
            ),
            1
        );
        let over_line_limit = format!(
            "AWS_ACCESS_KEY_ID={AWS_ID}\n{}AWS_SECRET_ACCESS_KEY={AWS_SECRET}",
            "\n".repeat(MAX_SECRET_EXPOSURE_PAIR_WINDOW_LINES)
        );
        assert_eq!(
            count(
                over_line_limit.as_bytes(),
                SecretExposureDetectorClass::AwsAccessKeyPair
            ),
            0
        );
    }

    #[test]
    fn stripe_live_secret_accepts_secret_and_restricted_but_not_public_or_test_keys() {
        let body = format!(
            "sk_live_{STRIPE_PAYLOAD}\nrk_live_{STRIPE_PAYLOAD}\npk_live_{STRIPE_PAYLOAD}\nsk_test_{STRIPE_PAYLOAD}\nrk_test_{STRIPE_PAYLOAD}\n"
        );
        assert_eq!(
            count(
                body.as_bytes(),
                SecretExposureDetectorClass::StripeLiveSecret
            ),
            2
        );
        assert_eq!(
            count(
                format!("prefixsk_live_{STRIPE_PAYLOAD}").as_bytes(),
                SecretExposureDetectorClass::StripeLiveSecret
            ),
            0
        );
        assert_eq!(
            count(
                b"key=sk_live_EXAMPLE_PLACEHOLDER_123456",
                SecretExposureDetectorClass::StripeLiveSecret
            ),
            0
        );
    }

    #[test]
    fn stripe_payload_boundaries_are_exact() {
        let minimum = format!("sk_live_{}", "Ab3d".repeat(MIN_STRIPE_PAYLOAD_BYTES / 4));
        let maximum = format!("sk_live_{}", "Ab3d".repeat(MAX_STRIPE_PAYLOAD_BYTES / 4));
        let too_short = format!(
            "sk_live_{}",
            "Ab3d".repeat(MIN_STRIPE_PAYLOAD_BYTES / 4 - 1)
        );
        let too_long = format!("sk_live_{}Z", "Ab3d".repeat(MAX_STRIPE_PAYLOAD_BYTES / 4));
        assert_eq!(
            count(
                minimum.as_bytes(),
                SecretExposureDetectorClass::StripeLiveSecret
            ),
            1
        );
        assert_eq!(
            count(
                maximum.as_bytes(),
                SecretExposureDetectorClass::StripeLiveSecret
            ),
            1
        );
        assert_eq!(
            count(
                too_short.as_bytes(),
                SecretExposureDetectorClass::StripeLiveSecret
            ),
            0
        );
        assert_eq!(
            count(
                too_long.as_bytes(),
                SecretExposureDetectorClass::StripeLiveSecret
            ),
            0
        );
    }

    #[test]
    fn stripe_scanner_consumes_one_adversarial_token_run_once() {
        let mut body = b"sk_live_".to_vec();
        while body.len() + b"sk_live_".len() <= MAX_SECRET_EXPOSURE_BODY_BYTES {
            body.extend_from_slice(b"sk_live_");
        }
        body.resize(MAX_SECRET_EXPOSURE_BODY_BYTES, b'A');

        let scan = scan_complete_text_body(&body).expect("bounded repeated token run scans");
        assert_eq!(scan.inspected_body_bytes(), MAX_SECRET_EXPOSURE_BODY_BYTES);
        assert_eq!(
            scan.count_for(SecretExposureDetectorClass::StripeLiveSecret),
            0
        );
    }

    #[test]
    fn bearer_requires_explicit_authorization_assignment() {
        let header = format!("Authorization: Bearer {BEARER_TOKEN}");
        let json = format!("{{\"authorization\":\"bearer {BEARER_TOKEN}\"}}");
        for body in [header, json] {
            assert_eq!(
                count(
                    body.as_bytes(),
                    SecretExposureDetectorClass::AuthorizationBearerAssignment
                ),
                1
            );
        }
        for body in [
            format!("token={BEARER_TOKEN}"),
            format!("Bearer {BEARER_TOKEN}"),
            format!("Authorization: Basic {BEARER_TOKEN}"),
            "Authorization: Bearer YOUR_TOKEN_PLACEHOLDER_123456".to_owned(),
        ] {
            assert_eq!(
                count(
                    body.as_bytes(),
                    SecretExposureDetectorClass::AuthorizationBearerAssignment
                ),
                0
            );
        }
    }

    #[test]
    fn bearer_token_limit_accepts_limit_and_rejects_limit_plus_one() {
        let token = "Ab3d".repeat(MAX_SECRET_EXPOSURE_TOKEN_BYTES / 4);
        let accepted = format!("Authorization: Bearer {token}");
        assert_eq!(
            count(
                accepted.as_bytes(),
                SecretExposureDetectorClass::AuthorizationBearerAssignment
            ),
            1
        );

        let rejected = format!("Authorization: Bearer {token}Z");
        assert_eq!(
            scan_complete_text_body(rejected.as_bytes()),
            Err(SecretExposureScanError::TokenLimitExceeded {
                body_bytes: rejected.len(),
                max_token_bytes: MAX_SECRET_EXPOSURE_TOKEN_BYTES,
            })
        );
    }

    #[test]
    fn assignment_endpoint_scans_are_linear_and_preserve_later_candidates() {
        let mut body = b"Authorization: invalid".to_vec();
        while body.len() + 24 <= MAX_SECRET_EXPOSURE_BODY_BYTES {
            body.extend_from_slice(b" authorization: invalid");
        }
        body.resize(MAX_SECRET_EXPOSURE_BODY_BYTES, b'x');

        let mut visits = 0usize;
        let inspected = for_each_assignment_value_case_insensitive(
            &body,
            b"authorization",
            |_, _| -> Result<(), ()> {
                visits += 1;
                Ok(())
            },
        )
        .unwrap();
        assert!(
            visits > 1,
            "adversarial invalid candidates remain observable"
        );
        assert!(
            inspected <= body.len(),
            "the spaced endpoint cursor scans each line byte at most once"
        );
        assert_eq!(
            count(
                &body,
                SecretExposureDetectorClass::AuthorizationBearerAssignment
            ),
            0
        );

        let later = format!("authorization=Basic ignored authorization=Bearer {BEARER_TOKEN}");
        assert_eq!(
            count(
                later.as_bytes(),
                SecretExposureDetectorClass::AuthorizationBearerAssignment
            ),
            1,
            "a later delimiterless assignment remains visible"
        );
    }

    #[test]
    fn bearer_assignment_occurrence_limit_is_exact() {
        let assignment = format!("Authorization=Bearer {BEARER_TOKEN};");
        let accepted = assignment.repeat(usize::from(MAX_SECRET_EXPOSURE_OCCURRENCES));
        assert_eq!(
            count(
                accepted.as_bytes(),
                SecretExposureDetectorClass::AuthorizationBearerAssignment
            ),
            MAX_SECRET_EXPOSURE_OCCURRENCES
        );
        let rejected = format!("{accepted}{assignment}");
        assert_eq!(
            scan_complete_text_body(rejected.as_bytes()),
            Err(SecretExposureScanError::OccurrenceLimitExceeded {
                body_bytes: rejected.len(),
                max_occurrences: MAX_SECRET_EXPOSURE_OCCURRENCES,
            })
        );
    }

    #[test]
    fn occurrence_limit_accepts_limit_and_rejects_limit_plus_one() {
        let token = format!("sk_live_{STRIPE_PAYLOAD}");
        let accepted =
            std::iter::repeat_n(token.as_str(), usize::from(MAX_SECRET_EXPOSURE_OCCURRENCES))
                .collect::<Vec<_>>()
                .join("\n");
        let scan = scan_complete_text_body(accepted.as_bytes()).expect("exact occurrence limit");
        assert_eq!(scan.occurrence_count(), MAX_SECRET_EXPOSURE_OCCURRENCES);

        let rejected = format!("{accepted}\n{token}");
        assert_eq!(
            scan_complete_text_body(rejected.as_bytes()),
            Err(SecretExposureScanError::OccurrenceLimitExceeded {
                body_bytes: rejected.len(),
                max_occurrences: MAX_SECRET_EXPOSURE_OCCURRENCES,
            })
        );
    }

    #[test]
    fn successful_and_failed_outputs_never_retain_canary_values() {
        let canary = format!("sk_live_{STRIPE_PAYLOAD}");
        let scan = scan_complete_text_body(canary.as_bytes()).expect("canary shape should match");
        assert!(!format!("{scan:?}").contains(STRIPE_PAYLOAD));

        let oversized = format!(
            "Authorization: Bearer {}",
            format!("{STRIPE_PAYLOAD}Z").repeat(32)
        );
        let error = scan_complete_text_body(oversized.as_bytes())
            .expect_err("oversized bearer candidate should be refused");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(STRIPE_PAYLOAD));
        assert!(!rendered.contains("Authorization"));
    }

    #[test]
    fn labelled_corpus_has_literal_per_detector_precision_and_recall_oracles() {
        #[derive(Clone)]
        struct CorpusCase {
            name: &'static str,
            body: Vec<u8>,
            expected: BTreeMap<SecretExposureDetectorClass, bool>,
        }

        fn expected(
            classes: &[SecretExposureDetectorClass],
        ) -> BTreeMap<SecretExposureDetectorClass, bool> {
            SecretExposureDetectorClass::ALL
                .into_iter()
                .map(|class| (class, classes.contains(&class)))
                .collect()
        }

        let pem_body = pem(PemLabel::Pkcs8, &format!("M{}", "A1b".repeat(21)));
        let cases = vec![
            CorpusCase {
                name: "synthetic-pkcs8-private-key",
                body: pem_body.into_bytes(),
                expected: expected(&[SecretExposureDetectorClass::PemPrivateKeyBlock]),
            },
            CorpusCase {
                name: "public-key-near-miss",
                body: format!(
                    "-----BEGIN PUBLIC KEY-----\nM{}\n-----END PUBLIC KEY-----\n",
                    "A1b".repeat(21)
                )
                .into_bytes(),
                expected: expected(&[]),
            },
            CorpusCase {
                name: "synthetic-paired-aws-assignments",
                body: format!("AWS_ACCESS_KEY_ID={AWS_ID}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\n")
                    .into_bytes(),
                expected: expected(&[SecretExposureDetectorClass::AwsAccessKeyPair]),
            },
            CorpusCase {
                name: "aws-public-identifier-alone",
                body: format!("AWS_ACCESS_KEY_ID={AWS_ID}\n").into_bytes(),
                expected: expected(&[]),
            },
            CorpusCase {
                name: "aws-documentation-example",
                body: concat!(
                    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
                    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                )
                .as_bytes()
                .to_vec(),
                expected: expected(&[]),
            },
            CorpusCase {
                name: "synthetic-stripe-live-secret",
                body: format!("key=sk_live_{STRIPE_PAYLOAD}\n").into_bytes(),
                expected: expected(&[SecretExposureDetectorClass::StripeLiveSecret]),
            },
            CorpusCase {
                name: "stripe-publishable-and-test-identifiers",
                body: format!(
                    "pk_live_{STRIPE_PAYLOAD}\nsk_test_{STRIPE_PAYLOAD}\nrk_test_{STRIPE_PAYLOAD}\n"
                )
                .into_bytes(),
                expected: expected(&[]),
            },
            CorpusCase {
                name: "escaped-stripe-near-miss",
                body: format!("sk\\u005flive\\u005f{STRIPE_PAYLOAD}\n").into_bytes(),
                expected: expected(&[]),
            },
            CorpusCase {
                name: "synthetic-explicit-bearer-assignment",
                body: format!("Authorization: Bearer {BEARER_TOKEN}\n").into_bytes(),
                expected: expected(&[SecretExposureDetectorClass::AuthorizationBearerAssignment]),
            },
            CorpusCase {
                name: "unbound-bearer-looking-text",
                body: format!("Bearer {BEARER_TOKEN}\n").into_bytes(),
                expected: expected(&[]),
            },
            CorpusCase {
                name: "split-stripe-near-miss",
                body: format!("sk_live_<span>{STRIPE_PAYLOAD}</span>\n").into_bytes(),
                expected: expected(&[]),
            },
            CorpusCase {
                name: "binary-abstention",
                body: b"prefix\xffsuffix".to_vec(),
                expected: expected(&[]),
            },
        ];

        let mut matrix = BTreeMap::new();
        for class in SecretExposureDetectorClass::ALL {
            matrix.insert(class, [0_u16; 4]); // true-positive, false-positive, false-negative, true-negative
        }
        for case in &cases {
            let observed = match scan_complete_text_body(&case.body) {
                Ok(scan) => scan
                    .class_counts()
                    .iter()
                    .map(|row| row.class())
                    .collect::<Vec<_>>(),
                Err(SecretExposureScanError::InvalidUtf8 { .. })
                    if case.name == "binary-abstention" =>
                {
                    Vec::new()
                },
                Err(error) => panic!(
                    "labelled corpus case {} failed unexpectedly: {error}",
                    case.name
                ),
            };
            for class in SecretExposureDetectorClass::ALL {
                let predicted = observed.contains(&class);
                let expected = case.expected[&class];
                let bucket = match (predicted, expected) {
                    (true, true) => 0,
                    (true, false) => 1,
                    (false, true) => 2,
                    (false, false) => 3,
                };
                matrix.get_mut(&class).expect("fixed detector class")[bucket] += 1;
            }
        }

        let literal_expected = [
            (
                SecretExposureDetectorClass::PemPrivateKeyBlock,
                [1, 0, 0, 11],
            ),
            (SecretExposureDetectorClass::AwsAccessKeyPair, [1, 0, 0, 11]),
            (SecretExposureDetectorClass::StripeLiveSecret, [1, 0, 0, 11]),
            (
                SecretExposureDetectorClass::AuthorizationBearerAssignment,
                [1, 0, 0, 11],
            ),
        ];
        for (class, expected_matrix) in literal_expected {
            let actual = matrix[&class];
            println!(
                "detector={} tp={} fp={} fn={} tn={}",
                class.as_str(),
                actual[0],
                actual[1],
                actual[2],
                actual[3]
            );
            assert_eq!(actual, expected_matrix);
        }
    }
}
