//! Observed defensive posture of a single HTTP response.
//!
//! [`DefenseState`] is a pure, bounded projection of the defensive signals in
//! one response: status class, challenge and rate-limit markers, and an optional
//! product fingerprint. It deliberately makes no payload or evasion decision — a
//! planner consumes this observation and decides how (or whether) to proceed.

use super::fingerprint::{fingerprint, DefenseFingerprint, FingerprintConfidence};

/// Coarse classification of a response status for defensive reasoning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DefenseStatusSignal {
    /// A status that carries no inherent blocking signal.
    Normal,
    /// `403 Forbidden`, a common block response.
    Forbidden,
    /// `406 Not Acceptable`, often a rule-engine rejection.
    NotAcceptable,
    /// `418`, sometimes used by edges as a bot-block sentinel.
    Teapot,
    /// `429 Too Many Requests`, an explicit rate-limit response.
    RateLimited,
    /// Any `5xx`, which is ambiguous rather than a deliberate block.
    ServerError,
}

impl DefenseStatusSignal {
    fn classify(status: u16) -> Self {
        match status {
            403 => Self::Forbidden,
            406 => Self::NotAcceptable,
            418 => Self::Teapot,
            429 => Self::RateLimited,
            500..=599 => Self::ServerError,
            _ => Self::Normal,
        }
    }

    /// Returns whether this status is a deliberate block signal.
    ///
    /// Rate limiting and server errors are handled separately because they are
    /// not, on their own, evidence of a request-blocking rule.
    pub const fn is_block(self) -> bool {
        matches!(self, Self::Forbidden | Self::NotAcceptable | Self::Teapot)
    }
}

/// Overall defensive posture inferred from one response.
///
/// Ordering is meaningful: a more defensive posture is greater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DefensePosture {
    /// No defensive reaction was observed.
    Open,
    /// Defensive infrastructure is present or throttling, but nothing was blocked.
    Suspected,
    /// The response is a deliberate block or challenge.
    Blocking,
}

/// Bounded, deterministic observation of a response's defensive posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefenseState {
    status: u16,
    status_signal: DefenseStatusSignal,
    challenged: bool,
    rate_limited: bool,
    rate_limit_headers_present: bool,
    fingerprint: Option<DefenseFingerprint>,
    posture: DefensePosture,
}

/// Lowercase body markers that indicate an interstitial challenge or block page.
const CHALLENGE_MARKERS: &[&str] = &[
    "attention required",
    "checking your browser",
    "please enable cookies",
    "captcha",
    "access denied",
    "request blocked",
    "you have been blocked",
    "this request was blocked",
];

/// Lowercase header names that indicate rate-limit accounting is in effect.
const RATE_LIMIT_HEADERS: &[&str] = &[
    "retry-after",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
];

impl DefenseState {
    pub(crate) fn from_assessment_projection(
        status: u16,
        challenged: bool,
        rate_limited: bool,
        rate_limit_headers_present: bool,
        fingerprint: Option<DefenseFingerprint>,
    ) -> Self {
        let status_signal = DefenseStatusSignal::classify(status);
        let rate_limited = rate_limited
            || rate_limit_headers_present
            || status_signal == DefenseStatusSignal::RateLimited;
        let posture = derive_posture(
            status_signal,
            challenged,
            rate_limited,
            fingerprint.as_ref(),
        );
        Self {
            status,
            status_signal,
            challenged,
            rate_limited,
            rate_limit_headers_present,
            fingerprint,
            posture,
        }
    }

    /// Builds the authorization-review projection from the exact retained
    /// status plus an independently typed challenge/rate-limit classification.
    /// A denial status alone is an authorization outcome, not defensive
    /// interference, so it remains observable without becoming execution
    /// suppression authority.
    #[cfg(feature = "authorization-review")]
    pub(crate) fn from_authorization_projection(
        status: u16,
        challenged: bool,
        rate_limited: bool,
    ) -> Self {
        let status_signal = if rate_limited {
            DefenseStatusSignal::RateLimited
        } else if challenged {
            DefenseStatusSignal::classify(status)
        } else {
            DefenseStatusSignal::Normal
        };
        let posture = if challenged {
            DefensePosture::Blocking
        } else if rate_limited {
            DefensePosture::Suspected
        } else {
            DefensePosture::Open
        };
        Self {
            status,
            status_signal,
            challenged,
            rate_limited,
            rate_limit_headers_present: false,
            fingerprint: None,
            posture,
        }
    }

    /// Observes the defensive posture of one response.
    ///
    /// `headers` is a transport-neutral `(name, value)` list matched
    /// case-insensitively. `body` is scanned only up to the fingerprint scan
    /// ceiling, so a large body cannot turn one observation into unbounded work.
    pub fn observe(status: u16, headers: &[(&str, &str)], body: &str) -> Self {
        let status_signal = DefenseStatusSignal::classify(status);
        let rate_limit_headers_present = headers.iter().any(|(name, _)| {
            RATE_LIMIT_HEADERS
                .iter()
                .any(|rl| name.eq_ignore_ascii_case(rl))
        });
        let rate_limited =
            status_signal == DefenseStatusSignal::RateLimited || rate_limit_headers_present;
        let challenged = body_has_challenge_marker(body);
        let fingerprint = fingerprint(headers, body);

        let posture = derive_posture(
            status_signal,
            challenged,
            rate_limited,
            fingerprint.as_ref(),
        );

        Self {
            status,
            status_signal,
            challenged,
            rate_limited,
            rate_limit_headers_present,
            fingerprint,
            posture,
        }
    }

    /// Returns the observed HTTP status code.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the coarse status classification.
    pub const fn status_signal(&self) -> DefenseStatusSignal {
        self.status_signal
    }

    /// Returns whether the body carried an interstitial challenge or block marker.
    pub const fn is_challenged(&self) -> bool {
        self.challenged
    }

    /// Returns whether the response is rate limited by status or headers.
    pub const fn is_rate_limited(&self) -> bool {
        self.rate_limited
    }

    /// Returns whether rate-limit accounting headers were present.
    pub const fn has_rate_limit_headers(&self) -> bool {
        self.rate_limit_headers_present
    }

    /// Returns the product fingerprint observed for this response, if any.
    pub const fn fingerprint(&self) -> Option<&DefenseFingerprint> {
        self.fingerprint.as_ref()
    }

    /// Returns the overall inferred defensive posture.
    pub const fn posture(&self) -> DefensePosture {
        self.posture
    }
}

fn body_has_challenge_marker(body: &str) -> bool {
    let prefix = super::fingerprint::MAX_FINGERPRINT_BODY_SCAN_BYTES.min(body.len());
    let mut end = prefix;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let lowered = body[..end].to_ascii_lowercase();
    CHALLENGE_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

fn derive_posture(
    status_signal: DefenseStatusSignal,
    challenged: bool,
    rate_limited: bool,
    fingerprint: Option<&DefenseFingerprint>,
) -> DefensePosture {
    if status_signal.is_block() || challenged {
        return DefensePosture::Blocking;
    }

    let strong_fingerprint =
        fingerprint.is_some_and(|print| print.confidence() >= FingerprintConfidence::Probable);
    if rate_limited || strong_fingerprint || fingerprint.is_some() {
        return DefensePosture::Suspected;
    }

    DefensePosture::Open
}

#[cfg(test)]
mod tests {
    use super::super::fingerprint::DefenseProduct;
    use super::*;

    #[test]
    fn a_plain_response_is_open() {
        let state = DefenseState::observe(200, &[("Server", "nginx")], "<html>ok</html>");
        assert_eq!(state.posture(), DefensePosture::Open);
        assert!(!state.is_challenged());
        assert!(!state.is_rate_limited());
        assert!(state.fingerprint().is_none());
    }

    #[test]
    fn a_forbidden_status_is_blocking() {
        let state = DefenseState::observe(403, &[], "forbidden");
        assert_eq!(state.status_signal(), DefenseStatusSignal::Forbidden);
        assert_eq!(state.posture(), DefensePosture::Blocking);
    }

    #[test]
    fn a_challenge_body_is_blocking_even_on_200() {
        let state = DefenseState::observe(
            200,
            &[("CF-RAY", "abc")],
            "Attention Required! Checking your browser before accessing.",
        );
        assert!(state.is_challenged());
        assert_eq!(state.posture(), DefensePosture::Blocking);
        assert_eq!(
            state.fingerprint().unwrap().product(),
            DefenseProduct::Cloudflare
        );
    }

    #[test]
    fn rate_limit_is_suspected_not_blocking() {
        let by_status = DefenseState::observe(429, &[], "slow down");
        assert!(by_status.is_rate_limited());
        assert_eq!(by_status.posture(), DefensePosture::Suspected);

        let by_header = DefenseState::observe(200, &[("Retry-After", "30")], "ok");
        assert!(by_header.is_rate_limited());
        assert!(by_header.has_rate_limit_headers());
        assert_eq!(by_header.posture(), DefensePosture::Suspected);
    }

    #[test]
    fn a_fingerprint_without_a_block_is_suspected() {
        let state = DefenseState::observe(200, &[("x-amzn-requestid", "id")], "ok");
        assert_eq!(state.posture(), DefensePosture::Suspected);
        assert_eq!(
            state.fingerprint().unwrap().product(),
            DefenseProduct::AwsWaf
        );
    }

    #[test]
    fn server_error_alone_is_not_a_block() {
        let state = DefenseState::observe(503, &[], "service unavailable");
        assert_eq!(state.status_signal(), DefenseStatusSignal::ServerError);
        assert_eq!(state.posture(), DefensePosture::Open);
    }

    #[test]
    fn observation_is_deterministic() {
        let first = DefenseState::observe(403, &[("CF-RAY", "x")], "access denied");
        let second = DefenseState::observe(403, &[("CF-RAY", "x")], "access denied");
        assert_eq!(first, second);
    }
}
