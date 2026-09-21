//! Bounded Cert Spotter provider execution under one web-assessment authority.
//!
//! Provider traffic is deliberately separate from the exact target origin, but
//! every dispatch consumes the assessment's one request/byte/deadline/cancel
//! authority. Returned CT names remain inert hypotheses and are never inserted
//! into the assessment subject plan or target evidence store.

use std::fmt;

use reqwest::{header, Client, StatusCode};
use url::{Host, Url};

use super::SharedWebRuntimeAuthority;
use crate::{
    recon_ct_provider::{
        CertSpotterPageOutcome, CertSpotterResponseAccumulator, CertSpotterResult,
        CertSpotterTerminal, ReconCtProviderExecutionMode, ReconCtProviderPolicy,
        MAX_CERT_SPOTTER_ELAPSED, MAX_CERT_SPOTTER_RESPONSE_PAGE_BYTES,
        MAX_CERT_SPOTTER_TOTAL_RESPONSE_BYTES,
    },
    DecisionExecutionStage, TransportDispatchOutcome,
};

const RECON_CT_PROVIDER_ACTION_ID: &str = "recon.certspotter.provider-page";
const CERT_SPOTTER_ACCEPT: &str = "application/json";

/// Stable, value-free classification for the first provider execution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconCtProviderFailureKind {
    ClientInitialization,
    RequestConstruction,
    ParentAuthorityUnavailable,
    Cancelled,
    DeadlineReached,
    TransportFailed,
    RedirectRefused,
    AccessRejected,
    Throttled,
    ProviderNotFound,
    ServerFailure,
    UnexpectedStatus,
    UnsupportedMedia,
    UnsupportedContentCoding,
    ResponseTooLarge,
    InvalidResponse,
}

impl ReconCtProviderFailureKind {
    /// Stable report token; never contains a URL, domain, response, or error.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientInitialization => "client_initialization",
            Self::RequestConstruction => "request_construction",
            Self::ParentAuthorityUnavailable => "parent_authority_unavailable",
            Self::Cancelled => "cancelled",
            Self::DeadlineReached => "deadline_reached",
            Self::TransportFailed => "transport_failed",
            Self::RedirectRefused => "redirect_refused",
            Self::AccessRejected => "access_rejected",
            Self::Throttled => "throttled",
            Self::ProviderNotFound => "provider_not_found",
            Self::ServerFailure => "server_failure",
            Self::UnexpectedStatus => "unexpected_status",
            Self::UnsupportedMedia => "unsupported_media",
            Self::UnsupportedContentCoding => "unsupported_content_coding",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

/// Runtime-owned provider audit plus the transport-neutral parsed result.
#[derive(Clone, Eq, PartialEq)]
pub struct WebAssessmentReconCtProviderAudit {
    result: CertSpotterResult,
    request_attempt_count: usize,
    request_admitted_count: usize,
    response_completed_count: usize,
    observed_response_bytes: u64,
    first_failure: Option<ReconCtProviderFailureKind>,
}

impl fmt::Debug for WebAssessmentReconCtProviderAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAssessmentReconCtProviderAudit")
            .field("result", &"<redacted>")
            .field("request_attempt_count", &self.request_attempt_count)
            .field("request_admitted_count", &self.request_admitted_count)
            .field("response_completed_count", &self.response_completed_count)
            .field("observed_response_bytes", &self.observed_response_bytes)
            .field("first_failure", &self.first_failure)
            .finish()
    }
}

impl WebAssessmentReconCtProviderAudit {
    #[must_use]
    pub const fn result(&self) -> &CertSpotterResult {
        &self.result
    }

    #[must_use]
    pub const fn request_attempt_count(&self) -> usize {
        self.request_attempt_count
    }

    #[must_use]
    pub const fn request_admitted_count(&self) -> usize {
        self.request_admitted_count
    }

    #[must_use]
    pub const fn response_completed_count(&self) -> usize {
        self.response_completed_count
    }

    /// Bytes actually delivered to this child, including a bounded final
    /// overrun chunk and responses that later failed parsing.
    #[must_use]
    pub const fn observed_response_bytes(&self) -> u64 {
        self.observed_response_bytes
    }

    #[must_use]
    pub const fn first_failure(&self) -> Option<ReconCtProviderFailureKind> {
        self.first_failure
    }

    /// Returns whether transport accounting and the parser-owned bounded result
    /// form one internally consistent provider execution receipt.
    ///
    /// This does not authenticate the provider or elevate any returned name to
    /// target authority. It only protects the report composition boundary from
    /// pairing unrelated counters and parsed results.
    pub(crate) fn is_consistent(&self) -> bool {
        use std::collections::BTreeSet;

        use crate::recon_ct_provider::{
            CertSpotterCompleteness, CertSpotterTerminal, MAX_CERT_SPOTTER_RESPONSE_PAGES,
            MAX_CERT_SPOTTER_RETAINED_NAMES, MAX_CERT_SPOTTER_TOTAL_RESPONSE_BYTES,
        };

        let audit = self.result.audit();
        let mut names = BTreeSet::new();
        let mut source_pairs = BTreeSet::new();
        let identities_are_unique = self.result.hypotheses().iter().all(|hypothesis| {
            names.insert(hypothesis.name())
                && source_pairs.insert((hypothesis.name(), hypothesis.first_issuance_id()))
        });
        let parser_selected_terminal = matches!(
            audit.terminal(),
            CertSpotterTerminal::ProviderExhausted
                | CertSpotterTerminal::HypothesisLimitReached
                | CertSpotterTerminal::PageLimitReached
        );
        let failure_matches_terminal = match self.first_failure {
            None => parser_selected_terminal,
            Some(ReconCtProviderFailureKind::Cancelled) => {
                audit.terminal() == CertSpotterTerminal::Cancelled
            },
            Some(ReconCtProviderFailureKind::DeadlineReached) => {
                audit.terminal() == CertSpotterTerminal::DeadlineReached
            },
            Some(ReconCtProviderFailureKind::ParentAuthorityUnavailable) => {
                audit.terminal() == CertSpotterTerminal::ParentAuthorityUnavailable
            },
            Some(_) => audit.terminal() == CertSpotterTerminal::TransportFailed,
        };

        self.request_admitted_count <= self.request_attempt_count
            && self.request_attempt_count <= MAX_CERT_SPOTTER_RESPONSE_PAGES
            && self.response_completed_count <= self.request_admitted_count
            && audit.page_count() <= self.response_completed_count
            && audit.page_count() <= MAX_CERT_SPOTTER_RESPONSE_PAGES
            && audit.response_bytes() <= MAX_CERT_SPOTTER_TOTAL_RESPONSE_BYTES
            && u64::try_from(audit.response_bytes())
                .is_ok_and(|accepted| accepted <= self.observed_response_bytes)
            && audit.retained_name_count() == self.result.hypotheses().len()
            && audit.retained_name_count() <= MAX_CERT_SPOTTER_RETAINED_NAMES
            && identities_are_unique
            && audit.completeness() == audit.terminal().completeness()
            && failure_matches_terminal
            && (self.first_failure.is_none()
                || audit.completeness() == CertSpotterCompleteness::Unknown)
    }
}

/// Validates the provider child authority against the selected assessment.
///
/// Production queries are bound to the exact target host. Owned loopback mode
/// is a test-only transport exception with its own explicit query declaration.
/// In every mode provider and target exact origins must remain distinct.
pub fn recon_ct_provider_scope_is_valid(policy: &ReconCtProviderPolicy, target: &Url) -> bool {
    let Ok(provider_origin) = Url::parse(policy.provider_origin()) else {
        return false;
    };
    if same_origin(&provider_origin, target) {
        return false;
    }
    match policy.execution_mode() {
        ReconCtProviderExecutionMode::Production => target
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(policy.query_domain())),
        ReconCtProviderExecutionMode::OwnedLoopbackFixture => {
            target.scheme() == "http"
                && target.port().is_some_and(|port| port != 0)
                && target.username().is_empty()
                && target.password().is_none()
                && match target.host() {
                    Some(Host::Ipv4(address)) => address.is_loopback(),
                    Some(Host::Ipv6(address)) => address.is_loopback(),
                    Some(Host::Domain(_)) | None => false,
                }
        },
    }
}

/// Executes at most two sequential provider requests under the shared parent.
pub(super) async fn execute_recon_ct_provider(
    policy: ReconCtProviderPolicy,
    target: &Url,
    authority: &SharedWebRuntimeAuthority,
) -> WebAssessmentReconCtProviderAudit {
    let mut accumulator = CertSpotterResponseAccumulator::for_policy(&policy);
    let mut accounting = ProviderAccounting::default();

    if !recon_ct_provider_scope_is_valid(&policy, target) {
        return finalize(
            accumulator,
            CertSpotterTerminal::ParentAuthorityUnavailable,
            accounting,
            Some(ReconCtProviderFailureKind::ParentAuthorityUnavailable),
        );
    }

    let client = match Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .user_agent(concat!(
            "termivar/",
            env!("CARGO_PKG_VERSION"),
            " cert-spotter-recon"
        ))
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return finalize(
                accumulator,
                CertSpotterTerminal::TransportFailed,
                accounting,
                Some(ReconCtProviderFailureKind::ClientInitialization),
            );
        },
    };

    let parent_timing = authority.start();
    let local_deadline = tokio::time::Instant::now()
        .checked_add(MAX_CERT_SPOTTER_ELAPSED)
        .unwrap_or_else(tokio::time::Instant::now);
    let deadline = parent_timing
        .deadline()
        .map_or(local_deadline, |parent| parent.min(local_deadline));

    loop {
        if authority.cancellation().is_cancelled() {
            return finalize(
                accumulator,
                CertSpotterTerminal::Cancelled,
                accounting,
                Some(ReconCtProviderFailureKind::Cancelled),
            );
        }
        if tokio::time::Instant::now() >= deadline {
            return finalize(
                accumulator,
                CertSpotterTerminal::DeadlineReached,
                accounting,
                Some(ReconCtProviderFailureKind::DeadlineReached),
            );
        }

        accounting.request_attempt_count = accounting.request_attempt_count.saturating_add(1);
        let preflight = match authority
            .request_accounting()
            .preflight(RECON_CT_PROVIDER_ACTION_ID, DecisionExecutionStage::Passive)
        {
            Ok(preflight) if preflight.remaining_response_bytes() > 0 => preflight,
            Ok(_) | Err(_) => {
                return finalize(
                    accumulator,
                    CertSpotterTerminal::ParentAuthorityUnavailable,
                    accounting,
                    Some(ReconCtProviderFailureKind::ParentAuthorityUnavailable),
                );
            },
        };
        debug_assert!(preflight.remaining_response_bytes() > 0);
        let expected_after = accumulator.next_after().map(ToOwned::to_owned);
        let request_url = match policy.build_request_url(expected_after.as_deref()) {
            Ok(url) if request_matches_policy(&url, &policy, expected_after.as_deref()) => url,
            _ => {
                return finalize(
                    accumulator,
                    CertSpotterTerminal::TransportFailed,
                    accounting,
                    Some(ReconCtProviderFailureKind::RequestConstruction),
                );
            },
        };
        let mut lease = match authority
            .request_accounting()
            .try_begin_with_request_body_bytes(
                RECON_CT_PROVIDER_ACTION_ID,
                DecisionExecutionStage::Passive,
                None,
                0,
            ) {
            Ok(lease) => lease,
            Err(_) => {
                return finalize(
                    accumulator,
                    CertSpotterTerminal::ParentAuthorityUnavailable,
                    accounting,
                    Some(ReconCtProviderFailureKind::ParentAuthorityUnavailable),
                );
            },
        };
        accounting.request_admitted_count = accounting.request_admitted_count.saturating_add(1);

        let request = client
            .get(request_url.clone())
            .header(header::ACCEPT, CERT_SPOTTER_ACCEPT)
            .header(header::ACCEPT_ENCODING, "identity");
        let response = tokio::select! {
            biased;
            () = authority.cancellation().cancelled() => {
                lease.finish(TransportDispatchOutcome::Cancelled);
                return finalize(
                    accumulator,
                    CertSpotterTerminal::Cancelled,
                    accounting,
                    Some(ReconCtProviderFailureKind::Cancelled),
                );
            }
            result = tokio::time::timeout_at(deadline, request.send()) => match result {
                Err(_) => {
                    lease.finish(TransportDispatchOutcome::RequestTimeout);
                    return finalize(
                        accumulator,
                        CertSpotterTerminal::DeadlineReached,
                        accounting,
                        Some(ReconCtProviderFailureKind::DeadlineReached),
                    );
                }
                Ok(Err(_)) => {
                    lease.finish(TransportDispatchOutcome::TransportFailure);
                    return finalize(
                        accumulator,
                        CertSpotterTerminal::TransportFailed,
                        accounting,
                        Some(ReconCtProviderFailureKind::TransportFailed),
                    );
                }
                Ok(Ok(response)) => response,
            }
        };

        if response.url() != &request_url {
            lease.finish(TransportDispatchOutcome::TransportFailure);
            return finalize(
                accumulator,
                CertSpotterTerminal::TransportFailed,
                accounting,
                Some(ReconCtProviderFailureKind::RedirectRefused),
            );
        }
        if response.status() != StatusCode::OK {
            let failure = status_failure(response.status());
            lease.finish(TransportDispatchOutcome::TransportFailure);
            return finalize(
                accumulator,
                CertSpotterTerminal::TransportFailed,
                accounting,
                Some(failure),
            );
        }
        if !json_content_type(response.headers()) {
            lease.finish(TransportDispatchOutcome::TransportFailure);
            return finalize(
                accumulator,
                CertSpotterTerminal::TransportFailed,
                accounting,
                Some(ReconCtProviderFailureKind::UnsupportedMedia),
            );
        }
        if !identity_content_coding(response.headers()) {
            lease.finish(TransportDispatchOutcome::TransportFailure);
            return finalize(
                accumulator,
                CertSpotterTerminal::TransportFailed,
                accounting,
                Some(ReconCtProviderFailureKind::UnsupportedContentCoding),
            );
        }
        let remaining_total =
            MAX_CERT_SPOTTER_TOTAL_RESPONSE_BYTES.saturating_sub(accumulator.response_bytes());
        if response.content_length().is_some_and(|length| {
            length > MAX_CERT_SPOTTER_RESPONSE_PAGE_BYTES as u64 || length > remaining_total as u64
        }) {
            // This is the provider child's own representation ceiling, not the
            // shared parent response-byte boundary.
            lease.finish(TransportDispatchOutcome::TransportFailure);
            return finalize(
                accumulator,
                CertSpotterTerminal::TransportFailed,
                accounting,
                Some(ReconCtProviderFailureKind::ResponseTooLarge),
            );
        }

        let mut response = response;
        let mut page = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(0)
                .min(MAX_CERT_SPOTTER_RESPONSE_PAGE_BYTES)
                .min(remaining_total),
        );
        loop {
            // One shared read gate bounds aggregate overrun to one delivered
            // chunk even if another child transport is active.
            let _read_guard = lease.acquire_response_read().await;
            if lease.remaining_response_bytes() == 0 {
                lease.finish(TransportDispatchOutcome::ResponseBudgetReached);
                return finalize(
                    accumulator,
                    CertSpotterTerminal::ParentAuthorityUnavailable,
                    accounting,
                    Some(ReconCtProviderFailureKind::ParentAuthorityUnavailable),
                );
            }
            let chunk = tokio::select! {
                biased;
                () = authority.cancellation().cancelled() => {
                    lease.finish(TransportDispatchOutcome::Cancelled);
                    return finalize(
                        accumulator,
                        CertSpotterTerminal::Cancelled,
                        accounting,
                        Some(ReconCtProviderFailureKind::Cancelled),
                    );
                }
                result = tokio::time::timeout_at(deadline, response.chunk()) => match result {
                    Err(_) => {
                        lease.finish(TransportDispatchOutcome::RequestTimeout);
                        return finalize(
                            accumulator,
                            CertSpotterTerminal::DeadlineReached,
                            accounting,
                            Some(ReconCtProviderFailureKind::DeadlineReached),
                        );
                    }
                    Ok(Err(_)) => {
                        lease.finish(TransportDispatchOutcome::TransportFailure);
                        return finalize(
                            accumulator,
                            CertSpotterTerminal::TransportFailed,
                            accounting,
                            Some(ReconCtProviderFailureKind::TransportFailed),
                        );
                    }
                    Ok(Ok(chunk)) => chunk,
                }
            };
            let Some(chunk) = chunk else {
                accounting.response_completed_count =
                    accounting.response_completed_count.saturating_add(1);
                // Every delivered byte was retained and end-of-body was
                // observed. A short parent retention allowance is handled in
                // the chunk branch below as a shared-budget terminal.
                lease.finish(TransportDispatchOutcome::Completed);
                break;
            };

            let observed = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            accounting.observed_response_bytes =
                accounting.observed_response_bytes.saturating_add(observed);
            let parent_retained = lease.observe_response_bytes(observed);
            let page_remaining = MAX_CERT_SPOTTER_RESPONSE_PAGE_BYTES.saturating_sub(page.len());
            let collection_remaining = remaining_total.saturating_sub(page.len());
            let local_retained = page_remaining.min(collection_remaining);
            let retained = usize::try_from(parent_retained)
                .unwrap_or(usize::MAX)
                .min(local_retained)
                .min(chunk.len());
            page.extend_from_slice(&chunk[..retained]);
            if retained < chunk.len() {
                let (dispatch_outcome, terminal, failure) =
                    retention_failure(parent_retained, observed);
                lease.finish(dispatch_outcome);
                return finalize(accumulator, terminal, accounting, Some(failure));
            }
        }

        let outcome = match accumulator.ingest_page(&page) {
            Ok(outcome) => outcome,
            Err(_) => {
                return finalize(
                    accumulator,
                    CertSpotterTerminal::TransportFailed,
                    accounting,
                    Some(ReconCtProviderFailureKind::InvalidResponse),
                );
            },
        };
        match outcome {
            CertSpotterPageOutcome::Continue { .. } => {},
            CertSpotterPageOutcome::Terminal(terminal) => {
                return finalize(accumulator, terminal, accounting, None);
            },
        }
    }
}

#[derive(Default)]
struct ProviderAccounting {
    request_attempt_count: usize,
    request_admitted_count: usize,
    response_completed_count: usize,
    observed_response_bytes: u64,
}

fn finalize(
    accumulator: CertSpotterResponseAccumulator,
    terminal: CertSpotterTerminal,
    accounting: ProviderAccounting,
    first_failure: Option<ReconCtProviderFailureKind>,
) -> WebAssessmentReconCtProviderAudit {
    let result = accumulator
        .into_result(terminal)
        .expect("runtime preserves the parser-selected Cert Spotter terminal");
    WebAssessmentReconCtProviderAudit {
        result,
        request_attempt_count: accounting.request_attempt_count,
        request_admitted_count: accounting.request_admitted_count,
        response_completed_count: accounting.response_completed_count,
        observed_response_bytes: accounting.observed_response_bytes,
        first_failure,
    }
}

fn request_matches_policy(
    url: &Url,
    policy: &ReconCtProviderPolicy,
    expected_after: Option<&str>,
) -> bool {
    let Ok(origin) = Url::parse(policy.provider_origin()) else {
        return false;
    };
    let Ok(expected_url) = policy.build_request_url(expected_after) else {
        return false;
    };
    let mut expected_query = vec![
        ("domain".to_owned(), policy.query_domain().to_owned()),
        ("expand".to_owned(), "dns_names".to_owned()),
    ];
    if let Some(after) = expected_after {
        expected_query.push(("after".to_owned(), after.to_owned()));
    }
    let actual_query = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();

    same_origin(url, &origin)
        && url.path() == "/v1/issuances"
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query() == expected_url.query()
        && actual_query == expected_query
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn retention_failure(
    parent_retained: u64,
    delivered: u64,
) -> (
    TransportDispatchOutcome,
    CertSpotterTerminal,
    ReconCtProviderFailureKind,
) {
    if parent_retained < delivered {
        (
            TransportDispatchOutcome::ResponseBudgetReached,
            CertSpotterTerminal::ParentAuthorityUnavailable,
            ReconCtProviderFailureKind::ParentAuthorityUnavailable,
        )
    } else {
        (
            TransportDispatchOutcome::TransportFailure,
            CertSpotterTerminal::TransportFailed,
            ReconCtProviderFailureKind::ResponseTooLarge,
        )
    }
}

fn json_content_type(headers: &header::HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none()
        && value
            .to_str()
            .ok()
            .filter(|value| !value.contains(','))
            .and_then(|value| value.split(';').next())
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(CERT_SPOTTER_ACCEPT))
}

fn identity_content_coding(headers: &header::HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_ENCODING).iter();
    match (values.next(), values.next()) {
        (None, None) => true,
        (Some(value), None) => value
            .to_str()
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case("identity")),
        _ => false,
    }
}

fn status_failure(status: StatusCode) -> ReconCtProviderFailureKind {
    if status.is_redirection() {
        ReconCtProviderFailureKind::RedirectRefused
    } else if status.as_u16() == 401 || status.as_u16() == 403 {
        ReconCtProviderFailureKind::AccessRejected
    } else if status.as_u16() == 404 {
        ReconCtProviderFailureKind::ProviderNotFound
    } else if status.as_u16() == 429 {
        ReconCtProviderFailureKind::Throttled
    } else if status.is_server_error() {
        ReconCtProviderFailureKind::ServerFailure
    } else {
        ReconCtProviderFailureKind::UnexpectedStatus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recon_ct_provider::parse_recon_ct_provider_policy;

    fn policy(mode: &str, origin: Option<&str>) -> ReconCtProviderPolicy {
        let origin = origin
            .map(|value| format!(",\"provider_origin\":\"{value}\""))
            .unwrap_or_default();
        parse_recon_ct_provider_policy(
            format!(
                r#"{{"schema":"security.recon-certspotter-policy/v1","revision":"rev-1","query_domain":"example.test","query_reference":"query-1","execution_mode":"{mode}","provider_use_authorized":true,"privacy_disclosure_acknowledged":true{origin}}}"#
            )
            .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn production_scope_requires_exact_target_host_and_separate_origin() {
        let policy = policy("production", None);
        assert!(recon_ct_provider_scope_is_valid(
            &policy,
            &Url::parse("https://example.test/").unwrap()
        ));
        assert!(!recon_ct_provider_scope_is_valid(
            &policy,
            &Url::parse("https://other.test/").unwrap()
        ));
        assert!(!recon_ct_provider_scope_is_valid(
            &parse_recon_ct_provider_policy(
                br#"{"schema":"security.recon-certspotter-policy/v1","revision":"rev-1","query_domain":"api.certspotter.com","query_reference":"query-1","execution_mode":"production","provider_use_authorized":true,"privacy_disclosure_acknowledged":true}"#
            )
            .unwrap(),
            &Url::parse("https://api.certspotter.com/").unwrap()
        ));
    }

    #[test]
    fn loopback_fixture_keeps_provider_and_target_exact_origins_separate() {
        let policy = policy("owned_loopback_fixture", Some("http://127.0.0.1:39002"));
        assert!(recon_ct_provider_scope_is_valid(
            &policy,
            &Url::parse("http://127.0.0.1:39001/").unwrap()
        ));
        assert!(!recon_ct_provider_scope_is_valid(
            &policy,
            &Url::parse("http://127.0.0.1:39002/").unwrap()
        ));
        for outside_fixture_scope in [
            "https://127.0.0.1:39001/",
            "http://127.0.0.1/",
            "http://localhost:39001/",
            "http://192.0.2.1:39001/",
            "https://example.test/",
        ] {
            assert!(
                !recon_ct_provider_scope_is_valid(
                    &policy,
                    &Url::parse(outside_fixture_scope).unwrap()
                ),
                "fixture policy accepted target {outside_fixture_scope}"
            );
        }
    }

    #[test]
    fn dispatch_guard_requires_exact_fixed_route_and_current_cursor() {
        let policy = policy("owned_loopback_fixture", Some("http://127.0.0.1:39002"));
        let first = policy.build_request_url(None).unwrap();
        assert!(request_matches_policy(&first, &policy, None));
        assert!(!request_matches_policy(&first, &policy, Some("opaque-1")));

        let next = policy.build_request_url(Some("opaque-1")).unwrap();
        assert!(request_matches_policy(&next, &policy, Some("opaque-1")));
        assert!(!request_matches_policy(&next, &policy, None));

        let mut extra = next.clone();
        extra.query_pairs_mut().append_pair("unexpected", "value");
        assert!(!request_matches_policy(&extra, &policy, Some("opaque-1")));

        let encoded_name = Url::parse(
            "http://127.0.0.1:39002/v1/issuances?dom%61in=example.test&expand=dns_names",
        )
        .unwrap();
        assert!(!request_matches_policy(&encoded_name, &policy, None));
        let encoded_value = Url::parse(
            "http://127.0.0.1:39002/v1/issuances?domain=example.test&expand=dns%5Fnames",
        )
        .unwrap();
        assert!(!request_matches_policy(&encoded_value, &policy, None));
        let encoded_cursor = Url::parse(
            "http://127.0.0.1:39002/v1/issuances?domain=example.test&expand=dns_names&after=opaque%2D1",
        )
        .unwrap();
        assert!(!request_matches_policy(
            &encoded_cursor,
            &policy,
            Some("opaque-1")
        ));

        let mut wrong_path = next;
        wrong_path.set_path("/v1/certificates");
        assert!(!request_matches_policy(
            &wrong_path,
            &policy,
            Some("opaque-1")
        ));
    }

    #[test]
    fn provider_client_construction_pins_retry_free_transport() {
        let source = include_str!("recon_ct_runtime.rs");
        let retry_free = concat!(".retry(reqwest::retry::", "never())");
        assert_eq!(
            source.matches(retry_free).count(),
            1,
            "the provider client must explicitly disable dependency-level retries"
        );
    }

    #[test]
    fn response_representation_headers_must_be_single_and_unambiguous() {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(json_content_type(&headers));
        assert!(identity_content_coding(&headers));

        headers.append(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/html"),
        );
        assert!(!json_content_type(&headers));

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::CONTENT_ENCODING,
            header::HeaderValue::from_static("identity"),
        );
        assert!(identity_content_coding(&headers));
        headers.append(
            header::CONTENT_ENCODING,
            header::HeaderValue::from_static("gzip"),
        );
        assert!(!identity_content_coding(&headers));

        let mut compound = header::HeaderMap::new();
        compound.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json; charset=utf-8, text/html"),
        );
        compound.insert(
            header::CONTENT_ENCODING,
            header::HeaderValue::from_static("identity, gzip"),
        );
        assert!(!json_content_type(&compound));
        assert!(!identity_content_coding(&compound));
    }

    #[test]
    fn response_overrun_distinguishes_parent_and_provider_local_limits() {
        assert_eq!(
            retention_failure(7, 8),
            (
                TransportDispatchOutcome::ResponseBudgetReached,
                CertSpotterTerminal::ParentAuthorityUnavailable,
                ReconCtProviderFailureKind::ParentAuthorityUnavailable,
            )
        );
        assert_eq!(
            retention_failure(8, 8),
            (
                TransportDispatchOutcome::TransportFailure,
                CertSpotterTerminal::TransportFailed,
                ReconCtProviderFailureKind::ResponseTooLarge,
            )
        );
    }

    #[test]
    fn provider_audit_debug_never_emits_raw_issuance_or_name_values() {
        let policy = policy("owned_loopback_fixture", Some("http://127.0.0.1:39002"));
        let mut accumulator = CertSpotterResponseAccumulator::for_policy(&policy);
        let page =
            br#"[{"id":"opaque/\u202ename@example.com","dns_names":["private.example.test"]}]"#;
        accumulator.ingest_page(page).unwrap();
        let audit = finalize(
            accumulator,
            CertSpotterTerminal::TransportFailed,
            ProviderAccounting {
                request_attempt_count: 1,
                request_admitted_count: 1,
                response_completed_count: 1,
                observed_response_bytes: page.len() as u64,
            },
            Some(ReconCtProviderFailureKind::TransportFailed),
        );

        let debug = format!("{audit:?}");
        assert!(debug.contains("result: \"<redacted>\""));
        assert!(!debug.contains("name@example.com"));
        assert!(!debug.contains("private.example.test"));
        assert!(!debug.contains("opaque/"));
        assert!(!debug.contains('\u{202e}'));
    }

    #[tokio::test]
    async fn exhausted_parent_response_budget_refuses_provider_before_dispatch() {
        let target = Url::parse("http://127.0.0.1:39001/").unwrap();
        let authority = SharedWebRuntimeAuthority::new_exact_origin(
            &target,
            crate::HttpEvidencePolicy::for_origin(target.clone()).unwrap(),
            crate::RuntimeBudget::default().with_max_response_bytes(0),
            tokio_util::sync::CancellationToken::new(),
        )
        .unwrap();
        let audit = execute_recon_ct_provider(
            policy("owned_loopback_fixture", Some("http://127.0.0.1:39002")),
            &target,
            &authority,
        )
        .await;

        assert_eq!(
            audit.result().audit().terminal(),
            CertSpotterTerminal::ParentAuthorityUnavailable
        );
        assert_eq!(audit.request_attempt_count(), 1);
        assert_eq!(audit.request_admitted_count(), 0);
        assert_eq!(audit.response_completed_count(), 0);
        assert_eq!(
            audit.first_failure(),
            Some(ReconCtProviderFailureKind::ParentAuthorityUnavailable)
        );
        assert_eq!(
            authority.request_accounting().snapshot().total_requests(),
            0
        );
    }

    #[test]
    fn failure_tokens_are_static_and_value_free() {
        let failures = [
            ReconCtProviderFailureKind::ClientInitialization,
            ReconCtProviderFailureKind::RequestConstruction,
            ReconCtProviderFailureKind::ParentAuthorityUnavailable,
            ReconCtProviderFailureKind::Cancelled,
            ReconCtProviderFailureKind::DeadlineReached,
            ReconCtProviderFailureKind::TransportFailed,
            ReconCtProviderFailureKind::RedirectRefused,
            ReconCtProviderFailureKind::AccessRejected,
            ReconCtProviderFailureKind::Throttled,
            ReconCtProviderFailureKind::ProviderNotFound,
            ReconCtProviderFailureKind::ServerFailure,
            ReconCtProviderFailureKind::UnexpectedStatus,
            ReconCtProviderFailureKind::UnsupportedMedia,
            ReconCtProviderFailureKind::UnsupportedContentCoding,
            ReconCtProviderFailureKind::ResponseTooLarge,
            ReconCtProviderFailureKind::InvalidResponse,
        ];
        for failure in failures {
            let token = failure.as_str();
            assert!(!token.is_empty());
            assert!(token
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        }
    }
}
