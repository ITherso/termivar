//! # Phase 6: bounded reflection observation
//!
//! This legacy phase records reproducible, byte-exact reflection of a benign
//! nonce. Reflection is an input/output observation, not proof that a browser
//! parsed or executed attacker-controlled script. Consequently this phase
//! does not establish an XSS claim.

use async_trait::async_trait;
use url::Url;
use uuid::Uuid;

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
    http_evidence::HttpProbeMethod,
    legacy_discovery::BoundedHttpResponse,
};

const XSS_REFLECTION_ACTION_ID: &str = "legacy.observation.reflection";
const REFLECTION_MARKER_PREFIX: &str = "venom-xss-reflection-";
const MAX_REFLECTION_REQUESTS: usize = 18;
const REQUESTS_PER_PARAMETER: usize = 3;

/// Conservative lexical location of an exact reflection.
///
/// These labels describe response syntax only. None of them establish
/// executable browser behavior or XSS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReflectionContext {
    HtmlText,
    DoubleQuotedAttribute,
    SingleQuotedAttribute,
    TagSyntax,
    ScriptElementText,
    NonHtmlText,
    Unknown,
}

/// Legacy phase-six reflection observer.
pub struct XssScanner;

impl XssScanner {
    fn analyze_context(body: &[u8], marker: &str, content_type: Option<&str>) -> ReflectionContext {
        let Some(body) = std::str::from_utf8(body).ok() else {
            return ReflectionContext::Unknown;
        };
        let Some(offset) = body.find(marker) else {
            return ReflectionContext::Unknown;
        };
        if !is_html_media_type(content_type) {
            return if is_textual_media_type(content_type) {
                ReflectionContext::NonHtmlText
            } else {
                ReflectionContext::Unknown
            };
        }

        let before = &body[..offset];
        let before_lower = before.to_ascii_lowercase();
        let script_open = before_lower.rfind("<script");
        let script_close = before_lower.rfind("</script");
        if script_open.is_some() && script_open > script_close {
            return ReflectionContext::ScriptElementText;
        }

        let last_open = before.rfind('<');
        let last_close = before.rfind('>');
        if let Some(open) = last_open.filter(|open| last_close.is_none_or(|close| close < *open)) {
            let tag_prefix = &before[open..];
            if !tag_prefix.matches('"').count().is_multiple_of(2) {
                ReflectionContext::DoubleQuotedAttribute
            } else if !tag_prefix.matches('\'').count().is_multiple_of(2) {
                ReflectionContext::SingleQuotedAttribute
            } else {
                ReflectionContext::TagSyntax
            }
        } else {
            ReflectionContext::HtmlText
        }
    }
}

#[async_trait]
impl ScanPhase for XssScanner {
    fn phase_number(&self) -> u8 {
        6
    }

    fn name(&self) -> &'static str {
        "Reflection Context Observer"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 6: bounded exact-reflection observation initiated".to_owned());
        let snapshot = ctx.discovery_snapshot();
        let mut observations = Vec::new();
        let mut requests = 0_usize;

        'endpoints: for (endpoint, parameters) in snapshot.endpoints() {
            let endpoint = ctx.canonicalize_discovery_url(&Url::parse(endpoint)?)?;
            for parameter in parameters {
                if MAX_REFLECTION_REQUESTS.saturating_sub(requests) < REQUESTS_PER_PARAMETER {
                    break 'endpoints;
                }
                let marker = format!(
                    "{REFLECTION_MARKER_PREFIX}{}&probe",
                    Uuid::new_v4().simple()
                );
                let baseline = ctx
                    .verification_request(
                        XSS_REFLECTION_ACTION_ID,
                        HttpProbeMethod::Get,
                        endpoint.clone(),
                    )
                    .await?;
                requests += 1;
                let probe_url = replace_query_parameter(&endpoint, parameter, &marker);
                let candidate = ctx
                    .verification_request(
                        XSS_REFLECTION_ACTION_ID,
                        HttpProbeMethod::Get,
                        probe_url.clone(),
                    )
                    .await?;
                requests += 1;
                let reproduction = ctx
                    .verification_request(XSS_REFLECTION_ACTION_ID, HttpProbeMethod::Get, probe_url)
                    .await?;
                requests += 1;

                let Some((context, media_type)) =
                    reproducible_exact_reflection(&baseline, &candidate, &reproduction, &marker)
                else {
                    continue;
                };

                observations.push(ScanFinding {
                    phase: self.phase_number(),
                    module_name: self.name().to_owned(),
                    severity: "INFO".to_owned(),
                    description: format!(
                        "Parameter '{parameter}' reproducibly reflected a byte-exact benign nonce; this is not evidence of script execution and does not establish XSS."
                    ),
                    evidence: format!(
                        "endpoint={}; media_type={media_type}; syntactic_context={context:?}; exact_reflection=true; response_truncated=false",
                        endpoint_subject(&endpoint)
                    ),
                });
            }
        }

        ctx.log(format!(
            "Phase 6: bounded reflection observation completed with {} INFO observations across {} requests",
            observations.len(), requests
        ));
        Ok(observations)
    }
}

fn reproducible_exact_reflection(
    baseline: &BoundedHttpResponse,
    candidate: &BoundedHttpResponse,
    reproduction: &BoundedHttpResponse,
    marker: &str,
) -> Option<(ReflectionContext, String)> {
    if [baseline, candidate, reproduction]
        .into_iter()
        .any(|response| response.body_truncated() || !(200..300).contains(&response.status()))
        || body_contains(baseline.body(), marker)
        || body_contains(baseline.body(), REFLECTION_MARKER_PREFIX)
        || !body_contains(candidate.body(), marker)
        || !body_contains(reproduction.body(), marker)
    {
        return None;
    }

    let candidate_media = normalized_media_type(candidate.content_type());
    let reproduction_media = normalized_media_type(reproduction.content_type());
    if candidate_media != reproduction_media {
        return None;
    }
    let candidate_context =
        XssScanner::analyze_context(candidate.body(), marker, candidate.content_type());
    let reproduction_context =
        XssScanner::analyze_context(reproduction.body(), marker, reproduction.content_type());
    (candidate_context == reproduction_context).then_some((
        candidate_context,
        candidate_media.unwrap_or_else(|| "unknown".to_owned()),
    ))
}

fn normalized_media_type(content_type: Option<&str>) -> Option<String> {
    content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}

fn is_html_media_type(content_type: Option<&str>) -> bool {
    matches!(
        normalized_media_type(content_type).as_deref(),
        Some("text/html" | "application/xhtml+xml")
    )
}

fn is_textual_media_type(content_type: Option<&str>) -> bool {
    normalized_media_type(content_type).is_some_and(|media| {
        media.starts_with("text/")
            || matches!(
                media.as_str(),
                "application/json" | "application/xml" | "application/xhtml+xml"
            )
            || media.ends_with("+json")
            || media.ends_with("+xml")
    })
}

fn replace_query_parameter(endpoint: &Url, name: &str, value: &str) -> Url {
    let retained = endpoint
        .query_pairs()
        .filter(|(existing, _)| existing != name)
        .map(|(existing, value)| (existing.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let mut mutated = endpoint.clone();
    mutated
        .query_pairs_mut()
        .clear()
        .extend_pairs(retained)
        .append_pair(name, value);
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
        Arc,
    };
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use super::*;
    use crate::{legacy_discovery::VerificationLimits, runner::ScanRunner};
    use termivar_core::{OutcomeStatus, SecuritySeverity};

    struct LocalFixture {
        target: Url,
        requests: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl Drop for LocalFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve_fixture(
        max_requests: usize,
        handler: impl Fn(&Url) -> String + Send + Sync + 'static,
    ) -> LocalFixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed_requests = Arc::clone(&requests);
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
                    assert!(request.len() <= 16 * 1_024);
                }
                observed_requests.fetch_add(1, Ordering::SeqCst);
                let request_target = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap()
                    .to_owned();
                let url = Url::parse(&format!("http://fixture{request_target}")).unwrap();
                let body = handler(&url);
                let wire = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                stream.write_all(wire.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        LocalFixture {
            target: Url::parse(&format!("http://{address}/reflect?input=baseline")).unwrap(),
            requests,
            task,
        }
    }

    fn scan_context(target: Url) -> ScanContext {
        let limits = VerificationLimits::new()
            .with_max_requests(8)
            .unwrap()
            .with_request_timeout(Duration::from_secs(1))
            .unwrap()
            .with_max_wall_time(Duration::from_secs(10))
            .unwrap()
            .with_body_limits(64 * 1_024, 16 * 1_024)
            .unwrap();
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        ScanContext::new_with_verification_limits(target, reqwest::Client::new(), telemetry, limits)
    }

    fn last_parameter(url: &Url, name: &str) -> Option<String> {
        url.query_pairs()
            .filter(|(parameter, _)| parameter == name)
            .map(|(_, value)| value.into_owned())
            .last()
    }

    #[test]
    fn phase_identity_is_stable() {
        assert_eq!(XssScanner.phase_number(), 6);
        assert_eq!(XssScanner.name(), "Reflection Context Observer");
    }

    #[test]
    fn context_labels_are_syntax_only() {
        let marker = "venom-xss-reflection-example&probe";
        assert_eq!(
            XssScanner::analyze_context(
                format!("<div>{marker}</div>").as_bytes(),
                marker,
                Some("text/html")
            ),
            ReflectionContext::HtmlText
        );
        assert_eq!(
            XssScanner::analyze_context(
                format!(r#"<input value="{marker}">"#).as_bytes(),
                marker,
                Some("text/html")
            ),
            ReflectionContext::DoubleQuotedAttribute
        );
        assert_eq!(
            XssScanner::analyze_context(
                format!("<script>const value = '{marker}';</script>").as_bytes(),
                marker,
                Some("text/html")
            ),
            ReflectionContext::ScriptElementText
        );
        assert_eq!(
            XssScanner::analyze_context(marker.as_bytes(), marker, Some("application/json")),
            ReflectionContext::NonHtmlText
        );
    }

    #[tokio::test]
    async fn exact_reproducible_reflection_is_info_only() {
        let fixture = serve_fixture(3, |url| {
            let value = last_parameter(url, "input").unwrap();
            if value.starts_with(REFLECTION_MARKER_PREFIX) {
                format!("<div>{value}</div>")
            } else {
                "<div>ordinary page</div>".to_owned()
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let observations = XssScanner.execute(&context).await.unwrap();

        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].severity, "INFO");
        assert!(observations[0].description.contains("not evidence"));
        assert!(observations[0]
            .description
            .contains("does not establish XSS"));
        assert!(observations[0]
            .evidence
            .contains("syntactic_context=HtmlText"));
    }

    #[tokio::test]
    async fn runner_projects_reflection_as_unverified_info_only() {
        let fixture = serve_fixture(3, |url| {
            let value = last_parameter(url, "input").unwrap();
            if value.starts_with(REFLECTION_MARKER_PREFIX) {
                format!("<div>{value}</div>")
            } else {
                "<div>ordinary page</div>".to_owned()
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());
        let mut runner = ScanRunner::new();
        runner.register_phase(Box::new(XssScanner));

        let report = runner.run_pipeline(context).await.unwrap();

        assert_eq!(report.outcomes().len(), 1);
        let observation = &report.outcomes()[0];
        assert_eq!(observation.severity(), SecuritySeverity::Info);
        assert_eq!(observation.disposition(), OutcomeStatus::Unknown);
        assert!(observation.verification_outcome().is_none());
        assert!(observation.evidence_ids().is_empty());
    }

    #[tokio::test]
    async fn encoded_or_inert_echo_does_not_establish_xss() {
        let fixture = serve_fixture(3, |url| {
            let value = last_parameter(url, "input").unwrap();
            if value.starts_with(REFLECTION_MARKER_PREFIX) {
                format!("<pre>{}</pre>", value.replace('&', "&amp;"))
            } else {
                "<div>ordinary page</div>".to_owned()
            }
        })
        .await;
        let context = scan_context(fixture.target.clone());

        let observations = XssScanner.execute(&context).await.unwrap();

        assert!(observations.is_empty());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
    }
}
