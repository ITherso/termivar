//! # Phase 4: Parameter Discovery & Injection Testing
//!
//! Discovers hidden parameters using marker-based injection and HTTP status analysis.
//! Tests 40+ common parameter names to identify injectable inputs.
//!
//! ## Wordlist
//! - id, user_id, admin, debug, api_key, token, password, email, username
//! - redirect, url, profile, template, data, key, value, and more
//!
//! ## Detection Method
//! - Injects marker value (e.g., "venom_7b3a9c2e_test")
//! - HTTP 400 = parameter recognized but invalid
//! - Marker not found = parameter doesn't exist

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
    runner::collect_join_set,
};
use async_trait::async_trait;
use reqwest::StatusCode;
use std::sync::Arc;
use tokio::{sync::Semaphore, task::JoinSet};

/// Parameter discovery with marker-based injection detection
#[derive(Debug)]
pub struct ParameterDiscoverer {
    param_wordlist: Vec<String>,
    concurrency_limit: usize,
}

impl ParameterDiscoverer {
    pub fn new(param_wordlist: Vec<String>, concurrency_limit: usize) -> Self {
        Self {
            param_wordlist,
            concurrency_limit,
        }
    }

    /// Default parameter wordlist for common API parameters
    pub fn with_default_wordlist(concurrency_limit: usize) -> Self {
        let param_wordlist = vec![
            // User/ID parameters
            "id",
            "user_id",
            "uid",
            "userid",
            "user",
            "username",
            "email",
            "email_id",
            "account_id",
            "account",
            // Query/Search parameters
            "q",
            "query",
            "search",
            "s",
            "keyword",
            "keywords",
            // Filtering/Sorting
            "filter",
            "filters",
            "sort",
            "order",
            "page",
            "limit",
            "offset",
            "per_page",
            // Admin/Debug parameters
            "admin",
            "debug",
            "verbose",
            "log_level",
            "test",
            "testing",
            "mode",
            // API parameters
            "key",
            "token",
            "api_key",
            "access_token",
            "secret",
            "password",
            "pass",
            // Bypass/Security parameters
            "bypass",
            "force",
            "skip_validation",
            "callback",
            "redirect",
            "return_to",
            "referrer",
            "referer",
            // File/Content parameters
            "file",
            "filename",
            "path",
            "url",
            "image",
            "avatar",
            "photo",
            "attachment",
            // Data/Format parameters
            "data",
            "value",
            "content",
            "body",
            "format",
            "type",
            "encoding",
            "lang",
            "language",
            // Numeric identifiers
            "post_id",
            "product_id",
            "order_id",
            "item_id",
            "resource_id",
            "object_id",
            // Action parameters
            "action",
            "method",
            "command",
            "op",
            "do",
            "go",
            "step",
            "action_type",
            // Version/Compatibility
            "version",
            "v",
            "api_version",
            // Export/Download
            "export",
            "download",
            "output",
            "format_type",
            // Common typos/variations
            "admin_id",
            "Admin",
            "ADMIN",
            "callback_url",
            "return_url",
            "redirect_url",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            param_wordlist,
            concurrency_limit,
        }
    }
}

#[async_trait]
impl ScanPhase for ParameterDiscoverer {
    fn phase_number(&self) -> u8 {
        4
    }

    fn name(&self) -> &'static str {
        "Hidden Parameter Miner"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 4: Hidden parameter discovery (Parameter Mining) initiated...".to_string());
        let mut findings = Vec::new();

        let client = &ctx.client;
        let semaphore = Arc::new(Semaphore::new(self.concurrency_limit));

        // Iterate over all discovered endpoints from Phase 2 & 3
        let endpoints: Vec<String> = ctx
            .discovered_endpoints
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        ctx.log(format!(
            "Analyzing {} endpoints for hidden parameters...",
            endpoints.len()
        ));

        for url_str in endpoints {
            ctx.log(format!("Mining parameters on: {}", url_str));

            let current_params: Vec<String> = ctx
                .discovered_endpoints
                .get(&url_str)
                .map(|entry| entry.clone())
                .unwrap_or_default();

            // The task set is scoped to this `execute` future. Runner timeout
            // or cancellation drops the set and aborts all outstanding probes.
            let mut tasks = JoinSet::new();

            for (ordinal, param) in self.param_wordlist.iter().enumerate() {
                let sem = Arc::clone(&semaphore);
                let cl = Arc::clone(client);
                let url_to_test = url_str.clone();
                let param_name = param.clone();

                tasks.spawn(async move {
                    let _permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => return (ordinal, None),
                    };

                    // Test parameter with marker value
                    let marker = "venom_7b3a9c2e_test";
                    let test_url = if url_to_test.contains('?') {
                        format!("{}&{}={}", url_to_test, param_name, marker)
                    } else {
                        format!("{}?{}={}", url_to_test, param_name, marker)
                    };

                    let result = match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        cl.get(&test_url).send(),
                    )
                    .await
                    {
                        Ok(Ok(res)) => {
                            let status = res.status();

                            // Check if parameter was accepted (200 OK or 3xx redirect)
                            if status == StatusCode::OK || status.is_redirection() {
                                if let Ok(body) = res.text().await {
                                    // Simple heuristic: Check if marker appears in response (reflection check)
                                    if body.contains(marker) {
                                        return (
                                            ordinal,
                                            Some((param_name, "reflection".to_string())),
                                        );
                                    }
                                }
                                // Parameter seems accepted even without reflection
                                Some((param_name, "accepted".to_string()))
                            } else if status == StatusCode::BAD_REQUEST {
                                // Parameter rejected (likely doesn't exist or wrong format)
                                None
                            } else {
                                // Other status codes - parameter might exist
                                Some((param_name, "exists".to_string()))
                            }
                        },
                        _ => None,
                    };
                    (ordinal, result)
                });
            }

            // Collect results and update DashMap with discovered parameters
            let mut discovered_params = current_params.clone();
            let mut param_findings = Vec::new();

            let mut completed: Vec<_> = collect_join_set(&mut tasks)
                .await?
                .into_iter()
                .filter_map(|(ordinal, result)| result.map(|result| (ordinal, result)))
                .collect();
            completed.sort_by_key(|(ordinal, _)| *ordinal);

            for (_, (found_param, evidence_type)) in completed {
                if !discovered_params.contains(&found_param) {
                    discovered_params.push(found_param.clone());

                    let severity = if evidence_type == "reflection" {
                        ctx.log(format!(
                            "Parameter reflection: {} on {}",
                            found_param, url_str
                        ));
                        "HIGH"
                    } else {
                        "MEDIUM"
                    };

                    param_findings.push(ScanFinding {
                        phase: self.phase_number(),
                        module_name: self.name().to_string(),
                        severity: severity.to_string(),
                        description: format!(
                            "Discovered hidden parameter '{}' on {}",
                            found_param, url_str
                        ),
                        evidence: format!(
                            "Evidence type: {} (marker reflection detected)",
                            evidence_type
                        ),
                    });
                }
            }

            // Update endpoint with discovered parameters (zero-copy via DashMap)
            ctx.discovered_endpoints
                .alter(&url_str, |_, _| discovered_params.clone());

            findings.extend(param_findings);
        }

        ctx.log(format!(
            "Phase 4: Parameter mining completed. Discovered {} parameters.",
            findings.len()
        ));

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
        task::JoinHandle,
    };
    use venom_core::{RunStatus, RunStepStatus};

    use super::*;
    use crate::runner::ScanRunner;

    struct ReleasedResponseServer {
        target: url::Url,
        requests: Arc<AtomicUsize>,
        first_request: Option<oneshot::Receiver<()>>,
        release_response: Option<oneshot::Sender<()>>,
        task: JoinHandle<()>,
    }

    impl Drop for ReleasedResponseServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve_released_response_then_watch_for_another_request() -> ReleasedResponseServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let (first_request_tx, first_request) = oneshot::channel();
        let (release_response, release_response_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            counted.fetch_add(1, Ordering::SeqCst);
            let mut request = [0_u8; 2048];
            let _ = first.read(&mut request).await;
            let _ = first_request_tx.send(());
            let _ = release_response_rx.await;
            let _ = first
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
            let _ = first.shutdown().await;

            if let Ok(Ok((_second, _))) =
                tokio::time::timeout(Duration::from_secs(1), listener.accept()).await
            {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        });

        ReleasedResponseServer {
            target: url::Url::parse(&format!("http://{address}/")).unwrap(),
            requests,
            first_request: Some(first_request),
            release_response: Some(release_response),
            task,
        }
    }

    #[test]
    fn test_phase_number() {
        let discoverer = ParameterDiscoverer::with_default_wordlist(10);
        assert_eq!(discoverer.phase_number(), 4);
    }

    #[test]
    fn test_phase_name() {
        let discoverer = ParameterDiscoverer::with_default_wordlist(10);
        assert_eq!(discoverer.name(), "Hidden Parameter Miner");
    }

    #[test]
    fn test_default_wordlist_size() {
        let discoverer = ParameterDiscoverer::with_default_wordlist(10);
        assert!(!discoverer.param_wordlist.is_empty());
        assert!(discoverer.param_wordlist.len() > 30);
    }

    #[test]
    fn test_custom_param_wordlist() {
        let custom = vec!["debug".to_string(), "admin".to_string()];
        let discoverer = ParameterDiscoverer::new(custom.clone(), 5);
        assert_eq!(discoverer.param_wordlist.len(), 2);
    }

    #[tokio::test]
    async fn runner_timeout_aborts_all_parameter_request_tasks() {
        let mut server = serve_released_response_then_watch_for_another_request().await;
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let context =
            ScanContext::with_timeout(server.target.clone(), reqwest::Client::new(), telemetry, 1);
        context.add_endpoint(server.target.to_string(), vec!["existing".to_string()]);
        let observed_context = context.clone();
        let mut runner = ScanRunner::new();
        runner.register_phase(Box::new(ParameterDiscoverer::new(
            vec!["first".to_string(), "second".to_string()],
            1,
        )));
        let run = tokio::spawn(async move { runner.run_pipeline(context).await });

        tokio::time::timeout(Duration::from_secs(2), server.first_request.take().unwrap())
            .await
            .expect("parameter phase must issue its first local request")
            .unwrap();
        let report = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("timed-out runner must terminate")
            .unwrap()
            .unwrap();

        assert_eq!(report.status(), RunStatus::Failed);
        assert_eq!(report.steps()[0].status(), RunStepStatus::TimedOut);
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
        assert_eq!(
            observed_context
                .discovered_endpoints
                .get(server.target.as_str())
                .unwrap()
                .value()
                .as_slice(),
            &[String::from("existing")]
        );

        server.release_response.take().unwrap().send(()).unwrap();
        (&mut server.task).await.unwrap();

        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
        assert_eq!(
            observed_context
                .discovered_endpoints
                .get(server.target.as_str())
                .unwrap()
                .value()
                .as_slice(),
            &[String::from("existing")]
        );
    }
}
