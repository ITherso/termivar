//! # Phase 3: Directory Fuzzing & Discovery
//!
//! Brute-forces common directories and endpoints using wordlist fuzzing
//! with semaphore-based rate limiting to avoid WAF triggers.
//!
//! ## Wordlist
//! - `/admin`, `/api/v*`, `/swagger`, `/graphql`, `/.git`, `/.env`
//! - `/backup`, `/test`, `/config`, `/uploads`, and 40+ more
//!
//! ## Detection
//! - 200 (OK): Valid endpoint
//! - 3xx (Redirect): Follow with caution
//! - 401/403: Protected endpoint (still valuable intel)

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

/// Directory fuzzer with concurrent requests and rate limiting
#[derive(Debug)]
pub struct DirectoryFuzzer {
    wordlist: Vec<String>,
    concurrency_limit: usize,
}

impl DirectoryFuzzer {
    /// Creates a legacy directory fuzzer, clamping zero concurrency to one.
    pub fn new(wordlist: Vec<String>, concurrency_limit: usize) -> Self {
        Self {
            wordlist,
            concurrency_limit: concurrency_limit.max(1),
        }
    }

    /// Uses the default wordlist, clamping zero concurrency to one.
    pub fn with_default_wordlist(concurrency_limit: usize) -> Self {
        let wordlist = vec![
            // Admin panels
            "/admin",
            "/admin/",
            "/administrator",
            "/admin/login",
            // API endpoints
            "/api",
            "/api/",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/api/public",
            "/api/private",
            "/api/internal",
            // Version control
            "/.git",
            "/.git/",
            "/.gitconfig",
            "/.github",
            "/.github/workflows",
            "/.svn",
            "/.hg",
            // Configuration files
            "/config",
            "/config/",
            "/configuration",
            "/settings",
            "/.env",
            "/web.config",
            "/app.config",
            "/.htaccess",
            // Common directories
            "/uploads",
            "/upload",
            "/files",
            "/attachments",
            "/backup",
            "/backups",
            "/.backup",
            "/logs",
            "/log",
            "/.logs",
            "/data",
            "/database",
            "/db",
            "/tmp",
            "/temp",
            "/.tmp",
            // Testing/debugging endpoints
            "/test",
            "/tests",
            "/testing",
            "/debug",
            "/debugger",
            "/.debug",
            "/status",
            "/health",
            "/healthcheck",
            // Documentation
            "/docs",
            "/doc",
            "/documentation",
            "/swagger",
            "/swagger-ui",
            "/swagger.json",
            "/graphql",
            "/graphql-ui",
            // Backup extensions
            "/.bak",
            "/.backup",
            "/.old",
            "/.orig",
            // Hidden directories
            "/.well-known",
            "/.well-known/",
            "/.well-known/acme-challenge",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            wordlist,
            concurrency_limit: concurrency_limit.max(1),
        }
    }
}

#[async_trait]
impl ScanPhase for DirectoryFuzzer {
    fn phase_number(&self) -> u8 {
        3
    }

    fn name(&self) -> &'static str {
        "Directory & Endpoint Fuzzer"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 3: Async directory and endpoint brute-force initiated...".to_string());
        let mut findings = Vec::new();

        let base_url = ctx.target.to_string();
        let client = &ctx.client;

        let semaphore = Arc::new(Semaphore::new(self.concurrency_limit));
        // `JoinSet` owns every request task. Dropping this phase future (for
        // example when the runner cancels or times it out) therefore aborts
        // the entire fan-out instead of detaching in-flight requests.
        let mut tasks = JoinSet::new();

        for (ordinal, word) in self.wordlist.iter().enumerate() {
            let target_url = if base_url.ends_with('/') && word.starts_with('/') {
                format!("{}{}", base_url.trim_end_matches('/'), word)
            } else if !base_url.ends_with('/') && !word.starts_with('/') {
                format!("{}/{}", base_url, word)
            } else {
                format!("{}{}", base_url, word)
            };

            let sem = Arc::clone(&semaphore);
            let cl = Arc::clone(client);
            let url_clone = target_url.clone();

            tasks.spawn(async move {
                let _permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(_) => return (ordinal, None),
                };

                let result = match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    cl.get(&url_clone).send(),
                )
                .await
                {
                    Ok(Ok(res)) => {
                        let status = res.status();

                        if status.is_success() || status.is_redirection() {
                            Some((url_clone, status))
                        } else if status == StatusCode::FORBIDDEN
                            || status == StatusCode::UNAUTHORIZED
                        {
                            // Protected endpoint (likely exists)
                            Some((url_clone, status))
                        } else {
                            None
                        }
                    },
                    _ => None,
                };
                (ordinal, result)
            });
        }

        let mut completed: Vec<_> = collect_join_set(&mut tasks)
            .await?
            .into_iter()
            .filter_map(|(ordinal, result)| result.map(|result| (ordinal, result)))
            .collect();
        completed.sort_by_key(|(ordinal, _)| *ordinal);

        for (_, (url, status)) in completed {
            ctx.discovered_endpoints.insert(url.clone(), Vec::new());
            if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
                ctx.log(format!("Protected: {} ({})", url, status));
            } else {
                ctx.log(format!("Found: {} ({})", url, status));
            }
            findings.push(ScanFinding {
                phase: self.phase_number(),
                module_name: self.name().to_string(),
                severity: if status.is_success() { "MEDIUM" } else { "LOW" }.to_string(),
                description: "Discovered hidden directory/endpoint via brute-force".to_string(),
                evidence: format!("URL: {} -> HTTP {}", url, status),
            });
        }

        ctx.log(format!(
            "Phase 3: Directory fuzzing completed. Discovered {} endpoints.",
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
    use tokio_util::sync::CancellationToken;
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
        let fuzzer = DirectoryFuzzer::with_default_wordlist(10);
        assert_eq!(fuzzer.phase_number(), 3);
    }

    #[test]
    fn test_phase_name() {
        let fuzzer = DirectoryFuzzer::with_default_wordlist(10);
        assert_eq!(fuzzer.name(), "Directory & Endpoint Fuzzer");
    }

    #[test]
    fn test_default_wordlist_not_empty() {
        let fuzzer = DirectoryFuzzer::with_default_wordlist(10);
        assert!(!fuzzer.wordlist.is_empty());
        assert!(fuzzer.wordlist.len() > 20);
    }

    #[test]
    fn test_custom_wordlist() {
        let custom = vec!["/custom".to_string(), "/test".to_string()];
        let fuzzer = DirectoryFuzzer::new(custom.clone(), 5);
        assert_eq!(fuzzer.wordlist.len(), 2);
        assert_eq!(fuzzer.concurrency_limit, 5);
    }

    #[test]
    fn zero_concurrency_is_clamped_to_one() {
        let custom = DirectoryFuzzer::new(vec!["/custom".to_string()], 0);
        let defaults = DirectoryFuzzer::with_default_wordlist(0);

        assert_eq!(custom.concurrency_limit, 1);
        assert_eq!(defaults.concurrency_limit, 1);
    }

    #[tokio::test]
    async fn runner_cancellation_aborts_all_directory_request_tasks() {
        let mut server = serve_released_response_then_watch_for_another_request().await;
        let cancellation = CancellationToken::new();
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let context = ScanContext::with_cancellation(
            server.target.clone(),
            reqwest::Client::new(),
            telemetry,
            60,
            cancellation.clone(),
        );
        let observed_context = context.clone();
        let mut runner = ScanRunner::new();
        runner.register_phase(Box::new(DirectoryFuzzer::new(
            vec!["/first".to_string(), "/second".to_string()],
            1,
        )));
        let run = tokio::spawn(async move { runner.run_pipeline(context).await });

        tokio::time::timeout(Duration::from_secs(2), server.first_request.take().unwrap())
            .await
            .expect("directory phase must issue its first local request")
            .unwrap();
        cancellation.cancel();
        let report = tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .expect("cancelled runner must terminate")
            .unwrap()
            .unwrap();

        assert_eq!(report.status(), RunStatus::Cancelled);
        assert_eq!(report.steps()[0].status(), RunStepStatus::Cancelled);
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
        assert!(observed_context.discovered_endpoints.is_empty());

        server.release_response.take().unwrap().send(()).unwrap();
        (&mut server.task).await.unwrap();

        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
        assert!(observed_context.discovered_endpoints.is_empty());
    }
}
