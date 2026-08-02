use crate::event_bus::EventBus;
use crate::knowledge::KnowledgeBase;
use crate::logging::{LogLevel, Logger};
use dashmap::{DashMap, DashSet};
use reqwest::Client;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Zero-copy shared state across all scan phases.
///
/// Construct contexts through [`ScanContext::new`] or one of the policy-aware
/// constructors. Additional runtime state may be introduced without requiring
/// extension authors to initialize internal fields.
///
/// # Examples
///
/// ```rust
/// use reqwest::Client;
/// use url::Url;
/// use venom_scanner::ScanContext;
///
/// let (telemetry_tx, _telemetry_rx) = tokio::sync::mpsc::unbounded_channel();
/// let context = ScanContext::new(
///     Url::parse("https://example.test")?,
///     Client::new(),
///     telemetry_tx,
/// );
///
/// assert_eq!(context.knowledge().stats().evidence, 0);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Direct construction is intentionally unsupported so new runtime state does
/// not break extension code:
///
/// ```compile_fail
/// use reqwest::Client;
/// use url::Url;
/// use venom_scanner::ScanContext;
///
/// let (telemetry_tx, _telemetry_rx) = tokio::sync::mpsc::unbounded_channel();
/// let context = ScanContext::new(
///     Url::parse("https://example.test").unwrap(),
///     Client::new(),
///     telemetry_tx,
/// );
/// let _modified = ScanContext {
///     phase_timeout_secs: 30,
///     ..context
/// };
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct ScanContext {
    /// Root URL whose scope is being scanned.
    pub target: Url,
    /// Shared HTTP client used by scan phases.
    pub client: Arc<Client>,
    /// Discovered endpoints mapped to their observed parameter names.
    pub discovered_endpoints: Arc<DashMap<String, Vec<String>>>,
    /// URLs already visited by discovery phases.
    pub visited_urls: Arc<DashSet<String>>,
    /// Asynchronous telemetry channel for logging and analysis.
    pub telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Structured logger shared by scan phases.
    pub logger: Arc<Logger>,
    /// Maximum runtime of an individual phase, in seconds.
    pub phase_timeout_secs: u64,
    /// Token used to propagate graceful scan cancellation.
    pub cancel_token: CancellationToken,
    /// Event bus used to publish scan lifecycle and progress events.
    pub event_bus: Arc<EventBus>,
    // Evidence-driven memory shared by discovery, reasoning, and execution phases.
    // Kept private so its construction and replacement remain runtime policy.
    knowledge: KnowledgeBase,
}

impl ScanContext {
    /// Creates a context with a five-minute phase timeout, a fresh cancellation
    /// token, and a fresh event bus.
    pub fn new(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> Self {
        Self::with_timeout(target, client, telemetry_tx, 300) // 5 min default
    }

    /// Creates a context with an explicit per-phase timeout in seconds.
    ///
    /// A fresh cancellation token and event bus are installed for the scan.
    pub fn with_timeout(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
        phase_timeout_secs: u64,
    ) -> Self {
        Self::with_cancellation(
            target,
            client,
            telemetry_tx,
            phase_timeout_secs,
            CancellationToken::new(),
        )
    }

    /// Creates a context with explicit timeout and cancellation policy.
    ///
    /// A fresh event bus is installed for the scan.
    pub fn with_cancellation(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
        phase_timeout_secs: u64,
        cancel_token: CancellationToken,
    ) -> Self {
        Self::with_event_bus(
            target,
            client,
            telemetry_tx,
            phase_timeout_secs,
            cancel_token,
            Arc::new(EventBus::new()),
        )
    }

    /// Creates a context with all externally configurable runtime services.
    ///
    /// Discovery collections, the logger, and the knowledge base always start
    /// empty. The supplied HTTP client is promoted into shared ownership.
    pub fn with_event_bus(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
        phase_timeout_secs: u64,
        cancel_token: CancellationToken,
        event_bus: Arc<EventBus>,
    ) -> Self {
        Self {
            target,
            client: Arc::new(client),
            discovered_endpoints: Arc::new(DashMap::new()),
            visited_urls: Arc::new(DashSet::new()),
            telemetry_tx,
            logger: Arc::new(Logger::new(LogLevel::Info)),
            phase_timeout_secs,
            cancel_token,
            event_bus,
            knowledge: KnowledgeBase::new(),
        }
    }

    /// Sends a plain-text message to the telemetry channel.
    ///
    /// Messages are dropped when the receiving side has closed.
    pub fn log(&self, msg: String) {
        let _ = self.telemetry_tx.send(msg);
    }

    /// Records a discovered endpoint and its observed parameter names.
    ///
    /// Recording the same URL again replaces its prior parameter list.
    pub fn add_endpoint(&self, url: String, params: Vec<String>) {
        self.discovered_endpoints.insert(url, params);
    }

    /// Marks a URL as visited for duplicate-scan prevention.
    pub fn mark_visited(&self, url: String) {
        self.visited_urls.insert(url);
    }

    /// Returns whether a URL has already been marked as visited.
    pub fn is_visited(&self, url: &str) -> bool {
        self.visited_urls.contains(url)
    }

    /// Returns the number of distinct discovered endpoint URLs.
    pub fn endpoint_count(&self) -> usize {
        self.discovered_endpoints.len()
    }

    /// Returns the evidence-driven knowledge base shared by this scan.
    ///
    /// The context retains ownership so the runtime can preserve one knowledge
    /// identity across phases and cloned contexts.
    pub fn knowledge(&self) -> &KnowledgeBase {
        &self.knowledge
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_context_creation() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let url = Url::parse("http://example.com").unwrap();
        let client = Client::new();

        let ctx = ScanContext::new(url, client, tx);
        assert_eq!(ctx.endpoint_count(), 0);
        assert_eq!(ctx.knowledge().stats().evidence, 0);
    }

    #[tokio::test]
    async fn test_add_endpoint_zero_copy() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let url = Url::parse("http://example.com").unwrap();
        let client = Client::new();
        let ctx = ScanContext::new(url, client, tx);

        ctx.add_endpoint(
            "/api/users".to_string(),
            vec!["id".to_string(), "email".to_string()],
        );
        assert_eq!(ctx.endpoint_count(), 1);

        let endpoints = ctx.discovered_endpoints.clone();
        assert!(endpoints.contains_key("/api/users"));
    }

    #[tokio::test]
    async fn test_visited_urls_concurrent() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let url = Url::parse("http://example.com").unwrap();
        let client = Client::new();
        let ctx = ScanContext::new(url, client, tx);

        ctx.mark_visited("http://example.com/page1".to_string());
        assert!(ctx.is_visited("http://example.com/page1"));
        assert!(!ctx.is_visited("http://example.com/page2"));
    }
}
