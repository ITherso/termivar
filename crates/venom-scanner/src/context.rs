//! Scan context: shared state for the historical `venom legacy-scan` pipeline.
//!
//! ## Runtime scope
//!
//! - **Build:** non-default `legacy-scanner` feature.
//! - **Execution:** Surface A — `ScanContext` owns the shared scan state. It also
//!   constructs and privately owns a `KnowledgeBase`, but the current legacy
//!   phases do not consume it (construction is not active use).
//! - **Default `venom scan`:** no.
//! - **Support:** legacy alpha.
//!
//! See `docs/internals/runtime-map.md`.

use crate::event_bus::EventBus;
use crate::http_evidence::HttpProbeMethod;
use crate::knowledge::KnowledgeBase;
use crate::legacy_discovery::{
    BoundedHttpResponse, DiscoveryDelta, DiscoveryForm, DiscoveryLimits, DiscoverySnapshot,
    LegacyDiscoveryAuthority,
};
use crate::logging::{LogLevel, Logger};
use crate::ScannerError;
use dashmap::{DashMap, DashSet};
use reqwest::Client;
use std::{collections::BTreeMap, sync::Arc, sync::Mutex};
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
    /// Raw HTTP client retained for unmigrated legacy phases 1 and 5–9 and
    /// custom phases that explicitly accept the legacy direct-I/O contract.
    ///
    /// Built-in discovery phases 2–4 ignore this client and use the private,
    /// exact-origin bounded discovery authority instead.
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
    // Shared, redirect-disabled authority for legacy discovery phases 2–4.
    discovery: LegacyDiscoveryAuthority,
    // Serializes typed discovery commits with their public compatibility-map
    // projection so internal consumers observe an old or complete new batch.
    discovery_bridge: Arc<Mutex<()>>,
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

    /// Creates a context with a host-selected finite discovery envelope and
    /// otherwise default runtime services.
    pub fn new_with_discovery_limits(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
        discovery_limits: DiscoveryLimits,
    ) -> Self {
        Self::new(target, client, telemetry_tx)
            .with_pre_execution_discovery_limits(discovery_limits)
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
    /// The authorized root endpoint is registered immediately; the visited
    /// set, typed forms, logger, and knowledge base start empty. The supplied
    /// raw HTTP client is promoted into shared ownership for unmigrated and
    /// custom legacy phases.
    pub fn with_event_bus(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
        phase_timeout_secs: u64,
        cancel_token: CancellationToken,
        event_bus: Arc<EventBus>,
    ) -> Self {
        let discovery = LegacyDiscoveryAuthority::new(
            &target,
            DiscoveryLimits::default(),
            cancel_token.clone(),
        );
        let discovered_endpoints = Arc::new(DashMap::new());
        for (url, parameters) in discovery.snapshot().endpoints() {
            discovered_endpoints.insert(url.clone(), parameters.iter().cloned().collect());
        }
        Self {
            target,
            client: Arc::new(client),
            discovered_endpoints,
            visited_urls: Arc::new(DashSet::new()),
            telemetry_tx,
            logger: Arc::new(Logger::new(LogLevel::Info)),
            phase_timeout_secs,
            cancel_token,
            event_bus,
            knowledge: KnowledgeBase::new(),
            discovery,
            discovery_bridge: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) fn with_pre_execution_discovery_limits(mut self, limits: DiscoveryLimits) -> Self {
        // Crate-owned composition calls this only before the context is shared
        // or any discovery request can consume authority. Keeping this seam
        // private prevents hosts from multiplying a live budget or discarding
        // committed typed state through mid-run reconfiguration.
        self.discovery =
            LegacyDiscoveryAuthority::new(&self.target, limits, self.cancel_token.clone());
        self.discovered_endpoints.clear();
        for (url, parameters) in self.discovery.snapshot().endpoints() {
            self.discovered_endpoints
                .insert(url.clone(), parameters.iter().cloned().collect());
        }
        self
    }

    /// Returns the configured discovery envelope.
    pub const fn discovery_limits(&self) -> DiscoveryLimits {
        self.discovery.limits()
    }

    pub(crate) async fn request(
        &self,
        action_id: &str,
        method: HttpProbeMethod,
        url: Url,
    ) -> Result<BoundedHttpResponse, ScannerError> {
        self.discovery.request(action_id, method, url).await
    }

    pub(crate) fn canonicalize_discovery_url(&self, url: &Url) -> Result<Url, ScannerError> {
        self.discovery.canonicalize(url)
    }

    pub(crate) fn discovery_snapshot(&self) -> DiscoverySnapshot {
        // Preserve the pre-1.0 host seeding contract while phases migrate to
        // typed state. Invalid or out-of-scope legacy strings are never
        // promoted into the bounded authority snapshot. Capture compatibility
        // mirrors first and clone typed state last: internal commits publish
        // typed state before updating those mirrors, so this ordering can
        // observe only the old or complete new typed batch, never a strict
        // partial internal commit.
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let legacy_endpoints = self
            .discovered_endpoints
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect::<BTreeMap<_, _>>();
        let legacy_visited = self
            .visited_urls
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<std::collections::BTreeSet<_>>();
        let mut snapshot = self.discovery.snapshot();
        for (raw_url, parameters) in legacy_endpoints {
            let Ok(url) = self.target.join(&raw_url) else {
                continue;
            };
            let Ok(url) = self.discovery.canonicalize(&url) else {
                continue;
            };
            snapshot.merge_endpoint(url, parameters);
        }
        for raw_url in legacy_visited {
            let Ok(url) = self.target.join(&raw_url) else {
                continue;
            };
            let Ok(url) = self.discovery.canonicalize(&url) else {
                continue;
            };
            snapshot.merge_visited(url);
        }
        snapshot
    }

    /// Returns stable typed form observations from bounded discovery.
    ///
    /// Ownership is parser-tree-descendant based; malformed HTML form-owner
    /// associations are not inferred.
    pub fn discovery_forms(&self) -> Vec<DiscoveryForm> {
        self.discovery.snapshot().forms().iter().cloned().collect()
    }

    pub(crate) fn commit_discovery(
        &self,
        action_id: &str,
        delta: DiscoveryDelta,
    ) -> Result<(), ScannerError> {
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let snapshot = self.discovery.commit(action_id, delta)?;
        for (url, parameters) in snapshot.endpoints() {
            self.discovered_endpoints
                .insert(url.clone(), parameters.iter().cloned().collect());
        }
        for url in snapshot.visited() {
            self.visited_urls.insert(url.clone());
        }
        Ok(())
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
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.discovered_endpoints.insert(url, params);
    }

    /// Marks a URL as visited for duplicate-scan prevention.
    pub fn mark_visited(&self, url: String) {
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.visited_urls.insert(url);
    }

    /// Returns whether a URL has already been marked as visited.
    pub fn is_visited(&self, url: &str) -> bool {
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.visited_urls.contains(url)
    }

    /// Returns the number of distinct discovered endpoint URLs.
    pub fn endpoint_count(&self) -> usize {
        let _bridge = self
            .discovery_bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        assert_eq!(
            ctx.endpoint_count(),
            1,
            "the authorized root is always registered"
        );
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
        assert_eq!(ctx.endpoint_count(), 2);

        let endpoints = ctx.discovered_endpoints.clone();
        assert!(endpoints.contains_key("/api/users"));
        let snapshot = ctx.discovery_snapshot();
        let canonical = "http://example.com/api/users";
        assert_eq!(
            snapshot.endpoints()[canonical],
            std::collections::BTreeSet::from(["email".to_owned(), "id".to_owned()]),
            "relative public host seeds remain visible to migrated phases"
        );
    }

    #[tokio::test]
    async fn public_endpoint_seed_derives_existing_query_names() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let target = Url::parse("http://example.com/").unwrap();
        let ctx = ScanContext::new(target, Client::new(), tx);

        ctx.add_endpoint("/search?q=known&mode=safe".to_owned(), Vec::new());

        let snapshot = ctx.discovery_snapshot();
        assert_eq!(
            snapshot.endpoints()["http://example.com/search?mode=safe&q=known"],
            std::collections::BTreeSet::from(["mode".to_owned(), "q".to_owned()])
        );
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
