use crate::event_bus::EventBus;
use crate::knowledge::KnowledgeBase;
use crate::logging::{LogLevel, Logger};
use dashmap::{DashMap, DashSet};
use reqwest::Client;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Zero-copy shared state across all scan phases
#[derive(Clone)]
pub struct ScanContext {
    pub target: Url,
    pub client: Arc<Client>,
    // Discovered endpoints with their parameters: "https://target.com/api/users" -> ["id", "email"]
    pub discovered_endpoints: Arc<DashMap<String, Vec<String>>>,
    // Set of visited URLs to prevent duplicate scanning
    pub visited_urls: Arc<DashSet<String>>,
    // Async telemetry channel for logging and analysis
    pub telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
    // Structured logger with filtering and formatting
    pub logger: Arc<Logger>,
    // Phase timeout in seconds (prevents single phase from hanging entire scan)
    pub phase_timeout_secs: u64,
    // Cancellation token for graceful scan cancellation (CTRL+C, Dashboard cancel, cloud kill)
    pub cancel_token: CancellationToken,
    // Event bus for publishing progress events (PhaseStarted, PhaseCompleted, PhaseFailed)
    pub event_bus: Arc<EventBus>,
    // Evidence-driven memory shared by discovery, reasoning, and execution phases
    pub knowledge: KnowledgeBase,
}

impl ScanContext {
    pub fn new(
        target: Url,
        client: Client,
        telemetry_tx: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> Self {
        Self::with_timeout(target, client, telemetry_tx, 300) // 5 min default
    }

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

    pub fn log(&self, msg: String) {
        let _ = self.telemetry_tx.send(msg);
    }

    pub fn add_endpoint(&self, url: String, params: Vec<String>) {
        self.discovered_endpoints.insert(url, params);
    }

    pub fn mark_visited(&self, url: String) {
        self.visited_urls.insert(url);
    }

    pub fn is_visited(&self, url: &str) -> bool {
        self.visited_urls.contains(url)
    }

    pub fn endpoint_count(&self) -> usize {
        self.discovered_endpoints.len()
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
        assert_eq!(ctx.knowledge.stats().evidence, 0);
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
