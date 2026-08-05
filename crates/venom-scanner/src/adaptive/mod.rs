//! Adaptive execution policy and payload mutation.
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The deterministic pipeline maps evidence-backed outcomes to runner
//! directives. The legacy payload engine analyzes recent response metrics and
//! recommends payload transformations based on:
//! - Detection patterns (blacklist detection)
//! - Response timing (rate limiting)
//! - Status codes (WAF blocking patterns)
//! - Content changes (response filtering)

pub mod payloads;
pub mod pipeline;
pub mod scoring;
pub mod strategy;

use std::collections::VecDeque;

pub use payloads::PayloadMutator;
pub use pipeline::{
    AdaptationLedger, AdaptationLimits, AdaptationRule, AdaptationRuleEvaluation, AdaptiveDecision,
    AdaptivePipeline, AdaptivePipelineError, AdaptiveRuleWrite, OutcomeSelector, PipelineDirective,
};
pub use scoring::{ResponseMetrics, ScoringEngine};
pub use strategy::{AdaptationStrategy, DetectionPattern, StrategySelector};

/// Learning engine for payload adaptation
#[derive(Debug)]
pub struct AdaptiveEngine {
    /// Recent response metrics
    history: VecDeque<ResponseMetrics>,
    /// Maximum history size
    max_history: usize,
    /// Scoring engine
    scoring: ScoringEngine,
}

impl AdaptiveEngine {
    /// Creates a new adaptive engine
    pub fn new() -> Self {
        Self {
            history: VecDeque::with_capacity(10),
            max_history: 10,
            scoring: ScoringEngine::new(),
        }
    }

    /// Adds response metrics to history
    pub fn record_response(&mut self, metrics: ResponseMetrics) {
        self.history.push_back(metrics);
        if self.history.len() > self.max_history {
            self.history.pop_front();
        }
    }

    /// Analyzes detection patterns in recent responses
    pub fn analyze_detection_pattern(&self) -> Option<DetectionPattern> {
        if self.history.len() < 3 {
            return None;
        }

        let recent = self.history.iter().rev().take(5);
        let blocked_count = recent
            .clone()
            .filter(|r| r.status == 403 || r.status == 406)
            .count();
        let timeout_count = recent.clone().filter(|r| r.elapsed_ms > 5000).count();

        if blocked_count >= 3 {
            return Some(DetectionPattern::StatusCodeBlocking(403));
        }
        if timeout_count >= 3 {
            return Some(DetectionPattern::RateLimiting);
        }

        None
    }

    /// Recommends next adaptation strategy
    pub fn recommend_strategy(&self) -> Vec<AdaptationStrategy> {
        let pattern = self.analyze_detection_pattern();
        StrategySelector::recommend(pattern)
    }

    /// Calculates detection probability (0.0 - 1.0)
    pub fn detection_probability(&self) -> f32 {
        self.scoring.detection_probability(&self.history)
    }

    /// Checks if payload should be adjusted based on metrics
    pub fn should_adjust_payload(&self) -> bool {
        self.scoring.should_adjust_payload(&self.history)
    }
}

impl Default for AdaptiveEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_engine_creation() {
        let engine = AdaptiveEngine::new();
        assert_eq!(engine.history.len(), 0);
    }

    #[test]
    fn test_response_recording() {
        let mut engine = AdaptiveEngine::new();
        let metrics = ResponseMetrics {
            status: 200,
            content_length: 1000,
            elapsed_ms: 100,
            has_error_keywords: false,
            redirect_count: 0,
        };

        engine.record_response(metrics.clone());
        assert_eq!(engine.history.len(), 1);
    }

    #[test]
    fn test_detection_probability() {
        let mut engine = AdaptiveEngine::new();

        for _ in 0..4 {
            engine.record_response(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 100,
                has_error_keywords: true,
                redirect_count: 0,
            });
        }

        let prob = engine.detection_probability();
        assert!(prob > 0.5);
    }

    #[test]
    fn test_should_adjust_payload() {
        let mut engine = AdaptiveEngine::new();

        for _ in 0..5 {
            engine.record_response(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 6000,
                has_error_keywords: true,
                redirect_count: 0,
            });
        }

        assert!(engine.should_adjust_payload());
    }

    #[test]
    fn test_recommend_strategies() {
        let mut engine = AdaptiveEngine::new();

        for _ in 0..4 {
            engine.record_response(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 100,
                has_error_keywords: false,
                redirect_count: 0,
            });
        }

        let strategies = engine.recommend_strategy();
        assert!(!strategies.is_empty());
    }
}
