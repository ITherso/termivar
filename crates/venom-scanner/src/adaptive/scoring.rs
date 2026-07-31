//! Response scoring and analysis for adaptive payloads

use std::collections::VecDeque;

/// Response metadata for analysis
#[derive(Debug, Clone)]
pub struct ResponseMetrics {
    /// HTTP status code
    pub status: u16,
    /// Response body length
    pub content_length: usize,
    /// Response time in milliseconds
    pub elapsed_ms: u64,
    /// Whether response contained error keywords
    pub has_error_keywords: bool,
    /// Number of redirects followed
    pub redirect_count: u8,
}

/// Configurable scoring weights (P1 - runtime adjustable)
///
/// Controls how each signal contributes to final score.
/// Example: Status-heavy detection vs Timing-heavy detection
#[derive(Debug, Clone)]
pub struct ScoringWeights {
    /// Weight for status code detection (0.0 - 1.0)
    /// Detects 403/406/418 blocks
    pub status_weight: f32,

    /// Weight for timing analysis (0.0 - 1.0)
    /// Detects responses >5000ms (slow = blocked)
    pub timing_weight: f32,

    /// Weight for error keyword detection (0.0 - 1.0)
    /// Detects SQL errors, XSS patterns, etc.
    pub content_weight: f32,
}

impl ScoringWeights {
    /// Default balanced weights
    pub fn default() -> Self {
        Self {
            status_weight: 0.4, // Status code matters most
            timing_weight: 0.3,
            content_weight: 0.3,
        }
    }

    /// Status-heavy detection (good for strict WAF)
    pub fn status_heavy() -> Self {
        Self {
            status_weight: 0.6, // Status matters more
            timing_weight: 0.2,
            content_weight: 0.2,
        }
    }

    /// Timing-heavy detection (good for content-based blocking)
    pub fn timing_heavy() -> Self {
        Self {
            status_weight: 0.2,
            timing_weight: 0.6, // Timing matters more
            content_weight: 0.2,
        }
    }

    /// Content-heavy detection (good for error-based detection)
    pub fn content_heavy() -> Self {
        Self {
            status_weight: 0.2,
            timing_weight: 0.2,
            content_weight: 0.6, // Content matters more
        }
    }

    /// Create custom weights (P1 A/B testing)
    pub fn custom(status: f32, timing: f32, content: f32) -> Result<Self, String> {
        let weights = Self {
            status_weight: status,
            timing_weight: timing,
            content_weight: content,
        };
        weights.validate()?;
        Ok(weights)
    }

    /// Validate weights sum to 1.0 (allows for floating point error)
    pub fn validate(&self) -> Result<(), String> {
        let sum = self.status_weight + self.timing_weight + self.content_weight;
        if (sum - 1.0).abs() > 0.001 {
            return Err(format!(
                "Weights must sum to 1.0 (got {}, status={}, timing={}, content={})",
                sum, self.status_weight, self.timing_weight, self.content_weight
            ));
        }

        if self.status_weight < 0.0 || self.timing_weight < 0.0 || self.content_weight < 0.0 {
            return Err("Weights must be non-negative".to_string());
        }

        Ok(())
    }
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self::default()
    }
}

/// Detects and scores response patterns (P1 - runtime configurable)
#[derive(Debug, Clone)]
pub struct ScoringEngine {
    /// Detection threshold
    pub detection_threshold: f32,

    /// Scoring weights (configurable at runtime)
    pub weights: ScoringWeights,
}

impl ScoringEngine {
    /// Creates new scoring engine with default weights
    pub fn new() -> Self {
        Self {
            detection_threshold: 0.7,
            weights: ScoringWeights::default(),
        }
    }

    /// Creates scoring engine with custom weights (P1 A/B testing)
    pub fn with_weights(weights: ScoringWeights) -> Result<Self, String> {
        weights.validate()?;
        Ok(Self {
            detection_threshold: 0.7,
            weights,
        })
    }

    /// Update weights at runtime (P1 - dynamic adjustment)
    pub fn set_weights(&mut self, weights: ScoringWeights) -> Result<(), String> {
        weights.validate()?;
        self.weights = weights;
        Ok(())
    }

    /// Calculates detection probability using configured weights (0.0 - 1.0)
    pub fn detection_probability(&self, history: &VecDeque<ResponseMetrics>) -> f32 {
        if history.is_empty() {
            return 0.0;
        }

        let mut score = 0.0;
        let recent_count = history.len().min(5);

        // Status code analysis (configurable weight)
        let blocked_ratio = history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.status == 403 || r.status == 406 || r.status == 418)
            .count() as f32
            / recent_count as f32;
        score += blocked_ratio * self.weights.status_weight;

        // Timing analysis (configurable weight)
        let slow_ratio = history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.elapsed_ms > 5000)
            .count() as f32
            / recent_count as f32;
        score += slow_ratio * self.weights.timing_weight;

        // Error keyword analysis (configurable weight)
        let error_ratio = history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.has_error_keywords)
            .count() as f32
            / recent_count as f32;
        score += error_ratio * self.weights.content_weight;

        (score * 100.0).min(1.0)
    }

    /// Checks if payload should be adjusted based on metrics
    pub fn should_adjust_payload(&self, history: &VecDeque<ResponseMetrics>) -> bool {
        self.detection_probability(history) > self.detection_threshold
    }

    /// Get breakdown of scoring components (for debugging/analysis)
    pub fn score_breakdown(&self, history: &VecDeque<ResponseMetrics>) -> ScoreBreakdown {
        if history.is_empty() {
            return ScoreBreakdown::default();
        }

        let recent_count = history.len().min(5);

        let status_score = history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.status == 403 || r.status == 406 || r.status == 418)
            .count() as f32
            / recent_count as f32;

        let timing_score = history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.elapsed_ms > 5000)
            .count() as f32
            / recent_count as f32;

        let content_score = history
            .iter()
            .rev()
            .take(recent_count)
            .filter(|r| r.has_error_keywords)
            .count() as f32
            / recent_count as f32;

        ScoreBreakdown {
            status_score,
            timing_score,
            content_score,
            status_contribution: status_score * self.weights.status_weight,
            timing_contribution: timing_score * self.weights.timing_weight,
            content_contribution: content_score * self.weights.content_weight,
            final_score: self.detection_probability(history),
        }
    }
}

/// Breakdown of scoring components (for transparency)
#[derive(Debug, Clone, Default)]
pub struct ScoreBreakdown {
    /// Raw status score (before weighting)
    pub status_score: f32,
    /// Raw timing score (before weighting)
    pub timing_score: f32,
    /// Raw content score (before weighting)
    pub content_score: f32,
    /// Weighted contribution from status
    pub status_contribution: f32,
    /// Weighted contribution from timing
    pub timing_contribution: f32,
    /// Weighted contribution from content
    pub content_contribution: f32,
    /// Final combined score
    pub final_score: f32,
}

impl Default for ScoringEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scoring_engine_creation() {
        let engine = ScoringEngine::new();
        assert_eq!(engine.detection_threshold, 0.7);
    }

    #[test]
    fn test_detection_probability_empty() {
        let engine = ScoringEngine::new();
        let history = VecDeque::new();
        assert_eq!(engine.detection_probability(&history), 0.0);
    }

    #[test]
    fn test_detection_probability_with_blocks() {
        let engine = ScoringEngine::new();
        let mut history = VecDeque::new();

        for _ in 0..4 {
            history.push_back(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 100,
                has_error_keywords: true,
                redirect_count: 0,
            });
        }

        let prob = engine.detection_probability(&history);
        assert!(prob > 0.5);
    }

    #[test]
    fn test_should_adjust_payload() {
        let engine = ScoringEngine::new();
        let mut history = VecDeque::new();

        for _ in 0..5 {
            history.push_back(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 6000,
                has_error_keywords: true,
                redirect_count: 0,
            });
        }

        assert!(engine.should_adjust_payload(&history));
    }

    // ═════════════════════════════════════════════════════════════════════
    // RUNTIME CONFIGURABLE WEIGHTS TESTS (P1)
    // ═════════════════════════════════════════════════════════════════════

    #[test]
    fn test_scoring_weights_default_sum_to_one() {
        let weights = ScoringWeights::default();
        let sum = weights.status_weight + weights.timing_weight + weights.content_weight;
        assert!((sum - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_scoring_weights_status_heavy() {
        let weights = ScoringWeights::status_heavy();
        assert!(weights.status_weight > weights.timing_weight);
        assert!(weights.status_weight > weights.content_weight);
        weights.validate().unwrap(); // Must be valid
    }

    #[test]
    fn test_scoring_weights_timing_heavy() {
        let weights = ScoringWeights::timing_heavy();
        assert!(weights.timing_weight > weights.status_weight);
        assert!(weights.timing_weight > weights.content_weight);
        weights.validate().unwrap();
    }

    #[test]
    fn test_scoring_weights_content_heavy() {
        let weights = ScoringWeights::content_heavy();
        assert!(weights.content_weight > weights.status_weight);
        assert!(weights.content_weight > weights.timing_weight);
        weights.validate().unwrap();
    }

    #[test]
    fn test_scoring_weights_custom_valid() {
        let weights = ScoringWeights::custom(0.5, 0.3, 0.2);
        assert!(weights.is_ok());
    }

    #[test]
    fn test_scoring_weights_custom_invalid_sum() {
        let weights = ScoringWeights::custom(0.5, 0.3, 0.3); // Sums to 1.1
        assert!(weights.is_err());
    }

    #[test]
    fn test_scoring_weights_custom_negative() {
        let weights = ScoringWeights::custom(-0.1, 0.5, 0.6);
        assert!(weights.is_err());
    }

    #[test]
    fn test_engine_with_status_heavy_weights() {
        let weights = ScoringWeights::status_heavy();
        let engine = ScoringEngine::with_weights(weights).unwrap();

        let mut history = VecDeque::new();
        // Add responses with only status blocks (no timing/content signals)
        for _ in 0..5 {
            history.push_back(ResponseMetrics {
                status: 403, // ← Status block
                content_length: 100,
                elapsed_ms: 100,           // ← Normal timing
                has_error_keywords: false, // ← No error keywords
                redirect_count: 0,
            });
        }

        let prob = engine.detection_probability(&history);
        // With status_heavy (0.6 weight), status blocks = 100%, so score ≈ 0.6
        assert!(prob > 0.5);
        assert!(prob < 0.7); // Less than if all signals present
    }

    #[test]
    fn test_engine_with_timing_heavy_weights() {
        let weights = ScoringWeights::timing_heavy();
        let engine = ScoringEngine::with_weights(weights).unwrap();

        let mut history = VecDeque::new();
        // Add responses with only timing signals (slow responses)
        for _ in 0..5 {
            history.push_back(ResponseMetrics {
                status: 200, // ← Normal response
                content_length: 100,
                elapsed_ms: 6000, // ← Slow (>5000ms)
                has_error_keywords: false,
                redirect_count: 0,
            });
        }

        let prob = engine.detection_probability(&history);
        // With timing_heavy (0.6 weight), slow ratio = 100%, so score ≈ 0.6
        assert!(prob > 0.5);
        assert!(prob < 0.7);
    }

    #[test]
    fn test_engine_runtime_weight_update() {
        let mut engine = ScoringEngine::new();
        let mut history = VecDeque::new();

        // Add responses with status blocks
        for _ in 0..5 {
            history.push_back(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 100,
                has_error_keywords: false,
                redirect_count: 0,
            });
        }

        let score_default = engine.detection_probability(&history);

        // Change to status_heavy weights
        engine.set_weights(ScoringWeights::status_heavy()).unwrap();
        let score_heavy = engine.detection_probability(&history);

        // Status-only signals should score higher with status_heavy
        assert!(score_heavy > score_default);

        // Change to content_heavy weights
        engine.set_weights(ScoringWeights::content_heavy()).unwrap();
        let score_content = engine.detection_probability(&history);

        // Content-only signals (0 in this test) should score lower with content_heavy
        assert!(score_content < score_default);
    }

    #[test]
    fn test_score_breakdown_transparency() {
        let engine = ScoringEngine::new();
        let mut history = VecDeque::new();

        for _ in 0..5 {
            history.push_back(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 6000,
                has_error_keywords: true,
                redirect_count: 0,
            });
        }

        let breakdown = engine.score_breakdown(&history);

        // All signals present
        assert_eq!(breakdown.status_score, 1.0);
        assert_eq!(breakdown.timing_score, 1.0);
        assert_eq!(breakdown.content_score, 1.0);

        // Contributions should be weighted
        assert!(breakdown.status_contribution > 0.0);
        assert!(breakdown.timing_contribution > 0.0);
        assert!(breakdown.content_contribution > 0.0);

        // Sum of contributions should equal final score
        let contribution_sum = breakdown.status_contribution
            + breakdown.timing_contribution
            + breakdown.content_contribution;
        assert!((contribution_sum - breakdown.final_score).abs() < 0.01);
    }

    #[test]
    fn test_a_b_testing_different_weights() {
        // A/B test scenario: Compare two weight strategies
        let mut history_a = VecDeque::new();
        let mut history_b = VecDeque::new();

        // Strategy A: Many status blocks, no timing issues
        for _ in 0..5 {
            history_a.push_back(ResponseMetrics {
                status: 403,
                content_length: 100,
                elapsed_ms: 100,
                has_error_keywords: false,
                redirect_count: 0,
            });
        }

        // Strategy B: Slow responses, no status blocks
        for _ in 0..5 {
            history_b.push_back(ResponseMetrics {
                status: 200,
                content_length: 100,
                elapsed_ms: 6000,
                has_error_keywords: false,
                redirect_count: 0,
            });
        }

        let engine_default = ScoringEngine::new();
        let engine_status_heavy =
            ScoringEngine::with_weights(ScoringWeights::status_heavy()).unwrap();
        let engine_timing_heavy =
            ScoringEngine::with_weights(ScoringWeights::timing_heavy()).unwrap();

        let score_a_default = engine_default.detection_probability(&history_a);
        let score_a_status = engine_status_heavy.detection_probability(&history_a);
        let score_a_timing = engine_timing_heavy.detection_probability(&history_a);

        // Status-heavy should score A higher than timing-heavy
        assert!(score_a_status > score_a_timing);

        let score_b_default = engine_default.detection_probability(&history_b);
        let score_b_timing = engine_timing_heavy.detection_probability(&history_b);
        let score_b_status = engine_status_heavy.detection_probability(&history_b);

        // Timing-heavy should score B higher than status-heavy
        assert!(score_b_timing > score_b_status);
    }
}
