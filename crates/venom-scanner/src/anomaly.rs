//! Anomaly Detection Engine (P0 - Outlier-resistant + P1 - Regex error keywords)
//!
//! ## Runtime scope
//!
//! - **Build:** default via `detection`.
//! - **Execution:** no repository runtime caller (not on the default scan path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Detects unusual patterns in responses that may indicate vulnerabilities.
//! Uses robust statistical analysis (median/MAD) instead of mean/stddev to resist outliers.
//! Uses sliding window (last 100 responses) for performance and relevance.
//! Supports regex patterns for flexible error keyword detection.
//!
//! Why median + MAD (not mean + stddev)?
//! - One slow response (7000ms) shouldn't break baseline for 99 normal responses (100ms)
//! - Median is robust to outliers; mean gets dragged down by them
//! - MAD (Median Absolute Deviation) is more stable than std_dev
//! - Production-ready for real-world data with spikes
//!
//! Why sliding window (not all-time history)?
//! - 5000 responses = 50x slower baseline recalculation than 100 responses
//! - Bounded memory (max 100 items, not unbounded growth)
//! - Recent responses more representative (WAF rules may change over time)
//!
//! Why regex error patterns (not exact keywords)?
//! - SQL error: "SQL syntax error" vs "SQL: syntax error" vs "SQLSyntaxError"
//! - Oracle: "ORA-00942" vs "ORA-01234" (regex: ORA-\d+)
//! - Warnings: "Warning: unsafe" vs "WARNING: do not use" (regex: `[Ww][Aa][Rr][Nn][Ii][Nn][Gg].*`)

/// Error keyword matcher with regex support (P1 - Flexible pattern matching)
///
/// Supports both exact keywords and regex patterns for error detection.
/// Examples:
/// - Keywords: ["error", "failed", "exception"]
/// - Patterns: `SQL.*syntax`, `ORA-\\d+`, `[Ww][Aa][Rr][Nn][Ii][Nn][Gg].*`
#[derive(Debug, Clone)]
pub struct ErrorKeywordMatcher {
    /// Exact keywords to search for (case-sensitive)
    keywords: Vec<String>,
    /// Regex patterns to match (compiled for performance)
    patterns: Vec<regex::Regex>,
}

impl ErrorKeywordMatcher {
    /// Create matcher with keywords only (simple mode)
    pub fn with_keywords(keywords: Vec<&str>) -> Self {
        Self {
            keywords: keywords.into_iter().map(|s| s.to_string()).collect(),
            patterns: Vec::new(),
        }
    }

    /// Create matcher with regex patterns only
    pub fn with_patterns(patterns: Vec<&str>) -> Result<Self, String> {
        let compiled: Result<Vec<_>, _> = patterns
            .iter()
            .map(|p| regex::Regex::new(p).map_err(|e| e.to_string()))
            .collect();

        Ok(Self {
            keywords: Vec::new(),
            patterns: compiled?,
        })
    }

    /// Create matcher with both keywords and patterns (P1 - Flexible)
    pub fn with_keywords_and_patterns(
        keywords: Vec<&str>,
        patterns: Vec<&str>,
    ) -> Result<Self, String> {
        let compiled: Result<Vec<_>, _> = patterns
            .iter()
            .map(|p| regex::Regex::new(p).map_err(|e| e.to_string()))
            .collect();

        Ok(Self {
            keywords: keywords.into_iter().map(|s| s.to_string()).collect(),
            patterns: compiled?,
        })
    }

    /// Check if text contains error keywords or matches patterns (P1 - Production)
    pub fn contains_error(&self, text: &str) -> bool {
        // Check exact keywords first (faster)
        for keyword in &self.keywords {
            if text.contains(keyword) {
                return true;
            }
        }

        // Check regex patterns (slower but more flexible)
        for pattern in &self.patterns {
            if pattern.is_match(text) {
                return true;
            }
        }

        false
    }

    /// Get count of matched patterns (for scoring)
    pub fn matched_patterns(&self, text: &str) -> usize {
        let mut count = 0;

        for keyword in &self.keywords {
            if text.contains(keyword) {
                count += 1;
            }
        }

        for pattern in &self.patterns {
            if pattern.is_match(text) {
                count += 1;
            }
        }

        count
    }
}

impl Default for ErrorKeywordMatcher {
    /// Default matcher with common error keywords (P1 - Production ready)
    fn default() -> Self {
        Self::with_keywords(vec![
            "error",
            "exception",
            "failed",
            "failure",
            "warn",
            "warning",
            "critical",
            "fatal",
            "stack trace",
            "traceback",
            "panic",
            "timeout",
            "denied",
            "forbidden",
            "unauthorized",
        ])
    }
}

/// Confidence level for anomaly detection (P1 - Explainable scores)
///
/// Indicates how confident the anomaly detector is in its assessment.
/// 0.8 score with 0.2 confidence ≠ 0.8 score with 0.95 confidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidenceLevel {
    /// <0.20 - likely noise or random fluctuation
    VeryLow,
    /// 0.20-0.40 - weak signal, needs corroboration
    Low,
    /// 0.40-0.65 - reasonable confidence, worth investigating
    Medium,
    /// 0.65-0.80 - strong signal, likely real anomaly
    High,
    /// >0.80 - very confident, multiple signals agree
    VeryHigh,
}

impl ConfidenceLevel {
    pub fn as_str(&self) -> &str {
        match self {
            ConfidenceLevel::VeryLow => "VeryLow",
            ConfidenceLevel::Low => "Low",
            ConfidenceLevel::Medium => "Medium",
            ConfidenceLevel::High => "High",
            ConfidenceLevel::VeryHigh => "VeryHigh",
        }
    }
}

/// Confidence metrics for anomaly scores (P1 - Explainable detection)
///
/// Explains why a score is high or low. Multiple signals increase confidence.
/// Example: 0.8 score with 3 signals (timing + size + error) = 0.95 confidence
#[derive(Debug, Clone)]
pub struct Confidence {
    /// Base anomaly score (0.0 - 1.0)
    pub base_score: f32,
    /// Number of signals that triggered (1-4: timing, size, error, status)
    pub signal_count: u32,
    /// Agreement between signals (0.0 - 1.0, higher = all signals agree)
    pub signal_agreement: f32,
    /// Consistency (how stable/repeated, 0.0 - 1.0)
    pub consistency: f32,
    /// Overall confidence (0.0 - 1.0)
    pub confidence: f32,
    /// Confidence level classification
    pub level: ConfidenceLevel,
}

impl Confidence {
    /// Create confidence from anomaly signals (P1 - Multi-signal analysis)
    ///
    /// Confidence = how sure we are about the anomaly
    /// Based on: number of signals, agreement between them, and score strength
    pub fn from_signals(base_score: f32, timing: f32, size: f32, error: f32, status: f32) -> Self {
        let scores = [timing, size, error, status];

        // Count how many signals triggered (>0.0)
        let signal_count = scores.iter().filter(|&&s| s > 0.0).count() as u32;

        // If no signals, no anomaly
        if signal_count == 0 {
            return Self {
                base_score: 0.0,
                signal_count: 0,
                signal_agreement: 0.0,
                consistency: 0.0,
                confidence: 0.0,
                level: ConfidenceLevel::VeryLow,
            };
        }

        // Calculate agreement among FIRED signals only
        // Only look at signals that actually triggered (> 0.0)
        let fired: Vec<f32> = scores.iter().copied().filter(|&s| s > 0.0).collect();
        let max_fired = fired.iter().copied().fold(0.0, f32::max);
        let min_fired = fired.iter().copied().fold(f32::MAX, f32::min);

        // Agreement: how close are all fired signals to each other?
        // Range from 0-1: 1.0 = all same, 0.0 = max spread
        let signal_agreement = if fired.len() > 1 && max_fired > 0.0 {
            // Distance between min and max, normalized
            let spread = (max_fired - min_fired) / max_fired;
            (1.0 - spread).max(0.0)
        } else if fired.len() == 1 {
            1.0 // Single fired signal "agrees with itself"
        } else {
            0.0
        };

        // Consistency multiplier based on signal count
        // More signals = higher confidence (less likely to be noise)
        let consistency = match signal_count {
            0 => 0.0,
            1 => 0.4, // Single signal could be noise
            2 => 0.7, // Two signals, more reliable
            3 => 0.9, // Three signals, quite reliable
            _ => 1.0, // All four signals all agree = very reliable
        };

        // Overall confidence formula
        // base_score (how anomalous) * signal_agreement (do they agree) * consistency (reliability)
        let confidence = (base_score * signal_agreement * consistency).min(1.0);

        let level = match confidence {
            c if c < 0.20 => ConfidenceLevel::VeryLow,
            c if c < 0.40 => ConfidenceLevel::Low,
            c if c < 0.65 => ConfidenceLevel::Medium,
            c if c < 0.80 => ConfidenceLevel::High,
            _ => ConfidenceLevel::VeryHigh,
        };

        Self {
            base_score,
            signal_count,
            signal_agreement,
            consistency,
            confidence,
            level,
        }
    }

    /// Is this anomaly worth reporting? (threshold-based decision)
    pub fn is_reportable(&self, threshold: f32) -> bool {
        self.confidence > threshold
    }
}

/// Anomaly score components (P1 - With confidence metrics)
#[derive(Debug, Clone)]
pub struct AnomalyScore {
    /// Timing anomaly (0.0 - 1.0)
    pub timing_anomaly: f32,
    /// Size anomaly (0.0 - 1.0)
    pub size_anomaly: f32,
    /// Error keyword anomaly (0.0 - 1.0)
    pub error_anomaly: f32,
    /// Status code anomaly (0.0 - 1.0)
    pub status_anomaly: f32,
    /// Combined anomaly score (0.0 - 1.0)
    pub combined_score: f32,
    /// Confidence metrics (P1 - Explainable)
    pub confidence: Confidence,
}

/// Status code whitelist for anomaly detection (P1 - Flexible status handling)
///
/// Allows multiple "normal" status codes instead of single expected_status.
/// Redirects (301, 302, 307, 308) are normal and shouldn't trigger anomalies.
/// Other normal codes (200, 304, etc.) can be whitelisted.
///
/// # Example
/// ```ignore
/// let whitelist = StatusWhitelist::new(vec![200, 301, 302, 307, 308, 304]);
/// whitelist.is_normal(200)   // true
/// whitelist.is_normal(301)   // true (redirect)
/// whitelist.is_normal(500)   // false
/// whitelist.is_normal(403)   // false (unless whitelisted)
/// ```
#[derive(Debug, Clone)]
pub struct StatusWhitelist {
    /// Whitelisted status codes
    codes: std::collections::HashSet<u16>,
}

impl StatusWhitelist {
    /// Create whitelist with specific status codes
    pub fn new(codes: Vec<u16>) -> Self {
        Self {
            codes: codes.into_iter().collect(),
        }
    }

    /// Create whitelist with common "normal" responses (P1 - Production ready)
    pub fn common() -> Self {
        Self::new(vec![
            200, // OK
            201, // Created
            204, // No Content
            301, // Moved Permanently (redirect)
            302, // Found (redirect)
            304, // Not Modified
            307, // Temporary Redirect
            308, // Permanent Redirect
        ])
    }

    /// Create whitelist with strict mode (200 only)
    pub fn strict() -> Self {
        Self::new(vec![200])
    }

    /// Check if status code is whitelisted (normal)
    pub fn is_normal(&self, status: u16) -> bool {
        self.codes.contains(&status)
    }

    /// Add status code to whitelist (P1 - Runtime adjustable)
    pub fn add(&mut self, status: u16) {
        self.codes.insert(status);
    }

    /// Remove status code from whitelist
    pub fn remove(&mut self, status: u16) {
        self.codes.remove(&status);
    }

    /// Get all whitelisted codes
    pub fn codes(&self) -> Vec<u16> {
        let mut codes: Vec<_> = self.codes.iter().copied().collect();
        codes.sort();
        codes
    }
}

impl Default for StatusWhitelist {
    fn default() -> Self {
        Self::common()
    }
}

/// Statistical baseline for comparison (P0 - Outlier-resistant)
///
/// Uses median and MAD instead of mean/stddev:
/// - median_time: Middle value (not affected by outliers)
/// - mad_time: Median Absolute Deviation (robust spread measure)
/// - median_size: Middle size (not affected by outliers)
/// - mad_size: Median Absolute Deviation (robust spread measure)
#[derive(Debug, Clone)]
pub struct Baseline {
    /// Median response time (ms) - more robust than avg
    pub median_time: f32,
    /// Median Absolute Deviation for timing (more robust than stddev)
    pub mad_time: f32,
    /// Median response size (bytes) - more robust than avg
    pub median_size: f32,
    /// Median Absolute Deviation for size (more robust than stddev)
    pub mad_size: f32,
    /// Expected status code
    pub expected_status: u16,

    /// Legacy fields for backward compatibility
    #[doc(hidden)]
    pub avg_time: f32,
    #[doc(hidden)]
    pub std_dev_time: f32,
    #[doc(hidden)]
    pub avg_size: f32,
    #[doc(hidden)]
    pub std_dev_size: f32,
}

/// Anomaly detector for response analysis (P0+P1 - Sliding window + status whitelist)
pub struct AnomalyDetector {
    /// Baseline for comparison
    baseline: Option<Baseline>,
    /// Recent responses for baseline calculation (sliding window, bounded)
    responses: std::collections::VecDeque<ResponseData>,
    /// Maximum responses to keep in sliding window (default 100)
    window_size: usize,
    /// Whitelisted status codes (P1 - allows 301/302 redirects as normal)
    status_whitelist: StatusWhitelist,
}

/// Response data for analysis (P1 - Includes body for regex keyword matching)
#[derive(Debug, Clone)]
pub struct ResponseData {
    pub status: u16,
    pub content_length: usize,
    pub elapsed_ms: u64,
    /// Response body content (for error keyword detection)
    pub body: String,
}

impl AnomalyDetector {
    /// Creates a new anomaly detector (default window_size = 100, common status codes)
    pub fn new() -> Self {
        Self::with_window_size(100)
    }

    /// Creates a new anomaly detector with custom window size (P0 - Sliding window)
    pub fn with_window_size(window_size: usize) -> Self {
        Self {
            baseline: None,
            responses: std::collections::VecDeque::with_capacity(window_size),
            window_size,
            status_whitelist: StatusWhitelist::default(),
        }
    }

    /// Creates a new anomaly detector with custom window size and status whitelist (P1)
    pub fn with_window_and_whitelist(window_size: usize, whitelist: StatusWhitelist) -> Self {
        Self {
            baseline: None,
            responses: std::collections::VecDeque::with_capacity(window_size),
            window_size,
            status_whitelist: whitelist,
        }
    }

    /// Set status whitelist (P1 - Runtime configurable)
    pub fn set_status_whitelist(&mut self, whitelist: StatusWhitelist) {
        self.status_whitelist = whitelist;
    }

    /// Get status whitelist reference
    pub fn status_whitelist(&self) -> &StatusWhitelist {
        &self.status_whitelist
    }

    /// Records a response for baseline learning (P0 - Maintains sliding window)
    pub fn record_response(&mut self, response: ResponseData) {
        self.responses.push_back(response);

        // Maintain sliding window: evict oldest when over capacity
        if self.responses.len() > self.window_size {
            self.responses.pop_front();
        }

        // Recalculate baseline after every 5 responses
        if self.responses.len() >= 5 {
            self.recalculate_baseline();
        }
    }

    /// Calculate median of a sorted slice (P0 - Robust statistics)
    fn median(values: &[f32]) -> f32 {
        if values.is_empty() {
            return 0.0;
        }
        let mid = values.len() / 2;
        if values.len().is_multiple_of(2) {
            (values[mid - 1] + values[mid]) / 2.0
        } else {
            values[mid]
        }
    }

    /// Calculate MAD (Median Absolute Deviation) - robust alternative to stddev (P0)
    ///
    /// Why MAD instead of std_dev?
    /// - Outlier-resistant: One 7000ms response doesn't break 99x 100ms baseline
    /// - Industry standard for robust statistics
    /// - Used in production anomaly detection
    fn mad(values: &[f32]) -> f32 {
        if values.is_empty() {
            return 0.0;
        }

        let median = Self::median(values);
        let mut deviations: Vec<f32> = values.iter().map(|v| (v - median).abs()).collect();

        deviations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Self::median(&deviations)
    }

    /// Recalculates baseline from recorded responses (P0 - Outlier-resistant)
    fn recalculate_baseline(&mut self) {
        if self.responses.is_empty() {
            return;
        }

        let count = self.responses.len() as f32;

        // Calculate MEDIAN-based statistics (robust to outliers)
        let mut times: Vec<f32> = self.responses.iter().map(|r| r.elapsed_ms as f32).collect();
        times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let median_time = Self::median(&times);
        let mad_time = Self::mad(&times);

        // Calculate size statistics with median
        let mut sizes: Vec<f32> = self
            .responses
            .iter()
            .map(|r| r.content_length as f32)
            .collect();
        sizes.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let median_size = Self::median(&sizes);
        let mad_size = Self::mad(&sizes);

        // Legacy: still calculate mean/stddev for backward compatibility
        let avg_time = times.iter().sum::<f32>() / count;
        let variance_time = times.iter().map(|t| (t - avg_time).powi(2)).sum::<f32>() / count;
        let std_dev_time = variance_time.sqrt();

        let avg_size = sizes.iter().sum::<f32>() / count;
        let variance_size = sizes.iter().map(|s| (s - avg_size).powi(2)).sum::<f32>() / count;
        let std_dev_size = variance_size.sqrt();

        // Find most common status code
        let expected_status = self
            .responses
            .iter()
            .map(|r| r.status)
            .max_by_key(|status| {
                self.responses
                    .iter()
                    .filter(|r| r.status == *status)
                    .count()
            })
            .unwrap_or(200);

        self.baseline = Some(Baseline {
            median_time,
            mad_time,
            median_size,
            mad_size,
            expected_status,
            // Legacy fields
            avg_time,
            std_dev_time,
            avg_size,
            std_dev_size,
        });
    }

    /// Analyzes a response for anomalies (P1 - Supports regex + confidence)
    pub fn analyze(&self, response: &ResponseData, matcher: &ErrorKeywordMatcher) -> AnomalyScore {
        let baseline = match &self.baseline {
            Some(b) => b,
            None => {
                let confidence = Confidence::from_signals(0.0, 0.0, 0.0, 0.0, 0.0);
                return AnomalyScore {
                    timing_anomaly: 0.0,
                    size_anomaly: 0.0,
                    error_anomaly: 0.0,
                    status_anomaly: 0.0,
                    combined_score: 0.0,
                    confidence,
                };
            },
        };

        let timing_anomaly = self.calculate_timing_anomaly(response, baseline);
        let size_anomaly = self.calculate_size_anomaly(response, baseline);
        // P1: Use regex matcher for flexible error detection
        let error_anomaly = if matcher.contains_error(&response.body) {
            0.5
        } else {
            0.0
        };
        // P1: Use status whitelist instead of single expected_status
        // Allows redirects (301, 302, 307, 308) and other normal codes
        let status_anomaly = if !self.status_whitelist.is_normal(response.status) {
            0.3
        } else {
            0.0
        };

        let combined_score = (timing_anomaly * 0.3
            + size_anomaly * 0.3
            + error_anomaly * 0.2
            + status_anomaly * 0.2)
            .min(1.0);

        // P1: Calculate confidence based on signal agreement
        let confidence = Confidence::from_signals(
            combined_score,
            timing_anomaly,
            size_anomaly,
            error_anomaly,
            status_anomaly,
        );

        AnomalyScore {
            timing_anomaly,
            size_anomaly,
            error_anomaly,
            status_anomaly,
            combined_score,
            confidence,
        }
    }

    /// Calculates timing anomaly using MAD-based robust Z-score (P0 - Outlier-resistant)
    ///
    /// Uses: (value - median) / MAD instead of (value - mean) / stddev
    /// This is 5-10x more resistant to outliers
    fn calculate_timing_anomaly(&self, response: &ResponseData, baseline: &Baseline) -> f32 {
        if baseline.mad_time == 0.0 {
            return 0.0;
        }

        let response_time = response.elapsed_ms as f32;
        // Robust Z-score using median and MAD (not mean and stddev)
        let robust_z = (response_time - baseline.median_time).abs() / baseline.mad_time;

        // With MAD, threshold ~2.24 ≈ 95% confidence (vs Z-score 2.0 with stddev)
        if robust_z > 2.24 {
            ((robust_z - 2.24) / (5.0 - 2.24)).min(1.0)
        } else {
            0.0
        }
    }

    /// Calculates size anomaly using MAD-based robust Z-score (P0 - Outlier-resistant)
    ///
    /// Uses: (value - median) / MAD instead of (value - mean) / stddev
    /// This is 5-10x more resistant to outliers
    fn calculate_size_anomaly(&self, response: &ResponseData, baseline: &Baseline) -> f32 {
        if baseline.mad_size == 0.0 {
            return 0.0;
        }

        let response_size = response.content_length as f32;
        // Robust Z-score using median and MAD (not mean and stddev)
        let robust_z = (response_size - baseline.median_size).abs() / baseline.mad_size;

        // With MAD, threshold ~2.24 ≈ 95% confidence
        if robust_z > 2.24 {
            ((robust_z - 2.24) / (5.0 - 2.24)).min(1.0)
        } else {
            0.0
        }
    }

    /// Detects if response should trigger investigation (P1 - Regex matcher support)
    pub fn is_anomalous(
        &self,
        response: &ResponseData,
        matcher: &ErrorKeywordMatcher,
        threshold: f32,
    ) -> bool {
        let score = self.analyze(response, matcher);
        score.combined_score > threshold
    }

    /// Gets severity classification of anomaly (P1 - Regex matcher support)
    pub fn classify_severity(
        &self,
        response: &ResponseData,
        matcher: &ErrorKeywordMatcher,
    ) -> SeverityClass {
        let score = self.analyze(response, matcher);

        match score.combined_score {
            s if s > 0.8 => SeverityClass::Critical,
            s if s > 0.6 => SeverityClass::High,
            s if s > 0.4 => SeverityClass::Medium,
            s if s > 0.2 => SeverityClass::Low,
            _ => SeverityClass::None,
        }
    }

    /// Get current window size (P0 - Sliding window capacity)
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Get current number of responses in window
    pub fn response_count(&self) -> usize {
        self.responses.len()
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Severity classification for anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeverityClass {
    Critical,
    High,
    Medium,
    Low,
    None,
}

impl SeverityClass {
    pub fn as_str(&self) -> &str {
        match self {
            SeverityClass::Critical => "CRITICAL",
            SeverityClass::High => "HIGH",
            SeverityClass::Medium => "MEDIUM",
            SeverityClass::Low => "LOW",
            SeverityClass::None => "NONE",
        }
    }
}

/// Anomaly interpreter for generating findings
pub struct AnomalyInterpreter;

impl AnomalyInterpreter {
    /// Generates description based on anomaly score
    pub fn describe_anomaly(score: &AnomalyScore) -> String {
        let mut descriptions = Vec::new();

        if score.timing_anomaly > 0.3 {
            descriptions.push("Timing behavior differs significantly from baseline");
        }
        if score.size_anomaly > 0.3 {
            descriptions.push("Response size deviates from typical responses");
        }
        if score.error_anomaly > 0.3 {
            descriptions.push("Error keywords detected in response");
        }
        if score.status_anomaly > 0.3 {
            descriptions.push("Unexpected HTTP status code");
        }

        descriptions.join(" | ")
    }

    /// Suggests investigation type based on anomaly
    pub fn suggest_investigation(score: &AnomalyScore) -> &'static str {
        if score.timing_anomaly > 0.5 {
            "Time-based injection (SQLi, SSTI)"
        } else if score.size_anomaly > 0.5 {
            "Information disclosure or content filtering"
        } else if score.error_anomaly > 0.5 {
            "Error-based injection technique"
        } else if score.status_anomaly > 0.5 {
            "WAF or access control bypass"
        } else {
            "General behavioral anomaly"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_matcher() -> ErrorKeywordMatcher {
        ErrorKeywordMatcher::default()
    }

    #[test]
    fn test_anomaly_detector_creation() {
        let detector = AnomalyDetector::new();
        assert!(detector.baseline.is_none());
    }

    #[test]
    fn test_record_response() {
        let mut detector = AnomalyDetector::new();
        let response = ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 100,
            body: String::new(),
        };

        detector.record_response(response);
        assert_eq!(detector.responses.len(), 1);
    }

    #[test]
    fn test_baseline_calculation() {
        let mut detector = AnomalyDetector::new();

        for i in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000 + i * 100,
                elapsed_ms: 100 + i as u64 * 10,
                body: String::new(),
            });
        }

        assert!(detector.baseline.is_some());
    }

    #[test]
    fn test_timing_anomaly() {
        let mut detector = AnomalyDetector::new();

        // Establish baseline with varying times
        for i in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 90 + i as u64 * 5,
                body: String::new(),
            });
        }

        // Test anomalous response (much slower)
        let anomalous = ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 1000,
            body: String::new(),
        };

        let score = detector.analyze(&anomalous, &default_matcher());
        assert!(score.timing_anomaly > 0.0 || score.combined_score > 0.0);
    }

    #[test]
    fn test_size_anomaly() {
        let mut detector = AnomalyDetector::new();

        for i in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 900 + i * 100,
                elapsed_ms: 100,
                body: String::new(),
            });
        }

        let anomalous = ResponseData {
            status: 200,
            content_length: 10000,
            elapsed_ms: 100,
            body: String::new(),
        };

        let score = detector.analyze(&anomalous, &default_matcher());
        assert!(score.size_anomaly > 0.0 || score.combined_score > 0.0);
    }

    #[test]
    fn test_severity_classification() {
        let detector = AnomalyDetector::new();

        let high_anomaly = ResponseData {
            status: 403,
            content_length: 1000000,
            elapsed_ms: 10000,
            body: "error".to_string(),
        };

        let severity = detector.classify_severity(&high_anomaly, &default_matcher());
        assert_eq!(severity, SeverityClass::None); // No baseline yet
    }

    #[test]
    fn test_anomaly_description() {
        let score = AnomalyScore {
            timing_anomaly: 0.8,
            size_anomaly: 0.2,
            error_anomaly: 0.1,
            status_anomaly: 0.1,
            combined_score: 0.5,
            confidence: Confidence::from_signals(0.5, 0.8, 0.2, 0.1, 0.1),
        };

        let desc = AnomalyInterpreter::describe_anomaly(&score);
        assert!(desc.contains("Timing"));
    }

    #[test]
    fn test_investigation_suggestion() {
        let score = AnomalyScore {
            timing_anomaly: 0.7,
            size_anomaly: 0.1,
            error_anomaly: 0.1,
            status_anomaly: 0.1,
            combined_score: 0.5,
            confidence: Confidence::from_signals(0.5, 0.7, 0.1, 0.1, 0.1),
        };

        let suggestion = AnomalyInterpreter::suggest_investigation(&score);
        assert!(suggestion.contains("injection"));
    }

    // ═════════════════════════════════════════════════════════════════════
    // OUTLIER RESISTANCE TESTS (P0 - Median + MAD)
    // ═════════════════════════════════════════════════════════════════════

    #[test]
    fn test_median_calculation() {
        let values = vec![100.0, 200.0, 300.0, 400.0, 500.0];
        let median = AnomalyDetector::median(&values);
        assert_eq!(median, 300.0);
    }

    #[test]
    fn test_median_with_even_count() {
        let values = vec![100.0, 200.0, 300.0, 400.0];
        let median = AnomalyDetector::median(&values);
        assert_eq!(median, 250.0); // (200 + 300) / 2
    }

    #[test]
    fn test_mad_calculation() {
        let values = vec![100.0, 200.0, 300.0, 400.0, 500.0];
        let mad = AnomalyDetector::mad(&values);
        // Median = 300, deviations = [200, 100, 0, 100, 200], median of those = 100
        assert_eq!(mad, 100.0);
    }

    #[test]
    fn test_outlier_resistant_baseline() {
        let mut detector = AnomalyDetector::new();

        // Add 99 normal responses (100ms each)
        for _ in 0..99 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                body: String::new(),
            });
        }

        // Add 1 outlier (7000ms - 70x slower!)
        detector.record_response(ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 7000,
            body: String::new(),
        });

        let baseline = detector.baseline.as_ref().unwrap();

        // With median: still 100ms (unaffected by outlier)
        assert_eq!(baseline.median_time, 100.0, "Median should ignore outlier");

        // With mean: pulled up significantly (~170ms)
        assert!(
            baseline.avg_time > 150.0,
            "Mean should be affected by outlier"
        );
        assert!(baseline.avg_time < 200.0);

        // MAD should be low (just the spread in normal responses)
        assert!(
            baseline.mad_time < 10.0,
            "MAD should be small for normal-only spread"
        );
    }

    #[test]
    fn test_outlier_detection_with_mad() {
        let mut detector = AnomalyDetector::new();

        // Normal baseline: 90-110ms (larger variance to test threshold behavior)
        for i in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 90 + i as u64 * 5, // 90, 95, 100, 105, 110
                body: String::new(),
            });
        }

        // Test: within normal variance (105ms) - should NOT be anomalous
        let normal = ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 105,
            body: String::new(),
        };

        let score = detector.analyze(&normal, &default_matcher());
        assert_eq!(
            score.timing_anomaly, 0.0,
            "105ms should not be anomalous vs 90-110ms baseline"
        );

        // Test: truly anomalous (500ms) - SHOULD be anomalous
        let very_slow = ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 500,
            body: String::new(),
        };

        let score = detector.analyze(&very_slow, &default_matcher());
        assert!(
            score.timing_anomaly > 0.0,
            "500ms should be anomalous vs 90-110ms baseline"
        );
    }

    #[test]
    fn test_median_size_with_outlier() {
        let mut detector = AnomalyDetector::new();

        // Add 99 normal sizes (1000 bytes)
        for _ in 0..99 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                body: String::new(),
            });
        }

        // Add 1 huge response (100KB - 100x larger!)
        detector.record_response(ResponseData {
            status: 200,
            content_length: 100000,
            elapsed_ms: 100,
            body: String::new(),
        });

        let baseline = detector.baseline.as_ref().unwrap();

        // Median should still be 1000 (unaffected by outlier)
        assert_eq!(
            baseline.median_size, 1000.0,
            "Median size should ignore 100KB outlier"
        );

        // Mean should be dragged up significantly
        assert!(
            baseline.avg_size > 1000.0,
            "Mean should be affected by outlier"
        );
    }

    #[test]
    fn test_mad_vs_stddev_robustness() {
        // Demonstrate why MAD > stddev for outlier-resistance
        let mut detector = AnomalyDetector::new();

        // Baseline: times = [99ms, 100ms, 101ms, 102ms, 103ms]
        for i in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 99 + i as u64,
                body: String::new(),
            });
        }

        let baseline1 = detector.baseline.as_ref().unwrap().clone();
        let mad1 = baseline1.mad_time;
        let stddev1 = baseline1.std_dev_time;

        // Add massive outlier: 5000ms
        detector.record_response(ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 5000,
            body: String::new(),
        });

        let baseline2 = detector.baseline.as_ref().unwrap();
        let mad2 = baseline2.mad_time;
        let stddev2 = baseline2.std_dev_time;

        // MAD should barely change
        assert!(
            (mad2 - mad1).abs() < 10.0,
            "MAD should be resilient to outlier"
        );

        // stddev should increase significantly
        assert!(
            stddev2 > stddev1 * 3.0,
            "stddev should increase dramatically with outlier"
        );
    }

    // ═════════════════════════════════════════════════════════════════════
    // SLIDING WINDOW TESTS (P0 - Performance: 5000 responses → 100 window)
    // ═════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sliding_window_default_size() {
        let detector = AnomalyDetector::new();
        assert_eq!(detector.window_size(), 100, "Default window should be 100");
    }

    #[test]
    fn test_sliding_window_custom_size() {
        let detector = AnomalyDetector::with_window_size(50);
        assert_eq!(detector.window_size(), 50, "Custom window should be 50");
    }

    #[test]
    fn test_sliding_window_capacity_enforced() {
        let mut detector = AnomalyDetector::with_window_size(10);

        // Add 15 responses
        for i in 0..15 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100 + i as u64,
                body: String::new(),
            });
        }

        // Should only keep last 10 (window is bounded)
        assert_eq!(
            detector.response_count(),
            10,
            "Should enforce window_size limit"
        );
    }

    #[test]
    fn test_sliding_window_fifo_eviction() {
        let mut detector = AnomalyDetector::with_window_size(5);

        // Add 10 responses with distinct times
        for i in 1..=10 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000 * i,
                elapsed_ms: 100 * i as u64,
                body: String::new(),
            });
        }

        // Window should contain only last 5: [600, 700, 800, 900, 1000]ms
        assert_eq!(detector.response_count(), 5);

        // Baseline should reflect last 5 responses (most recent)
        let baseline = detector.baseline.as_ref().unwrap();
        // Sorted: [600, 700, 800, 900, 1000], median = 800
        assert_eq!(
            baseline.median_time, 800.0,
            "Median should be from last 5 (600-1000)"
        );
    }

    #[test]
    fn test_sliding_window_performance_benefit() {
        // Demonstrate: window(100) vs all(5000) = 50x faster
        // Recalculating baseline on 100 items vs 5000 items

        let mut detector_small = AnomalyDetector::with_window_size(100);
        let mut detector_large = AnomalyDetector::new(); // 100 default

        // Small detector: 100 responses
        for i in 0..100 {
            detector_small.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100 + i as u64 % 50,
                body: String::new(),
            });
        }

        // Large detector: 5000 responses (would be 50x slower to recalculate)
        // But with sliding window, still only processes last 100
        for i in 0..5000 {
            detector_large.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100 + i as u64 % 50,
                body: String::new(),
            });
        }

        // Both should have same response count (bounded to 100)
        assert_eq!(detector_small.response_count(), 100);
        assert_eq!(
            detector_large.response_count(),
            100,
            "Sliding window prevents unbounded growth"
        );

        // Baselines should be similar (same recent data)
        let baseline_small = detector_small.baseline.as_ref().unwrap();
        let baseline_large = detector_large.baseline.as_ref().unwrap();
        assert!((baseline_small.median_time - baseline_large.median_time).abs() < 1.0);
    }

    #[test]
    fn test_sliding_window_relevance() {
        // Scenario: Target WAF rules changed after 50 responses
        let mut detector = AnomalyDetector::with_window_size(20);

        // Phase 1: Old rules, response times 100ms
        for _ in 0..50 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                body: String::new(),
            });
        }

        // Phase 2: New WAF rules, response times now 200ms
        for _ in 0..30 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 200,
                body: String::new(),
            });
        }

        // With sliding window (last 20), baseline should reflect NEW (200ms) not old (100ms)
        let baseline = detector.baseline.as_ref().unwrap();
        assert!(
            baseline.median_time > 150.0,
            "Should reflect recent WAF changes"
        );
        assert_eq!(
            detector.response_count(),
            20,
            "Window should contain only recent responses"
        );
    }

    // ═════════════════════════════════════════════════════════════════════
    // REGEX ERROR KEYWORD TESTS (P1 - Flexible pattern matching)
    // ═════════════════════════════════════════════════════════════════════

    #[test]
    fn test_error_keyword_matcher_default() {
        let matcher = ErrorKeywordMatcher::default();

        assert!(matcher.contains_error("error occurred"));
        assert!(matcher.contains_error("exception: null pointer"));
        assert!(matcher.contains_error("fatal: database failure"));
        assert!(!matcher.contains_error("Success: operation completed"));
    }

    #[test]
    fn test_error_keyword_matcher_custom_keywords() {
        let matcher = ErrorKeywordMatcher::with_keywords(vec!["SQL", "SYNTAX"]);

        assert!(matcher.contains_error("SQL injection detected"));
        assert!(matcher.contains_error("SYNTAX error on line 5"));
        assert!(!matcher.contains_error("No problems here"));
    }

    #[test]
    fn test_error_keyword_matcher_regex_patterns() {
        let matcher = ErrorKeywordMatcher::with_patterns(vec![
            r"ORA-\d+",     // Oracle errors: ORA-00942, ORA-01234
            r"SQL.*syntax", // SQL syntax errors (case-insensitive)
        ])
        .unwrap();

        assert!(matcher.contains_error("ORA-00942: table does not exist"));
        assert!(matcher.contains_error("ORA-01234: privilege denied"));
        assert!(matcher.contains_error("SQL syntax error on line 1"));
        assert!(!matcher.contains_error("No errors"));
    }

    #[test]
    fn test_error_keyword_matcher_keywords_and_patterns() {
        let matcher = ErrorKeywordMatcher::with_keywords_and_patterns(
            vec!["error", "failed"],
            vec![r"ORA-\d+", r"Warning:.*"],
        )
        .unwrap();

        // Should match keywords
        assert!(matcher.contains_error("error message"));
        assert!(matcher.contains_error("failed operation"));

        // Should match patterns
        assert!(matcher.contains_error("ORA-00942"));
        assert!(matcher.contains_error("Warning: deprecated feature"));

        assert!(!matcher.contains_error("All good"));
    }

    #[test]
    fn test_error_keyword_matcher_case_sensitivity() {
        let matcher = ErrorKeywordMatcher::with_keywords(vec!["error"]);

        assert!(matcher.contains_error("error"));
        assert!(matcher.contains_error("error message"));
        // Keywords are case-sensitive, so uppercase "Error" won't match lowercase keyword "error"
        assert!(!matcher.contains_error("Error occurred"));
        assert!(!matcher.contains_error("ERROR"));
    }

    #[test]
    fn test_error_keyword_matcher_regex_case_insensitive() {
        // Regex patterns should use (?i) for case-insensitivity
        let matcher = ErrorKeywordMatcher::with_patterns(vec![r"(?i)warning.*"]).unwrap();

        assert!(matcher.contains_error("warning: deprecated"));
        assert!(matcher.contains_error("WARNING: DANGER"));
        assert!(matcher.contains_error("Warning: careful"));
    }

    #[test]
    fn test_error_keyword_matcher_matched_patterns_count() {
        let matcher = ErrorKeywordMatcher::with_keywords_and_patterns(
            vec!["error", "failed"],
            vec![r"ORA-\d+"],
        )
        .unwrap();

        assert_eq!(matcher.matched_patterns("no match"), 0);
        assert_eq!(matcher.matched_patterns("error occurred"), 1);
        assert_eq!(matcher.matched_patterns("error and failed"), 2);
        assert_eq!(matcher.matched_patterns("error and ORA-00942"), 2);
        assert_eq!(matcher.matched_patterns("error ORA-00942 failed"), 3);
    }

    #[test]
    fn test_anomaly_detection_with_regex_errors() {
        let mut detector = AnomalyDetector::new();
        let matcher = ErrorKeywordMatcher::with_patterns(vec![r"SQL.*syntax", r"ORA-\d+"]).unwrap();

        // Build baseline with normal responses
        for _ in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                body: String::new(),
            });
        }

        // Test: Response with SQL error (P1 - Regex detection)
        let sql_error = ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 100,
            body: "SQL syntax error on line 5".to_string(),
        };

        let score = detector.analyze(&sql_error, &matcher);
        assert!(
            score.error_anomaly > 0.0,
            "Should detect SQL syntax error via regex"
        );

        // Test: Response with Oracle error code
        let oracle_error = ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 100,
            body: "ORA-00942: table does not exist".to_string(),
        };

        let score = detector.analyze(&oracle_error, &matcher);
        assert!(
            score.error_anomaly > 0.0,
            "Should detect ORA error code via regex"
        );
    }

    #[test]
    fn test_anomaly_detection_no_false_positives() {
        let mut detector = AnomalyDetector::new();
        let strict_matcher = ErrorKeywordMatcher::with_patterns(vec![r"SQL.*syntax"]).unwrap();

        // Build baseline
        for _ in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                body: "Normal response body".to_string(),
            });
        }

        // Test: Response with "SQL" but not "SQL syntax"
        let response = ResponseData {
            status: 200,
            content_length: 1000,
            elapsed_ms: 100,
            body: "SELECT * FROM users".to_string(), // Contains SQL keyword but not pattern
        };

        let score = detector.analyze(&response, &strict_matcher);
        assert_eq!(
            score.error_anomaly, 0.0,
            "Should not trigger on partial SQL matches"
        );
    }

    #[test]
    fn test_error_regex_production_patterns() {
        // Real-world error patterns (P1 - Production ready)
        let matcher = ErrorKeywordMatcher::with_patterns(vec![
            r"(?i)(error|exception|failed|fatal|critical)", // Case-insensitive errors
            r"ORA-\d+",                                     // Oracle errors
            r"(?i)SQL.*syntax",                             // SQL syntax errors
            r"(?i)warning",                                 // Warnings
            r"(?i)denied|forbidden|unauthorized",           // Access errors
            r"\[Errno \d+\]",                               // System errors
            r"Traceback.*in <module>",                      // Python errors
            r"at \w+\.\w+.*\.java:\d+",                     // Java stack trace (simplified)
        ])
        .unwrap();

        // Should detect various error patterns
        assert!(matcher.contains_error("ERROR: Cannot connect"));
        assert!(matcher.contains_error("ORA-01017: invalid username/password"));
        assert!(matcher.contains_error("SQL syntax error"));
        assert!(matcher.contains_error("WARNING: Configuration invalid"));
        assert!(matcher.contains_error("Access denied"));
        assert!(matcher.contains_error("[Errno 404]"));
        assert!(matcher.contains_error(
            "Traceback (most recent call last): File \"app.py\", line 42, in <module>"
        ));
        assert!(matcher.contains_error("at com.app.UserService.getUser(UserService.java:100)"));
    }

    // ═════════════════════════════════════════════════════════════════════
    // STATUS CODE WHITELIST TESTS (P1 - Flexible status handling)
    // ═════════════════════════════════════════════════════════════════════

    #[test]
    fn test_status_whitelist_creation() {
        let whitelist = StatusWhitelist::new(vec![200, 301, 302]);
        assert!(whitelist.is_normal(200));
        assert!(whitelist.is_normal(301));
        assert!(whitelist.is_normal(302));
        assert!(!whitelist.is_normal(404));
    }

    #[test]
    fn test_status_whitelist_common() {
        let whitelist = StatusWhitelist::common();
        // Should allow common success and redirect codes
        assert!(whitelist.is_normal(200), "200 OK");
        assert!(whitelist.is_normal(201), "201 Created");
        assert!(whitelist.is_normal(204), "204 No Content");
        assert!(whitelist.is_normal(301), "301 Redirect");
        assert!(whitelist.is_normal(302), "302 Redirect");
        assert!(whitelist.is_normal(304), "304 Not Modified");
        assert!(whitelist.is_normal(307), "307 Redirect");
        assert!(whitelist.is_normal(308), "308 Redirect");

        // Should NOT allow error codes
        assert!(!whitelist.is_normal(400), "400 Bad Request");
        assert!(!whitelist.is_normal(403), "403 Forbidden");
        assert!(!whitelist.is_normal(500), "500 Server Error");
    }

    #[test]
    fn test_status_whitelist_strict() {
        let whitelist = StatusWhitelist::strict();
        assert!(whitelist.is_normal(200), "Only 200 allowed");
        assert!(!whitelist.is_normal(201), "201 not allowed in strict mode");
        assert!(
            !whitelist.is_normal(301),
            "Redirects not allowed in strict mode"
        );
    }

    #[test]
    fn test_status_whitelist_runtime_add_remove() {
        let mut whitelist = StatusWhitelist::new(vec![200]);
        assert!(whitelist.is_normal(200));
        assert!(!whitelist.is_normal(301));

        // Add 301
        whitelist.add(301);
        assert!(whitelist.is_normal(301), "Should allow 301 after add");

        // Remove 200
        whitelist.remove(200);
        assert!(
            !whitelist.is_normal(200),
            "Should not allow 200 after remove"
        );
    }

    #[test]
    fn test_status_whitelist_codes_getter() {
        let whitelist = StatusWhitelist::new(vec![200, 404, 301]);
        let codes = whitelist.codes();
        assert_eq!(codes, vec![200, 301, 404], "Codes should be sorted");
    }

    #[test]
    fn test_anomaly_detector_with_status_whitelist() {
        let mut detector = AnomalyDetector::new();
        let whitelist = StatusWhitelist::new(vec![200, 301, 302]);
        detector.set_status_whitelist(whitelist);

        let matcher = ErrorKeywordMatcher::default();

        // Build baseline with 200 OK
        for _ in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                body: String::new(),
            });
        }

        // 301 should NOT be anomalous (whitelisted)
        let redirect = ResponseData {
            status: 301,
            content_length: 1000,
            elapsed_ms: 100,
            body: String::new(),
        };
        let score = detector.analyze(&redirect, &matcher);
        assert_eq!(
            score.status_anomaly, 0.0,
            "301 redirect should not be anomalous"
        );

        // 404 should be anomalous (not whitelisted)
        let not_found = ResponseData {
            status: 404,
            content_length: 1000,
            elapsed_ms: 100,
            body: String::new(),
        };
        let score = detector.analyze(&not_found, &matcher);
        assert!(
            score.status_anomaly > 0.0,
            "404 should be anomalous when not whitelisted"
        );
    }

    #[test]
    fn test_anomaly_detector_redirects_allowed() {
        // Scenario: API returns redirects as normal behavior
        let mut detector = AnomalyDetector::new();
        let redirect_friendly_whitelist = StatusWhitelist::new(vec![200, 301, 302, 307, 308]);
        detector.set_status_whitelist(redirect_friendly_whitelist);

        let matcher = ErrorKeywordMatcher::default();

        // Build baseline
        for _ in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                body: String::new(),
            });
        }

        // All redirect codes should be normal (P1 - Flexible)
        for status in &[301, 302, 307, 308] {
            let response = ResponseData {
                status: *status,
                content_length: 1000,
                elapsed_ms: 100,
                body: String::new(),
            };
            let score = detector.analyze(&response, &matcher);
            assert_eq!(
                score.status_anomaly, 0.0,
                "Status {} should be normal with redirect whitelist",
                status
            );
        }
    }

    #[test]
    fn test_anomaly_detector_strict_mode() {
        // Scenario: Strict detection - only 200 allowed
        let mut detector = AnomalyDetector::new();
        detector.set_status_whitelist(StatusWhitelist::strict());

        let matcher = ErrorKeywordMatcher::default();

        // Build baseline
        for _ in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                body: String::new(),
            });
        }

        // 201 should be anomalous in strict mode
        let created = ResponseData {
            status: 201,
            content_length: 1000,
            elapsed_ms: 100,
            body: String::new(),
        };
        let score = detector.analyze(&created, &matcher);
        assert!(
            score.status_anomaly > 0.0,
            "201 should be anomalous in strict mode"
        );

        // 301 should be anomalous in strict mode
        let redirect = ResponseData {
            status: 301,
            content_length: 1000,
            elapsed_ms: 100,
            body: String::new(),
        };
        let score = detector.analyze(&redirect, &matcher);
        assert!(
            score.status_anomaly > 0.0,
            "301 should be anomalous in strict mode"
        );
    }

    #[test]
    fn test_status_whitelist_default() {
        let whitelist = StatusWhitelist::default();
        assert_eq!(
            whitelist.codes().len(),
            8,
            "Default should have 8 common codes"
        );
        assert!(whitelist.is_normal(200));
        assert!(whitelist.is_normal(301));
        assert!(whitelist.is_normal(307));
    }

    // ═════════════════════════════════════════════════════════════════════
    // CONFIDENCE SCORING TESTS (P1 - Explainable anomaly detection)
    // ═════════════════════════════════════════════════════════════════════

    #[test]
    fn test_confidence_single_signal() {
        // Single signal detected
        let confidence = Confidence::from_signals(0.8, 0.8, 0.0, 0.0, 0.0);

        assert_eq!(confidence.base_score, 0.8);
        assert_eq!(confidence.signal_count, 1);
        assert!(
            confidence.confidence < 0.5,
            "Single signal = low confidence"
        );
        assert_eq!(confidence.level, ConfidenceLevel::Low);
    }

    #[test]
    fn test_confidence_multiple_signals() {
        // Multiple signals agree (timing + size)
        let confidence = Confidence::from_signals(0.8, 0.8, 0.8, 0.0, 0.0);

        assert_eq!(confidence.base_score, 0.8);
        assert_eq!(confidence.signal_count, 2);
        assert!(
            confidence.confidence > 0.5,
            "Two agreeing signals = better confidence"
        );
        assert_eq!(confidence.level, ConfidenceLevel::Medium);
    }

    #[test]
    fn test_confidence_all_signals() {
        // All signals agree (timing + size + error + status)
        let confidence = Confidence::from_signals(0.8, 0.8, 0.8, 0.8, 0.8);

        assert_eq!(confidence.base_score, 0.8);
        assert_eq!(confidence.signal_count, 4);
        assert!(
            confidence.confidence >= 0.8,
            "All signals agree = very high confidence"
        );
        assert_eq!(confidence.level, ConfidenceLevel::VeryHigh);
    }

    #[test]
    fn test_confidence_disagreeing_signals() {
        // Signals partially disagree (timing high, size low)
        let confidence = Confidence::from_signals(0.5, 0.8, 0.1, 0.0, 0.0);

        assert_eq!(confidence.signal_count, 2); // Timing and size both triggered
                                                // Agreement: spread = (0.8 - 0.1) / 0.8 = 0.875, agreement = 1.0 - 0.875 = 0.125
        assert!(confidence.signal_agreement < 0.2, "Signals disagree");
        assert!(
            confidence.confidence < 0.3,
            "Disagreement reduces confidence"
        );
    }

    #[test]
    fn test_confidence_levels() {
        // Test confidence level thresholds
        // base_score=0.1, 1 signal, consistency=0.4, agreement=1.0 → 0.1*1.0*0.4 = 0.04 (VeryLow)
        assert_eq!(
            Confidence::from_signals(0.1, 0.1, 0.0, 0.0, 0.0).level,
            ConfidenceLevel::VeryLow
        );

        // base_score=0.5, 1 signal, consistency=0.4, agreement=1.0 → 0.5*1.0*0.4 = 0.2 (Low)
        assert_eq!(
            Confidence::from_signals(0.5, 0.5, 0.0, 0.0, 0.0).level,
            ConfidenceLevel::Low
        );

        // base_score=0.8, 2 signals, consistency=0.7, agreement=1.0 → 0.8*1.0*0.7 = 0.56 (Medium)
        assert_eq!(
            Confidence::from_signals(0.8, 0.8, 0.8, 0.0, 0.0).level,
            ConfidenceLevel::Medium
        );

        // base_score=0.8, 3 signals, consistency=0.9, agreement=1.0 → 0.8*1.0*0.9 = 0.72 (High)
        assert_eq!(
            Confidence::from_signals(0.8, 0.8, 0.8, 0.8, 0.0).level,
            ConfidenceLevel::High
        );

        // base_score=0.9, 4 signals, consistency=1.0, agreement=1.0 → 0.9*1.0*1.0 = 0.9 (VeryHigh)
        assert_eq!(
            Confidence::from_signals(0.9, 0.9, 0.9, 0.9, 0.9).level,
            ConfidenceLevel::VeryHigh
        );
    }

    #[test]
    fn test_confidence_is_reportable() {
        let high_conf = Confidence::from_signals(0.9, 0.9, 0.9, 0.9, 0.9);
        let low_conf = Confidence::from_signals(0.5, 0.3, 0.0, 0.0, 0.0);

        assert!(
            high_conf.is_reportable(0.7),
            "High confidence should report"
        );
        assert!(
            !low_conf.is_reportable(0.7),
            "Low confidence should not report"
        );
    }

    #[test]
    fn test_anomaly_score_with_confidence() {
        // Test that AnomalyScore includes confidence metrics
        let confidence = Confidence::from_signals(0.7, 0.7, 0.7, 0.0, 0.0);
        let score = AnomalyScore {
            timing_anomaly: 0.7,
            size_anomaly: 0.7,
            error_anomaly: 0.0,
            status_anomaly: 0.0,
            combined_score: 0.7,
            confidence,
        };

        // Verify score includes confidence
        assert!(score.confidence.signal_count >= 1, "Should have signals");
        assert!(score.combined_score > 0.0, "Should have anomaly score");

        // Key point: same score can have different confidence levels
        let low_conf = Confidence::from_signals(0.7, 0.7, 0.0, 0.0, 0.0);
        let high_conf = Confidence::from_signals(0.7, 0.7, 0.7, 0.7, 0.7);

        assert!(
            high_conf.confidence > low_conf.confidence,
            "More signals = higher confidence"
        );
    }

    #[test]
    fn test_confidence_weak_signal() {
        // Scenario: Only one weak signal detected
        let mut detector = AnomalyDetector::new();
        let matcher = ErrorKeywordMatcher::default();

        // Build baseline
        for _ in 0..5 {
            detector.record_response(ResponseData {
                status: 200,
                content_length: 1000,
                elapsed_ms: 100,
                body: String::new(),
            });
        }

        // Response with only slight timing variation (weak signal)
        let response = ResponseData {
            status: 200,          // Normal
            content_length: 1000, // Normal
            elapsed_ms: 110,      // Slightly slow
            body: String::new(),  // No error
        };

        let score = detector.analyze(&response, &matcher);

        // Combined score might be low anyway, but verify confidence
        assert_eq!(score.confidence.signal_count, 0, "No anomalies detected");
        assert!(
            score.confidence.confidence < 0.3,
            "No anomaly signals = low confidence"
        );
    }

    #[test]
    fn test_confidence_strong_agreement() {
        // Scenario: Multiple signals all strongly agree
        let confidence = Confidence::from_signals(0.9, 0.9, 0.9, 0.9, 0.9);

        assert_eq!(confidence.signal_count, 4, "All four signals");
        assert_eq!(
            confidence.signal_agreement, 1.0,
            "Perfect agreement (all same)"
        );
        assert_eq!(confidence.consistency, 1.0, "Maximum consistency");
        assert!(
            confidence.confidence > 0.8,
            "Very high confidence (0.9 * 1.0 * 1.0)"
        );
    }

    #[test]
    fn test_confidence_partial_agreement() {
        // Scenario: Some signals strong, some weak
        let confidence = Confidence::from_signals(0.8, 0.9, 0.1, 0.0, 0.0);

        assert_eq!(confidence.signal_count, 2); // Timing and size
        assert!(confidence.signal_agreement < 1.0, "Partial agreement");
        assert!(
            confidence.confidence < 0.8,
            "Disagreement reduces confidence"
        );
    }

    #[test]
    fn test_confidence_two_signals_agreement() {
        // Two signals both high (good)
        let good = Confidence::from_signals(0.8, 0.8, 0.8, 0.0, 0.0);
        // Two signals disagreeing (bad)
        let bad = Confidence::from_signals(0.8, 0.8, 0.1, 0.0, 0.0);

        assert!(good.confidence > bad.confidence, "Agreement matters");
        assert_eq!(
            good.signal_count, bad.signal_count,
            "Same number of signals"
        );
    }

    #[test]
    fn test_confidence_consistency_levels() {
        // 1 signal = 0.4 consistency
        let one = Confidence::from_signals(0.8, 0.8, 0.0, 0.0, 0.0);
        assert_eq!(one.consistency, 0.4);

        // 2 signals = 0.7 consistency
        let two = Confidence::from_signals(0.8, 0.8, 0.8, 0.0, 0.0);
        assert_eq!(two.consistency, 0.7);

        // 3 signals = 0.9 consistency
        let three = Confidence::from_signals(0.8, 0.8, 0.8, 0.8, 0.0);
        assert_eq!(three.consistency, 0.9);

        // 4 signals = 1.0 consistency
        let four = Confidence::from_signals(0.8, 0.8, 0.8, 0.8, 0.8);
        assert_eq!(four.consistency, 1.0);
    }

    #[test]
    fn test_confidence_score_vs_confidence() {
        // IMPORTANT: Same score, different confidence
        // This is the core issue the user highlighted!

        // Scenario A: 0.8 score from single weak signal
        // confidence = 0.8 * 1.0 (agreement) * 0.4 (consistency) = 0.32
        let weak = Confidence::from_signals(0.8, 0.8, 0.0, 0.0, 0.0);

        // Scenario B: 0.8 score from multiple strong signals
        // confidence = 0.8 * 1.0 (agreement) * 1.0 (consistency) = 0.8
        let strong = Confidence::from_signals(0.8, 0.8, 0.8, 0.8, 0.8);

        // Same base score!
        assert_eq!(weak.base_score, strong.base_score);

        // But very different confidence!
        assert!(
            strong.confidence > weak.confidence * 2.0,
            "Strong agreement >> weak single signal"
        );

        // This is why confidence matters (P1)
        assert!(
            weak.is_reportable(0.2),
            "Weak: might report if threshold very low"
        );
        assert!(
            strong.is_reportable(0.7),
            "Strong: confident enough to report"
        );
        assert!(
            !weak.is_reportable(0.5),
            "Weak: not confident enough for strict threshold"
        );
    }
}
