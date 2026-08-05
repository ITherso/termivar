//! Advanced Detection & WAF Bypass Techniques
//!
//! ## Runtime scope
//!
//! - **Build:** default via `detection`.
//! - **Execution:** no repository runtime caller (not on the default scan path).
//! - **Default `venom scan`:** no.
//! - **Support:** experimental/scaffold (detection helpers; not automatic WAF bypass).
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Behavioral analysis, signature evasion, and WAF bypass strategies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Behavioral signature for vulnerability detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralSignature {
    pub signature_id: String,
    pub vulnerability_type: String,
    pub indicators: Vec<BehaviorIndicator>,
    pub threshold: f32,
    pub confidence: f32,
}

/// Individual behavior indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorIndicator {
    pub indicator_type: IndicatorType,
    pub metric: String,
    pub operator: ComparisonOperator,
    pub value: f32,
    pub weight: f32,
}

/// Types of behavioral indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorType {
    #[serde(rename = "timing")]
    Timing,
    #[serde(rename = "size")]
    Size,
    #[serde(rename = "pattern")]
    Pattern,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "consistency")]
    Consistency,
}

impl IndicatorType {
    pub fn as_str(&self) -> &str {
        match self {
            IndicatorType::Timing => "timing",
            IndicatorType::Size => "size",
            IndicatorType::Pattern => "pattern",
            IndicatorType::Error => "error",
            IndicatorType::Consistency => "consistency",
        }
    }
}

/// Comparison operators for threshold checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOperator {
    #[serde(rename = "greater_than")]
    GreaterThan,
    #[serde(rename = "less_than")]
    LessThan,
    #[serde(rename = "equals")]
    Equals,
    #[serde(rename = "contains")]
    Contains,
}

impl ComparisonOperator {
    pub fn as_str(&self) -> &str {
        match self {
            ComparisonOperator::GreaterThan => "greater_than",
            ComparisonOperator::LessThan => "less_than",
            ComparisonOperator::Equals => "equals",
            ComparisonOperator::Contains => "contains",
        }
    }
}

/// WAF bypass technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafBypassTechnique {
    pub technique_id: String,
    pub technique_name: String,
    pub category: BypassCategory,
    pub description: String,
    pub effectiveness_score: f32,
    pub false_positive_rate: f32,
    pub evasion_methods: Vec<String>,
}

/// WAF bypass categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BypassCategory {
    #[serde(rename = "encoding")]
    Encoding,
    #[serde(rename = "obfuscation")]
    Obfuscation,
    #[serde(rename = "fragmentation")]
    Fragmentation,
    #[serde(rename = "normalization")]
    Normalization,
    #[serde(rename = "timing")]
    Timing,
}

impl BypassCategory {
    pub fn as_str(&self) -> &str {
        match self {
            BypassCategory::Encoding => "encoding",
            BypassCategory::Obfuscation => "obfuscation",
            BypassCategory::Fragmentation => "fragmentation",
            BypassCategory::Normalization => "normalization",
            BypassCategory::Timing => "timing",
        }
    }
}

/// Behavioral analyzer for advanced detection
pub struct BehavioralAnalyzer {
    signatures: HashMap<String, BehavioralSignature>,
}

impl BehavioralAnalyzer {
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
        }
    }

    /// Registers a behavioral signature
    pub fn register_signature(&mut self, signature: BehavioralSignature) {
        self.signatures
            .insert(signature.signature_id.clone(), signature);
    }

    /// Analyzes response data against behavioral signatures
    pub fn analyze(&self, response_data: &BehavioralAnalysisData) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        for signature in self.signatures.values() {
            let mut matched_indicators = 0;
            let mut confidence_score = 0.0;

            for indicator in &signature.indicators {
                if self.check_indicator(indicator, response_data) {
                    matched_indicators += 1;
                    confidence_score += indicator.weight;
                }
            }

            if matched_indicators as f32 >= signature.threshold {
                results.push(DetectionResult {
                    detection_id: format!(
                        "det_{}",
                        signature
                            .signature_id
                            .split('_')
                            .next()
                            .unwrap_or("unknown")
                    ),
                    vulnerability_type: signature.vulnerability_type.clone(),
                    confidence: (confidence_score / signature.indicators.len() as f32).min(1.0),
                    matched_indicators,
                    total_indicators: signature.indicators.len(),
                });
            }
        }

        results
    }

    fn check_indicator(
        &self,
        indicator: &BehaviorIndicator,
        data: &BehavioralAnalysisData,
    ) -> bool {
        match indicator.operator {
            ComparisonOperator::GreaterThan => data.get_metric(&indicator.metric) > indicator.value,
            ComparisonOperator::LessThan => data.get_metric(&indicator.metric) < indicator.value,
            ComparisonOperator::Equals => {
                (data.get_metric(&indicator.metric) - indicator.value).abs() < 0.01
            },
            ComparisonOperator::Contains => false, // Pattern matching would be implemented here
        }
    }

    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

impl Default for BehavioralAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Analysis data for behavioral detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysisData {
    pub response_time_ms: f32,
    pub response_size_bytes: u32,
    pub error_keywords_count: u32,
    pub unique_patterns: u32,
    pub consistency_score: f32,
}

impl BehavioralAnalysisData {
    pub fn get_metric(&self, metric: &str) -> f32 {
        match metric {
            "response_time" => self.response_time_ms,
            "response_size" => self.response_size_bytes as f32,
            "error_keywords" => self.error_keywords_count as f32,
            "unique_patterns" => self.unique_patterns as f32,
            "consistency" => self.consistency_score,
            _ => 0.0,
        }
    }
}

/// Detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub detection_id: String,
    pub vulnerability_type: String,
    pub confidence: f32,
    pub matched_indicators: usize,
    pub total_indicators: usize,
}

/// WAF bypass strategy selector
pub struct WafBypassSelector {
    techniques: HashMap<String, WafBypassTechnique>,
}

impl WafBypassSelector {
    pub fn new() -> Self {
        Self {
            techniques: HashMap::new(),
        }
    }

    /// Registers a WAF bypass technique
    pub fn register_technique(&mut self, technique: WafBypassTechnique) {
        self.techniques
            .insert(technique.technique_id.clone(), technique);
    }

    /// Selects best technique for a given category
    pub fn select_best(&self, category: BypassCategory) -> Option<&WafBypassTechnique> {
        self.techniques
            .values()
            .filter(|t| t.category == category)
            .max_by(|a, b| {
                a.effectiveness_score
                    .partial_cmp(&b.effectiveness_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Gets all techniques in category
    pub fn get_by_category(&self, category: BypassCategory) -> Vec<&WafBypassTechnique> {
        self.techniques
            .values()
            .filter(|t| t.category == category)
            .collect()
    }

    /// Ranks techniques by effectiveness
    pub fn rank_by_effectiveness(&self) -> Vec<&WafBypassTechnique> {
        let mut techniques: Vec<_> = self.techniques.values().collect();
        techniques.sort_by(|a, b| {
            b.effectiveness_score
                .partial_cmp(&a.effectiveness_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        techniques
    }

    pub fn technique_count(&self) -> usize {
        self.techniques.len()
    }
}

impl Default for WafBypassSelector {
    fn default() -> Self {
        Self::new()
    }
}

/// Signature evasion engine
pub struct SignatureEvasionEngine {
    evasion_rules: Vec<EversionRule>,
}

/// Rule for signature evasion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EversionRule {
    pub rule_id: String,
    pub target_signature: String,
    pub mutation_strategy: String,
    pub mutation_type: EversionType,
    pub effectiveness: f32,
}

/// Types of evasion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EversionType {
    #[serde(rename = "encoding")]
    Encoding,
    #[serde(rename = "manipulation")]
    Manipulation,
    #[serde(rename = "noise")]
    Noise,
    #[serde(rename = "bypass")]
    Bypass,
}

impl EversionType {
    pub fn as_str(&self) -> &str {
        match self {
            EversionType::Encoding => "encoding",
            EversionType::Manipulation => "manipulation",
            EversionType::Noise => "noise",
            EversionType::Bypass => "bypass",
        }
    }
}

impl SignatureEvasionEngine {
    pub fn new() -> Self {
        Self {
            evasion_rules: Vec::new(),
        }
    }

    /// Adds evasion rule
    pub fn add_rule(&mut self, rule: EversionRule) {
        self.evasion_rules.push(rule);
    }

    /// Gets rules for target signature
    pub fn get_rules_for_signature(&self, target: &str) -> Vec<&EversionRule> {
        self.evasion_rules
            .iter()
            .filter(|r| r.target_signature == target)
            .collect()
    }

    /// Gets best evasion rule
    pub fn get_best_rule(&self, target: &str) -> Option<&EversionRule> {
        self.get_rules_for_signature(target)
            .into_iter()
            .max_by(|a, b| {
                a.effectiveness
                    .partial_cmp(&b.effectiveness)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    pub fn rule_count(&self) -> usize {
        self.evasion_rules.len()
    }
}

impl Default for SignatureEvasionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_behavioral_signature_creation() {
        let sig = BehavioralSignature {
            signature_id: "sig_sqli_1".to_string(),
            vulnerability_type: "SQLi".to_string(),
            indicators: vec![],
            threshold: 2.0,
            confidence: 0.95,
        };

        assert_eq!(sig.vulnerability_type, "SQLi");
    }

    #[test]
    fn test_behavior_indicator() {
        let indicator = BehaviorIndicator {
            indicator_type: IndicatorType::Timing,
            metric: "response_time".to_string(),
            operator: ComparisonOperator::GreaterThan,
            value: 5000.0,
            weight: 0.5,
        };

        assert_eq!(indicator.indicator_type, IndicatorType::Timing);
    }

    #[test]
    fn test_behavioral_analyzer() {
        let mut analyzer = BehavioralAnalyzer::new();
        let sig = BehavioralSignature {
            signature_id: "sig_1".to_string(),
            vulnerability_type: "SQLi".to_string(),
            indicators: vec![],
            threshold: 1.0,
            confidence: 0.9,
        };

        analyzer.register_signature(sig);
        assert_eq!(analyzer.signature_count(), 1);
    }

    #[test]
    fn test_waf_bypass_technique() {
        let technique = WafBypassTechnique {
            technique_id: "waf_bypass_1".to_string(),
            technique_name: "URL Encoding".to_string(),
            category: BypassCategory::Encoding,
            description: "Use double URL encoding".to_string(),
            effectiveness_score: 0.85,
            false_positive_rate: 0.05,
            evasion_methods: vec!["double_url_encode".to_string()],
        };

        assert_eq!(technique.category, BypassCategory::Encoding);
    }

    #[test]
    fn test_waf_bypass_selector() {
        let mut selector = WafBypassSelector::new();

        let technique = WafBypassTechnique {
            technique_id: "waf_1".to_string(),
            technique_name: "Encoding".to_string(),
            category: BypassCategory::Encoding,
            description: "Test".to_string(),
            effectiveness_score: 0.9,
            false_positive_rate: 0.05,
            evasion_methods: vec![],
        };

        selector.register_technique(technique);
        assert_eq!(selector.technique_count(), 1);
    }

    #[test]
    fn test_signature_evasion_engine() {
        let mut engine = SignatureEvasionEngine::new();

        let rule = EversionRule {
            rule_id: "evasion_1".to_string(),
            target_signature: "mod_security_rule_1".to_string(),
            mutation_strategy: "hex_encode".to_string(),
            mutation_type: EversionType::Encoding,
            effectiveness: 0.88,
        };

        engine.add_rule(rule);
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn test_behavioral_analysis_data() {
        let data = BehavioralAnalysisData {
            response_time_ms: 150.0,
            response_size_bytes: 512,
            error_keywords_count: 3,
            unique_patterns: 2,
            consistency_score: 0.95,
        };

        assert_eq!(data.get_metric("response_time"), 150.0);
        assert_eq!(data.get_metric("response_size"), 512.0);
    }

    #[test]
    fn test_detection_result() {
        let result = DetectionResult {
            detection_id: "det_sqli_1".to_string(),
            vulnerability_type: "SQLi".to_string(),
            confidence: 0.92,
            matched_indicators: 3,
            total_indicators: 5,
        };

        assert!(result.confidence > 0.9);
    }

    #[test]
    fn test_indicator_types() {
        assert_eq!(IndicatorType::Timing.as_str(), "timing");
        assert_eq!(IndicatorType::Size.as_str(), "size");
        assert_eq!(IndicatorType::Pattern.as_str(), "pattern");
    }

    #[test]
    fn test_evasion_types() {
        assert_eq!(EversionType::Encoding.as_str(), "encoding");
        assert_eq!(EversionType::Manipulation.as_str(), "manipulation");
    }
}
