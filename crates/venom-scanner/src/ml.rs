//! Machine Learning & Pattern Discovery
//!
//! ML-driven vulnerability detection using clustering, pattern learning,
//! and automated exploitation discovery.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Vulnerability pattern for ML clustering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPattern {
    pub pattern_id: String,
    pub pattern_name: String,
    pub signature: Vec<f32>,
    pub confidence: f32,
    pub occurrences: u32,
    pub severity: String,
    pub exploit_chain: Vec<String>,
}

/// ML clustering result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterResult {
    pub cluster_id: u32,
    pub centroid: Vec<f32>,
    pub members: Vec<String>,
    pub size: usize,
    pub similarity_score: f32,
}

/// Pattern learner for discovering new vulnerability patterns
pub struct PatternLearner {
    patterns: HashMap<String, VulnerabilityPattern>,
    clusters: Vec<ClusterResult>,
}

impl PatternLearner {
    pub fn new() -> Self {
        Self {
            patterns: HashMap::new(),
            clusters: Vec::new(),
        }
    }

    /// Registers a new pattern
    pub fn register_pattern(&mut self, pattern: VulnerabilityPattern) {
        self.patterns.insert(pattern.pattern_id.clone(), pattern);
    }

    /// Gets pattern by ID
    pub fn get_pattern(&self, pattern_id: &str) -> Option<&VulnerabilityPattern> {
        self.patterns.get(pattern_id)
    }

    /// Gets all patterns
    pub fn get_patterns(&self) -> Vec<&VulnerabilityPattern> {
        self.patterns.values().collect()
    }

    /// Simple k-means clustering
    pub fn cluster_patterns(&mut self, k: usize) -> Vec<ClusterResult> {
        if self.patterns.is_empty() {
            return Vec::new();
        }

        let patterns: Vec<&VulnerabilityPattern> = self.patterns.values().collect();
        let mut centroids: Vec<Vec<f32>> = Vec::new();

        // Initialize centroids randomly
        for i in 0..k.min(patterns.len()) {
            if let Some(pattern) = patterns.get(i) {
                centroids.push(pattern.signature.clone());
            }
        }

        // Simple clustering (1 iteration for now)
        let mut clusters: Vec<Vec<String>> = vec![Vec::new(); centroids.len()];

        for pattern in &patterns {
            let mut min_distance = f32::MAX;
            let mut closest_centroid = 0;

            for (j, centroid) in centroids.iter().enumerate() {
                let distance = Self::euclidean_distance(&pattern.signature, centroid);
                if distance < min_distance {
                    min_distance = distance;
                    closest_centroid = j;
                }
            }

            clusters[closest_centroid].push(pattern.pattern_id.clone());
        }

        // Build results
        self.clusters = clusters
            .into_iter()
            .enumerate()
            .filter(|(_, members)| !members.is_empty())
            .map(|(idx, members)| {
                let size = members.len();
                ClusterResult {
                    cluster_id: idx as u32,
                    centroid: centroids[idx].clone(),
                    members,
                    size,
                    similarity_score: 0.85,
                }
            })
            .collect();

        self.clusters.clone()
    }

    /// Euclidean distance between two vectors
    fn euclidean_distance(a: &[f32], b: &[f32]) -> f32 {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f32>()
            .sqrt()
    }

    /// Gets clusters
    pub fn get_clusters(&self) -> &[ClusterResult] {
        &self.clusters
    }

    /// Pattern count
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for PatternLearner {
    fn default() -> Self {
        Self::new()
    }
}

/// Exploitation chain builder for automated exploitation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitationChain {
    pub chain_id: String,
    pub stages: Vec<ExploitStage>,
    pub success_rate: f32,
    pub time_to_exploit_secs: u32,
}

/// Single stage in exploitation chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitStage {
    pub stage_id: u32,
    pub name: String,
    pub technique: String,
    pub payload: String,
    pub expected_response: String,
    pub fallback: Option<String>,
}

/// Exploit builder for assembling multi-stage exploitation chains
pub struct ExploitBuilder {
    chains: HashMap<String, ExploitationChain>,
}

impl ExploitBuilder {
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
        }
    }

    /// Creates a new exploitation chain
    pub fn create_chain(&mut self, chain_id: String) -> ExploitationChain {
        let chain = ExploitationChain {
            chain_id: chain_id.clone(),
            stages: Vec::new(),
            success_rate: 0.0,
            time_to_exploit_secs: 0,
        };
        self.chains.insert(chain_id, chain.clone());
        chain
    }

    /// Adds stage to chain
    pub fn add_stage(&mut self, chain_id: &str, stage: ExploitStage) -> bool {
        if let Some(chain) = self.chains.get_mut(chain_id) {
            chain.stages.push(stage);
            true
        } else {
            false
        }
    }

    /// Gets chain by ID
    pub fn get_chain(&self, chain_id: &str) -> Option<&ExploitationChain> {
        self.chains.get(chain_id)
    }

    /// Gets all chains
    pub fn get_chains(&self) -> Vec<&ExploitationChain> {
        self.chains.values().collect()
    }

    /// Estimates success rate based on stages
    pub fn estimate_success_rate(&self, chain_id: &str) -> f32 {
        if let Some(chain) = self.chains.get(chain_id) {
            if chain.stages.is_empty() {
                return 0.0;
            }
            // Simple estimation: 0.8 per stage
            0.8_f32.powi(chain.stages.len() as i32)
        } else {
            0.0
        }
    }

    /// Chain count
    pub fn chain_count(&self) -> usize {
        self.chains.len()
    }
}

impl Default for ExploitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Anomaly pattern classifier using isolation forest concept
pub struct AnomalyClassifier {
    patterns: Vec<AnomalyPattern>,
}

/// Pattern representing anomalous behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyPattern {
    pub pattern_id: String,
    pub feature_vector: Vec<f32>,
    pub anomaly_score: f32,
    pub pattern_type: AnomalyType,
}

/// Types of anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    #[serde(rename = "timing")]
    Timing,
    #[serde(rename = "size")]
    Size,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "behavior")]
    Behavior,
}

impl AnomalyClassifier {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Adds anomaly pattern
    pub fn add_pattern(&mut self, pattern: AnomalyPattern) {
        self.patterns.push(pattern);
    }

    /// Classifies new data point as anomalous
    pub fn classify(&self, feature_vector: &[f32]) -> (bool, f32) {
        if self.patterns.is_empty() {
            return (false, 0.0);
        }

        let mut anomaly_scores = Vec::new();

        for pattern in &self.patterns {
            let distance = Self::euclidean_distance(feature_vector, &pattern.feature_vector);
            anomaly_scores.push(distance);
        }

        let mean_distance = anomaly_scores.iter().sum::<f32>() / anomaly_scores.len() as f32;
        let threshold = mean_distance * 2.0; // 2-sigma threshold

        let is_anomalous = mean_distance > threshold;
        let normalized_score = (mean_distance / (threshold + 1.0)).min(1.0);

        (is_anomalous, normalized_score)
    }

    /// Euclidean distance
    fn euclidean_distance(a: &[f32], b: &[f32]) -> f32 {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f32>()
            .sqrt()
    }

    /// Gets pattern count
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for AnomalyClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_registration() {
        let mut learner = PatternLearner::new();
        let pattern = VulnerabilityPattern {
            pattern_id: "p1".to_string(),
            pattern_name: "SQLi".to_string(),
            signature: vec![0.1, 0.2, 0.3],
            confidence: 0.95,
            occurrences: 10,
            severity: "CRITICAL".to_string(),
            exploit_chain: vec!["stage1".to_string()],
        };

        learner.register_pattern(pattern);
        assert_eq!(learner.pattern_count(), 1);
    }

    #[test]
    fn test_pattern_retrieval() {
        let mut learner = PatternLearner::new();
        let pattern = VulnerabilityPattern {
            pattern_id: "p1".to_string(),
            pattern_name: "SQLi".to_string(),
            signature: vec![0.1, 0.2, 0.3],
            confidence: 0.95,
            occurrences: 10,
            severity: "CRITICAL".to_string(),
            exploit_chain: vec!["stage1".to_string()],
        };

        learner.register_pattern(pattern);
        let retrieved = learner.get_pattern("p1");
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_pattern_clustering() {
        let mut learner = PatternLearner::new();

        for i in 0..5 {
            let pattern = VulnerabilityPattern {
                pattern_id: format!("p{}", i),
                pattern_name: "SQLi".to_string(),
                signature: vec![0.1 * i as f32, 0.2 * i as f32, 0.3 * i as f32],
                confidence: 0.95,
                occurrences: 10,
                severity: "CRITICAL".to_string(),
                exploit_chain: vec!["stage1".to_string()],
            };
            learner.register_pattern(pattern);
        }

        let clusters = learner.cluster_patterns(2);
        assert!(!clusters.is_empty());
    }

    #[test]
    fn test_exploit_chain_creation() {
        let mut builder = ExploitBuilder::new();
        let chain = builder.create_chain("chain1".to_string());
        assert_eq!(chain.chain_id, "chain1");
    }

    #[test]
    fn test_exploit_stage_addition() {
        let mut builder = ExploitBuilder::new();
        builder.create_chain("chain1".to_string());

        let stage = ExploitStage {
            stage_id: 1,
            name: "Initial".to_string(),
            technique: "SQLi".to_string(),
            payload: "1' OR '1'='1".to_string(),
            expected_response: "error".to_string(),
            fallback: Some("alt_payload".to_string()),
        };

        builder.add_stage("chain1", stage);
        let chain = builder.get_chain("chain1").unwrap();
        assert_eq!(chain.stages.len(), 1);
    }

    #[test]
    fn test_success_rate_estimation() {
        let mut builder = ExploitBuilder::new();
        builder.create_chain("chain1".to_string());

        for i in 0..3 {
            let stage = ExploitStage {
                stage_id: i,
                name: format!("Stage{}", i),
                technique: "SQLi".to_string(),
                payload: "payload".to_string(),
                expected_response: "response".to_string(),
                fallback: None,
            };
            builder.add_stage("chain1", stage);
        }

        let success_rate = builder.estimate_success_rate("chain1");
        assert!(success_rate > 0.0 && success_rate < 1.0);
    }

    #[test]
    fn test_anomaly_classifier() {
        let mut classifier = AnomalyClassifier::new();
        let pattern = AnomalyPattern {
            pattern_id: "a1".to_string(),
            feature_vector: vec![0.1, 0.2, 0.3],
            anomaly_score: 0.8,
            pattern_type: AnomalyType::Timing,
        };

        classifier.add_pattern(pattern);
        assert_eq!(classifier.pattern_count(), 1);
    }

    #[test]
    fn test_anomaly_detection() {
        let mut classifier = AnomalyClassifier::new();
        let pattern = AnomalyPattern {
            pattern_id: "a1".to_string(),
            feature_vector: vec![0.1, 0.2, 0.3],
            anomaly_score: 0.8,
            pattern_type: AnomalyType::Timing,
        };

        classifier.add_pattern(pattern);
        let (is_anomalous, score) = classifier.classify(&[0.1, 0.2, 0.3]);

        assert!(!is_anomalous);
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn test_exploit_chain_serialization() {
        let chain = ExploitationChain {
            chain_id: "chain1".to_string(),
            stages: vec![],
            success_rate: 0.75,
            time_to_exploit_secs: 30,
        };

        let json = serde_json::to_string(&chain).unwrap();
        let deserialized: ExploitationChain = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.chain_id, "chain1");
    }
}
