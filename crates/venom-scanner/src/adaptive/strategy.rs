//! Payload adaptation strategy selection based on detected patterns

/// Payload adaptation strategy based on analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptationStrategy {
    /// Increase encoding depth
    IncreaseEncoding,
    /// Add delays between requests
    AddDelay,
    /// Use case variation
    CaseVariation,
    /// Use comment injection
    CommentInjection,
    /// Reduce payload size
    ReducePayload,
    /// Use parameter pollution
    ParameterPollution,
    /// Change HTTP method
    ChangeMethod,
    /// Add decoy parameters
    AddDecoys,
}

/// Detected pattern in responses
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionPattern {
    /// Status code blocking (e.g., 403, 406)
    StatusCodeBlocking(u16),
    /// Rate limiting pattern
    RateLimiting,
    /// Content filtering (response content modified)
    ContentFiltering,
}

/// Recommends strategies based on detected patterns
pub struct StrategySelector;

impl StrategySelector {
    /// Recommends adaptation strategies for a detection pattern
    pub fn recommend(pattern: Option<DetectionPattern>) -> Vec<AdaptationStrategy> {
        let mut strategies = Vec::new();

        match pattern {
            Some(DetectionPattern::StatusCodeBlocking(_)) => {
                strategies.push(AdaptationStrategy::IncreaseEncoding);
                strategies.push(AdaptationStrategy::CommentInjection);
                strategies.push(AdaptationStrategy::AddDecoys);
            },
            Some(DetectionPattern::RateLimiting) => {
                strategies.push(AdaptationStrategy::AddDelay);
                strategies.push(AdaptationStrategy::ChangeMethod);
            },
            Some(DetectionPattern::ContentFiltering) => {
                strategies.push(AdaptationStrategy::CaseVariation);
                strategies.push(AdaptationStrategy::ReducePayload);
            },
            None => {
                strategies.push(AdaptationStrategy::ParameterPollution);
            },
        }

        strategies
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recommend_for_status_blocking() {
        let strategies =
            StrategySelector::recommend(Some(DetectionPattern::StatusCodeBlocking(403)));
        assert!(strategies.contains(&AdaptationStrategy::IncreaseEncoding));
        assert!(strategies.contains(&AdaptationStrategy::CommentInjection));
        assert!(strategies.contains(&AdaptationStrategy::AddDecoys));
    }

    #[test]
    fn test_recommend_for_rate_limiting() {
        let strategies = StrategySelector::recommend(Some(DetectionPattern::RateLimiting));
        assert!(strategies.contains(&AdaptationStrategy::AddDelay));
        assert!(strategies.contains(&AdaptationStrategy::ChangeMethod));
    }

    #[test]
    fn test_recommend_for_content_filtering() {
        let strategies = StrategySelector::recommend(Some(DetectionPattern::ContentFiltering));
        assert!(strategies.contains(&AdaptationStrategy::CaseVariation));
        assert!(strategies.contains(&AdaptationStrategy::ReducePayload));
    }

    #[test]
    fn test_recommend_none() {
        let strategies = StrategySelector::recommend(None);
        assert!(strategies.contains(&AdaptationStrategy::ParameterPollution));
    }
}
