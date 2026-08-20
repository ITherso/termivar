//! Experimental deviation records and text-marker matching.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `detection`.
//! - **Execution:** no repository runtime caller.
//! - **Default `venom scan`:** no.
//! - **Support:** experimental data/helper scaffold.
//!
//! This module does not establish baselines, calculate statistical confidence,
//! classify a vulnerability, assign severity, or emit a finding. Hosts may
//! validate externally computed deviation vectors and use the matcher as a
//! literal/regex text utility. See `docs/internals/runtime-map.md`.

use thiserror::Error;

/// Literal and regular-expression text matcher.
#[derive(Debug, Clone)]
pub struct ErrorKeywordMatcher {
    keywords: Vec<String>,
    patterns: Vec<regex::Regex>,
}

impl ErrorKeywordMatcher {
    /// Creates a matcher from literal strings.
    #[must_use]
    pub fn with_keywords(keywords: Vec<&str>) -> Self {
        Self {
            keywords: keywords.into_iter().map(str::to_owned).collect(),
            patterns: Vec::new(),
        }
    }

    /// Creates a matcher from regular expressions.
    pub fn with_patterns(patterns: Vec<&str>) -> Result<Self, String> {
        let patterns = patterns
            .into_iter()
            .map(regex::Regex::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            keywords: Vec::new(),
            patterns,
        })
    }

    /// Creates a matcher from literals and regular expressions.
    pub fn with_keywords_and_patterns(
        keywords: Vec<&str>,
        patterns: Vec<&str>,
    ) -> Result<Self, String> {
        let mut matcher = Self::with_patterns(patterns)?;
        matcher.keywords = keywords.into_iter().map(str::to_owned).collect();
        Ok(matcher)
    }

    /// Returns whether any configured literal or expression matches `text`.
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        self.keywords.iter().any(|keyword| text.contains(keyword))
            || self.patterns.iter().any(|pattern| pattern.is_match(text))
    }

    /// Counts configured literals and expressions that match `text`.
    #[must_use]
    pub fn match_count(&self, text: &str) -> usize {
        self.keywords
            .iter()
            .filter(|keyword| text.contains(keyword.as_str()))
            .count()
            + self
                .patterns
                .iter()
                .filter(|pattern| pattern.is_match(text))
                .count()
    }
}

/// Neutral dimensions in a caller-supplied deviation vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviationDimension {
    Timing,
    ResponseSize,
    TextMarker,
    StatusCode,
}

/// Caller-supplied normalized deviation vector.
///
/// Values are descriptive inputs only. No vulnerability, confidence, severity,
/// or reporting decision is derived from them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResponseDeviation {
    pub timing: f32,
    pub response_size: f32,
    pub text_marker: f32,
    pub status_code: f32,
}

impl ResponseDeviation {
    /// Validates that every dimension is finite and normalized to `0..=1`.
    pub fn validate(&self) -> Result<(), ResponseDeviationValidationError> {
        for (dimension, value) in [
            (DeviationDimension::Timing, self.timing),
            (DeviationDimension::ResponseSize, self.response_size),
            (DeviationDimension::TextMarker, self.text_marker),
            (DeviationDimension::StatusCode, self.status_code),
        ] {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(ResponseDeviationValidationError::InvalidDimension { dimension });
            }
        }
        Ok(())
    }

    /// Returns the largest nonzero dimension after validation.
    ///
    /// Equal values use the stable enum order shown in the source.
    pub fn dominant_dimension(
        &self,
    ) -> Result<Option<DeviationDimension>, ResponseDeviationValidationError> {
        self.validate()?;
        let mut dominant = None;
        let mut maximum = 0.0_f32;
        for (dimension, value) in [
            (DeviationDimension::Timing, self.timing),
            (DeviationDimension::ResponseSize, self.response_size),
            (DeviationDimension::TextMarker, self.text_marker),
            (DeviationDimension::StatusCode, self.status_code),
        ] {
            if value > maximum {
                maximum = value;
                dominant = Some(dimension);
            }
        }
        Ok(dominant)
    }
}

/// Validation failure for a caller-supplied deviation vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ResponseDeviationValidationError {
    #[error("response deviation dimension {dimension:?} must be finite and within 0..=1")]
    InvalidDimension { dimension: DeviationDimension },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_reports_only_literal_and_regex_matches() {
        let matcher = ErrorKeywordMatcher::with_keywords_and_patterns(
            vec!["literal-marker"],
            vec![r"code-[0-9]+"],
        )
        .expect("valid pattern");

        assert!(matcher.is_match("literal-marker and code-42"));
        assert_eq!(matcher.match_count("literal-marker and code-42"), 2);
        assert!(!matcher.is_match("ordinary text"));
    }

    #[test]
    fn invalid_regex_is_rejected() {
        assert!(ErrorKeywordMatcher::with_patterns(vec!["("]).is_err());
    }

    #[test]
    fn deviation_vector_rejects_nonfinite_and_out_of_range_values() {
        for invalid in [f32::NAN, f32::INFINITY, -0.1, 1.1] {
            let vector = ResponseDeviation {
                timing: invalid,
                response_size: 0.0,
                text_marker: 0.0,
                status_code: 0.0,
            };
            assert_eq!(
                vector.validate(),
                Err(ResponseDeviationValidationError::InvalidDimension {
                    dimension: DeviationDimension::Timing,
                })
            );
        }
    }

    #[test]
    fn dominant_dimension_is_the_actual_maximum_with_stable_ties() {
        let vector = ResponseDeviation {
            timing: 0.2,
            response_size: 0.7,
            text_marker: 0.7,
            status_code: 0.3,
        };
        assert_eq!(
            vector.dominant_dimension(),
            Ok(Some(DeviationDimension::ResponseSize))
        );

        let zero = ResponseDeviation {
            timing: 0.0,
            response_size: 0.0,
            text_marker: 0.0,
            status_code: 0.0,
        };
        assert_eq!(zero.dominant_dimension(), Ok(None));
    }
}
