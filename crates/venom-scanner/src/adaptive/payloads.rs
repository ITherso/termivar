//! Payload mutation and encoding variations (P1 - Trait-based for plugins)

use super::strategy::DetectionPattern;

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// PayloadTransformer trait (P1 - Plugin Interface)
///
/// Implement this trait to create custom payload mutations.
/// Examples: encoding, case flipping, comment injection, etc.
///
/// # Example Plugin
/// ```ignore
/// pub struct CustomTransformer;
///
/// impl PayloadTransformer for CustomTransformer {
///     fn name(&self) -> &str { "custom" }
///
///     fn transform(&self, payload: &str) -> String {
///         // Your custom mutation logic
///         format!("CUSTOM[{}]", payload)
///     }
/// }
/// ```
pub trait PayloadTransformer: Send + Sync {
    /// Unique identifier for this transformer
    fn name(&self) -> &str;

    /// Transform/mutate the payload
    fn transform(&self, payload: &str) -> String;

    /// Optional: called before transformation (for validation/setup)
    fn pre_transform(&self, _payload: &str) -> Result<(), String> {
        Ok(())
    }

    /// Optional: called after transformation (for validation)
    fn post_transform(&self, _transformed: &str) -> Result<(), String> {
        Ok(())
    }

    /// Mutate with pre/post hooks
    fn transform_safe(&self, payload: &str) -> Result<String, String> {
        self.pre_transform(payload)?;
        let transformed = self.transform(payload);
        self.post_transform(&transformed)?;
        Ok(transformed)
    }
}

/// Encoding mutation (case flip)
#[derive(Debug, Clone)]
pub struct EncodingTransformer;

impl PayloadTransformer for EncodingTransformer {
    fn name(&self) -> &str {
        "encoding"
    }

    fn transform(&self, payload: &str) -> String {
        payload
            .chars()
            .map(|c| {
                if c.is_alphabetic() {
                    if c.is_uppercase() {
                        c.to_lowercase().to_string()
                    } else {
                        c.to_uppercase().to_string()
                    }
                } else {
                    c.to_string()
                }
            })
            .collect()
    }
}

/// Case mutation (alternating case)
#[derive(Debug, Clone)]
pub struct CaseTransformer;

impl PayloadTransformer for CaseTransformer {
    fn name(&self) -> &str {
        "case"
    }

    fn transform(&self, payload: &str) -> String {
        payload
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if c.is_alphabetic() {
                    if i % 2 == 0 {
                        c.to_uppercase().to_string()
                    } else {
                        c.to_lowercase().to_string()
                    }
                } else {
                    c.to_string()
                }
            })
            .collect()
    }
}

/// Parameter pollution with a deterministic input-derived decoy.
#[derive(Debug, Clone)]
pub struct PollutionTransformer;

impl PayloadTransformer for PollutionTransformer {
    fn name(&self) -> &str {
        "pollution"
    }

    fn transform(&self, payload: &str) -> String {
        let fingerprint = payload.bytes().fold(FNV_OFFSET_BASIS, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
        });
        format!("{payload}&_={fingerprint:016x}")
    }
}

/// Comment injection
#[derive(Debug, Clone)]
pub struct CommentTransformer;

impl PayloadTransformer for CommentTransformer {
    fn name(&self) -> &str {
        "comment"
    }

    fn transform(&self, payload: &str) -> String {
        format!("{}/**/", payload)
    }
}

/// Decoy parameters
#[derive(Debug, Clone)]
pub struct DecoyTransformer;

impl PayloadTransformer for DecoyTransformer {
    fn name(&self) -> &str {
        "decoy"
    }

    fn transform(&self, payload: &str) -> String {
        format!("{}&x=1&y=2&z=3", payload)
    }
}

/// Payload size reduction
#[derive(Debug, Clone)]
pub struct ReductionTransformer {
    pub max_size: usize,
}

impl PayloadTransformer for ReductionTransformer {
    fn name(&self) -> &str {
        "reduction"
    }

    fn transform(&self, payload: &str) -> String {
        if payload.len() > self.max_size {
            let mut boundary = self.max_size;
            while !payload.is_char_boundary(boundary) {
                boundary -= 1;
            }
            payload[..boundary].to_string()
        } else {
            payload.to_string()
        }
    }
}

/// Composite transformer (chains multiple transformers)
pub struct CompositeTransformer {
    transformers: Vec<Box<dyn PayloadTransformer>>,
}

impl CompositeTransformer {
    /// Create composite from multiple transformers
    pub fn new(transformers: Vec<Box<dyn PayloadTransformer>>) -> Self {
        Self { transformers }
    }

    /// Add a transformer to the chain
    pub fn add(&mut self, transformer: Box<dyn PayloadTransformer>) {
        self.transformers.push(transformer);
    }
}

impl PayloadTransformer for CompositeTransformer {
    fn name(&self) -> &str {
        "composite"
    }

    fn transform(&self, payload: &str) -> String {
        let mut result = payload.to_string();
        for transformer in &self.transformers {
            result = transformer.transform(&result);
        }
        result
    }

    fn transform_safe(&self, payload: &str) -> Result<String, String> {
        self.pre_transform(payload)?;
        let mut result = payload.to_string();
        for transformer in &self.transformers {
            result = transformer.transform_safe(&result)?;
        }
        self.post_transform(&result)?;
        Ok(result)
    }
}

/// Legacy API - Payload mutation based on analysis
/// Kept for backward compatibility
pub struct PayloadMutator;

impl PayloadMutator {
    /// Mutates payload based on detection pattern
    pub fn mutate(payload: &str, pattern: Option<DetectionPattern>) -> String {
        let transformer: Box<dyn PayloadTransformer> = match pattern {
            Some(DetectionPattern::StatusCodeBlocking(_)) => Box::new(EncodingTransformer),
            Some(DetectionPattern::RateLimiting) => Box::new(PollutionTransformer),
            Some(DetectionPattern::ContentFiltering) => Box::new(CaseTransformer),
            None => return payload.to_string(),
        };

        transformer.transform(payload)
    }

    /// Applies encoding mutation (case flip)
    pub fn apply_encoding_mutation(payload: &str) -> String {
        EncodingTransformer.transform(payload)
    }

    /// Applies case mutation (alternating case)
    pub fn case_mutate(payload: &str) -> String {
        CaseTransformer.transform(payload)
    }

    /// Applies parameter pollution with a deterministic input-derived decoy.
    pub fn apply_parameter_pollution(payload: &str) -> String {
        PollutionTransformer.transform(payload)
    }

    /// Adds comment injection
    pub fn inject_comment(payload: &str) -> String {
        CommentTransformer.transform(payload)
    }

    /// Reduces payload size (basic truncation)
    pub fn reduce_payload(payload: &str, max_size: usize) -> String {
        ReductionTransformer { max_size }.transform(payload)
    }

    /// Adds decoy parameters
    pub fn add_decoys(payload: &str) -> String {
        DecoyTransformer.transform(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Legacy API tests (backward compatibility)
    #[test]
    fn test_encoding_mutation() {
        let original = "SELECT";
        let mutated = PayloadMutator::apply_encoding_mutation(original);
        assert_ne!(original, mutated);
        assert_eq!(mutated, "select");
    }

    #[test]
    fn test_case_mutation() {
        let original = "test";
        let mutated = PayloadMutator::case_mutate(original);
        assert_eq!(mutated, "TeStT".chars().take(4).collect::<String>());
    }

    #[test]
    fn test_parameter_pollution() {
        let original = "test";
        let mutated = PayloadMutator::apply_parameter_pollution(original);
        assert!(mutated.contains("&_="));
    }

    #[test]
    fn test_parameter_pollution_is_deterministic() {
        let first = PollutionTransformer.transform("same-payload");
        let second = PollutionTransformer.transform("same-payload");
        let different = PollutionTransformer.transform("different-payload");

        assert_eq!(first, second);
        assert_eq!(first, "same-payload&_=105c6f89bedd8768");
        assert_ne!(first, different);
    }

    #[test]
    fn test_mutation_status_blocking() {
        let original = "SELECT * FROM users";
        let mutated =
            PayloadMutator::mutate(original, Some(DetectionPattern::StatusCodeBlocking(403)));
        assert_ne!(original, mutated);
    }

    #[test]
    fn test_mutation_rate_limiting() {
        let original = "test";
        let mutated = PayloadMutator::mutate(original, Some(DetectionPattern::RateLimiting));
        assert!(mutated.contains("&_="));
    }

    #[test]
    fn test_comment_injection() {
        let payload = "test";
        let injected = PayloadMutator::inject_comment(payload);
        assert_eq!(injected, "test/**/");
    }

    #[test]
    fn test_reduce_payload() {
        let payload = "verylongpayload";
        let reduced = PayloadMutator::reduce_payload(payload, 4);
        assert_eq!(reduced, "very");
    }

    #[test]
    fn test_add_decoys() {
        let payload = "test";
        let with_decoys = PayloadMutator::add_decoys(payload);
        assert!(with_decoys.contains("&x=1"));
    }

    // ═════════════════════════════════════════════════════════════════════
    // TRAIT-BASED TESTS (P1 - Plugin Interface)
    // ═════════════════════════════════════════════════════════════════════

    #[test]
    fn test_encoding_transformer_trait() {
        let transformer = EncodingTransformer;
        let original = "SELECT";
        let transformed = transformer.transform(original);
        assert_eq!(transformed, "select");
        assert_eq!(transformer.name(), "encoding");
    }

    #[test]
    fn test_case_transformer_trait() {
        let transformer = CaseTransformer;
        let original = "test";
        let transformed = transformer.transform(original);
        assert_ne!(original, transformed);
        assert_eq!(transformer.name(), "case");
    }

    #[test]
    fn test_pollution_transformer_trait() {
        let transformer = PollutionTransformer;
        let original = "test";
        let transformed = transformer.transform(original);
        assert!(transformed.contains("&_="));
        assert_eq!(transformer.name(), "pollution");
    }

    #[test]
    fn test_comment_transformer_trait() {
        let transformer = CommentTransformer;
        let original = "test";
        let transformed = transformer.transform(original);
        assert_eq!(transformed, "test/**/");
        assert_eq!(transformer.name(), "comment");
    }

    #[test]
    fn test_decoy_transformer_trait() {
        let transformer = DecoyTransformer;
        let original = "test";
        let transformed = transformer.transform(original);
        assert!(transformed.contains("&x=1"));
        assert_eq!(transformer.name(), "decoy");
    }

    #[test]
    fn test_reduction_transformer_trait() {
        let transformer = ReductionTransformer { max_size: 5 };
        let original = "verylongpayload";
        let transformed = transformer.transform(original);
        assert_eq!(transformed, "veryl");
        assert_eq!(transformer.name(), "reduction");
    }

    #[test]
    fn test_reduction_respects_utf8_boundaries() {
        let payload = "éclair";

        assert_eq!(ReductionTransformer { max_size: 0 }.transform(payload), "");
        assert_eq!(ReductionTransformer { max_size: 1 }.transform(payload), "");
        assert_eq!(ReductionTransformer { max_size: 2 }.transform(payload), "é");
        assert_eq!(
            ReductionTransformer { max_size: 3 }.transform(payload),
            "éc"
        );
    }

    #[test]
    fn test_transformer_safe_with_hooks() {
        let transformer = EncodingTransformer;
        let original = "TEST";
        let result = transformer.transform_safe(original);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test");
    }

    #[test]
    fn test_custom_transformer_plugin() {
        // Example of a custom plugin (P1 - User can implement)
        struct UppercaseTransformer;

        impl PayloadTransformer for UppercaseTransformer {
            fn name(&self) -> &str {
                "uppercase_plugin"
            }

            fn transform(&self, payload: &str) -> String {
                payload.to_uppercase()
            }
        }

        let transformer = UppercaseTransformer;
        let original = "test";
        let transformed = transformer.transform(original);
        assert_eq!(transformed, "TEST");
        assert_eq!(transformer.name(), "uppercase_plugin");
    }

    #[test]
    fn test_composite_transformer_chain() {
        // Chain multiple transformers
        let transformers: Vec<Box<dyn PayloadTransformer>> =
            vec![Box::new(EncodingTransformer), Box::new(CommentTransformer)];

        let composite = CompositeTransformer::new(transformers);
        let original = "SELECT";
        let transformed = composite.transform(original);

        // Should be: SELECT → select → select/**/
        assert_eq!(transformed, "select/**/");
    }

    #[test]
    fn test_composite_transformer_multiple_chains() {
        // Test with 3 transformations
        let transformers: Vec<Box<dyn PayloadTransformer>> = vec![
            Box::new(EncodingTransformer),
            Box::new(DecoyTransformer),
            Box::new(CommentTransformer),
        ];

        let composite = CompositeTransformer::new(transformers);
        let original = "XSS";
        let transformed = composite.transform(original);

        // Check all transformations applied
        assert!(transformed.contains("&x=1")); // Decoy added
        assert!(transformed.contains("/**/")); // Comment added
        assert!(!transformed.contains("X")); // Encoding applied (no uppercase)
    }

    #[test]
    fn test_transformer_dyn_dispatch() {
        // Test polymorphism (P1 - core plugin feature)
        let transformers: Vec<Box<dyn PayloadTransformer>> = vec![
            Box::new(EncodingTransformer),
            Box::new(CaseTransformer),
            Box::new(PollutionTransformer),
            Box::new(CommentTransformer),
            Box::new(DecoyTransformer),
            Box::new(ReductionTransformer { max_size: 100 }),
        ];

        let payload = "test";
        for transformer in transformers {
            let result = transformer.transform(payload);
            assert!(!result.is_empty());
            assert_ne!(transformer.name(), "");
        }
    }

    #[test]
    fn test_composite_add_runtime() {
        // P1 - Build composite at runtime
        let mut composite = CompositeTransformer::new(vec![]);

        composite.add(Box::new(EncodingTransformer));
        composite.add(Box::new(CommentTransformer));

        let original = "SELECT";
        let transformed = composite.transform(original);
        assert_eq!(transformed, "select/**/");
    }

    #[test]
    fn test_composite_safe_transform_runs_each_child_hook_in_order() {
        use std::sync::{Arc, Mutex};

        struct HookTransformer {
            id: &'static str,
            events: Arc<Mutex<Vec<String>>>,
        }

        impl PayloadTransformer for HookTransformer {
            fn name(&self) -> &str {
                self.id
            }

            fn pre_transform(&self, payload: &str) -> Result<(), String> {
                self.events
                    .lock()
                    .unwrap()
                    .push(format!("pre:{}:{payload}", self.id));
                Ok(())
            }

            fn transform(&self, payload: &str) -> String {
                self.events
                    .lock()
                    .unwrap()
                    .push(format!("transform:{}:{payload}", self.id));
                format!("{payload}{}", self.id)
            }

            fn post_transform(&self, payload: &str) -> Result<(), String> {
                self.events
                    .lock()
                    .unwrap()
                    .push(format!("post:{}:{payload}", self.id));
                Ok(())
            }
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let composite = CompositeTransformer::new(vec![
            Box::new(HookTransformer {
                id: "a",
                events: events.clone(),
            }),
            Box::new(HookTransformer {
                id: "b",
                events: events.clone(),
            }),
        ]);

        assert_eq!(composite.transform_safe("seed").unwrap(), "seedab");
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "pre:a:seed",
                "transform:a:seed",
                "post:a:seeda",
                "pre:b:seeda",
                "transform:b:seeda",
                "post:b:seedab",
            ]
        );
    }
}
