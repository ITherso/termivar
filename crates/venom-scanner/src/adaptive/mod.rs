//! Outcome-driven adaptive execution policy.
//!
//! ## Runtime scope
//!
//! - **Build:** default via `scanning`.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `venom scan`:** yes, through `StandardWebDecisionRuntime`.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The deterministic pipeline maps evidence-backed outcomes to declarative
//! runner directives. It does not score raw responses, infer a defense product,
//! mutate payload bytes, or select attack-shaped transformations.

pub mod pipeline;

pub use pipeline::{
    AdaptationLedger, AdaptationLimits, AdaptationRule, AdaptationRuleEvaluation, AdaptiveDecision,
    AdaptivePipeline, AdaptivePipelineError, AdaptiveRuleWrite, OutcomeSelector, PipelineDirective,
};
