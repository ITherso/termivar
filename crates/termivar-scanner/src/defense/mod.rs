//! Observation-only defensive posture layer.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** observation/shadow composition is assessment-only. The
//!   standalone standard runtime remains unchanged; assessment enforcement is
//!   an explicit opt-in and defaults off.
//! - **Default `termivar scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! This module turns raw response signals into a typed, bounded observation of a
//! target's defensive behavior — product fingerprints and an overall
//! [`DefenseState`]. It never selects a payload or an evasion technique: that
//! decision belongs to the planner, which consumes these observations. This
//! separation is deliberate, so a defensive-fingerprint change can never silently
//! change attack behavior.
//!
//! The former legacy WAF detector/evasion utility has been removed. Payload
//! derivation lives behind [`crate::payload_strategies`].

pub mod enforcement;
pub mod fingerprint;
pub mod policy;
pub mod projection;
pub mod shadow_planning;
pub mod state;
pub mod transition;

pub use enforcement::{defense_aware_plan, DefensePlanningPolicy};
pub use fingerprint::{
    fingerprint, DefenseFingerprint, DefenseProduct, FingerprintConfidence,
    MAX_FINGERPRINT_BODY_SCAN_BYTES,
};
pub use policy::{recommend, DefenseResponse};
pub use projection::{
    project_defense_state, project_defense_transition, project_outcome, DefenseObservationContext,
    ObservedOutcome,
};
pub use shadow_planning::{
    decide, defense_aware_shadow_plan, explanation_code, render_explanation,
    DefenseAwareShadowPlan, DefenseInteractionClass, InteractionDecision, PlanAdjustment,
    ResourceDefenseObservation, ResourceDefenseSignal, ShadowPlanDelta, SuppressedAction,
};
pub use state::{DefensePosture, DefenseState, DefenseStatusSignal};
pub use transition::{DefenseTransition, DefenseTransitionKind, PostureShift};

/// Applies the monotonic defense decision table at the assessment-composition
/// boundary. This adapter cannot add actions or increase their intensity.
#[cfg(feature = "scanning")]
pub(crate) fn assessment_interaction_decision(
    response: DefenseResponse,
    class: DefenseInteractionClass,
) -> InteractionDecision {
    shadow_planning::decide(response, class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_layer_reexports_compose() {
        // The re-exported surface is enough to observe a response end to end
        // without reaching into submodules.
        let state = DefenseState::observe(
            403,
            &[("Server", "cloudflare"), ("CF-RAY", "abc")],
            "Attention Required!",
        );
        assert_eq!(state.posture(), DefensePosture::Blocking);
        let print: &DefenseFingerprint = state.fingerprint().unwrap();
        assert_eq!(print.product(), DefenseProduct::Cloudflare);
        assert_eq!(print.confidence(), FingerprintConfidence::Strong);
    }
}
