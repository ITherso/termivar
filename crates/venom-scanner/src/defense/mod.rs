//! Observation-only defensive posture layer.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** host/test only via an explicit API. **Not composed into
//!   `StandardWebDecisionRuntime`**; no production runtime caller exists in the
//!   repository — `tests/defense_aware_planning_demo.rs` exercises it, and
//!   external hosts may integrate projection/shadow/enforcement explicitly.
//! - **Default `venom scan`:** no.
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
