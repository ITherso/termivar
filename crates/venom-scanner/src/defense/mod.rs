//! Observation-only defensive posture layer.
//!
//! This module turns raw response signals into a typed, bounded observation of a
//! target's defensive behavior — product fingerprints and an overall
//! [`DefenseState`]. It never selects a payload or an evasion technique: that
//! decision belongs to the planner, which consumes these observations. This
//! separation is deliberate, so a defensive-fingerprint change can never silently
//! change attack behavior.
//!
//! The legacy [`crate::waf`] utility remains for backward compatibility. New work
//! should build on this observation layer; payload derivation lives in
//! [`crate::payload_strategies`].

pub mod fingerprint;
pub mod policy;
pub mod projection;
pub mod state;
pub mod transition;

pub use fingerprint::{
    fingerprint, DefenseFingerprint, DefenseProduct, FingerprintConfidence,
    MAX_FINGERPRINT_BODY_SCAN_BYTES,
};
pub use policy::{recommend, DefenseResponse};
pub use projection::{
    project_defense_state, project_defense_transition, project_outcome, DefenseObservationContext,
    ObservedOutcome,
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
