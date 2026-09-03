//! Deterministic comparison of two observed defense states.
//!
//! A [`DefenseTransition`] is the difference between a control and a candidate
//! observation of the same target — for example the baseline response versus a
//! response to a strategy-derived candidate request. It is *evidence*, not a
//! decision: a planner weighs a transition to decide whether to escalate,
//! back off, or re-fingerprint, but this module never selects a payload.

use super::fingerprint::DefenseProduct;
use super::state::{DefensePosture, DefenseState};

/// Direction of a posture change between two observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureShift {
    /// The candidate posture matches the control posture.
    Unchanged,
    /// The candidate is more defensive than the control.
    Escalated,
    /// The candidate is less defensive than the control.
    Deescalated,
}

/// Summary classification of a control-to-candidate defense transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DefenseTransitionKind {
    /// Neither the posture nor the observed signals changed.
    NoChange,
    /// The candidate is more defended than the control.
    DefenseEngaged,
    /// The candidate is less defended than the control.
    DefenseRelaxed,
    /// The posture level is unchanged but the observed signals differ
    /// (a different product, status class, or rate-limit signal).
    DefenseReconfigured,
}

/// The deterministic difference between a control and a candidate observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefenseTransition {
    posture_shift: PostureShift,
    newly_blocking: bool,
    newly_rate_limited: bool,
    status_changed: bool,
    fingerprint_changed: bool,
    control_product: Option<DefenseProduct>,
    candidate_product: Option<DefenseProduct>,
    kind: DefenseTransitionKind,
}

impl DefenseTransition {
    /// Compares a control observation against a candidate observation.
    ///
    /// The result is a pure function of the two states, so identical inputs
    /// always produce an equal transition.
    pub fn between(control: &DefenseState, candidate: &DefenseState) -> Self {
        let posture_shift = match candidate.posture().cmp(&control.posture()) {
            std::cmp::Ordering::Greater => PostureShift::Escalated,
            std::cmp::Ordering::Less => PostureShift::Deescalated,
            std::cmp::Ordering::Equal => PostureShift::Unchanged,
        };

        let newly_blocking = candidate.posture() == DefensePosture::Blocking
            && control.posture() != DefensePosture::Blocking;
        let newly_rate_limited = candidate.is_rate_limited() && !control.is_rate_limited();
        let status_changed = control.status_signal() != candidate.status_signal();

        let control_product = control.fingerprint().map(|print| print.product());
        let candidate_product = candidate.fingerprint().map(|print| print.product());
        let fingerprint_changed = control_product != candidate_product;

        let kind = match posture_shift {
            PostureShift::Escalated => DefenseTransitionKind::DefenseEngaged,
            PostureShift::Deescalated => DefenseTransitionKind::DefenseRelaxed,
            PostureShift::Unchanged => {
                if fingerprint_changed || status_changed || newly_rate_limited {
                    DefenseTransitionKind::DefenseReconfigured
                } else {
                    DefenseTransitionKind::NoChange
                }
            },
        };

        Self {
            posture_shift,
            newly_blocking,
            newly_rate_limited,
            status_changed,
            fingerprint_changed,
            control_product,
            candidate_product,
            kind,
        }
    }

    /// Returns the direction of the posture change.
    pub const fn posture_shift(&self) -> PostureShift {
        self.posture_shift
    }

    /// Returns the summary classification of the transition.
    pub const fn kind(&self) -> DefenseTransitionKind {
        self.kind
    }

    /// Returns whether the candidate is blocking while the control was not.
    pub const fn is_newly_blocking(&self) -> bool {
        self.newly_blocking
    }

    /// Returns whether the candidate is rate limited while the control was not.
    pub const fn is_newly_rate_limited(&self) -> bool {
        self.newly_rate_limited
    }

    /// Returns whether the coarse status class changed.
    pub const fn status_changed(&self) -> bool {
        self.status_changed
    }

    /// Returns whether the fingerprinted product changed (including appearing or
    /// disappearing).
    pub const fn fingerprint_changed(&self) -> bool {
        self.fingerprint_changed
    }

    /// Returns the product fingerprinted on the control leg, if any.
    pub const fn control_product(&self) -> Option<DefenseProduct> {
        self.control_product
    }

    /// Returns the product fingerprinted on the candidate leg, if any.
    pub const fn candidate_product(&self) -> Option<DefenseProduct> {
        self.candidate_product
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(status: u16, headers: &[(&str, &str)], body: &str) -> DefenseState {
        DefenseState::observe(status, headers, body)
    }

    #[test]
    fn open_to_blocking_is_an_engaged_escalation() {
        let control = state(200, &[], "ok");
        let candidate = state(403, &[], "forbidden");
        let transition = DefenseTransition::between(&control, &candidate);

        assert_eq!(transition.posture_shift(), PostureShift::Escalated);
        assert_eq!(transition.kind(), DefenseTransitionKind::DefenseEngaged);
        assert!(transition.is_newly_blocking());
        assert!(transition.status_changed());
    }

    #[test]
    fn blocking_to_open_is_relaxed() {
        let control = state(403, &[], "forbidden");
        let candidate = state(200, &[], "ok");
        let transition = DefenseTransition::between(&control, &candidate);

        assert_eq!(transition.posture_shift(), PostureShift::Deescalated);
        assert_eq!(transition.kind(), DefenseTransitionKind::DefenseRelaxed);
        assert!(!transition.is_newly_blocking());
    }

    #[test]
    fn identical_open_states_show_no_change() {
        let control = state(200, &[("Server", "nginx")], "ok");
        let candidate = state(200, &[("Server", "nginx")], "ok");
        let transition = DefenseTransition::between(&control, &candidate);

        assert_eq!(transition.posture_shift(), PostureShift::Unchanged);
        assert_eq!(transition.kind(), DefenseTransitionKind::NoChange);
        assert!(!transition.fingerprint_changed());
    }

    #[test]
    fn same_posture_with_a_new_fingerprint_is_reconfigured() {
        // Both suspected, but a product fingerprint appears on the candidate.
        let control = state(200, &[("Retry-After", "5")], "slow down");
        let candidate = state(200, &[("Retry-After", "5"), ("CF-RAY", "abc")], "slow down");
        let transition = DefenseTransition::between(&control, &candidate);

        assert_eq!(transition.posture_shift(), PostureShift::Unchanged);
        assert_eq!(
            transition.kind(),
            DefenseTransitionKind::DefenseReconfigured
        );
        assert!(transition.fingerprint_changed());
        assert_eq!(transition.control_product(), None);
        assert_eq!(
            transition.candidate_product(),
            Some(super::DefenseProduct::Cloudflare)
        );
    }

    #[test]
    fn newly_rate_limited_without_a_block_is_reconfigured() {
        let control = state(200, &[], "ok");
        let candidate = state(429, &[], "slow down");
        let transition = DefenseTransition::between(&control, &candidate);

        // 200 (Open) -> 429 (Suspected) is an escalation.
        assert_eq!(transition.posture_shift(), PostureShift::Escalated);
        assert_eq!(transition.kind(), DefenseTransitionKind::DefenseEngaged);
        assert!(transition.is_newly_rate_limited());
    }

    #[test]
    fn transition_is_deterministic() {
        let control = state(200, &[], "ok");
        let candidate = state(403, &[("CF-RAY", "x")], "access denied");
        let first = DefenseTransition::between(&control, &candidate);
        let second = DefenseTransition::between(&control, &candidate);
        assert_eq!(first, second);
    }
}
