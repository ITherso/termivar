//! Deterministic escalation policy over observed defense evidence.
//!
//! This module maps a [`DefenseState`] — and, when available, the
//! [`DefenseTransition`] from a control to a candidate — into a typed
//! [`DefenseResponse`] the planner can act on. It is the single place that turns
//! observation into a *recommendation*, and it deliberately recommends rather
//! than acts: it never selects a payload or an evasion technique. The planner
//! remains responsible for choosing (or not choosing) a strategy.

use super::state::{DefensePosture, DefenseState};
use super::transition::DefenseTransition;

/// Recommended planner reaction to observed defensive behavior.
///
/// Ordering is meaningful: a more restrictive response is greater, so a caller
/// can combine several observations by taking the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DefenseResponse {
    /// No defensive reaction was observed; proceed normally.
    Proceed,
    /// Defensive infrastructure is present but nothing was blocked; proceed and
    /// record the observation.
    Observe,
    /// Rate limiting is in effect; the planner should reduce its request cadence
    /// before continuing.
    Backoff,
    /// The candidate request provoked a block the control did not; the planner
    /// should reconsider its strategy rather than repeat the same request.
    Reconsider,
    /// A standing hard block or challenge; the planner should stop this line.
    Halt,
}

/// Recommends a planner reaction from a single observation and an optional
/// control-to-candidate transition.
///
/// The recommendation is a pure function of its inputs. When a transition shows
/// the candidate was newly blocked while the control was not, the block is
/// attributed to the candidate request and the response is [`Reconsider`];
/// a block present without that attribution is a standing [`Halt`].
///
/// [`Reconsider`]: DefenseResponse::Reconsider
/// [`Halt`]: DefenseResponse::Halt
pub fn recommend(state: &DefenseState, transition: Option<&DefenseTransition>) -> DefenseResponse {
    if transition.is_some_and(DefenseTransition::is_newly_blocking) {
        return DefenseResponse::Reconsider;
    }
    if state.posture() == DefensePosture::Blocking {
        return DefenseResponse::Halt;
    }
    if state.is_rate_limited() {
        return DefenseResponse::Backoff;
    }
    if state.posture() == DefensePosture::Suspected {
        return DefenseResponse::Observe;
    }
    DefenseResponse::Proceed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(status: u16, headers: &[(&str, &str)], body: &str) -> DefenseState {
        DefenseState::observe(status, headers, body)
    }

    #[test]
    fn an_open_response_proceeds() {
        let open = state(200, &[("Server", "nginx")], "ok");
        assert_eq!(recommend(&open, None), DefenseResponse::Proceed);
    }

    #[test]
    fn a_present_but_non_blocking_defense_is_observed() {
        let suspected = state(200, &[("x-amzn-requestid", "id")], "ok");
        assert_eq!(recommend(&suspected, None), DefenseResponse::Observe);
    }

    #[test]
    fn rate_limiting_recommends_backoff() {
        let limited = state(429, &[], "slow down");
        assert_eq!(recommend(&limited, None), DefenseResponse::Backoff);
    }

    #[test]
    fn a_standing_block_halts() {
        let blocked = state(403, &[], "forbidden");
        assert_eq!(recommend(&blocked, None), DefenseResponse::Halt);
    }

    #[test]
    fn a_candidate_provoked_block_is_reconsidered_not_halted() {
        let control = state(200, &[], "ok");
        let candidate = state(403, &[], "forbidden");
        let transition = DefenseTransition::between(&control, &candidate);
        // The block is attributed to the candidate, so the planner should change
        // strategy rather than treat the whole line as blocked.
        assert_eq!(
            recommend(&candidate, Some(&transition)),
            DefenseResponse::Reconsider
        );
    }

    #[test]
    fn a_pre_existing_block_still_halts_even_with_a_transition() {
        let control = state(403, &[], "forbidden");
        let candidate = state(403, &[], "forbidden");
        let transition = DefenseTransition::between(&control, &candidate);
        // Both legs are blocked, so the block is not attributed to the candidate.
        assert_eq!(
            recommend(&candidate, Some(&transition)),
            DefenseResponse::Halt
        );
    }

    #[test]
    fn responses_order_by_restrictiveness() {
        assert!(DefenseResponse::Halt > DefenseResponse::Reconsider);
        assert!(DefenseResponse::Reconsider > DefenseResponse::Backoff);
        assert!(DefenseResponse::Backoff > DefenseResponse::Observe);
        assert!(DefenseResponse::Observe > DefenseResponse::Proceed);
    }

    #[test]
    fn recommendation_is_deterministic() {
        let control = state(200, &[], "ok");
        let candidate = state(403, &[("CF-RAY", "x")], "access denied");
        let transition = DefenseTransition::between(&control, &candidate);
        let first = recommend(&candidate, Some(&transition));
        let second = recommend(&candidate, Some(&transition));
        assert_eq!(first, second);
    }
}
