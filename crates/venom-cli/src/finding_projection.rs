//! Typed Finding Projection Contract (first phase — model + fail-closed policy).
//!
//! ## Runtime scope
//!
//! - **Build:** `venom-cli` binary crate.
//! - **Execution:** an internal typed model that projects a
//!   [`DecisionScanSummary`] — the same typed value the `decision-scan` renderers
//!   read — into finding *dispositions*. It never parses rendered text or the JSON
//!   contract.
//! - **Default `venom scan`:** no.
//! - **Support:** first phase. It is **not wired to any CLI output** (no text, no
//!   `decision-scan/v1` JSON, no SARIF) and is retained for its tests only until a
//!   later phase consumes it — hence `#![allow(dead_code)]`.
//!
//! The purpose of this phase is to draw the boundary between *verification* and
//! *reporting*. A conclusive or successful verification is a fact about a
//! detection, not a security finding. This model is **fail-closed**: a record can
//! only be `Reportable` when every independent gate holds, and no gate is ever
//! satisfied by inference. Because no action is currently classified as a
//! reportable vulnerability and no [`FindingKind`] is defined, the initial policy
//! legitimately produces **zero** reportable findings — that is the correct
//! boundary, not a failure.
#![allow(dead_code)]

use crate::decision_scan::DecisionScanSummary;

/// The explicit finding decision for one verification outcome. A plain
/// `reportable: bool` is deliberately avoided so the *reason* for not reporting is
/// never lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FindingDisposition {
    /// Meets every reportability gate. (Unreachable under the initial policy.)
    Reportable,
    /// Could match a finding shape but is withheld by policy.
    Suppressed,
    /// Not a finding at all (e.g. a technology/authentication detection).
    NotAFinding,
    /// A human must decide; never auto-promoted to a finding.
    NeedsHumanReview,
}

/// The kind of security finding a record maps to. **No kinds are defined yet**, so
/// this enum is intentionally uninhabited: `Option<FindingKind>` can only ever be
/// `None`, which keeps the "finding kind mapped" gate fail-closed by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FindingKind {}

/// The verifier-owned resolution of an outcome, independent of reportability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerificationStatus {
    Positive,
    Negative,
    Blocked,
    Inconclusive,
    NeedsReview,
    FalsePositive,
    Other,
}

/// Whether the evidence is sufficient to *report*, not merely to detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceSufficiency {
    Sufficient,
    Insufficient,
    Unknown,
}

/// The final reportability gate result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reportability {
    Reportable,
    NotReportable,
}

/// Why a record was not reported, preserved so the decision is auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FindingSuppressionReason {
    /// The action only detects a technology; a technology is not a vulnerability.
    TechnologyDetectionOnly,
    /// The action only detects an authentication mechanism.
    AuthenticationDetectionOnly,
    /// The action is outside the known catalog; fail-closed to human review.
    UnmappedAction,
    /// The outcome did not conclude; a human must decide.
    InconclusiveOutcome,
    /// The runtime itself requested human review.
    RuntimeRequestedReview,
    /// No finding kind is mapped for this action/status.
    NoReportableFindingKind,
}

/// One finding disposition derived from one verification outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingProjection {
    pub disposition: FindingDisposition,
    pub kind: Option<FindingKind>,
    pub source_action_id: String,
    pub verification_status: VerificationStatus,
    pub evidence_sufficiency: EvidenceSufficiency,
    pub reportability: Reportability,
    pub suppression_reason: Option<FindingSuppressionReason>,
}

/// Semantic class of a planner action for reporting purposes. Every current action
/// is a detection; none is a reportable vulnerability class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionClass {
    TechnologyDetection,
    AuthenticationDetection,
    /// A vulnerability-class action. **No action is classified here yet.**
    Reportable,
    /// Not in the known catalog.
    Unmapped,
}

/// Explicit action classification — no inference. An action id absent from the
/// catalog is `Unmapped` (fail-closed), never assumed benign.
fn classify_action(action_id: &str) -> ActionClass {
    match action_id {
        "web.action.http-basic.auth-boundary"
        | "web.action.http-bearer.auth-boundary"
        | "web.action.sanctum.auth-boundary" => ActionClass::AuthenticationDetection,
        "web.action.laravel.route-discovery"
        | "web.action.laravel.input-analysis"
        | "web.action.livewire.component-discovery"
        | "web.action.nginx.configuration"
        | "web.action.apache.configuration"
        | "web.action.php.input-discovery" => ActionClass::TechnologyDetection,
        // No reportable vulnerability action exists yet.
        _ => ActionClass::Unmapped,
    }
}

/// Maps a stable outcome-status label (the same one the JSON emits) to a typed
/// verification status. Fail-closed: unknown labels become `Other`.
fn verification_status(status: &str) -> VerificationStatus {
    match status {
        "success" => VerificationStatus::Positive,
        "confirmed_negative" => VerificationStatus::Negative,
        "blocked" => VerificationStatus::Blocked,
        "unknown" => VerificationStatus::Inconclusive,
        "needs_review" => VerificationStatus::NeedsReview,
        "false_positive" => VerificationStatus::FalsePositive,
        _ => VerificationStatus::Other,
    }
}

/// Evidence sufficiency for *reporting*. Only a conclusive positive/negative is
/// treated as sufficient; inconclusive/blocked/needs-review are insufficient.
fn evidence_sufficiency(status: VerificationStatus, conclusive: bool) -> EvidenceSufficiency {
    match status {
        VerificationStatus::Positive | VerificationStatus::Negative if conclusive => {
            EvidenceSufficiency::Sufficient
        },
        VerificationStatus::Inconclusive
        | VerificationStatus::NeedsReview
        | VerificationStatus::Blocked => EvidenceSufficiency::Insufficient,
        _ => EvidenceSufficiency::Unknown,
    }
}

/// The finding kind mapped for an (action class, status). **None is defined yet**,
/// so this always returns `None`, keeping the reportability gate fail-closed.
fn finding_kind(_class: ActionClass, _status: VerificationStatus) -> Option<FindingKind> {
    None
}

/// Projects one verification outcome into a finding disposition, fail-closed.
///
/// Reportable requires **every** gate — reportable action class, positive
/// verification, sufficient evidence, and a mapped finding kind — with none
/// satisfied by inference. Everything else is `NotAFinding` (a detection resolved
/// definitively) or `NeedsHumanReview` (inconclusive, runtime-requested review, or
/// an unmapped action).
fn project_outcome(action_id: &str, status: &str, conclusive: bool) -> FindingProjection {
    let verification = verification_status(status);
    let class = classify_action(action_id);
    let sufficiency = evidence_sufficiency(verification, conclusive);
    let kind = finding_kind(class, verification);

    let is_reportable = matches!(class, ActionClass::Reportable)
        && matches!(verification, VerificationStatus::Positive)
        && matches!(sufficiency, EvidenceSufficiency::Sufficient)
        && kind.is_some();

    let (disposition, suppression_reason) = if is_reportable {
        (FindingDisposition::Reportable, None)
    } else if matches!(class, ActionClass::Unmapped) {
        (
            FindingDisposition::NeedsHumanReview,
            Some(FindingSuppressionReason::UnmappedAction),
        )
    } else {
        match verification {
            VerificationStatus::NeedsReview => (
                FindingDisposition::NeedsHumanReview,
                Some(FindingSuppressionReason::RuntimeRequestedReview),
            ),
            VerificationStatus::Inconclusive => (
                FindingDisposition::NeedsHumanReview,
                Some(FindingSuppressionReason::InconclusiveOutcome),
            ),
            _ => {
                let reason = match class {
                    ActionClass::AuthenticationDetection => {
                        FindingSuppressionReason::AuthenticationDetectionOnly
                    },
                    ActionClass::TechnologyDetection => {
                        FindingSuppressionReason::TechnologyDetectionOnly
                    },
                    _ => FindingSuppressionReason::NoReportableFindingKind,
                };
                (FindingDisposition::NotAFinding, Some(reason))
            },
        }
    };

    let reportability = if is_reportable {
        Reportability::Reportable
    } else {
        Reportability::NotReportable
    };

    FindingProjection {
        disposition,
        kind,
        source_action_id: action_id.to_owned(),
        verification_status: verification,
        evidence_sufficiency: sufficiency,
        reportability,
        suppression_reason,
    }
}

/// Projects a full [`DecisionScanSummary`] into per-outcome finding dispositions,
/// in outcome order. Built from the typed summary, never from rendered text or
/// JSON. Under the initial policy this never yields a `Reportable` disposition.
pub(crate) fn project_findings(summary: &DecisionScanSummary) -> Vec<FindingProjection> {
    summary
        .outcomes
        .iter()
        .map(|outcome| project_outcome(&outcome.action_id, outcome.status, outcome.conclusive))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTTP_BASIC: &str = "web.action.http-basic.auth-boundary";
    const LIVEWIRE: &str = "web.action.livewire.component-discovery";
    const ROUTE: &str = "web.action.laravel.route-discovery";

    #[test]
    fn http_basic_success_is_not_a_finding() {
        let p = project_outcome(HTTP_BASIC, "success", true);
        assert_eq!(p.disposition, FindingDisposition::NotAFinding);
        assert_eq!(p.reportability, Reportability::NotReportable);
        assert_eq!(
            p.suppression_reason,
            Some(FindingSuppressionReason::AuthenticationDetectionOnly)
        );
        assert!(p.kind.is_none());
    }

    #[test]
    fn livewire_success_is_not_a_finding() {
        let p = project_outcome(LIVEWIRE, "success", true);
        assert_eq!(p.disposition, FindingDisposition::NotAFinding);
        assert_eq!(p.reportability, Reportability::NotReportable);
        assert_eq!(
            p.suppression_reason,
            Some(FindingSuppressionReason::TechnologyDetectionOnly)
        );
    }

    #[test]
    fn confirmed_negative_is_conclusive_but_not_reportable() {
        let p = project_outcome(HTTP_BASIC, "confirmed_negative", true);
        // Conclusive (a definite negative with sufficient evidence) yet never a finding.
        assert_eq!(p.verification_status, VerificationStatus::Negative);
        assert_eq!(p.evidence_sufficiency, EvidenceSufficiency::Sufficient);
        assert_eq!(p.reportability, Reportability::NotReportable);
        assert_eq!(p.disposition, FindingDisposition::NotAFinding);
    }

    #[test]
    fn blocked_is_not_promoted_to_a_finding() {
        let p = project_outcome(HTTP_BASIC, "blocked", false);
        assert_eq!(p.reportability, Reportability::NotReportable);
        assert_ne!(p.disposition, FindingDisposition::Reportable);
    }

    #[test]
    fn unknown_requires_no_automatic_finding() {
        let p = project_outcome(ROUTE, "unknown", false);
        assert_eq!(p.verification_status, VerificationStatus::Inconclusive);
        assert_eq!(p.reportability, Reportability::NotReportable);
        assert_eq!(p.disposition, FindingDisposition::NeedsHumanReview);
        assert_eq!(
            p.suppression_reason,
            Some(FindingSuppressionReason::InconclusiveOutcome)
        );
    }

    #[test]
    fn needs_review_never_becomes_reportable_automatically() {
        let p = project_outcome(ROUTE, "needs_review", false);
        assert_eq!(p.reportability, Reportability::NotReportable);
        assert_eq!(p.disposition, FindingDisposition::NeedsHumanReview);
    }

    #[test]
    fn unmapped_action_fails_closed() {
        // Even a conclusive "success" on an unknown action never auto-reports.
        let p = project_outcome("web.action.some.future-thing", "success", true);
        assert_eq!(p.reportability, Reportability::NotReportable);
        assert_eq!(p.disposition, FindingDisposition::NeedsHumanReview);
        assert_eq!(
            p.suppression_reason,
            Some(FindingSuppressionReason::UnmappedAction)
        );
    }

    #[test]
    fn no_current_status_ever_projects_a_reportable_finding() {
        // Sweep every documented status against a known detection action: the
        // initial fail-closed policy must never yield Reportable.
        for status in [
            "success",
            "blocked",
            "unknown",
            "false_positive",
            "needs_review",
            "confirmed_negative",
            "other",
        ] {
            let p = project_outcome(HTTP_BASIC, status, true);
            assert_ne!(
                p.disposition,
                FindingDisposition::Reportable,
                "status {status} must not be reportable"
            );
            assert_eq!(p.reportability, Reportability::NotReportable);
        }
    }
}
