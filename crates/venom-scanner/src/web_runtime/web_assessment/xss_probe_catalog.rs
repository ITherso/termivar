//! Closed metadata-first catalog for bounded structural XSS review.
//!
//! Catalog breadth is deliberately independent from network breadth. Selection
//! happens before payload materialization and admits at most one exact-context
//! family for a complete assessment in V1.

use std::collections::BTreeSet;

use super::ExactHtmlReflectionContext;

pub(in crate::web_runtime) const XSS_V1_MAX_SELECTED_FAMILIES: usize = 1;
/// One shared-authority child bootstrap plus one control/candidate action.
pub(in crate::web_runtime) const XSS_V1_MAX_TOTAL_REQUESTS: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum XssProbeFamily {
    HtmlTextBoundary,
    UriAttributeStructure,
    EventHandlerStructure,
    ScriptContentStructure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum XssStructuralEvidenceExpectation {
    CandidateSpecificParserBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum XssMaximumDisposition {
    NeedsReview,
}

impl XssProbeFamily {
    pub(in crate::web_runtime) const fn all() -> [Self; 4] {
        [
            Self::HtmlTextBoundary,
            Self::UriAttributeStructure,
            Self::EventHandlerStructure,
            Self::ScriptContentStructure,
        ]
    }

    pub(in crate::web_runtime) const fn stable_id(self) -> &'static str {
        match self {
            Self::HtmlTextBoundary => "web.review.xss.family.html-text-boundary@1",
            Self::UriAttributeStructure => "web.review.xss.family.uri-attribute-structure@1",
            Self::EventHandlerStructure => "web.review.xss.family.event-handler-structure@1",
            Self::ScriptContentStructure => "web.review.xss.family.script-content-structure@1",
        }
    }

    pub(in crate::web_runtime) const fn revision(self) -> u32 {
        let _ = self;
        1
    }

    pub(in crate::web_runtime) const fn seed_code(self) -> &'static str {
        match self {
            Self::HtmlTextBoundary => "html",
            Self::UriAttributeStructure => "uri",
            Self::EventHandlerStructure => "handler",
            Self::ScriptContentStructure => "script",
        }
    }

    /// Stable normalized wire-shape identity used before materialization.
    pub(in crate::web_runtime) const fn candidate_shape_id(self) -> &'static str {
        match self {
            Self::HtmlTextBoundary => "html-custom-element-boundary@1",
            Self::UriAttributeStructure => "relative-uri-component-structure@1",
            Self::EventHandlerStructure => "javascript-block-comment-handler@1",
            Self::ScriptContentStructure => "javascript-block-comment-script@1",
        }
    }

    pub(in crate::web_runtime) const fn compatible_context(self) -> ExactHtmlReflectionContext {
        match self {
            Self::HtmlTextBoundary => ExactHtmlReflectionContext::HtmlText,
            Self::UriAttributeStructure => ExactHtmlReflectionContext::UriAttribute,
            Self::EventHandlerStructure => ExactHtmlReflectionContext::EventHandlerAttribute,
            Self::ScriptContentStructure => ExactHtmlReflectionContext::ScriptElementContent,
        }
    }

    /// Metadata-only priority. Higher specificity wins; ties use stable ID.
    pub(in crate::web_runtime) const fn priority(self) -> u16 {
        match self {
            Self::EventHandlerStructure | Self::ScriptContentStructure => 400,
            Self::UriAttributeStructure => 300,
            Self::HtmlTextBoundary => 200,
        }
    }

    pub(in crate::web_runtime) const fn request_cost(self) -> u8 {
        let _ = self;
        2
    }

    pub(in crate::web_runtime) const fn operational_risk_basis_points(self) -> u16 {
        let _ = self;
        700
    }

    pub(in crate::web_runtime) const fn expected_evidence(
        self,
    ) -> XssStructuralEvidenceExpectation {
        let _ = self;
        XssStructuralEvidenceExpectation::CandidateSpecificParserBoundary
    }

    pub(in crate::web_runtime) const fn maximum_disposition(self) -> XssMaximumDisposition {
        let _ = self;
        XssMaximumDisposition::NeedsReview
    }

    const fn selection_score(self) -> u16 {
        self.priority()
            .saturating_sub(self.operational_risk_basis_points() / 100)
            .saturating_sub(self.request_cost() as u16)
    }

    pub(in crate::web_runtime) const fn replay_required(self) -> bool {
        let _ = self;
        false
    }
}

/// Selects a deterministic, duplicate-free executable subset without creating
/// payload bytes. An unsupported or incomplete context produces no action.
pub(in crate::web_runtime) fn select_xss_probe_families(
    context: ExactHtmlReflectionContext,
) -> Vec<XssProbeFamily> {
    let mut compatible = XssProbeFamily::all()
        .into_iter()
        .filter(|family| {
            family.compatible_context() == context
                && family.revision() == 1
                && family.request_cost() <= 2
                && family.request_cost().saturating_add(1) <= XSS_V1_MAX_TOTAL_REQUESTS
                && !family.replay_required()
                && family.operational_risk_basis_points() <= 1_000
                && family.maximum_disposition() == XssMaximumDisposition::NeedsReview
                && family.expected_evidence()
                    == XssStructuralEvidenceExpectation::CandidateSpecificParserBoundary
        })
        .collect::<Vec<_>>();
    compatible.sort_by(|left, right| {
        right
            .selection_score()
            .cmp(&left.selection_score())
            .then_with(|| left.stable_id().cmp(right.stable_id()))
    });
    let mut normalized_candidates = BTreeSet::new();
    compatible
        .into_iter()
        .filter(|family| normalized_candidates.insert((context, family.candidate_shape_id())))
        .take(XSS_V1_MAX_SELECTED_FAMILIES)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_context_compatibility_is_typed_and_closed() {
        let cases = [
            (
                ExactHtmlReflectionContext::HtmlText,
                Some(XssProbeFamily::HtmlTextBoundary),
            ),
            (
                ExactHtmlReflectionContext::UriAttribute,
                Some(XssProbeFamily::UriAttributeStructure),
            ),
            (
                ExactHtmlReflectionContext::EventHandlerAttribute,
                Some(XssProbeFamily::EventHandlerStructure),
            ),
            (
                ExactHtmlReflectionContext::ScriptElementContent,
                Some(XssProbeFamily::ScriptContentStructure),
            ),
            (ExactHtmlReflectionContext::AttributeValue, None),
            (ExactHtmlReflectionContext::HtmlComment, None),
            (ExactHtmlReflectionContext::StyleAttribute, None),
            (ExactHtmlReflectionContext::Incomplete, None),
        ];
        for (context, expected) in cases {
            assert_eq!(
                select_xss_probe_families(context).first().copied(),
                expected
            );
        }
    }

    #[test]
    fn identities_are_versioned_unique_and_request_cost_is_bounded() {
        let mut ids = BTreeSet::new();
        let mut shapes = BTreeSet::new();
        for family in XssProbeFamily::all() {
            assert!(ids.insert(family.stable_id()));
            assert!(shapes.insert(family.candidate_shape_id()));
            assert!(family.stable_id().ends_with("@1"));
            assert_eq!(family.revision(), 1);
            assert_eq!(family.request_cost(), 2);
            assert_eq!(family.request_cost() + 1, XSS_V1_MAX_TOTAL_REQUESTS);
            assert_eq!(family.operational_risk_basis_points(), 700);
            assert_eq!(
                family.maximum_disposition(),
                XssMaximumDisposition::NeedsReview
            );
            assert!(!family.replay_required());
        }
    }

    #[test]
    fn selection_is_deterministic_and_never_expands_with_catalog_breadth() {
        let first = select_xss_probe_families(ExactHtmlReflectionContext::HtmlText);
        assert_eq!(
            first,
            select_xss_probe_families(ExactHtmlReflectionContext::HtmlText)
        );
        assert!(first.len() <= XSS_V1_MAX_SELECTED_FAMILIES);
        for _ in 0..1_000 {
            assert_eq!(
                select_xss_probe_families(ExactHtmlReflectionContext::HtmlText),
                first
            );
        }
    }
}
