//! Closed metadata-first catalog for bounded structural XSS review.
//!
//! Catalog breadth is deliberately independent from network breadth. Selection
//! happens before payload materialization and admits at most one exact-context
//! family for a complete assessment in V1.

use std::{collections::BTreeSet, fmt};

use super::{
    attribute_source_context::{
        AttributeQuoteMode, AttributeReflectionAnchor, AttributeSourceResult,
    },
    ExactHtmlReflectionContext,
};
use crate::web_actions::NativeWebReviewActionKind;

pub(in crate::web_runtime) const XSS_V1_MAX_SELECTED_FAMILIES: usize = 1;
/// One shared-authority child bootstrap plus one control/candidate action.
pub(in crate::web_runtime) const XSS_V1_MAX_TOTAL_REQUESTS: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum XssProbeFamily {
    HtmlTextBoundary,
    AttributeValueBoundary,
    UriAttributeBoundary,
    EventHandlerAttributeBoundary,
    UriAttributeStructure,
    EventHandlerStructure,
    ScriptContentStructure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum XssStructuralEvidenceExpectation {
    CandidateSpecificParserBoundary,
}

/// Evidence capability required before a catalog family can become network
/// work. Catalog membership deliberately does not imply V1 executability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum XssEvidenceCapability {
    /// The bounded HTML parser can prove one exact scanner-owned node boundary.
    ExactHtmlNodeBoundary,
    /// Source quote evidence plus the bounded DOM can prove two exact inert
    /// scanner-owned attributes on the expected host element and sink.
    ExactHtmlAttributeBoundary,
    /// Exact source quote state is required and is not retained by the DOM.
    AttributeSourceQuoteMode,
    /// A stronger script-boundary candidate/evidence contract is not in V1.
    ScriptBoundaryTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web_runtime) enum XssMaximumDisposition {
    NeedsReview,
}

impl XssProbeFamily {
    pub(in crate::web_runtime) const fn all() -> [Self; 7] {
        [
            Self::HtmlTextBoundary,
            Self::AttributeValueBoundary,
            Self::UriAttributeBoundary,
            Self::EventHandlerAttributeBoundary,
            Self::UriAttributeStructure,
            Self::EventHandlerStructure,
            Self::ScriptContentStructure,
        ]
    }

    pub(in crate::web_runtime) const fn stable_id(self) -> &'static str {
        match self {
            Self::HtmlTextBoundary => "web.review.xss.family.html-text-boundary@1",
            Self::AttributeValueBoundary => "web.review.xss.family.attribute-value-boundary@1",
            Self::UriAttributeBoundary => "web.review.xss.family.uri-attribute-boundary@1",
            Self::EventHandlerAttributeBoundary => {
                "web.review.xss.family.event-handler-attribute-boundary@1"
            },
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
            Self::AttributeValueBoundary => "attribute",
            Self::UriAttributeBoundary => "uri",
            Self::EventHandlerAttributeBoundary => "handler",
            Self::UriAttributeStructure => "uri",
            Self::EventHandlerStructure => "handler",
            Self::ScriptContentStructure => "script",
        }
    }

    /// Stable normalized wire-shape identity used before materialization.
    pub(in crate::web_runtime) const fn candidate_shape_id(self) -> &'static str {
        match self {
            Self::HtmlTextBoundary => "html-inert-element-boundary@1",
            Self::AttributeValueBoundary => "ordinary-inert-attribute-boundary@1",
            Self::UriAttributeBoundary => "uri-inert-attribute-boundary@1",
            Self::EventHandlerAttributeBoundary => "handler-inert-attribute-boundary@1",
            Self::UriAttributeStructure => "relative-uri-component-structure@1",
            Self::EventHandlerStructure => "javascript-block-comment-handler@1",
            Self::ScriptContentStructure => "javascript-block-comment-script@1",
        }
    }

    pub(in crate::web_runtime) const fn compatible_context(self) -> ExactHtmlReflectionContext {
        match self {
            Self::HtmlTextBoundary => ExactHtmlReflectionContext::HtmlText,
            Self::AttributeValueBoundary => ExactHtmlReflectionContext::AttributeValue,
            Self::UriAttributeBoundary | Self::UriAttributeStructure => {
                ExactHtmlReflectionContext::UriAttribute
            },
            Self::EventHandlerAttributeBoundary | Self::EventHandlerStructure => {
                ExactHtmlReflectionContext::EventHandlerAttribute
            },
            Self::ScriptContentStructure => ExactHtmlReflectionContext::ScriptElementContent,
        }
    }

    /// Metadata-only priority. Higher specificity wins; ties use stable ID.
    pub(in crate::web_runtime) const fn priority(self) -> u16 {
        match self {
            Self::EventHandlerAttributeBoundary => 600,
            Self::UriAttributeBoundary => 500,
            Self::AttributeValueBoundary => 450,
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

    pub(in crate::web_runtime) const fn evidence_capability(self) -> XssEvidenceCapability {
        match self {
            Self::HtmlTextBoundary => XssEvidenceCapability::ExactHtmlNodeBoundary,
            Self::AttributeValueBoundary
            | Self::UriAttributeBoundary
            | Self::EventHandlerAttributeBoundary => {
                XssEvidenceCapability::ExactHtmlAttributeBoundary
            },
            Self::UriAttributeStructure | Self::EventHandlerStructure => {
                XssEvidenceCapability::AttributeSourceQuoteMode
            },
            Self::ScriptContentStructure => XssEvidenceCapability::ScriptBoundaryTransition,
        }
    }

    /// V1 executes only families whose success can be proven by the currently
    /// committed bounded parser evidence. Metadata-only families remain closed,
    /// versioned extension points and create no request obligation.
    pub(in crate::web_runtime) const fn is_v1_executable(self) -> bool {
        matches!(
            self.evidence_capability(),
            XssEvidenceCapability::ExactHtmlNodeBoundary
                | XssEvidenceCapability::ExactHtmlAttributeBoundary
        )
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

/// One metadata-selected executable family and its optional exact source
/// anchor. Payload materialization occurs only after this value is selected.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct XssProbeSelection {
    family: XssProbeFamily,
    attribute_anchor: Option<AttributeReflectionAnchor>,
}

impl XssProbeSelection {
    pub(in crate::web_runtime) const fn family(&self) -> XssProbeFamily {
        self.family
    }

    pub(in crate::web_runtime) const fn attribute_anchor(
        &self,
    ) -> Option<&AttributeReflectionAnchor> {
        self.attribute_anchor.as_ref()
    }

    pub(in crate::web_runtime) const fn quote_mode(&self) -> Option<AttributeQuoteMode> {
        match &self.attribute_anchor {
            Some(anchor) => Some(anchor.quote_mode()),
            None => None,
        }
    }

    /// Stable non-secret family/quote evidence identity. Candidate byte
    /// changes require a new strategy revision rather than changing this ID.
    pub(in crate::web_runtime) const fn variant_id(&self) -> &'static str {
        match (self.family, self.quote_mode()) {
            (XssProbeFamily::HtmlTextBoundary, None) => {
                "web.review.xss.variant.html-text-boundary@1"
            },
            (XssProbeFamily::AttributeValueBoundary, Some(AttributeQuoteMode::DoubleQuoted)) => {
                "web.review.xss.variant.attribute-value.double-quoted@1"
            },
            (XssProbeFamily::AttributeValueBoundary, Some(AttributeQuoteMode::SingleQuoted)) => {
                "web.review.xss.variant.attribute-value.single-quoted@1"
            },
            (XssProbeFamily::AttributeValueBoundary, Some(AttributeQuoteMode::Unquoted)) => {
                "web.review.xss.variant.attribute-value.unquoted@1"
            },
            (XssProbeFamily::UriAttributeBoundary, Some(AttributeQuoteMode::DoubleQuoted)) => {
                "web.review.xss.variant.uri-attribute.double-quoted@1"
            },
            (XssProbeFamily::UriAttributeBoundary, Some(AttributeQuoteMode::SingleQuoted)) => {
                "web.review.xss.variant.uri-attribute.single-quoted@1"
            },
            (XssProbeFamily::UriAttributeBoundary, Some(AttributeQuoteMode::Unquoted)) => {
                "web.review.xss.variant.uri-attribute.unquoted@1"
            },
            (
                XssProbeFamily::EventHandlerAttributeBoundary,
                Some(AttributeQuoteMode::DoubleQuoted),
            ) => "web.review.xss.variant.event-handler.double-quoted@1",
            (
                XssProbeFamily::EventHandlerAttributeBoundary,
                Some(AttributeQuoteMode::SingleQuoted),
            ) => "web.review.xss.variant.event-handler.single-quoted@1",
            (XssProbeFamily::EventHandlerAttributeBoundary, Some(AttributeQuoteMode::Unquoted)) => {
                "web.review.xss.variant.event-handler.unquoted@1"
            },
            _ => "web.review.xss.variant.unsupported@1",
        }
    }

    pub(in crate::web_runtime) const fn action_kind(&self) -> NativeWebReviewActionKind {
        match self.family {
            XssProbeFamily::HtmlTextBoundary => NativeWebReviewActionKind::XssStructuralQueryPair,
            XssProbeFamily::AttributeValueBoundary
            | XssProbeFamily::UriAttributeBoundary
            | XssProbeFamily::EventHandlerAttributeBoundary => {
                NativeWebReviewActionKind::XssAttributeBoundaryQueryPair
            },
            XssProbeFamily::UriAttributeStructure
            | XssProbeFamily::EventHandlerStructure
            | XssProbeFamily::ScriptContentStructure => {
                NativeWebReviewActionKind::XssStructuralQueryPair
            },
        }
    }

    pub(in crate::web_runtime) fn strategy_seed(&self, identity: &str) -> String {
        match self.quote_mode() {
            Some(quote_mode) => format!(
                "{}:{}:{identity}",
                self.family.seed_code(),
                quote_mode.stable_id()
            ),
            None => format!("{}:{identity}", self.family.seed_code()),
        }
    }
}

impl fmt::Debug for XssProbeSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XssProbeSelection")
            .field("family", &self.family.stable_id())
            .field("quote_mode", &self.quote_mode())
            .field(
                "attribute_anchor",
                &self.attribute_anchor.as_ref().map(|_| "<bounded-anchor>"),
            )
            .finish()
    }
}

/// Selects a deterministic, duplicate-free executable subset without creating
/// payload bytes. An unsupported or incomplete context produces no action.
pub(in crate::web_runtime) fn select_xss_probe_families(
    context: ExactHtmlReflectionContext,
    attribute_source: &AttributeSourceResult,
) -> Vec<XssProbeSelection> {
    let exact_anchor = attribute_source.exact_anchor();
    let mut compatible = XssProbeFamily::all()
        .into_iter()
        .filter(|family| {
            family.is_v1_executable()
                && family.compatible_context() == context
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
        .filter_map(|family| {
            let attribute_anchor = match family.evidence_capability() {
                XssEvidenceCapability::ExactHtmlNodeBoundary => None,
                XssEvidenceCapability::ExactHtmlAttributeBoundary => {
                    let anchor = exact_anchor?.clone();
                    if anchor.context() != context {
                        return None;
                    }
                    Some(anchor)
                },
                XssEvidenceCapability::AttributeSourceQuoteMode
                | XssEvidenceCapability::ScriptBoundaryTransition => return None,
            };
            let quote_id = attribute_anchor
                .as_ref()
                .map_or("none", |anchor| anchor.quote_mode().stable_id());
            normalized_candidates
                .insert((context, family.candidate_shape_id(), quote_id))
                .then_some(XssProbeSelection {
                    family,
                    attribute_anchor,
                })
        })
        .take(XSS_V1_MAX_SELECTED_FAMILIES)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::{
        classify_exact_html_reflection, cross_validate_attribute_reflection_source,
    };

    const MARKER: &str = "venom-reflection-candidate-0123456789abcdef-end";
    const IDENTITY: &str = "0123456789abcdef0123456789abcdef";

    fn exact_attribute_source(
        element: &str,
        attribute: &str,
        quote_mode: AttributeQuoteMode,
    ) -> (ExactHtmlReflectionContext, AttributeSourceResult) {
        let value = match quote_mode {
            AttributeQuoteMode::DoubleQuoted => format!("\"{MARKER}\""),
            AttributeQuoteMode::SingleQuoted => format!("'{MARKER}'"),
            AttributeQuoteMode::Unquoted => MARKER.to_owned(),
        };
        let html = format!("<{element} {attribute}={value}></{element}>");
        let context = classify_exact_html_reflection(&html, MARKER);
        let source = cross_validate_attribute_reflection_source(&html, MARKER, context);
        assert!(matches!(
            &source,
            AttributeSourceResult::ExactAttributeAnchor(_)
        ));
        (context, source)
    }

    #[test]
    fn exact_context_compatibility_is_typed_and_closed() {
        let cases = [
            (
                ExactHtmlReflectionContext::HtmlText,
                Some(XssProbeFamily::HtmlTextBoundary),
            ),
            (ExactHtmlReflectionContext::UriAttribute, None),
            (ExactHtmlReflectionContext::EventHandlerAttribute, None),
            (ExactHtmlReflectionContext::ScriptElementContent, None),
            (ExactHtmlReflectionContext::AttributeValue, None),
            (ExactHtmlReflectionContext::HtmlComment, None),
            (ExactHtmlReflectionContext::StyleAttribute, None),
            (ExactHtmlReflectionContext::Incomplete, None),
        ];
        for (context, expected) in cases {
            let selected = select_xss_probe_families(context, &AttributeSourceResult::Absent);
            assert_eq!(selected.first().map(XssProbeSelection::family), expected);
            assert!(selected
                .first()
                .is_none_or(|selection| selection.attribute_anchor().is_none()));
        }
    }

    #[test]
    fn exact_source_anchor_selects_each_attribute_family_in_each_quote_mode() {
        let mut variant_ids = BTreeSet::new();
        for (element, attribute, expected_context, expected_family) in [
            (
                "div",
                "title",
                ExactHtmlReflectionContext::AttributeValue,
                XssProbeFamily::AttributeValueBoundary,
            ),
            (
                "a",
                "href",
                ExactHtmlReflectionContext::UriAttribute,
                XssProbeFamily::UriAttributeBoundary,
            ),
            (
                "button",
                "onclick",
                ExactHtmlReflectionContext::EventHandlerAttribute,
                XssProbeFamily::EventHandlerAttributeBoundary,
            ),
        ] {
            for quote_mode in [
                AttributeQuoteMode::DoubleQuoted,
                AttributeQuoteMode::SingleQuoted,
                AttributeQuoteMode::Unquoted,
            ] {
                let (context, source) = exact_attribute_source(element, attribute, quote_mode);
                assert_eq!(context, expected_context);

                let selected = select_xss_probe_families(context, &source);
                assert_eq!(selected.len(), 1);
                let selection = &selected[0];
                assert_eq!(selection.family(), expected_family);
                assert_eq!(selection.quote_mode(), Some(quote_mode));
                assert!(selection.variant_id().ends_with("@1"));
                assert!(variant_ids.insert(selection.variant_id()));
                assert_eq!(
                    selection.action_kind(),
                    NativeWebReviewActionKind::XssAttributeBoundaryQueryPair
                );
                assert_eq!(
                    selection.strategy_seed(IDENTITY),
                    format!(
                        "{}:{}:{IDENTITY}",
                        expected_family.seed_code(),
                        quote_mode.stable_id()
                    )
                );
                let anchor = selection.attribute_anchor().unwrap();
                assert_eq!(anchor.element_local_name(), element);
                assert_eq!(anchor.attribute_local_name(), attribute);
                assert_eq!(anchor.context(), context);
            }
        }
        assert_eq!(variant_ids.len(), 9);
    }

    #[test]
    fn attribute_selection_requires_one_exact_context_matching_source_anchor() {
        for context in [
            ExactHtmlReflectionContext::AttributeValue,
            ExactHtmlReflectionContext::UriAttribute,
            ExactHtmlReflectionContext::EventHandlerAttribute,
        ] {
            for source in [
                AttributeSourceResult::Absent,
                AttributeSourceResult::Ambiguous,
                AttributeSourceResult::Unsupported,
                AttributeSourceResult::Incomplete,
            ] {
                assert!(select_xss_probe_families(context, &source).is_empty());
            }
        }

        let (_, uri_source) = exact_attribute_source("a", "href", AttributeQuoteMode::DoubleQuoted);
        for mismatched_context in [
            ExactHtmlReflectionContext::AttributeValue,
            ExactHtmlReflectionContext::EventHandlerAttribute,
        ] {
            assert!(select_xss_probe_families(mismatched_context, &uri_source).is_empty());
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
        for family in [
            XssProbeFamily::HtmlTextBoundary,
            XssProbeFamily::AttributeValueBoundary,
            XssProbeFamily::UriAttributeBoundary,
            XssProbeFamily::EventHandlerAttributeBoundary,
        ] {
            assert!(family.is_v1_executable());
        }
        for family in [
            XssProbeFamily::UriAttributeStructure,
            XssProbeFamily::EventHandlerStructure,
            XssProbeFamily::ScriptContentStructure,
        ] {
            assert!(!family.is_v1_executable());
            assert!(select_xss_probe_families(
                family.compatible_context(),
                &AttributeSourceResult::Absent,
            )
            .is_empty());
        }
    }

    #[test]
    fn selection_is_deterministic_and_never_expands_with_catalog_breadth() {
        let first = select_xss_probe_families(
            ExactHtmlReflectionContext::HtmlText,
            &AttributeSourceResult::Absent,
        );
        assert_eq!(
            first,
            select_xss_probe_families(
                ExactHtmlReflectionContext::HtmlText,
                &AttributeSourceResult::Absent,
            )
        );
        assert!(first.len() <= XSS_V1_MAX_SELECTED_FAMILIES);
        assert_eq!(
            first[0].action_kind(),
            NativeWebReviewActionKind::XssStructuralQueryPair
        );
        assert_eq!(first[0].strategy_seed(IDENTITY), format!("html:{IDENTITY}"));

        let (context, source) =
            exact_attribute_source("a", "href", AttributeQuoteMode::SingleQuoted);
        let attribute_first = select_xss_probe_families(context, &source);
        assert!(attribute_first.len() <= XSS_V1_MAX_SELECTED_FAMILIES);
        for _ in 0..1_000 {
            assert_eq!(
                select_xss_probe_families(
                    ExactHtmlReflectionContext::HtmlText,
                    &AttributeSourceResult::Absent,
                ),
                first
            );
            assert_eq!(select_xss_probe_families(context, &source), attribute_first);
        }
    }
}
