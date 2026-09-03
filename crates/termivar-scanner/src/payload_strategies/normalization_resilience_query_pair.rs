//! Typed, bounded equivalent-representation pair for normalization review.
//!
//! The inherited [`PayloadVariantRole`] vocabulary maps `Control` to the first
//! transformed candidate and `Candidate` to its distinct replay. The canonical
//! parent control/candidate pair is committed before this strategy is selected
//! and is never re-sent by this implementation.

use std::fmt;

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};

pub(crate) const NORMALIZATION_RESILIENCE_QUERY_PAIR_ID: &str =
    "web.review.normalization-resilience";
pub(crate) const NORMALIZATION_RESILIENCE_QUERY_PAIR_REVISION: u32 = 1;

const NORMALIZATION_SEED_SCHEMA: &str = "v1";
const NORMALIZATION_IDENTITY_BYTES: usize = 32;

/// Parent structural family retained in the typed normalization seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum NormalizationProbeFamily {
    HtmlText,
    AttributeValue,
    UriAttribute,
    EventHandlerAttribute,
}

impl NormalizationProbeFamily {
    const fn seed_code(self) -> &'static str {
        match self {
            Self::HtmlText => "html-text",
            Self::AttributeValue => "attribute-value",
            Self::UriAttribute => "uri-attribute",
            Self::EventHandlerAttribute => "event-handler-attribute",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "html-text" => Some(Self::HtmlText),
            "attribute-value" => Some(Self::AttributeValue),
            "uri-attribute" => Some(Self::UriAttribute),
            "event-handler-attribute" => Some(Self::EventHandlerAttribute),
            _ => None,
        }
    }

    const fn is_attribute(self) -> bool {
        matches!(
            self,
            Self::AttributeValue | Self::UriAttribute | Self::EventHandlerAttribute
        )
    }
}

/// Source quote contract retained without source bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum NormalizationProbeQuote {
    NotApplicable,
    DoubleQuoted,
    SingleQuoted,
    Unquoted,
}

impl NormalizationProbeQuote {
    const fn seed_code(self) -> &'static str {
        match self {
            Self::NotApplicable => "none",
            Self::DoubleQuoted => "double-quoted",
            Self::SingleQuoted => "single-quoted",
            Self::Unquoted => "unquoted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::NotApplicable),
            "double-quoted" => Some(Self::DoubleQuoted),
            "single-quoted" => Some(Self::SingleQuoted),
            "unquoted" => Some(Self::Unquoted),
            _ => None,
        }
    }
}

/// V1 transforms that have a source-linked serializer implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ExecutableNormalizationTransform {
    HtmlTokenCase,
    HtmlInterTokenTab,
}

impl ExecutableNormalizationTransform {
    const fn seed_code(self) -> &'static str {
        match self {
            Self::HtmlTokenCase => "html-token-case",
            Self::HtmlInterTokenTab => "html-inter-token-tab",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "html-token-case" => Some(Self::HtmlTokenCase),
            "html-inter-token-tab" => Some(Self::HtmlInterTokenTab),
            _ => None,
        }
    }
}

/// Closed, raw-target-free seed for one transformed candidate/replay pair.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NormalizationProbeSeed {
    transform: ExecutableNormalizationTransform,
    family: NormalizationProbeFamily,
    quote: NormalizationProbeQuote,
    transformed_identity: String,
    replay_identity: String,
}

impl NormalizationProbeSeed {
    pub(crate) fn new(
        transform: ExecutableNormalizationTransform,
        family: NormalizationProbeFamily,
        quote: NormalizationProbeQuote,
        transformed_identity: &str,
        replay_identity: &str,
    ) -> Option<Self> {
        if !is_canonical_identity(transformed_identity)
            || !is_canonical_identity(replay_identity)
            || transformed_identity == replay_identity
            || !is_compatible(transform, family, quote)
        {
            return None;
        }
        Some(Self {
            transform,
            family,
            quote,
            transformed_identity: transformed_identity.to_owned(),
            replay_identity: replay_identity.to_owned(),
        })
    }

    pub(crate) fn encode(&self) -> String {
        format!(
            "{NORMALIZATION_SEED_SCHEMA}:{}:{}:{}:{}:{}",
            self.transform.seed_code(),
            self.family.seed_code(),
            self.quote.seed_code(),
            self.transformed_identity,
            self.replay_identity
        )
    }

    fn parse(value: &[u8]) -> Option<Self> {
        let value = std::str::from_utf8(value).ok()?;
        let mut parts = value.split(':');
        let schema = parts.next()?;
        let transform = ExecutableNormalizationTransform::parse(parts.next()?)?;
        let family = NormalizationProbeFamily::parse(parts.next()?)?;
        let quote = NormalizationProbeQuote::parse(parts.next()?)?;
        let transformed_identity = parts.next()?;
        let replay_identity = parts.next()?;
        if schema != NORMALIZATION_SEED_SCHEMA || parts.next().is_some() {
            return None;
        }
        Self::new(
            transform,
            family,
            quote,
            transformed_identity,
            replay_identity,
        )
    }

    fn identity_for(&self, role: PayloadVariantRole) -> &str {
        match role {
            PayloadVariantRole::Control => &self.transformed_identity,
            PayloadVariantRole::Candidate => &self.replay_identity,
        }
    }
}

impl fmt::Debug for NormalizationProbeSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalizationProbeSeed")
            .field("transform", &self.transform)
            .field("family", &self.family)
            .field("quote", &self.quote)
            .field("transformed_identity", &"<redacted>")
            .field("replay_identity", &"<redacted>")
            .finish()
    }
}

fn is_canonical_identity(identity: &str) -> bool {
    identity.len() == NORMALIZATION_IDENTITY_BYTES
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

const fn is_compatible(
    transform: ExecutableNormalizationTransform,
    family: NormalizationProbeFamily,
    quote: NormalizationProbeQuote,
) -> bool {
    match transform {
        ExecutableNormalizationTransform::HtmlTokenCase => {
            matches!(family, NormalizationProbeFamily::HtmlText)
                && matches!(quote, NormalizationProbeQuote::NotApplicable)
        },
        ExecutableNormalizationTransform::HtmlInterTokenTab => {
            family.is_attribute() && !matches!(quote, NormalizationProbeQuote::NotApplicable)
        },
    }
}

fn canonical_probe(
    family: NormalizationProbeFamily,
    quote: NormalizationProbeQuote,
    identity: &str,
) -> Option<String> {
    match (family, quote) {
        (NormalizationProbeFamily::HtmlText, NormalizationProbeQuote::NotApplicable) => {
            Some(format!(
                "<span data-venom-xss-boundary-token=\"{identity}\"></span>"
            ))
        },
        (family, NormalizationProbeQuote::DoubleQuoted) if family.is_attribute() => Some(format!(
            "\" data-venom-xss-boundary-token=\"{identity}\" data-venom-xss-tail-token=\"{identity}"
        )),
        (family, NormalizationProbeQuote::SingleQuoted) if family.is_attribute() => Some(format!(
            "' data-venom-xss-boundary-token='{identity}' data-venom-xss-tail-token='{identity}"
        )),
        (family, NormalizationProbeQuote::Unquoted) if family.is_attribute() => Some(format!(
            "venom-xss-inert-{identity} data-venom-xss-boundary-token={identity} data-venom-xss-tail-token={identity}"
        )),
        _ => None,
    }
}

fn transformed_probe(seed: &NormalizationProbeSeed, role: PayloadVariantRole) -> Option<Vec<u8>> {
    let identity = seed.identity_for(role);
    let output = match seed.transform {
        ExecutableNormalizationTransform::HtmlTokenCase => {
            format!("<SPAN DATA-VENOM-XSS-BOUNDARY-TOKEN=\"{identity}\"></SPAN>")
        },
        ExecutableNormalizationTransform::HtmlInterTokenTab => {
            let canonical = canonical_probe(seed.family, seed.quote, identity)?;
            let separator = canonical.find(' ')?;
            let mut output = String::with_capacity(canonical.len());
            output.push_str(&canonical[..separator]);
            output.push('\t');
            output.push_str(&canonical[separator + 1..]);
            output
        },
    };
    if output
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0'))
    {
        return None;
    }
    Some(output.into_bytes())
}

#[derive(Debug, Clone)]
pub(crate) struct NormalizationResilienceQueryPairStrategy {
    reference: PayloadStrategyRef,
}

impl NormalizationResilienceQueryPairStrategy {
    pub(crate) fn new() -> Self {
        Self {
            reference: PayloadStrategyRef::new(
                NORMALIZATION_RESILIENCE_QUERY_PAIR_ID,
                NORMALIZATION_RESILIENCE_QUERY_PAIR_REVISION,
            )
            .expect("the normalization-resilience strategy identity is static and valid"),
        }
    }
}

impl Default for NormalizationResilienceQueryPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for NormalizationResilienceQueryPairStrategy {
    fn strategy_ref(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        let seed = NormalizationProbeSeed::parse(seed.as_bytes())
            .ok_or(PayloadStrategyError::DerivationFailed)?;
        let value = transformed_probe(&seed, role).ok_or(PayloadStrategyError::DerivationFailed)?;
        PayloadArtifact::new(self.reference.clone(), role, value, limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload_strategies::{
        XssAttributeBoundaryQueryPairStrategy, XssStructuralQueryPairStrategy,
    };

    const CANDIDATE_ID: &str = "0123456789abcdef0123456789abcdef";
    const REPLAY_ID: &str = "fedcba9876543210fedcba9876543210";

    fn limits() -> PayloadStrategyLimits {
        PayloadStrategyLimits::new(512, 512).unwrap()
    }

    fn artifact(
        transform: ExecutableNormalizationTransform,
        family: NormalizationProbeFamily,
        quote: NormalizationProbeQuote,
        role: PayloadVariantRole,
    ) -> PayloadArtifact {
        let typed =
            NormalizationProbeSeed::new(transform, family, quote, CANDIDATE_ID, REPLAY_ID).unwrap();
        let seed = PayloadSeed::new(typed.encode().into_bytes(), limits()).unwrap();
        NormalizationResilienceQueryPairStrategy::new()
            .derive_one(role, &seed, limits())
            .unwrap()
    }

    #[test]
    fn typed_canonical_serializer_preserves_existing_xss_wire_contracts() {
        let structural = XssStructuralQueryPairStrategy::new();
        let structural_seed =
            PayloadSeed::new(format!("html:{CANDIDATE_ID}").into_bytes(), limits()).unwrap();
        let canonical = structural
            .derive_one(PayloadVariantRole::Candidate, &structural_seed, limits())
            .unwrap();
        assert_eq!(
            canonical_probe(
                NormalizationProbeFamily::HtmlText,
                NormalizationProbeQuote::NotApplicable,
                CANDIDATE_ID,
            )
            .unwrap()
            .as_bytes(),
            canonical.as_bytes()
        );

        let attribute = XssAttributeBoundaryQueryPairStrategy::new();
        for (quote, quote_code) in [
            (NormalizationProbeQuote::DoubleQuoted, "double-quoted"),
            (NormalizationProbeQuote::SingleQuoted, "single-quoted"),
            (NormalizationProbeQuote::Unquoted, "unquoted"),
        ] {
            let attribute_seed = PayloadSeed::new(
                format!("attribute:{quote_code}:{CANDIDATE_ID}").into_bytes(),
                limits(),
            )
            .unwrap();
            let existing = attribute
                .derive_one(PayloadVariantRole::Candidate, &attribute_seed, limits())
                .unwrap();
            assert_eq!(
                canonical_probe(
                    NormalizationProbeFamily::AttributeValue,
                    quote,
                    CANDIDATE_ID,
                )
                .unwrap()
                .as_bytes(),
                existing.as_bytes()
            );
        }
    }

    #[test]
    fn transforms_only_typed_scanner_syntax_and_keeps_identities_distinct() {
        let candidate = artifact(
            ExecutableNormalizationTransform::HtmlTokenCase,
            NormalizationProbeFamily::HtmlText,
            NormalizationProbeQuote::NotApplicable,
            PayloadVariantRole::Control,
        );
        let replay = artifact(
            ExecutableNormalizationTransform::HtmlTokenCase,
            NormalizationProbeFamily::HtmlText,
            NormalizationProbeQuote::NotApplicable,
            PayloadVariantRole::Candidate,
        );
        assert_eq!(
            std::str::from_utf8(candidate.as_bytes()).unwrap(),
            format!("<SPAN DATA-VENOM-XSS-BOUNDARY-TOKEN=\"{CANDIDATE_ID}\"></SPAN>")
        );
        assert_eq!(
            std::str::from_utf8(replay.as_bytes()).unwrap(),
            format!("<SPAN DATA-VENOM-XSS-BOUNDARY-TOKEN=\"{REPLAY_ID}\"></SPAN>")
        );
        assert_ne!(candidate.receipt().sha256(), replay.receipt().sha256());

        let tab = artifact(
            ExecutableNormalizationTransform::HtmlInterTokenTab,
            NormalizationProbeFamily::AttributeValue,
            NormalizationProbeQuote::DoubleQuoted,
            PayloadVariantRole::Control,
        );
        let tab = std::str::from_utf8(tab.as_bytes()).unwrap();
        assert!(tab.starts_with("\"\tdata-venom-xss-boundary-token="));
        assert!(tab.contains(CANDIDATE_ID));
        assert!(!tab
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0')));
    }

    #[test]
    fn invalid_incompatible_or_secret_shaped_seeds_fail_closed_and_redact() {
        assert!(NormalizationProbeSeed::new(
            ExecutableNormalizationTransform::HtmlTokenCase,
            NormalizationProbeFamily::AttributeValue,
            NormalizationProbeQuote::DoubleQuoted,
            CANDIDATE_ID,
            REPLAY_ID,
        )
        .is_none());
        assert!(NormalizationProbeSeed::new(
            ExecutableNormalizationTransform::HtmlInterTokenTab,
            NormalizationProbeFamily::HtmlText,
            NormalizationProbeQuote::NotApplicable,
            CANDIDATE_ID,
            REPLAY_ID,
        )
        .is_none());
        assert!(NormalizationProbeSeed::new(
            ExecutableNormalizationTransform::HtmlTokenCase,
            NormalizationProbeFamily::HtmlText,
            NormalizationProbeQuote::NotApplicable,
            CANDIDATE_ID,
            CANDIDATE_ID,
        )
        .is_none());

        let typed = NormalizationProbeSeed::new(
            ExecutableNormalizationTransform::HtmlTokenCase,
            NormalizationProbeFamily::HtmlText,
            NormalizationProbeQuote::NotApplicable,
            CANDIDATE_ID,
            REPLAY_ID,
        )
        .unwrap();
        let debug = format!("{typed:?}");
        assert!(!debug.contains(CANDIDATE_ID));
        assert!(!debug.contains(REPLAY_ID));

        let strategy = NormalizationResilienceQueryPairStrategy::new();
        for invalid in [
            "v2:html-token-case:html-text:none:0123456789abcdef0123456789abcdef:fedcba9876543210fedcba9876543210",
            "v1:unknown:html-text:none:0123456789abcdef0123456789abcdef:fedcba9876543210fedcba9876543210",
            "v1:html-token-case:html-text:none:short:fedcba9876543210fedcba9876543210",
            "v1:html-token-case:html-text:none:0123456789ABCDEF0123456789ABCDEF:fedcba9876543210fedcba9876543210",
        ] {
            let seed = PayloadSeed::new(invalid.as_bytes().to_vec(), limits()).unwrap();
            assert_eq!(
                strategy.derive_one(PayloadVariantRole::Control, &seed, limits()),
                Err(PayloadStrategyError::DerivationFailed)
            );
        }
    }

    #[test]
    fn output_limits_and_receipts_remain_bounded_and_raw_value_free() {
        let typed = NormalizationProbeSeed::new(
            ExecutableNormalizationTransform::HtmlTokenCase,
            NormalizationProbeFamily::HtmlText,
            NormalizationProbeQuote::NotApplicable,
            CANDIDATE_ID,
            REPLAY_ID,
        )
        .unwrap();
        let seed = PayloadSeed::new(typed.encode().into_bytes(), limits()).unwrap();
        let tiny = PayloadStrategyLimits::new(512, 8).unwrap();
        assert!(matches!(
            NormalizationResilienceQueryPairStrategy::new().derive_one(
                PayloadVariantRole::Control,
                &seed,
                tiny,
            ),
            Err(PayloadStrategyError::ArtifactTooLarge { .. })
        ));

        let artifact = artifact(
            ExecutableNormalizationTransform::HtmlTokenCase,
            NormalizationProbeFamily::HtmlText,
            NormalizationProbeQuote::NotApplicable,
            PayloadVariantRole::Control,
        );
        for rendered in [
            format!("{artifact:?}"),
            serde_json::to_string(&artifact.receipt()).unwrap(),
        ] {
            assert!(!rendered.contains(CANDIDATE_ID));
            assert!(!rendered.contains("<SPAN"));
        }
    }
}
