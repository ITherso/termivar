//! Pure byte-encoding transforms and the corrected evasion-technique dispatcher.
//!
//! This is the relocated, corrected home for the encoders and the evasion enum
//! that previously lived on the legacy [`crate::waf`] utility. The enum fixes the
//! `EvisionTechnique`/`WhespaceVariation` misspellings while remaining wire- and
//! source-compatible with the legacy names. Every transform is deterministic and
//! behavior-equivalent to its legacy counterpart.
//!
//! Nothing here is registered as a runtime strategy, wired to an executor, or
//! allowed to issue a request: these are pure building blocks. Deriving an
//! artifact routes through [`crate::payload_strategy::PayloadArtifact`], which
//! enforces the per-turn byte bound and raw-payload redaction.

use serde::{Deserialize, Serialize};

use super::normalization;
use crate::payload_strategy::{
    PayloadArtifact, PayloadStrategyError, PayloadStrategyLimits, PayloadStrategyRef,
    PayloadVariantRole,
};

/// Percent-encodes every character outside the URL unreserved set.
///
/// Behavior-equivalent to `waf::PayloadEncoder::url_encode`.
pub fn url_encode(payload: &str) -> String {
    payload
        .chars()
        .map(|character| {
            if character.is_alphanumeric()
                || character == '-'
                || character == '_'
                || character == '.'
                || character == '~'
            {
                character.to_string()
            } else {
                format!("%{:02X}", character as u8)
            }
        })
        .collect()
}

/// Applies [`url_encode`] twice.
///
/// Behavior-equivalent to `waf::PayloadEncoder::double_url_encode`.
pub fn double_url_encode(payload: &str) -> String {
    url_encode(&url_encode(payload))
}

/// Percent-hex-encodes every byte.
///
/// Behavior-equivalent to `waf::PayloadEncoder::hex_encode`.
pub fn hex_encode(payload: &str) -> String {
    payload
        .bytes()
        .map(|byte| format!("%{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// Payload evasion technique, correcting the legacy `EvisionTechnique` spelling.
///
/// The serialized form uses stable `snake_case` names; the legacy
/// `whespace_variation` spelling is accepted on deserialization for backward
/// compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvasionTechnique {
    /// Case variation: `select` -> `SeLeCt`.
    CaseVariation,
    /// Inline SQL comment injection: `select` -> `sel/**/ect`.
    CommentInjection,
    /// Whitespace variation: spaces become tabs. (Was `WhespaceVariation`.)
    #[serde(alias = "whespace_variation")]
    WhitespaceVariation,
    /// URL percent-encoding.
    Encoding,
    /// HTTP parameter pollution: a duplicate `id` parameter.
    ParameterPollution,
    /// CRLF/newline escaping for HTTP splitting.
    HttpSplitting,
}

impl EvasionTechnique {
    /// Applies this technique to `payload`, returning a single variant.
    ///
    /// Behavior-equivalent, per technique, to the legacy
    /// `waf::PayloadEncoder::apply_evasion` dispatch.
    pub fn apply(self, payload: &str) -> String {
        match self {
            Self::CaseVariation => normalization::case_variation(payload),
            Self::CommentInjection => normalization::sql_comment_injection(payload),
            Self::WhitespaceVariation => normalization::whitespace_to_tab(payload),
            Self::Encoding => url_encode(payload),
            Self::ParameterPollution => format!("{payload}&id={payload}"),
            Self::HttpSplitting => payload.replace('\n', "%0A"),
        }
    }
}

/// Applies each technique to `payload`, producing one variant per technique.
///
/// Behavior-equivalent to `waf::PayloadEncoder::apply_evasion`.
pub fn apply_evasion(payload: &str, techniques: &[EvasionTechnique]) -> Vec<String> {
    techniques
        .iter()
        .map(|technique| technique.apply(payload))
        .collect()
}

/// Derives a single bounded, redacted artifact from one evasion technique.
///
/// The derived bytes never bypass the payload-artifact contract: the per-turn
/// byte limit is enforced and the raw bytes are redacted from debug output and
/// receipts. This routes encoding output through the same safety envelope as any
/// other payload artifact.
pub fn encode_into_artifact(
    strategy: &PayloadStrategyRef,
    role: PayloadVariantRole,
    payload: &str,
    technique: EvasionTechnique,
    limits: PayloadStrategyLimits,
) -> Result<PayloadArtifact, PayloadStrategyError> {
    PayloadArtifact::new(
        strategy.clone(),
        role,
        technique.apply(payload).into_bytes(),
        limits,
    )
}

/// Maps a legacy [`crate::waf::EvisionTechnique`] to its corrected form.
#[cfg(feature = "scanning")]
impl From<crate::waf::EvisionTechnique> for EvasionTechnique {
    fn from(legacy: crate::waf::EvisionTechnique) -> Self {
        use crate::waf::EvisionTechnique as Legacy;
        match legacy {
            Legacy::CaseVariation => Self::CaseVariation,
            Legacy::CommentInjection => Self::CommentInjection,
            Legacy::WhespaceVariation => Self::WhitespaceVariation,
            Legacy::Encoding => Self::Encoding,
            Legacy::ParameterPollution => Self::ParameterPollution,
            Legacy::HttpSplitting => Self::HttpSplitting,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> PayloadStrategyRef {
        PayloadStrategyRef::new("encoding.fixture", 1).unwrap()
    }

    #[test]
    fn encoders_match_expected_forms_and_are_deterministic() {
        assert_eq!(url_encode("a b/c"), "a%20b%2Fc");
        assert_eq!(url_encode("a b/c"), url_encode("a b/c"));
        assert_eq!(double_url_encode(" "), "%2520");
        assert_eq!(hex_encode("AB"), "%41%42");
    }

    #[test]
    fn apply_evasion_dispatches_each_technique() {
        let payload = "select a b\nc";
        let variants = apply_evasion(
            payload,
            &[
                EvasionTechnique::CaseVariation,
                EvasionTechnique::CommentInjection,
                EvasionTechnique::WhitespaceVariation,
                EvasionTechnique::Encoding,
                EvasionTechnique::ParameterPollution,
                EvasionTechnique::HttpSplitting,
            ],
        );
        assert_eq!(variants.len(), 6);
        assert_eq!(variants[1], "sel/**/ect a b\nc");
        assert_eq!(variants[2], "select\ta\tb\nc");
        assert_eq!(variants[4], format!("{payload}&id={payload}"));
        assert_eq!(variants[5], "select a b%0Ac");
    }

    #[test]
    fn apply_evasion_is_deterministic() {
        let payload = "SELECT id FROM t WHERE x = 1";
        let techniques = [EvasionTechnique::Encoding, EvasionTechnique::CaseVariation];
        assert_eq!(
            apply_evasion(payload, &techniques),
            apply_evasion(payload, &techniques)
        );
    }

    #[test]
    fn serde_uses_stable_names_and_accepts_the_legacy_typo() {
        assert_eq!(
            serde_json::to_string(&EvasionTechnique::WhitespaceVariation).unwrap(),
            "\"whitespace_variation\""
        );
        let corrected: EvasionTechnique = serde_json::from_str("\"whitespace_variation\"").unwrap();
        assert_eq!(corrected, EvasionTechnique::WhitespaceVariation);
        // Serialization compatibility: the legacy typo spelling still deserializes.
        let legacy: EvasionTechnique = serde_json::from_str("\"whespace_variation\"").unwrap();
        assert_eq!(legacy, EvasionTechnique::WhitespaceVariation);
    }

    #[test]
    fn encode_into_artifact_enforces_the_byte_bound() {
        let reference = reference();
        // url_encode("<a>") expands to "%3Ca%3E" (7 bytes), over a 4-byte ceiling.
        let tight = PayloadStrategyLimits::new(64, 4).unwrap();
        assert!(matches!(
            encode_into_artifact(
                &reference,
                PayloadVariantRole::Candidate,
                "<a>",
                EvasionTechnique::Encoding,
                tight,
            ),
            Err(PayloadStrategyError::ArtifactTooLarge { .. })
        ));

        let ok = encode_into_artifact(
            &reference,
            PayloadVariantRole::Control,
            "ab",
            EvasionTechnique::Encoding,
            PayloadStrategyLimits::default(),
        )
        .unwrap();
        assert_eq!(ok.as_bytes(), b"ab");
    }

    #[test]
    fn encode_into_artifact_redacts_the_raw_payload() {
        let reference = reference();
        let artifact = encode_into_artifact(
            &reference,
            PayloadVariantRole::Candidate,
            "zzzz",
            EvasionTechnique::CaseVariation,
            PayloadStrategyLimits::default(),
        )
        .unwrap();
        // case_variation("zzzz") == "ZzZz"; neither the raw nor the derived value
        // may appear in debug output or the audit receipt.
        assert_eq!(artifact.as_bytes(), b"ZzZz");
        let debug = format!("{artifact:?}");
        let receipt_json = serde_json::to_string(&artifact.receipt()).unwrap();
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("ZzZz"));
        assert!(!debug.contains("zzzz"));
        assert!(!receipt_json.contains("ZzZz"));
        assert_eq!(artifact.receipt().sha256().len(), 64);
    }
}

#[cfg(all(test, feature = "scanning"))]
mod legacy_equivalence {
    use super::*;

    #[test]
    fn encoders_match_the_legacy_encoder() {
        use crate::waf::PayloadEncoder as Legacy;
        for input in [
            "' OR '1'='1",
            "SELECT * FROM users",
            "a b/c?d=e&f",
            "<script>alert(1)</script>",
            "unioN select",
        ] {
            assert_eq!(
                url_encode(input),
                Legacy::url_encode(input),
                "url_encode {input}"
            );
            assert_eq!(
                double_url_encode(input),
                Legacy::double_url_encode(input),
                "double_url_encode {input}"
            );
            assert_eq!(
                hex_encode(input),
                Legacy::hex_encode(input),
                "hex_encode {input}"
            );
            assert_eq!(
                normalization::case_variation(input),
                Legacy::case_variation(input),
                "case_variation {input}"
            );
            assert_eq!(
                normalization::sql_comment_injection(input),
                Legacy::comment_injection_sql(input),
                "comment_injection {input}"
            );
        }
    }

    #[test]
    fn apply_evasion_matches_the_legacy_dispatch_for_every_technique() {
        use crate::waf::{EvisionTechnique as Legacy, PayloadEncoder as LegacyEncoder};
        let payload = "SELECT a b\nc union";
        let corrected = [
            EvasionTechnique::CaseVariation,
            EvasionTechnique::CommentInjection,
            EvasionTechnique::WhitespaceVariation,
            EvasionTechnique::Encoding,
            EvasionTechnique::ParameterPollution,
            EvasionTechnique::HttpSplitting,
        ];
        let legacy = [
            Legacy::CaseVariation,
            Legacy::CommentInjection,
            Legacy::WhespaceVariation,
            Legacy::Encoding,
            Legacy::ParameterPollution,
            Legacy::HttpSplitting,
        ];

        assert_eq!(
            apply_evasion(payload, &corrected),
            LegacyEncoder::apply_evasion(payload, &legacy)
        );

        // Each legacy variant, including the typo spelling, maps to its corrected
        // form, so old source keeps compiling and converts across cleanly.
        for (corrected, legacy) in corrected.iter().zip(legacy.iter()) {
            assert_eq!(*corrected, EvasionTechnique::from(*legacy));
        }
    }
}
