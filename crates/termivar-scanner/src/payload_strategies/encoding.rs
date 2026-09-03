//! Pure, bounded byte-encoding helpers.
//!
//! These functions do not select an input, issue a request, fingerprint a
//! defense product, or imply bypass behavior. Encoding into a payload artifact
//! preserves the standard byte limit and redacted receipt boundary.

use serde::{Deserialize, Serialize};

use crate::payload_strategy::{
    PayloadArtifact, PayloadStrategyError, PayloadStrategyLimits, PayloadStrategyRef,
    PayloadVariantRole,
};

/// Percent-encodes every byte outside the ASCII URL-unreserved set.
#[must_use]
pub fn percent_encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len());
    for byte in input {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(*byte));
        } else {
            output.push_str(&format!("%{:02X}", *byte));
        }
    }
    output
}

/// Encodes every byte as lowercase hexadecimal without interpreting it.
#[must_use]
pub fn hex_encode(input: &[u8]) -> String {
    input.iter().map(|byte| format!("{:02x}", *byte)).collect()
}

/// Neutral byte encoding selected by an integrating host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncoding {
    Percent,
    Hex,
}

impl PayloadEncoding {
    #[must_use]
    pub fn apply(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Percent => percent_encode(input).into_bytes(),
            Self::Hex => hex_encode(input).into_bytes(),
        }
    }
}

/// Encodes one bounded payload artifact under the existing strategy identity.
pub fn encode_into_artifact(
    strategy: &PayloadStrategyRef,
    role: PayloadVariantRole,
    input: &[u8],
    encoding: PayloadEncoding,
    limits: PayloadStrategyLimits,
) -> Result<PayloadArtifact, PayloadStrategyError> {
    PayloadArtifact::new(strategy.clone(), role, encoding.apply(input), limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> PayloadStrategyRef {
        PayloadStrategyRef::new("encoding.fixture", 1).expect("valid fixture identity")
    }

    #[test]
    fn encoders_are_byte_based_and_deterministic() {
        assert_eq!(percent_encode(b"a b/c"), "a%20b%2Fc");
        assert_eq!(hex_encode(b"AB"), "4142");
        assert_eq!(percent_encode(&[0xff]), "%FF");
        assert_eq!(percent_encode(b"a b"), percent_encode(b"a b"));
    }

    #[test]
    fn artifact_encoding_enforces_the_byte_bound_and_redacts_values() {
        let tight = PayloadStrategyLimits::new(64, 4).expect("valid limits");
        assert!(matches!(
            encode_into_artifact(
                &reference(),
                PayloadVariantRole::Candidate,
                b"<a>",
                PayloadEncoding::Percent,
                tight,
            ),
            Err(PayloadStrategyError::ArtifactTooLarge { .. })
        ));

        let artifact = encode_into_artifact(
            &reference(),
            PayloadVariantRole::Control,
            b"ab",
            PayloadEncoding::Hex,
            PayloadStrategyLimits::default(),
        )
        .expect("bounded artifact");
        assert_eq!(artifact.as_bytes(), b"6162");
        assert!(!format!("{artifact:?}").contains("6162"));
        assert!(!serde_json::to_string(&artifact.receipt())
            .expect("receipt serializes")
            .contains("6162"));
    }
}
