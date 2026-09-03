//! Non-executing quote-aware HTML attribute-boundary probe pair.
//!
//! The seed is closed metadata only: one attribute family code, one exact
//! source quote mode, and one scanner-owned lowercase hexadecimal identity.
//! Target values never participate in payload derivation.

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};

pub const XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID: &str =
    "web.review.xss.attribute-boundary-query-pair";
pub const XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION: u32 = 1;

#[derive(Debug, Clone)]
pub struct XssAttributeBoundaryQueryPairStrategy {
    reference: PayloadStrategyRef,
}

impl XssAttributeBoundaryQueryPairStrategy {
    pub fn new() -> Self {
        Self {
            reference: PayloadStrategyRef::new(
                XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID,
                XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION,
            )
            .expect("the XSS attribute-boundary strategy identity is static and valid"),
        }
    }

    fn derive_value(seed: &[u8], role: PayloadVariantRole) -> Option<String> {
        let seed = std::str::from_utf8(seed).ok()?;
        let mut parts = seed.split(':');
        let family = parts.next()?;
        let quote_mode = parts.next()?;
        let identity = parts.next()?;
        if parts.next().is_some()
            || !matches!(family, "attribute" | "uri" | "handler")
            || !matches!(quote_mode, "double-quoted" | "single-quoted" | "unquoted")
            || identity.len() != 32
            || !identity
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return None;
        }
        if role == PayloadVariantRole::Control {
            return Some(format!("venom-xss-attribute-control-{identity}-end"));
        }
        match quote_mode {
            "double-quoted" => Some(format!(
                "\" data-venom-xss-boundary-token=\"{identity}\" data-venom-xss-tail-token=\"{identity}"
            )),
            "single-quoted" => Some(format!(
                "' data-venom-xss-boundary-token='{identity}' data-venom-xss-tail-token='{identity}"
            )),
            "unquoted" => Some(format!(
                "venom-xss-inert-{identity} data-venom-xss-boundary-token={identity} data-venom-xss-tail-token={identity}"
            )),
            _ => None,
        }
    }
}

impl Default for XssAttributeBoundaryQueryPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for XssAttributeBoundaryQueryPairStrategy {
    fn strategy_ref(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        let value = Self::derive_value(seed.as_bytes(), role)
            .ok_or(PayloadStrategyError::DerivationFailed)?;
        PayloadArtifact::new(self.reference.clone(), role, value.into_bytes(), limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: &str = "0123456789abcdef0123456789abcdef";

    fn limits() -> PayloadStrategyLimits {
        PayloadStrategyLimits::new(256, 256).unwrap()
    }

    fn derive(family: &str, quote: &str, role: PayloadVariantRole) -> String {
        let strategy = XssAttributeBoundaryQueryPairStrategy::new();
        let seed = PayloadSeed::new(
            format!("{family}:{quote}:{IDENTITY}").into_bytes(),
            limits(),
        )
        .unwrap();
        String::from_utf8(
            strategy
                .derive_one(role, &seed, limits())
                .unwrap()
                .as_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn quote_variants_have_exact_inert_bounded_wire_shapes() {
        assert_eq!(
            derive("attribute", "double-quoted", PayloadVariantRole::Candidate),
            format!(
                "\" data-venom-xss-boundary-token=\"{IDENTITY}\" data-venom-xss-tail-token=\"{IDENTITY}"
            )
        );
        assert_eq!(
            derive("uri", "single-quoted", PayloadVariantRole::Candidate),
            format!(
                "' data-venom-xss-boundary-token='{IDENTITY}' data-venom-xss-tail-token='{IDENTITY}"
            )
        );
        assert_eq!(
            derive("handler", "unquoted", PayloadVariantRole::Candidate),
            format!(
                "venom-xss-inert-{IDENTITY} data-venom-xss-boundary-token={IDENTITY} data-venom-xss-tail-token={IDENTITY}"
            )
        );

        for family in ["attribute", "uri", "handler"] {
            for quote in ["double-quoted", "single-quoted", "unquoted"] {
                let control = derive(family, quote, PayloadVariantRole::Control);
                let candidate = derive(family, quote, PayloadVariantRole::Candidate);
                assert_ne!(control, candidate);
                assert!(candidate.len() <= 256);
                for forbidden in [
                    "alert",
                    "prompt",
                    "confirm",
                    "javascript:",
                    "data:",
                    "fetch",
                    "document.",
                    "window.",
                    "http://",
                    "https://",
                    "//",
                ] {
                    assert!(!candidate.contains(forbidden), "{forbidden} in {candidate}");
                }
            }
        }
    }

    #[test]
    fn unknown_family_quote_and_noncanonical_identity_fail_closed() {
        let strategy = XssAttributeBoundaryQueryPairStrategy::new();
        for value in [
            format!("unknown:double-quoted:{IDENTITY}"),
            format!("attribute:unknown:{IDENTITY}"),
            "attribute:double-quoted:short".to_owned(),
            "attribute:double-quoted:0123456789ABCDEF0123456789ABCDEF".to_owned(),
            format!("attribute:double-quoted:{IDENTITY}:extra"),
        ] {
            let seed = PayloadSeed::new(value.into_bytes(), limits()).unwrap();
            for role in [PayloadVariantRole::Control, PayloadVariantRole::Candidate] {
                assert!(matches!(
                    strategy.derive_one(role, &seed, limits()),
                    Err(PayloadStrategyError::DerivationFailed)
                ));
            }
        }
    }
}
