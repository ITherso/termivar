//! Bounded, non-destructive SQL quote-balance review mutation.
//!
//! The candidate appends one unmatched ASCII quote to an inert scanner-owned
//! token. It contains no comment, operator, statement separator, function,
//! or data-bearing syntax, so its intended effect is limited to parser
//! behavior rather than changing legitimate result selection.

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};

pub const SQL_QUOTE_BALANCE_QUERY_PAIR_ID: &str = "web.review.sql.quote-balance-query-pair";
pub const SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION: u32 = 1;

#[derive(Debug, Clone)]
pub struct SqlQuoteBalanceQueryPairStrategy {
    reference: PayloadStrategyRef,
}

impl SqlQuoteBalanceQueryPairStrategy {
    pub fn new() -> Self {
        Self {
            reference: PayloadStrategyRef::new(
                SQL_QUOTE_BALANCE_QUERY_PAIR_ID,
                SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION,
            )
            .expect("the SQL quote-balance strategy identity is static and valid"),
        }
    }

    fn valid_seed(seed: &[u8]) -> bool {
        (8..=64).contains(&seed.len())
            && seed.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
    }
}

impl Default for SqlQuoteBalanceQueryPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for SqlQuoteBalanceQueryPairStrategy {
    fn strategy_ref(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        if !Self::valid_seed(seed.as_bytes()) {
            return Err(PayloadStrategyError::DerivationFailed);
        }
        let mut bytes = seed.as_bytes().to_vec();
        if role == PayloadVariantRole::Candidate {
            bytes.push(b'\'');
        }
        PayloadArtifact::new(self.reference.clone(), role, bytes, limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> PayloadStrategyLimits {
        PayloadStrategyLimits::new(64, 65).unwrap()
    }

    #[test]
    fn catalog_is_exactly_one_quote_and_contains_no_sql_control_syntax() {
        let strategy = SqlQuoteBalanceQueryPairStrategy::new();
        let seed = PayloadSeed::new(b"venom-review-a1b2c3".to_vec(), limits()).unwrap();
        let control = strategy
            .derive_one(PayloadVariantRole::Control, &seed, limits())
            .unwrap();
        let candidate = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed, limits())
            .unwrap();
        assert_eq!(control.as_bytes(), b"venom-review-a1b2c3");
        assert_eq!(candidate.as_bytes(), b"venom-review-a1b2c3'");
        for forbidden in [b";".as_slice(), b"--", b"/*", b"=", b"(", b")"] {
            assert!(!candidate
                .as_bytes()
                .windows(forbidden.len())
                .any(|w| w == forbidden));
        }
    }

    #[test]
    fn unsafe_or_ambiguous_seeds_fail_closed() {
        let strategy = SqlQuoteBalanceQueryPairStrategy::new();
        for value in [
            b"short".as_slice(),
            b"contains space",
            b"contains'quote",
            b"contains;statement",
            b"contains=operator",
        ] {
            let seed = PayloadSeed::new(value.to_vec(), limits()).unwrap();
            for role in [PayloadVariantRole::Control, PayloadVariantRole::Candidate] {
                assert!(matches!(
                    strategy.derive_one(role, &seed, limits()),
                    Err(PayloadStrategyError::DerivationFailed)
                ));
            }
        }
    }

    #[test]
    fn repeat_is_byte_deterministic_and_bounded() {
        let strategy = SqlQuoteBalanceQueryPairStrategy::new();
        let seed = PayloadSeed::new(b"venom-review-repeat".to_vec(), limits()).unwrap();
        let first = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed, limits())
            .unwrap();
        let second = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed, limits())
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.strategy(), strategy.strategy_ref());
    }
}
