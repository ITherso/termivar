use crate::ProviderError;
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Minimum administrator bearer-token bytes.
pub const MIN_ADMIN_TOKEN_BYTES: usize = 32;
/// Maximum administrator bearer-token bytes.
pub const MAX_ADMIN_TOKEN_BYTES: usize = 4_096;

const ADMIN_TOKEN_DIGEST_DOMAIN: &[u8] = b"security.termivar-oast.admin-token-digest/v1\0";
const SESSION_TOKEN_DIGEST_DOMAIN: &[u8] = b"security.termivar-oast.session-token-digest/v1\0";

/// Move-only operator administrator material.
///
/// The provider consumes this wrapper during construction and retains only a
/// domain-separated digest. Callers must supply high-entropy material; length
/// and safe bearer bytes are enforced, while entropy is not guessed.
pub struct AdminToken {
    bytes: Zeroizing<Vec<u8>>,
}

impl AdminToken {
    /// Validates bounded visible ASCII suitable for one Bearer credential.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, ProviderError> {
        if !valid_admin_bytes(&bytes) {
            bytes.zeroize();
            return Err(ProviderError::InvalidAdminToken);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    pub(crate) fn expose_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl fmt::Debug for AdminToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminToken(<redacted>)")
    }
}

pub(crate) struct SecretDigest([u8; 32]);

impl SecretDigest {
    pub(crate) fn admin(token: &AdminToken) -> Self {
        digest(ADMIN_TOKEN_DIGEST_DOMAIN, token.expose_bytes())
    }

    pub(crate) fn session(token: &[u8]) -> Self {
        digest(SESSION_TOKEN_DIGEST_DOMAIN, token)
    }

    pub(crate) fn matches_admin(&self, candidate: &[u8]) -> bool {
        if !valid_admin_bytes(candidate) {
            return false;
        }
        bool::from(
            self.0
                .ct_eq(&digest(ADMIN_TOKEN_DIGEST_DOMAIN, candidate).0),
        )
    }

    pub(crate) fn matches_session(&self, candidate: &[u8]) -> bool {
        bool::from(
            self.0
                .ct_eq(&digest(SESSION_TOKEN_DIGEST_DOMAIN, candidate).0),
        )
    }
}

impl fmt::Debug for SecretDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretDigest(<redacted>)")
    }
}

impl Drop for SecretDigest {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn digest(domain: &[u8], secret: &[u8]) -> SecretDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(secret);
    SecretDigest(hasher.finalize().into())
}

fn valid_admin_bytes(bytes: &[u8]) -> bool {
    (MIN_ADMIN_TOKEN_BYTES..=MAX_ADMIN_TOKEN_BYTES).contains(&bytes.len())
        && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"ADMIN-TOKEN-MUST-NOT-LEAK-7D91A04F";

    #[test]
    fn admin_material_is_bounded_move_only_and_redacted() {
        let token = AdminToken::new(SECRET.to_vec()).unwrap();
        assert_eq!(format!("{token:?}"), "AdminToken(<redacted>)");
        for invalid in [
            Vec::new(),
            vec![b'a'; MIN_ADMIN_TOKEN_BYTES - 1],
            vec![b'a'; MAX_ADMIN_TOKEN_BYTES + 1],
            [vec![b'a'; MIN_ADMIN_TOKEN_BYTES], vec![b'\n']].concat(),
        ] {
            assert!(matches!(
                AdminToken::new(invalid),
                Err(ProviderError::InvalidAdminToken)
            ));
        }
        assert!(!format!("{:?}", ProviderError::InvalidAdminToken)
            .as_bytes()
            .windows(SECRET.len())
            .any(|window| window == SECRET));
    }

    #[test]
    fn comparisons_are_domain_separated_and_constant_time_primitives() {
        let token = AdminToken::new(SECRET.to_vec()).unwrap();
        let digest = SecretDigest::admin(&token);
        assert!(digest.matches_admin(SECRET));
        assert!(!digest.matches_admin(b"WRONG-TOKEN-MUST-NOT-LEAK-7D91A04F"));
        assert_ne!(SecretDigest::session(SECRET).0, digest.0);
    }
}
