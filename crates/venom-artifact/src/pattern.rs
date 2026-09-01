//! Checked exact/wildcard artifact pattern compilation.

use crate::ArtifactError;
use std::fmt;

/// Maximum bytes represented by one compiled signature.
pub const MAX_PATTERN_BYTES: usize = 256;
/// Minimum exact literal bytes required by the V1 quality contract.
pub const MIN_LITERAL_BYTES: usize = 2;
const MAX_PATTERN_TEXT_BYTES: usize = MAX_PATTERN_BYTES * 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PatternAtom {
    Exact(u8),
    Wildcard,
}

/// A canonical, compiled exact/wildcard byte signature.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactPattern {
    atoms: Box<[PatternAtom]>,
    canonical: String,
    literal_count: usize,
    anchor_offset: usize,
    anchor_byte: u8,
}

impl ArtifactPattern {
    /// Compiles canonical hexadecimal atoms and `?`/`??` wildcard atoms.
    pub fn parse(source: &str) -> Result<Self, ArtifactError> {
        if source.is_empty() || source.len() > MAX_PATTERN_TEXT_BYTES {
            return Err(ArtifactError::InvalidPattern);
        }
        if !source
            .bytes()
            .all(|byte| byte.is_ascii_whitespace() || byte.is_ascii_hexdigit() || byte == b'?')
        {
            return Err(ArtifactError::InvalidPattern);
        }

        let mut atoms = Vec::new();
        for token in source.split_ascii_whitespace() {
            if atoms.len() >= MAX_PATTERN_BYTES {
                return Err(ArtifactError::LimitExceeded {
                    field: "signature pattern bytes",
                    limit: MAX_PATTERN_BYTES,
                });
            }
            let atom = match token {
                "?" | "??" => PatternAtom::Wildcard,
                _ if token.len() == 2 => {
                    let value =
                        u8::from_str_radix(token, 16).map_err(|_| ArtifactError::InvalidPattern)?;
                    PatternAtom::Exact(value)
                },
                _ => return Err(ArtifactError::InvalidPattern),
            };
            atoms.push(atom);
        }
        if atoms.is_empty() {
            return Err(ArtifactError::InvalidPattern);
        }

        let literals = atoms
            .iter()
            .enumerate()
            .filter_map(|(offset, atom)| match atom {
                PatternAtom::Exact(byte) => Some((offset, *byte)),
                PatternAtom::Wildcard => None,
            })
            .collect::<Vec<_>>();
        if literals.len() < MIN_LITERAL_BYTES {
            return Err(ArtifactError::InsufficientLiteralBytes);
        }
        let (anchor_offset, anchor_byte) = literals[0];
        let canonical = atoms
            .iter()
            .map(|atom| match atom {
                PatternAtom::Exact(byte) => format!("{byte:02X}"),
                PatternAtom::Wildcard => "??".to_owned(),
            })
            .collect::<Vec<_>>()
            .join(" ");

        Ok(Self {
            atoms: atoms.into_boxed_slice(),
            canonical,
            literal_count: literals.len(),
            anchor_offset,
            anchor_byte,
        })
    }

    /// Returns the deterministic V1 textual representation.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Returns the number of bytes matched by the signature.
    pub fn len(&self) -> usize {
        self.atoms.len()
    }

    /// Returns whether this compiled pattern is empty (always false for valid patterns).
    pub fn is_empty(&self) -> bool {
        self.atoms.is_empty()
    }

    /// Returns the number of exact literal atoms.
    pub fn literal_count(&self) -> usize {
        self.literal_count
    }

    pub(crate) fn anchor(&self) -> (usize, u8) {
        (self.anchor_offset, self.anchor_byte)
    }

    pub(crate) fn matches_at(&self, input: &[u8], start: usize) -> bool {
        let Some(end) = start.checked_add(self.atoms.len()) else {
            return false;
        };
        let Some(candidate) = input.get(start..end) else {
            return false;
        };
        self.atoms
            .iter()
            .zip(candidate)
            .all(|(atom, byte)| match atom {
                PatternAtom::Exact(expected) => expected == byte,
                PatternAtom::Wildcard => true,
            })
    }
}

impl fmt::Debug for ArtifactPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactPattern")
            .field("pattern_bytes", &self.atoms.len())
            .field("literal_count", &self.literal_count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_lowercase_wildcards_and_spaces() {
        let pattern = ArtifactPattern::parse("41\t  4a\n? 44").expect("pattern");
        assert_eq!(pattern.canonical(), "41 4A ?? 44");
        assert_eq!(pattern.len(), 4);
        assert_eq!(pattern.literal_count(), 3);
        assert_eq!(pattern.anchor(), (0, 0x41));
        assert!(pattern.matches_at(&[0x41, 0x4a, 0xff, 0x44], 0));
        assert!(!pattern.matches_at(&[0x41, 0x4b, 0xff, 0x44], 0));
    }

    #[test]
    fn accepts_leading_wildcard_with_two_literals() {
        let pattern = ArtifactPattern::parse("?? 41 42").expect("pattern");
        assert_eq!(pattern.anchor(), (1, 0x41));
        assert!(pattern.matches_at(&[0xff, 0x41, 0x42], 0));
    }

    #[test]
    fn rejects_empty_malformed_control_and_weak_patterns() {
        for source in ["", "   ", "4", "GG 41", "41\0 42", "41 42 junk"] {
            assert_eq!(
                ArtifactPattern::parse(source),
                Err(ArtifactError::InvalidPattern),
                "source={source:?}"
            );
        }
        for source in ["?? ??", "41 ??"] {
            assert_eq!(
                ArtifactPattern::parse(source),
                Err(ArtifactError::InsufficientLiteralBytes)
            );
        }
    }

    #[test]
    fn enforces_compiled_and_text_limits() {
        let exact_limit = std::iter::repeat_n("41", MAX_PATTERN_BYTES)
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            ArtifactPattern::parse(&exact_limit).expect("limit").len(),
            256
        );
        let over_limit = format!("{exact_limit} 42");
        assert_eq!(
            ArtifactPattern::parse(&over_limit),
            Err(ArtifactError::LimitExceeded {
                field: "signature pattern bytes",
                limit: MAX_PATTERN_BYTES
            })
        );
        assert_eq!(
            ArtifactPattern::parse(&"A".repeat(MAX_PATTERN_TEXT_BYTES + 1)),
            Err(ArtifactError::InvalidPattern)
        );
    }

    #[test]
    fn checked_range_never_panics_at_absurd_start() {
        let pattern = ArtifactPattern::parse("41 42").expect("pattern");
        assert!(!pattern.matches_at(&[0x41, 0x42], usize::MAX));
    }
}
