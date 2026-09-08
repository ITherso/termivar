//! Bounded version keys shared by WordPress production and offline readers.
//!
//! This module owns no advisory policy. A caller must select one closed
//! comparison profile before parsing both operands. The PHP release-subset
//! ordering is pinned to PHP 8.3.0's `versioning.c` at commit
//! `d26068059e83fe40de3430a512471d194119bee0`; only the grammar accepted below
//! is supported, rather than PHP's permissive handling of arbitrary labels.

use std::cmp::Ordering;

use thiserror::Error;

/// Returns the bounded interpretation work for one external association:
/// one visit per range, one parse per declared patched version, and the
/// patched-version by range checks needed to detect source contradictions.
pub(crate) fn checked_external_interpretation_work(
    range_count: usize,
    patched_version_count: usize,
) -> Option<usize> {
    range_count
        .checked_add(patched_version_count)?
        .checked_add(range_count.checked_mul(patched_version_count)?)
}

pub(crate) fn checked_accumulate_external_interpretation_work(
    current: usize,
    range_count: usize,
    patched_version_count: usize,
    limit: usize,
) -> Option<usize> {
    let next = current.checked_add(checked_external_interpretation_work(
        range_count,
        patched_version_count,
    )?)?;
    (next <= limit).then_some(next)
}

pub(crate) const MAX_WORDPRESS_VERSION_COMPONENTS: usize = 8;
pub(crate) const MAX_WORDPRESS_VERSION_BYTES: usize = 64;
const MAX_PHP_NUMERIC_VALUE: u32 = 2_147_483_647;
const MAX_PHP_NUMERIC_DIGITS: usize = 10;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressComparisonProfile {
    NumericDottedV1,
    PhpReleaseSubsetV1,
}

impl WordPressComparisonProfile {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::NumericDottedV1 => "numeric-dotted/v1",
            Self::PhpReleaseSubsetV1 => "php-release-subset/v1",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ProfiledVersionError> {
        match value {
            "numeric-dotted/v1" => Ok(Self::NumericDottedV1),
            "php-release-subset/v1" => Ok(Self::PhpReleaseSubsetV1),
            _ => Err(ProfiledVersionError),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NumericDottedVersion {
    components: Vec<u32>,
}

impl NumericDottedVersion {
    pub fn parse(value: &str) -> Result<Self, NumericDottedVersionError> {
        if value.is_empty() || value.len() > MAX_WORDPRESS_VERSION_BYTES {
            return Err(NumericDottedVersionError);
        }
        let mut components = Vec::new();
        for part in value.split('.') {
            if components.len() == MAX_WORDPRESS_VERSION_COMPONENTS
                || part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return Err(NumericDottedVersionError);
            }
            let component = part
                .bytes()
                .try_fold(0_u32, |value, digit| {
                    value.checked_mul(10)?.checked_add(u32::from(digit - b'0'))
                })
                .ok_or(NumericDottedVersionError)?;
            components.push(component);
        }
        while components.len() > 1 && components.last() == Some(&0) {
            components.pop();
        }
        Ok(Self { components })
    }

    #[must_use]
    pub fn components(&self) -> &[u32] {
        &self.components
    }
}

impl Ord for NumericDottedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.components.cmp(&other.components)
    }
}

impl PartialOrd for NumericDottedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("unsupported numeric-dotted WordPress version")]
pub struct NumericDottedVersionError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhpReleaseStage {
    Dev,
    Alpha,
    Beta,
    Rc,
    PatchLevel,
}

impl PhpReleaseStage {
    const fn rank(self) -> u8 {
        match self {
            Self::Dev => 0,
            Self::Alpha => 1,
            Self::Beta => 2,
            Self::Rc => 3,
            Self::PatchLevel => 5,
        }
    }
}

/// A deliberately bounded subset of PHP's release-version comparison input.
///
/// Separators and recognized aliases are retained only in the caller's raw
/// evidence. This key contains the semantic token sequence used for ordering.
#[derive(Clone, Debug)]
pub struct PhpReleaseSubsetVersion {
    components: [u32; MAX_WORDPRESS_VERSION_COMPONENTS],
    component_count: u8,
    suffix: Option<PhpReleaseStage>,
    suffix_counter: Option<u32>,
}

impl PhpReleaseSubsetVersion {
    pub fn parse(value: &str) -> Result<Self, PhpReleaseSubsetVersionError> {
        if value.is_empty()
            || value.len() > MAX_WORDPRESS_VERSION_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(PhpReleaseSubsetVersionError);
        }

        let bytes = value.as_bytes();
        let mut components = [0_u32; MAX_WORDPRESS_VERSION_COMPONENTS];
        let mut component_count = 0_usize;
        let mut cursor = 0_usize;

        loop {
            if component_count == MAX_WORDPRESS_VERSION_COMPONENTS {
                return Err(PhpReleaseSubsetVersionError);
            }
            components[component_count] = parse_php_number(bytes, &mut cursor)?;
            component_count += 1;
            if cursor == bytes.len() {
                return Ok(Self {
                    components,
                    component_count: component_count as u8,
                    suffix: None,
                    suffix_counter: None,
                });
            }

            if is_php_separator(bytes[cursor]) {
                cursor += 1;
                if cursor == bytes.len() {
                    return Err(PhpReleaseSubsetVersionError);
                }
                if bytes[cursor].is_ascii_digit() {
                    continue;
                }
            }
            break;
        }

        let suffix = parse_php_suffix(bytes, &mut cursor)?;
        let suffix_counter = if cursor == bytes.len() {
            None
        } else {
            if is_php_separator(bytes[cursor]) {
                cursor += 1;
                if cursor == bytes.len() {
                    return Err(PhpReleaseSubsetVersionError);
                }
            }
            let counter = parse_php_number(bytes, &mut cursor)?;
            if cursor != bytes.len() {
                return Err(PhpReleaseSubsetVersionError);
            }
            Some(counter)
        };

        Ok(Self {
            components,
            component_count: component_count as u8,
            suffix: Some(suffix),
            suffix_counter,
        })
    }

    fn part(&self, index: usize) -> Option<PhpVersionPart> {
        let component_count = usize::from(self.component_count);
        if index < component_count {
            return Some(PhpVersionPart::Number(self.components[index]));
        }
        if index == component_count {
            return self.suffix.map(PhpVersionPart::Special);
        }
        if index == component_count + 1 && self.suffix.is_some() {
            return self.suffix_counter.map(PhpVersionPart::Number);
        }
        None
    }

    fn compare(&self, other: &Self) -> Ordering {
        let mut index = 0_usize;
        loop {
            match (self.part(index), other.part(index)) {
                (Some(left), Some(right)) => {
                    let ordering = compare_php_parts(left, right);
                    if ordering != Ordering::Equal {
                        return ordering;
                    }
                    index += 1;
                },
                (None, None) => return Ordering::Equal,
                (Some(PhpVersionPart::Number(_)), None) => return Ordering::Greater,
                (None, Some(PhpVersionPart::Number(_))) => return Ordering::Less,
                (Some(PhpVersionPart::Special(stage)), None) => {
                    return stage.rank().cmp(&PHP_FINAL_FORM_RANK);
                },
                (None, Some(PhpVersionPart::Special(stage))) => {
                    return PHP_FINAL_FORM_RANK.cmp(&stage.rank());
                },
            }
        }
    }
}

impl PartialEq for PhpReleaseSubsetVersion {
    fn eq(&self, other: &Self) -> bool {
        self.compare(other) == Ordering::Equal
    }
}

impl Eq for PhpReleaseSubsetVersion {}

impl Ord for PhpReleaseSubsetVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare(other)
    }
}

impl PartialOrd for PhpReleaseSubsetVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("unsupported PHP release-subset WordPress version")]
pub struct PhpReleaseSubsetVersionError;

const PHP_FINAL_FORM_RANK: u8 = 4;

#[derive(Clone, Copy)]
enum PhpVersionPart {
    Number(u32),
    Special(PhpReleaseStage),
}

fn compare_php_parts(left: PhpVersionPart, right: PhpVersionPart) -> Ordering {
    match (left, right) {
        (PhpVersionPart::Number(left), PhpVersionPart::Number(right)) => left.cmp(&right),
        (PhpVersionPart::Special(left), PhpVersionPart::Special(right)) => {
            left.rank().cmp(&right.rank())
        },
        (PhpVersionPart::Number(_), PhpVersionPart::Special(right)) => {
            PHP_FINAL_FORM_RANK.cmp(&right.rank())
        },
        (PhpVersionPart::Special(left), PhpVersionPart::Number(_)) => {
            left.rank().cmp(&PHP_FINAL_FORM_RANK)
        },
    }
}

fn parse_php_number(bytes: &[u8], cursor: &mut usize) -> Result<u32, PhpReleaseSubsetVersionError> {
    let start = *cursor;
    let mut value = 0_u32;
    while *cursor < bytes.len() && bytes[*cursor].is_ascii_digit() {
        if *cursor - start == MAX_PHP_NUMERIC_DIGITS {
            return Err(PhpReleaseSubsetVersionError);
        }
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(bytes[*cursor] - b'0')))
            .filter(|value| *value <= MAX_PHP_NUMERIC_VALUE)
            .ok_or(PhpReleaseSubsetVersionError)?;
        *cursor += 1;
    }
    if *cursor == start {
        return Err(PhpReleaseSubsetVersionError);
    }
    Ok(value)
}

fn parse_php_suffix(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<PhpReleaseStage, PhpReleaseSubsetVersionError> {
    let remaining = &bytes[*cursor..];
    let (stage, length) = if remaining.starts_with(b"alpha") {
        (PhpReleaseStage::Alpha, 5)
    } else if remaining.starts_with(b"beta") {
        (PhpReleaseStage::Beta, 4)
    } else if remaining.starts_with(b"dev") {
        (PhpReleaseStage::Dev, 3)
    } else if remaining.starts_with(b"RC") || remaining.starts_with(b"rc") {
        (PhpReleaseStage::Rc, 2)
    } else if remaining.starts_with(b"pl") {
        (PhpReleaseStage::PatchLevel, 2)
    } else if remaining.starts_with(b"a") {
        (PhpReleaseStage::Alpha, 1)
    } else if remaining.starts_with(b"b") {
        (PhpReleaseStage::Beta, 1)
    } else if remaining.starts_with(b"p") {
        (PhpReleaseStage::PatchLevel, 1)
    } else {
        return Err(PhpReleaseSubsetVersionError);
    };
    *cursor += length;
    Ok(stage)
}

const fn is_php_separator(byte: u8) -> bool {
    matches!(byte, b'.' | b'-' | b'_' | b'+')
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProfiledVersionKey {
    NumericDotted(NumericDottedVersion),
    PhpReleaseSubset(PhpReleaseSubsetVersion),
}

impl ProfiledVersionKey {
    pub(crate) fn parse(
        profile: WordPressComparisonProfile,
        value: &str,
    ) -> Result<Self, ProfiledVersionError> {
        match profile {
            WordPressComparisonProfile::NumericDottedV1 => NumericDottedVersion::parse(value)
                .map(Self::NumericDotted)
                .map_err(|_| ProfiledVersionError),
            WordPressComparisonProfile::PhpReleaseSubsetV1 => PhpReleaseSubsetVersion::parse(value)
                .map(Self::PhpReleaseSubset)
                .map_err(|_| ProfiledVersionError),
        }
    }

    pub(crate) fn compare(&self, other: &Self) -> Result<Ordering, ProfiledVersionError> {
        match (self, other) {
            (Self::NumericDotted(left), Self::NumericDotted(right)) => Ok(left.cmp(right)),
            (Self::PhpReleaseSubset(left), Self::PhpReleaseSubset(right)) => Ok(left.cmp(right)),
            _ => Err(ProfiledVersionError),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("versions do not belong to one supported comparison profile")]
pub(crate) struct ProfiledVersionError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn php_subset_matches_reviewed_upstream_known_answers() {
        for (left, right, expected) in [
            ("1.0", "1.0.0", Ordering::Less),
            ("2.4.0-beta1", "2.4.0", Ordering::Less),
            ("1.0RC1", "1.0rc1", Ordering::Equal),
            ("1.0-beta2", "1.0-beta10", Ordering::Less),
            ("1.0", "1.0pl1", Ordering::Less),
            ("1.0-alpha1", "1.0a1", Ordering::Equal),
            ("1.0-beta", "1.0-beta0", Ordering::Less),
            ("1.0+beta1", "1.0-beta1", Ordering::Equal),
            ("1.0+1", "1.0.1", Ordering::Equal),
            ("1.01", "1.1", Ordering::Equal),
            ("1.0.1", "1.0pl1", Ordering::Less),
            ("1.0-dev1", "1.0alpha1", Ordering::Less),
            ("1.0alpha1", "1.0-beta1", Ordering::Less),
            ("1.0beta1", "1.0RC1", Ordering::Less),
            ("1.0rc1", "1.0", Ordering::Less),
            ("1.0", "1.0-p1", Ordering::Less),
            ("1_0_rc_1", "1.0RC1", Ordering::Equal),
            ("1.0p1", "1.0pl1", Ordering::Equal),
            ("1.0dev", "1.0dev0", Ordering::Less),
        ] {
            let left = PhpReleaseSubsetVersion::parse(left).unwrap();
            let right = PhpReleaseSubsetVersion::parse(right).unwrap();
            assert_eq!(left.cmp(&right), expected);
            assert_eq!(right.cmp(&left), expected.reverse());
        }
    }

    #[test]
    fn php_subset_rejects_values_outside_the_documented_grammar() {
        for value in [
            "",
            "v1.0",
            "1.0-stable",
            "1.0-ALPHA1",
            "1.0-Beta1",
            "1..0",
            "1.0-",
            "1.0--beta1",
            "1.0beta1pl1",
            "1.0 beta1",
            "1.0\0beta1",
            "1.0é",
            "beta2",
            "alpha1",
            "RC1",
            "pl1",
            "1.0#N#",
            "1.0+vendor1",
            "2147483648",
            "00000000001",
            "1.2.3.4.5.6.7.8.9",
        ] {
            assert_eq!(
                PhpReleaseSubsetVersion::parse(value),
                Err(PhpReleaseSubsetVersionError),
                "unexpectedly accepted {value:?}"
            );
        }
    }

    #[test]
    fn profiles_keep_trailing_zero_semantics_distinct() {
        assert_eq!(
            NumericDottedVersion::parse("1.0").unwrap(),
            NumericDottedVersion::parse("1.0.0").unwrap()
        );
        assert!(
            PhpReleaseSubsetVersion::parse("1.0").unwrap()
                < PhpReleaseSubsetVersion::parse("1.0.0").unwrap()
        );
        assert_eq!(
            PhpReleaseSubsetVersion::parse("01.002").unwrap(),
            PhpReleaseSubsetVersion::parse("1.2").unwrap()
        );
        assert!(PhpReleaseSubsetVersion::parse("2147483647").is_ok());
        assert!(PhpReleaseSubsetVersion::parse("1.2.3.4.5.6.7.8").is_ok());
    }

    #[test]
    fn semantic_aliases_deduplicate_and_profiles_never_compare_implicitly() {
        use std::collections::BTreeSet;

        let aliases = ["1.0-alpha1", "1.0a1", "1_0_a_01"]
            .map(|value| PhpReleaseSubsetVersion::parse(value).unwrap())
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(aliases.len(), 1);

        let numeric =
            ProfiledVersionKey::parse(WordPressComparisonProfile::NumericDottedV1, "1.0").unwrap();
        let php = ProfiledVersionKey::parse(WordPressComparisonProfile::PhpReleaseSubsetV1, "1.0")
            .unwrap();
        let php_alias =
            ProfiledVersionKey::parse(WordPressComparisonProfile::PhpReleaseSubsetV1, "1_0_a_01")
                .unwrap();
        let php_canonical =
            ProfiledVersionKey::parse(WordPressComparisonProfile::PhpReleaseSubsetV1, "1.0-alpha1")
                .unwrap();
        assert_eq!(php_alias, php_canonical);
        assert_ne!(numeric, php);
        assert_eq!(numeric.compare(&php), Err(ProfiledVersionError));
    }

    #[test]
    fn accepted_php_subset_order_is_reflexive_antisymmetric_and_transitive() {
        let values = [
            "1.0dev1",
            "1.0alpha1",
            "1.0beta1",
            "1.0RC1",
            "1.0",
            "1.0.1",
            "1.0pl1",
        ]
        .map(|value| PhpReleaseSubsetVersion::parse(value).unwrap());
        for value in &values {
            assert_eq!(value.cmp(value), Ordering::Equal);
        }
        for pair in values.windows(2) {
            assert!(pair[0] < pair[1]);
            assert!(pair[1] > pair[0]);
        }
        for left in 0..values.len() {
            for middle in 0..values.len() {
                for right in 0..values.len() {
                    if values[left] <= values[middle] && values[middle] <= values[right] {
                        assert!(values[left] <= values[right]);
                    }
                }
            }
        }
    }

    #[test]
    fn external_interpretation_work_charges_the_patched_range_product() {
        assert_eq!(checked_external_interpretation_work(0, 0), Some(0));
        assert_eq!(checked_external_interpretation_work(64, 0), Some(64));
        assert_eq!(checked_external_interpretation_work(0, 64), Some(64));
        assert_eq!(checked_external_interpretation_work(64, 64), Some(4_224));
        assert_eq!(checked_external_interpretation_work(usize::MAX, 1), None);
        assert_eq!(
            checked_external_interpretation_work(usize::MAX / 2 + 1, 2),
            None
        );
        assert_eq!(
            checked_accumulate_external_interpretation_work(95_040, 64, 64, 98_304),
            None
        );
        assert_eq!(
            checked_accumulate_external_interpretation_work(90_000, 64, 64, 98_304),
            Some(94_224)
        );
    }
}
