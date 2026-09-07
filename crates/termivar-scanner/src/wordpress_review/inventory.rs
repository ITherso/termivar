use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::{
    parse_bounded_json, validate_root_url, validate_source_version, WordPressActivationState,
    WordPressComponentIdentity, WordPressComponentKind, WordPressContext,
    WordPressContextComponent, WordPressReviewError, MAX_CONTEXT_JSON_NODES,
    MAX_WORDPRESS_CONTEXT_COMPONENTS, MAX_WORDPRESS_SLUG_BYTES,
};

/// Total bytes accepted across all saved WordPress inventory inputs.
pub const MAX_WORDPRESS_SAVED_INVENTORY_BYTES: usize = 1024 * 1024;
const MAX_WORDPRESS_INVENTORY_INFORMATIONAL_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressLocalInputClass {
    PluginsJson,
    ThemesJson,
    CoreVersionFile,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordPressLocalInputProvenance {
    class: WordPressLocalInputClass,
    byte_length: usize,
    sha256: [u8; 32],
}

impl WordPressLocalInputProvenance {
    #[must_use]
    pub const fn new(
        class: WordPressLocalInputClass,
        byte_length: usize,
        sha256: [u8; 32],
    ) -> Self {
        Self {
            class,
            byte_length,
            sha256,
        }
    }

    #[must_use]
    pub const fn class(&self) -> WordPressLocalInputClass {
        self.class
    }

    #[must_use]
    pub const fn byte_length(&self) -> usize {
        self.byte_length
    }

    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressInventoryCategoryStatus {
    NotSupplied,
    Supplied,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressInventoryEntryStatus {
    CoreVersionSupplied,
    Active,
    Inactive,
    NetworkActive,
    MustUse,
    DropIn,
    Parent,
}

impl WordPressInventoryEntryStatus {
    pub(super) const fn activation(self) -> Option<WordPressActivationState> {
        match self {
            Self::Active => Some(WordPressActivationState::Active),
            Self::Inactive => Some(WordPressActivationState::Inactive),
            Self::NetworkActive => Some(WordPressActivationState::NetworkActive),
            Self::CoreVersionSupplied | Self::MustUse | Self::DropIn | Self::Parent => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressSavedInventoryCoverage {
    core: WordPressInventoryCategoryStatus,
    plugins: WordPressInventoryCategoryStatus,
    themes: WordPressInventoryCategoryStatus,
}

impl WordPressSavedInventoryCoverage {
    #[must_use]
    pub const fn core(&self) -> WordPressInventoryCategoryStatus {
        self.core
    }

    #[must_use]
    pub const fn plugins(&self) -> WordPressInventoryCategoryStatus {
        self.plugins
    }

    #[must_use]
    pub const fn themes(&self) -> WordPressInventoryCategoryStatus {
        self.themes
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressInventoryLimitationReason {
    DropInIdentityIsNotCatalogSlug,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordPressInventoryLimitation {
    declared_name: String,
    version: Option<String>,
    status: WordPressInventoryEntryStatus,
    reason: WordPressInventoryLimitationReason,
}

impl WordPressInventoryLimitation {
    #[must_use]
    pub fn declared_name(&self) -> &str {
        &self.declared_name
    }

    #[must_use]
    pub const fn status(&self) -> WordPressInventoryEntryStatus {
        self.status
    }

    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    #[must_use]
    pub const fn reason(&self) -> WordPressInventoryLimitationReason {
        self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressSavedInventorySummary {
    coverage: WordPressSavedInventoryCoverage,
    component_count: usize,
    limitations: Vec<WordPressInventoryLimitation>,
}

impl WordPressSavedInventorySummary {
    #[must_use]
    pub const fn coverage(&self) -> &WordPressSavedInventoryCoverage {
        &self.coverage
    }

    #[must_use]
    pub const fn component_count(&self) -> usize {
        self.component_count
    }

    #[must_use]
    pub fn limitations(&self) -> &[WordPressInventoryLimitation] {
        &self.limitations
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressSavedInventory {
    context: WordPressContext,
    summary: WordPressSavedInventorySummary,
    expected_inputs: Vec<(WordPressLocalInputClass, usize)>,
}

impl WordPressSavedInventory {
    #[must_use]
    pub const fn summary(&self) -> &WordPressSavedInventorySummary {
        &self.summary
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        WordPressContext,
        WordPressSavedInventorySummary,
        Vec<(WordPressLocalInputClass, usize)>,
    ) {
        (self.context, self.summary, self.expected_inputs)
    }
}

/// Parses explicitly selected, already-saved WP-CLI inventory bytes.
///
/// The caller owns filesystem acquisition. This pure parser neither executes
/// WP-CLI nor authenticates that the inputs describe `root`.
pub fn parse_wordpress_saved_inventory(
    root: Url,
    plugins: Option<&[u8]>,
    themes: Option<&[u8]>,
    core: Option<&[u8]>,
) -> Result<WordPressSavedInventory, WordPressReviewError> {
    if plugins.is_none() && themes.is_none() && core.is_none() {
        return Err(WordPressReviewError::EmptyInput);
    }
    let total_bytes = [plugins, themes, core]
        .into_iter()
        .flatten()
        .try_fold(0_usize, |total, bytes| total.checked_add(bytes.len()))
        .ok_or(WordPressReviewError::InventoryTooLarge)?;
    if total_bytes > MAX_WORDPRESS_SAVED_INVENTORY_BYTES {
        return Err(WordPressReviewError::InventoryTooLarge);
    }
    let root_url = validate_root_url(root.as_str())?;
    let mut expected_inputs = Vec::with_capacity(3);
    let mut rows = Vec::new();
    let mut limitations = Vec::new();

    if let Some(bytes) = plugins {
        expected_inputs.push((WordPressLocalInputClass::PluginsJson, bytes.len()));
        parse_component_rows(
            bytes,
            WordPressComponentKind::Plugin,
            &mut rows,
            &mut limitations,
        )?;
    }
    if let Some(bytes) = themes {
        expected_inputs.push((WordPressLocalInputClass::ThemesJson, bytes.len()));
        parse_component_rows(
            bytes,
            WordPressComponentKind::Theme,
            &mut rows,
            &mut limitations,
        )?;
    }
    if let Some(bytes) = core {
        expected_inputs.push((WordPressLocalInputClass::CoreVersionFile, bytes.len()));
        let version = parse_core_version(bytes)?;
        rows.push(SavedComponent {
            identity: WordPressComponentIdentity::core(),
            version: Some(version),
            status: WordPressInventoryEntryStatus::CoreVersionSupplied,
        });
    }

    if rows
        .len()
        .checked_add(limitations.len())
        .is_none_or(|count| count > MAX_WORDPRESS_CONTEXT_COMPONENTS)
    {
        return Err(WordPressReviewError::InventoryComponentLimitExceeded);
    }
    let mut identities = BTreeSet::new();
    for row in &rows {
        if !identities.insert(row.identity.clone()) {
            return Err(WordPressReviewError::DuplicateComponent);
        }
    }
    rows.sort_by(|left, right| left.identity.cmp(&right.identity));
    limitations.sort();
    let mut limitation_names = BTreeSet::new();
    if limitations
        .iter()
        .any(|limitation| !limitation_names.insert(limitation.declared_name.as_str()))
    {
        return Err(WordPressReviewError::DuplicateComponent);
    }
    expected_inputs.sort_by_key(|(class, _)| *class);

    let components = rows
        .into_iter()
        .map(|row| WordPressContextComponent {
            identity: row.identity,
            version: row.version,
            activation: row.status.activation(),
            patches: Vec::new(),
            inventory_status: Some(row.status),
        })
        .collect::<Vec<_>>();
    let summary = WordPressSavedInventorySummary {
        coverage: WordPressSavedInventoryCoverage {
            core: category_status(core),
            plugins: category_status(plugins),
            themes: category_status(themes),
        },
        component_count: components.len(),
        limitations,
    };
    Ok(WordPressSavedInventory {
        context: WordPressContext {
            root_url,
            hosting_os: None,
            multisite: None,
            components,
        },
        summary,
        expected_inputs,
    })
}

pub(super) fn validate_inventory_provenance(
    expected_inputs: &[(WordPressLocalInputClass, usize)],
    mut provenance: Vec<WordPressLocalInputProvenance>,
) -> Result<Vec<WordPressLocalInputProvenance>, WordPressReviewError> {
    provenance.sort();
    if provenance.len() != expected_inputs.len()
        || provenance
            .windows(2)
            .any(|pair| pair[0].class == pair[1].class)
        || provenance
            .iter()
            .zip(expected_inputs)
            .any(|(actual, expected)| {
                actual.class != expected.0 || actual.byte_length != expected.1
            })
    {
        return Err(WordPressReviewError::InvalidInventoryProvenance);
    }
    Ok(provenance)
}

const fn category_status(bytes: Option<&[u8]>) -> WordPressInventoryCategoryStatus {
    if bytes.is_some() {
        WordPressInventoryCategoryStatus::Supplied
    } else {
        WordPressInventoryCategoryStatus::NotSupplied
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryRowWire {
    name: String,
    status: String,
    version: String,
    #[serde(default)]
    update: Option<InventoryInformationalWire>,
    #[serde(default)]
    update_version: Option<InventoryInformationalWire>,
    #[serde(default)]
    auto_update: Option<InventoryInformationalWire>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum InventoryInformationalWire {
    String(String),
    Bool(bool),
}

struct SavedComponent {
    identity: WordPressComponentIdentity,
    version: Option<String>,
    status: WordPressInventoryEntryStatus,
}

fn parse_component_rows(
    bytes: &[u8],
    kind: WordPressComponentKind,
    rows: &mut Vec<SavedComponent>,
    limitations: &mut Vec<WordPressInventoryLimitation>,
) -> Result<(), WordPressReviewError> {
    let retained = rows
        .len()
        .checked_add(limitations.len())
        .ok_or(WordPressReviewError::InventoryComponentLimitExceeded)?;
    let remaining = MAX_WORDPRESS_CONTEXT_COMPONENTS
        .checked_sub(retained)
        .ok_or(WordPressReviewError::InventoryComponentLimitExceeded)?;
    let value = parse_bounded_json(
        bytes,
        MAX_WORDPRESS_SAVED_INVENTORY_BYTES,
        MAX_CONTEXT_JSON_NODES,
        remaining,
        WordPressReviewError::InventoryTooLarge,
    )?;
    if !matches!(value, Value::Array(_)) {
        return Err(WordPressReviewError::InvalidInventory);
    }
    let parsed: Vec<InventoryRowWire> =
        serde_json::from_value(value).map_err(|_| WordPressReviewError::InvalidInventory)?;
    let mut declared_names = BTreeSet::new();
    if parsed
        .iter()
        .any(|entry| !declared_names.insert(entry.name.as_str()))
    {
        return Err(WordPressReviewError::DuplicateComponent);
    }
    for entry in parsed {
        let status = parse_status(kind, &entry.status)?;
        // These documented ordinary WP-CLI projection fields are deliberately
        // accepted but are not installation identity or version evidence.
        for informational in [
            entry.update.as_ref(),
            entry.update_version.as_ref(),
            entry.auto_update.as_ref(),
        ] {
            validate_discarded_informational(informational)?;
        }
        let version = parse_inventory_version(&entry.version, status)?;
        if status == WordPressInventoryEntryStatus::DropIn {
            validate_drop_in_name(&entry.name)?;
            limitations.push(WordPressInventoryLimitation {
                declared_name: entry.name,
                version,
                status,
                reason: WordPressInventoryLimitationReason::DropInIdentityIsNotCatalogSlug,
            });
            continue;
        }
        let identity = WordPressComponentIdentity::new(kind, entry.name)
            .map_err(|_| WordPressReviewError::InvalidInventory)?;
        rows.push(SavedComponent {
            identity,
            version,
            status,
        });
    }
    Ok(())
}

fn parse_status(
    kind: WordPressComponentKind,
    value: &str,
) -> Result<WordPressInventoryEntryStatus, WordPressReviewError> {
    let status = match (kind, value) {
        (_, "active") => WordPressInventoryEntryStatus::Active,
        (_, "inactive") => WordPressInventoryEntryStatus::Inactive,
        (WordPressComponentKind::Plugin, "active-network") => {
            WordPressInventoryEntryStatus::NetworkActive
        },
        (WordPressComponentKind::Plugin, "must-use") => WordPressInventoryEntryStatus::MustUse,
        (WordPressComponentKind::Plugin, "dropin") => WordPressInventoryEntryStatus::DropIn,
        (WordPressComponentKind::Theme, "parent") => WordPressInventoryEntryStatus::Parent,
        _ => return Err(WordPressReviewError::InvalidInventory),
    };
    Ok(status)
}

fn validate_drop_in_name(value: &str) -> Result<(), WordPressReviewError> {
    if value.is_empty()
        || value.len() > MAX_WORDPRESS_SLUG_BYTES
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(WordPressReviewError::InvalidInventory);
    }
    Ok(())
}

fn validate_discarded_informational(
    value: Option<&InventoryInformationalWire>,
) -> Result<(), WordPressReviewError> {
    match value {
        Some(InventoryInformationalWire::String(value))
            if value.len() > MAX_WORDPRESS_INVENTORY_INFORMATIONAL_BYTES
                || value.chars().any(char::is_control) =>
        {
            Err(WordPressReviewError::InvalidInventory)
        },
        Some(InventoryInformationalWire::Bool(value)) => {
            let _ = *value;
            Ok(())
        },
        Some(InventoryInformationalWire::String(_)) | None => Ok(()),
    }
}

fn parse_core_version(bytes: &[u8]) -> Result<String, WordPressReviewError> {
    if bytes.is_empty() || bytes.len() > super::MAX_WORDPRESS_VERSION_BYTES + 2 {
        return Err(WordPressReviewError::InvalidInventory);
    }
    let line = if let Some(line) = bytes.strip_suffix(b"\r\n") {
        line
    } else if let Some(line) = bytes.strip_suffix(b"\n") {
        line
    } else {
        bytes
    };
    if line.contains(&b'\n') || line.contains(&b'\r') {
        return Err(WordPressReviewError::InvalidInventory);
    }
    let line = std::str::from_utf8(line).map_err(|_| WordPressReviewError::InvalidInventory)?;
    if line.chars().any(char::is_whitespace) {
        return Err(WordPressReviewError::InvalidInventory);
    }
    validate_source_version(line).map_err(|_| WordPressReviewError::InvalidInventory)
}

fn parse_inventory_version(
    value: &str,
    status: WordPressInventoryEntryStatus,
) -> Result<Option<String>, WordPressReviewError> {
    if value.is_empty() {
        return if matches!(
            status,
            WordPressInventoryEntryStatus::MustUse | WordPressInventoryEntryStatus::DropIn
        ) {
            Ok(None)
        } else {
            Err(WordPressReviewError::InvalidInventory)
        };
    }
    if value.chars().any(char::is_whitespace) {
        return Err(WordPressReviewError::InvalidInventory);
    }
    validate_source_version(value)
        .map(Some)
        .map_err(|_| WordPressReviewError::InvalidInventory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wordpress_review::{
        evaluate_wordpress_review, parse_wordpress_context, WordPressComponentEvidenceClass,
        WordPressEvidenceSource, WordPressReviewInputs,
    };

    const PLUGINS: &str = r#"[
      {"name":"zeta-plugin","status":"inactive","version":"vendor-release-x",
       "update":"none","update_version":"","auto_update":"off"},
      {"name":"network-plugin","status":"active-network","version":"2.0"},
      {"name":"must-use-plugin","status":"must-use","version":""},
      {"name":"object-cache.php","status":"dropin","version":""}
    ]"#;
    const THEMES: &str = r#"[
      {"name":"parent-theme","status":"parent","version":"3.1"},
      {"name":"active-theme","status":"active","version":"4.0"}
    ]"#;
    const CORE: &[u8] = b"6.9.4-beta1\r\n";

    fn root() -> Url {
        Url::parse("https://example.test/").unwrap()
    }

    fn provenance(
        plugins: Option<&[u8]>,
        themes: Option<&[u8]>,
        core: Option<&[u8]>,
    ) -> Vec<WordPressLocalInputProvenance> {
        let mut result = Vec::new();
        if let Some(bytes) = core {
            result.push(WordPressLocalInputProvenance::new(
                WordPressLocalInputClass::CoreVersionFile,
                bytes.len(),
                [3; 32],
            ));
        }
        if let Some(bytes) = themes {
            result.push(WordPressLocalInputProvenance::new(
                WordPressLocalInputClass::ThemesJson,
                bytes.len(),
                [2; 32],
            ));
        }
        if let Some(bytes) = plugins {
            result.push(WordPressLocalInputProvenance::new(
                WordPressLocalInputClass::PluginsJson,
                bytes.len(),
                [1; 32],
            ));
        }
        result
    }

    #[test]
    fn saved_inventory_preserves_coverage_statuses_limitations_and_provenance() {
        let plugin_bytes = PLUGINS.as_bytes();
        let theme_bytes = THEMES.as_bytes();
        let inventory = parse_wordpress_saved_inventory(
            root(),
            Some(plugin_bytes),
            Some(theme_bytes),
            Some(CORE),
        )
        .unwrap();

        assert_eq!(
            inventory.summary().coverage().plugins(),
            WordPressInventoryCategoryStatus::Supplied
        );
        assert_eq!(
            inventory.summary().coverage().themes(),
            WordPressInventoryCategoryStatus::Supplied
        );
        assert_eq!(
            inventory.summary().coverage().core(),
            WordPressInventoryCategoryStatus::Supplied
        );
        assert_eq!(inventory.summary().component_count(), 6);
        assert_eq!(inventory.summary().limitations().len(), 1);
        let limitation = &inventory.summary().limitations()[0];
        assert_eq!(limitation.declared_name(), "object-cache.php");
        assert_eq!(limitation.status(), WordPressInventoryEntryStatus::DropIn);
        assert_eq!(limitation.version(), None);
        assert_eq!(
            limitation.reason(),
            WordPressInventoryLimitationReason::DropInIdentityIsNotCatalogSlug
        );

        let inputs = WordPressReviewInputs::from_saved_inventory(
            inventory,
            None,
            provenance(Some(plugin_bytes), Some(theme_bytes), Some(CORE)),
        )
        .unwrap();
        let result = evaluate_wordpress_review(&[], &inputs).unwrap();
        assert_eq!(result.local_input_provenance().len(), 3);
        assert_eq!(
            result.local_input_provenance()[0].class(),
            WordPressLocalInputClass::PluginsJson
        );
        assert_eq!(result.local_input_provenance()[0].sha256(), &[1; 32]);
        assert_eq!(result.inventory_summary(), inputs.inventory_summary());

        let zeta = result
            .components()
            .iter()
            .find(|component| component.identity().slug() == "zeta-plugin")
            .unwrap();
        assert_eq!(
            zeta.evidence_class(),
            WordPressComponentEvidenceClass::OperatorSupplied
        );
        assert_eq!(
            zeta.identity_sources(),
            &[WordPressEvidenceSource::OperatorContext]
        );
        assert_eq!(zeta.versions()[0].value(), "vendor-release-x");
        assert_eq!(
            zeta.inventory_status(),
            Some(WordPressInventoryEntryStatus::Inactive)
        );
        assert_eq!(zeta.activation(), Some(WordPressActivationState::Inactive));

        let network = result
            .components()
            .iter()
            .find(|component| component.identity().slug() == "network-plugin")
            .unwrap();
        assert_eq!(
            network.inventory_status(),
            Some(WordPressInventoryEntryStatus::NetworkActive)
        );
        assert_eq!(
            network.activation(),
            Some(WordPressActivationState::NetworkActive)
        );

        let must_use = result
            .components()
            .iter()
            .find(|component| component.identity().slug() == "must-use-plugin")
            .unwrap();
        assert!(must_use.versions().is_empty());
        assert_eq!(
            must_use.inventory_status(),
            Some(WordPressInventoryEntryStatus::MustUse)
        );
        assert_eq!(must_use.activation(), None);

        let parent = result
            .components()
            .iter()
            .find(|component| component.identity().slug() == "parent-theme")
            .unwrap();
        assert_eq!(
            parent.inventory_status(),
            Some(WordPressInventoryEntryStatus::Parent)
        );
        assert_eq!(parent.activation(), None);
        assert!(!result
            .components()
            .iter()
            .any(|component| component.identity().slug() == "object-cache.php"));
    }

    #[test]
    fn categories_not_selected_remain_explicitly_not_supplied() {
        let inventory = parse_wordpress_saved_inventory(root(), Some(b"[]"), None, None).unwrap();
        assert_eq!(
            inventory.summary().coverage().plugins(),
            WordPressInventoryCategoryStatus::Supplied
        );
        assert_eq!(
            inventory.summary().coverage().themes(),
            WordPressInventoryCategoryStatus::NotSupplied
        );
        assert_eq!(
            inventory.summary().coverage().core(),
            WordPressInventoryCategoryStatus::NotSupplied
        );
        assert_eq!(inventory.summary().component_count(), 0);
    }

    #[test]
    fn strict_inventory_rows_reject_unknown_duplicate_or_inapplicable_fields() {
        let unknown = br#"[{"name":"sample","status":"active","version":"1.0","path":"/tmp/x"}]"#;
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(unknown), None, None),
            Err(WordPressReviewError::InvalidInventory)
        );

        let duplicate_key =
            br#"[{"name":"sample","name":"other","status":"active","version":"1.0"}]"#;
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(duplicate_key), None, None),
            Err(WordPressReviewError::DuplicateKey)
        );

        let plugin_parent = br#"[{"name":"sample","status":"parent","version":"1.0"}]"#;
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(plugin_parent), None, None),
            Err(WordPressReviewError::InvalidInventory)
        );

        let theme_network = br#"[{"name":"sample","status":"active-network","version":"1.0"}]"#;
        assert_eq!(
            parse_wordpress_saved_inventory(root(), None, Some(theme_network), None),
            Err(WordPressReviewError::InvalidInventory)
        );
    }

    #[test]
    fn duplicate_component_and_drop_in_rows_fail_deterministically() {
        let duplicate = br#"[
          {"name":"sample","status":"active","version":"1.0"},
          {"name":"sample","status":"inactive","version":"1.1"}
        ]"#;
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(duplicate), None, None),
            Err(WordPressReviewError::DuplicateComponent)
        );

        let duplicate_drop_in = br#"[
          {"name":"object-cache.php","status":"dropin","version":""},
          {"name":"object-cache.php","status":"dropin","version":"1.0"}
        ]"#;
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(duplicate_drop_in), None, None),
            Err(WordPressReviewError::DuplicateComponent)
        );

        let conflicting_classification = br#"[
          {"name":"sample","status":"active","version":"1.0"},
          {"name":"sample","status":"dropin","version":""}
        ]"#;
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(conflicting_classification), None, None),
            Err(WordPressReviewError::DuplicateComponent)
        );
    }

    #[test]
    fn plugin_and_theme_with_same_slug_remain_distinct_component_identities() {
        let plugin = br#"[{"name":"shared-name","status":"inactive","version":"1.0"}]"#;
        let theme = br#"[{"name":"shared-name","status":"parent","version":"2.0"}]"#;
        let inventory =
            parse_wordpress_saved_inventory(root(), Some(plugin), Some(theme), None).unwrap();
        assert_eq!(inventory.context.components().len(), 2);
        assert_eq!(
            inventory.context.components()[0].identity().kind(),
            WordPressComponentKind::Plugin
        );
        assert_eq!(
            inventory.context.components()[1].identity().kind(),
            WordPressComponentKind::Theme
        );
    }

    #[test]
    fn inventory_versions_reject_console_whitespace_but_keep_unsupported_labels() {
        for version in [" 1.0", "1.0 ", "1.0 beta"] {
            let document =
                format!(r#"[{{"name":"sample","status":"active","version":"{version}"}}]"#);
            assert_eq!(
                parse_wordpress_saved_inventory(root(), Some(document.as_bytes()), None, None),
                Err(WordPressReviewError::InvalidInventory)
            );
        }
        let unsupported = br#"[{"name":"sample","status":"active","version":"vendor-build-x"}]"#;
        let inventory =
            parse_wordpress_saved_inventory(root(), Some(unsupported), None, None).unwrap();
        assert_eq!(
            inventory.context.components()[0].version(),
            Some("vendor-build-x")
        );

        let empty_active = br#"[{"name":"sample","status":"active","version":""}]"#;
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(empty_active), None, None),
            Err(WordPressReviewError::InvalidInventory)
        );
    }

    #[test]
    fn discarded_default_fields_are_scalar_and_independently_bounded() {
        let ordinary_scalars = br#"[{
          "name":"sample","status":"active","version":"1.0",
          "update":false,"update_version":null,"auto_update":true
        }]"#;
        let inventory =
            parse_wordpress_saved_inventory(root(), Some(ordinary_scalars), None, None).unwrap();
        assert_eq!(inventory.context.components().len(), 1);
        assert_eq!(
            inventory.context.components()[0].identity().slug(),
            "sample"
        );
        assert_eq!(inventory.context.components()[0].version(), Some("1.0"));
        assert_eq!(
            inventory.context.components()[0].inventory_status(),
            Some(WordPressInventoryEntryStatus::Active)
        );
        assert!(inventory.context.components()[0].patches().is_empty());

        let oversized = "x".repeat(MAX_WORDPRESS_INVENTORY_INFORMATIONAL_BYTES + 1);
        let document = format!(
            r#"[{{"name":"sample","status":"active","version":"1.0","update":"{oversized}"}}]"#
        );
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(document.as_bytes()), None, None),
            Err(WordPressReviewError::InvalidInventory)
        );

        let control =
            b"[{\"name\":\"sample\",\"status\":\"active\",\"version\":\"1.0\",\"auto_update\":\"on\\nnoise\"}]";
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(control), None, None),
            Err(WordPressReviewError::InvalidInventory)
        );

        let nested =
            br#"[{"name":"sample","status":"active","version":"1.0","update":{"state":"none"}}]"#;
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(nested), None, None),
            Err(WordPressReviewError::InvalidInventory)
        );

        let array =
            br#"[{"name":"sample","status":"active","version":"1.0","update_version":["2.0"]}]"#;
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(array), None, None),
            Err(WordPressReviewError::InvalidInventory)
        );

        let number = br#"[{"name":"sample","status":"active","version":"1.0","auto_update":1}]"#;
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(number), None, None),
            Err(WordPressReviewError::InvalidInventory)
        );
    }

    #[test]
    fn core_version_accepts_only_one_exact_line_with_optional_final_newline() {
        for bytes in [
            b"6.9.4-beta1".as_slice(),
            b"6.9.4-beta1\n".as_slice(),
            b"6.9.4-beta1\r\n".as_slice(),
        ] {
            let inventory =
                parse_wordpress_saved_inventory(root(), None, None, Some(bytes)).unwrap();
            assert_eq!(
                inventory.context.components()[0].version(),
                Some("6.9.4-beta1")
            );
        }
        for bytes in [
            b" 6.9.4".as_slice(),
            b"6.9.4 ".as_slice(),
            b"6.9.4\nnoise".as_slice(),
            b"6.9.4\n\n".as_slice(),
            b"".as_slice(),
        ] {
            assert_eq!(
                parse_wordpress_saved_inventory(root(), None, None, Some(bytes)),
                Err(WordPressReviewError::InvalidInventory)
            );
        }
    }

    #[test]
    fn provenance_must_match_every_supplied_input_class_and_exact_length() {
        let bytes = b"[]";
        let inventory = parse_wordpress_saved_inventory(root(), Some(bytes), None, None).unwrap();
        assert_eq!(
            WordPressReviewInputs::from_saved_inventory(inventory.clone(), None, Vec::new()),
            Err(WordPressReviewError::InvalidInventoryProvenance)
        );
        assert_eq!(
            WordPressReviewInputs::from_saved_inventory(
                inventory.clone(),
                None,
                vec![WordPressLocalInputProvenance::new(
                    WordPressLocalInputClass::PluginsJson,
                    bytes.len() + 1,
                    [1; 32],
                )],
            ),
            Err(WordPressReviewError::InvalidInventoryProvenance)
        );
        assert_eq!(
            WordPressReviewInputs::from_saved_inventory(
                inventory.clone(),
                None,
                vec![WordPressLocalInputProvenance::new(
                    WordPressLocalInputClass::ThemesJson,
                    bytes.len(),
                    [1; 32],
                )],
            ),
            Err(WordPressReviewError::InvalidInventoryProvenance)
        );
        assert_eq!(
            WordPressReviewInputs::from_saved_inventory(
                inventory,
                None,
                vec![
                    WordPressLocalInputProvenance::new(
                        WordPressLocalInputClass::PluginsJson,
                        bytes.len(),
                        [1; 32],
                    ),
                    WordPressLocalInputProvenance::new(
                        WordPressLocalInputClass::PluginsJson,
                        bytes.len(),
                        [2; 32],
                    ),
                ],
            ),
            Err(WordPressReviewError::InvalidInventoryProvenance)
        );
    }

    #[test]
    fn aggregate_byte_and_component_limits_are_enforced_before_evaluation() {
        let oversized = vec![b' '; MAX_WORDPRESS_SAVED_INVENTORY_BYTES + 1];
        assert_eq!(
            parse_wordpress_saved_inventory(root(), Some(&oversized), None, None),
            Err(WordPressReviewError::InventoryTooLarge)
        );

        let rows = (0..MAX_WORDPRESS_CONTEXT_COMPONENTS)
            .map(|index| {
                format!(r#"{{"name":"plugin-{index}","status":"active","version":"1.0"}}"#)
            })
            .collect::<Vec<_>>()
            .join(",");
        let document = format!("[{rows}]");
        assert_eq!(
            parse_wordpress_saved_inventory(
                root(),
                Some(document.as_bytes()),
                None,
                Some(b"6.9.4"),
            ),
            Err(WordPressReviewError::InventoryComponentLimitExceeded)
        );
    }

    #[test]
    fn inventory_requires_at_least_one_explicit_input() {
        assert_eq!(
            parse_wordpress_saved_inventory(root(), None, None, None),
            Err(WordPressReviewError::EmptyInput)
        );
    }

    #[test]
    fn existing_context_inputs_do_not_acquire_saved_inventory_metadata() {
        let context = parse_wordpress_context(
            br#"{
              "schema":"security.wordpress-context/v1",
              "root":"https://example.test/",
              "components":[
                {"kind":"plugin","slug":"sample","version":"1.0","activation":"active"}
              ]
            }"#,
        )
        .unwrap();
        assert_eq!(context.components()[0].inventory_status(), None);

        let result =
            evaluate_wordpress_review(&[], &WordPressReviewInputs::new(Some(context), None))
                .unwrap();
        assert_eq!(result.inventory_summary(), None);
        assert!(result.local_input_provenance().is_empty());
        assert_eq!(result.components()[0].inventory_status(), None);
    }
}
