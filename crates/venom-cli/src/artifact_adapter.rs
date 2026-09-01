//! Opt-in local-file boundary for the independent artifact signature domain.
//!
//! The adapter accepts exactly one signature manifest and one input file. It
//! performs no discovery, recursion, network access, or file writes; the
//! `venom-artifact` library remains path-agnostic.

use crate::ArtifactOutputFormat;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::path::Path;
use venom_artifact::{
    ArtifactCatalog, ArtifactScanLimits, ArtifactScanner, ArtifactSignaturePack,
    DEFAULT_INPUT_BYTES, DEFAULT_MATCHES_PER_SCAN, DEFAULT_READER_CHUNK_BYTES,
    MAX_SIGNATURE_MANIFEST_BYTES,
};

#[derive(Clone, Copy)]
enum FileRole {
    Signatures,
    Artifact,
}

/// Bounded diagnostics intentionally omit local paths, source bytes, matched
/// bytes, and platform error strings.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactCliError {
    SignatureFileRejected,
    ArtifactFileRejected,
    SignatureReadFailed,
    SignatureManifestTooLarge,
    SignatureManifestInvalid,
    CatalogInvalid,
    ArtifactInputTooLarge,
    ScanFailed,
    ScanIncomplete,
    RenderFailed,
    OutputFailed,
}

impl fmt::Display for ArtifactCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SignatureFileRejected => {
                "signature input must be one explicit readable regular file (links are rejected)"
            },
            Self::ArtifactFileRejected => {
                "artifact input must be one explicit readable regular file (links are rejected)"
            },
            Self::SignatureReadFailed => "signature manifest could not be read",
            Self::SignatureManifestTooLarge => "signature manifest exceeds the compiled byte limit",
            Self::SignatureManifestInvalid => "signature manifest is invalid",
            Self::CatalogInvalid => "signature catalog is invalid",
            Self::ArtifactInputTooLarge => "artifact input exceeds the configured byte limit",
            Self::ScanFailed => "artifact scan failed",
            Self::ScanIncomplete => "artifact scan stopped before complete input coverage",
            Self::RenderFailed => "artifact report could not be rendered",
            Self::OutputFailed => "artifact report could not be written to standard output",
        })
    }
}

impl fmt::Debug for ArtifactCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ArtifactCliError {}

/// Executes the explicit-file adapter. Observations do not change the success
/// exit status; an incomplete scan does.
pub(crate) fn scan_file(
    signatures_path: &Path,
    input_path: &Path,
    format: ArtifactOutputFormat,
) -> Result<(), ArtifactCliError> {
    let signatures = open_regular_readonly(signatures_path, FileRole::Signatures)?;
    let manifest = read_signature_manifest(signatures)?;
    let pack = ArtifactSignaturePack::parse_toml(&manifest)
        .map_err(|_| ArtifactCliError::SignatureManifestInvalid)?;
    let mut builder = ArtifactCatalog::builder();
    builder
        .register(pack)
        .map_err(|_| ArtifactCliError::CatalogInvalid)?;
    let catalog = builder
        .seal()
        .map_err(|_| ArtifactCliError::CatalogInvalid)?;

    let mut input = open_regular_readonly(input_path, FileRole::Artifact)?;
    let input_length = input
        .metadata()
        .map_err(|_| ArtifactCliError::ArtifactFileRejected)?
        .len();
    let limits = limits_for_known_regular_file(input_length)?;
    let scanner =
        ArtifactScanner::new(&catalog, limits).map_err(|_| ArtifactCliError::ScanFailed)?;
    // The opened-file metadata authorizes exactly this many bytes. `Take`
    // prevents a concurrent file growth from expanding that authority, while
    // the scanner's one-byte-larger ceiling lets the bounded reader expose EOF
    // even when the original file length equals the CLI's accepted maximum.
    let report = scanner
        .scan_reader(Read::by_ref(&mut input).take(input_length))
        .map_err(|_| ArtifactCliError::ScanFailed)?;

    let rendered = match format {
        ArtifactOutputFormat::Text => report
            .render_text()
            .map_err(|_| ArtifactCliError::RenderFailed)?,
        ArtifactOutputFormat::Json => report
            .to_json()
            .map_err(|_| ArtifactCliError::RenderFailed)?,
    };
    write_stdout(&rendered)?;
    if report.is_complete() {
        Ok(())
    } else {
        Err(ArtifactCliError::ScanIncomplete)
    }
}

fn limits_for_known_regular_file(
    input_length: u64,
) -> Result<ArtifactScanLimits, ArtifactCliError> {
    if input_length > DEFAULT_INPUT_BYTES {
        return Err(ArtifactCliError::ArtifactInputTooLarge);
    }
    let eof_probe_ceiling = input_length
        .checked_add(1)
        .ok_or(ArtifactCliError::ArtifactInputTooLarge)?;
    ArtifactScanLimits::new(
        eof_probe_ceiling,
        DEFAULT_MATCHES_PER_SCAN,
        DEFAULT_READER_CHUNK_BYTES,
    )
    .map_err(|_| ArtifactCliError::ArtifactInputTooLarge)
}

fn open_regular_readonly(path: &Path, role: FileRole) -> Result<File, ArtifactCliError> {
    let rejected = || match role {
        FileRole::Signatures => ArtifactCliError::SignatureFileRejected,
        FileRole::Artifact => ArtifactCliError::ArtifactFileRejected,
    };
    let path_metadata = std::fs::symlink_metadata(path).map_err(|_| rejected())?;
    if !path_metadata.is_file() || metadata_is_link_like(&path_metadata) {
        return Err(rejected());
    }

    let file = File::open(path).map_err(|_| rejected())?;
    let opened_metadata = file.metadata().map_err(|_| rejected())?;
    if !opened_metadata.is_file() || metadata_is_link_like(&opened_metadata) {
        return Err(rejected());
    }
    Ok(file)
}

fn read_signature_manifest(mut file: File) -> Result<Vec<u8>, ArtifactCliError> {
    let byte_limit = u64::try_from(MAX_SIGNATURE_MANIFEST_BYTES)
        .map_err(|_| ArtifactCliError::SignatureManifestTooLarge)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(byte_limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ArtifactCliError::SignatureReadFailed)?;
    if bytes.len() > MAX_SIGNATURE_MANIFEST_BYTES {
        return Err(ArtifactCliError::SignatureManifestTooLarge);
    }
    Ok(bytes)
}

fn write_stdout(rendered: &str) -> Result<(), ArtifactCliError> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(rendered.as_bytes())
        .map_err(|_| ArtifactCliError::OutputFailed)?;
    if !rendered.ends_with('\n') {
        lock.write_all(b"\n")
            .map_err(|_| ArtifactCliError::OutputFailed)?;
    }
    Ok(())
}

#[cfg(unix)]
fn metadata_is_link_like(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn metadata_is_link_like(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(any(unix, windows)))]
fn metadata_is_link_like(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_are_closed_and_do_not_echo_path_or_source() {
        let secret = "VENOM-ARTIFACT-CLI-MUST-NOT-LEAK-SECRET-123";
        for error in [
            ArtifactCliError::SignatureFileRejected,
            ArtifactCliError::ArtifactFileRejected,
            ArtifactCliError::SignatureReadFailed,
            ArtifactCliError::SignatureManifestTooLarge,
            ArtifactCliError::SignatureManifestInvalid,
            ArtifactCliError::CatalogInvalid,
            ArtifactCliError::ArtifactInputTooLarge,
            ArtifactCliError::ScanFailed,
            ArtifactCliError::ScanIncomplete,
            ArtifactCliError::RenderFailed,
            ArtifactCliError::OutputFailed,
        ] {
            assert!(!format!("{error:?} {error}").contains(secret));
        }
    }

    #[test]
    fn explicit_regular_file_policy_rejects_directories() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            open_regular_readonly(directory.path(), FileRole::Artifact),
            Err(ArtifactCliError::ArtifactFileRejected)
        ));
        assert!(matches!(
            open_regular_readonly(directory.path(), FileRole::Signatures),
            Err(ArtifactCliError::SignatureFileRejected)
        ));
    }

    #[test]
    fn manifest_reader_enforces_the_compiled_limit_before_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let exact_path = directory.path().join("exact.toml");
        std::fs::write(&exact_path, vec![b'a'; MAX_SIGNATURE_MANIFEST_BYTES]).unwrap();
        let exact = open_regular_readonly(&exact_path, FileRole::Signatures).unwrap();
        assert_eq!(
            read_signature_manifest(exact).unwrap().len(),
            MAX_SIGNATURE_MANIFEST_BYTES
        );

        let excess_path = directory.path().join("excess.toml");
        std::fs::write(&excess_path, vec![b'a'; MAX_SIGNATURE_MANIFEST_BYTES + 1]).unwrap();
        let excess = open_regular_readonly(&excess_path, FileRole::Signatures).unwrap();
        assert_eq!(
            read_signature_manifest(excess).unwrap_err(),
            ArtifactCliError::SignatureManifestTooLarge
        );
    }

    #[test]
    fn exact_default_file_length_retains_eof_proof_without_widening_file_authority() {
        let exact = limits_for_known_regular_file(DEFAULT_INPUT_BYTES).expect("exact limit");
        assert_eq!(exact.max_input_bytes(), DEFAULT_INPUT_BYTES + 1);
        assert_eq!(
            limits_for_known_regular_file(DEFAULT_INPUT_BYTES + 1).unwrap_err(),
            ArtifactCliError::ArtifactInputTooLarge
        );
    }
}
