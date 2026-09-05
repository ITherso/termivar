//! CLI-owned publication of one completed assessment in two report formats.
//!
//! This module owns no assessment or network authority. It borrows one
//! completed [`AssessmentRunReport`], renders the existing HTML and JSON
//! projections, and publishes those bytes into an exclusively created local
//! directory. `manifest.json` is the completion marker; the directory itself
//! is not presented as an atomic snapshot.

use same_file::Handle;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
};
use termivar_scanner::{
    web_runtime::AssessmentRunReport, ReportFormat, ReportGenerator, MAX_RENDERED_REPORT_BYTES,
};

pub(crate) const REPORT_BUNDLE_SCHEMA: &str = "termivar-report-bundle/v1";
pub(crate) const ASSESSMENT_HTML_NAME: &str = "assessment.html";
pub(crate) const ASSESSMENT_JSON_NAME: &str = "assessment.json";
pub(crate) const MANIFEST_NAME: &str = "manifest.json";
pub(crate) const MAX_MANIFEST_BYTES: usize = 64 * 1_024;
pub(crate) const MAX_REPORT_BUNDLE_BYTES: usize =
    MAX_RENDERED_REPORT_BYTES * 2 + MAX_MANIFEST_BYTES;

const HTML_TEMP_NAME: &str = ".assessment.html.termivar.tmp";
const JSON_TEMP_NAME: &str = ".assessment.json.termivar.tmp";
const MANIFEST_TEMP_NAME: &str = ".manifest.json.termivar.tmp";

/// Fully rendered, bounded bundle bytes derived from one assessment value.
pub(crate) struct RenderedReportBundle {
    html: Vec<u8>,
    json: Vec<u8>,
    manifest: Vec<u8>,
}

impl fmt::Debug for RenderedReportBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedReportBundle")
            .field("html_bytes", &self.html.len())
            .field("json_bytes", &self.json.len())
            .field("manifest_bytes", &self.manifest.len())
            .finish()
    }
}

impl RenderedReportBundle {
    fn total_len(&self) -> Option<usize> {
        self.html
            .len()
            .checked_add(self.json.len())?
            .checked_add(self.manifest.len())
    }

    #[cfg(test)]
    fn from_test_bytes(html: &[u8], json: &[u8]) -> Self {
        let manifest = build_manifest(
            html,
            json,
            ManifestAssessment {
                profile: "web-review",
                status: "complete",
                subject_count: 0,
                item_count: 0,
            },
        )
        .expect("small test bundle must serialize");
        Self {
            html: html.to_vec(),
            json: json.to_vec(),
            manifest,
        }
    }
}

/// Renders HTML and JSON from the same immutable completed assessment.
pub(crate) fn render_report_bundle(
    report: &AssessmentRunReport,
) -> Result<RenderedReportBundle, Box<dyn Error>> {
    render_report_bundle_with(report, existing_assessment_renderer)
}

type AssessmentRenderer = fn(&AssessmentRunReport, ReportFormat) -> Result<String, Box<dyn Error>>;

fn existing_assessment_renderer(
    report: &AssessmentRunReport,
    format: ReportFormat,
) -> Result<String, Box<dyn Error>> {
    ReportGenerator::generate_assessment(report, format).map_err(Into::into)
}

fn render_report_bundle_with(
    report: &AssessmentRunReport,
    render: AssessmentRenderer,
) -> Result<RenderedReportBundle, Box<dyn Error>> {
    let html = render(report, ReportFormat::Html)?.into_bytes();
    let json = render(report, ReportFormat::Json)?.into_bytes();
    let manifest = build_manifest(
        &html,
        &json,
        ManifestAssessment {
            profile: report.profile().profile().id(),
            status: "complete",
            subject_count: report.subject_count(),
            item_count: report.item_count(),
        },
    )?;
    let bundle = RenderedReportBundle {
        html,
        json,
        manifest,
    };
    validate_bundle_sizes(&bundle)?;
    Ok(bundle)
}

fn validate_bundle_sizes(bundle: &RenderedReportBundle) -> io::Result<()> {
    if bundle.html.len() > MAX_RENDERED_REPORT_BYTES
        || bundle.json.len() > MAX_RENDERED_REPORT_BYTES
        || bundle.manifest.len() > MAX_MANIFEST_BYTES
        || bundle
            .total_len()
            .is_none_or(|len| len > MAX_REPORT_BUNDLE_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rendered report bundle exceeds the byte limit",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct ReportBundleManifest<'a> {
    schema: &'static str,
    producer: ManifestProducer,
    assessment: ManifestAssessment<'a>,
    files: [ManifestFile<'a>; 2],
}

#[derive(Serialize)]
struct ManifestProducer {
    product: &'static str,
    version: &'static str,
}

#[derive(Clone, Copy, Serialize)]
struct ManifestAssessment<'a> {
    profile: &'a str,
    status: &'static str,
    subject_count: usize,
    item_count: usize,
}

#[derive(Serialize)]
struct ManifestFile<'a> {
    name: &'a str,
    format: &'a str,
    media_type: &'a str,
    byte_length: u64,
    sha256: String,
}

fn build_manifest(
    html: &[u8],
    json: &[u8],
    assessment: ManifestAssessment<'_>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let files = [
        manifest_file(ASSESSMENT_HTML_NAME, ReportFormat::Html, html)?,
        manifest_file(ASSESSMENT_JSON_NAME, ReportFormat::Json, json)?,
    ];
    let document = ReportBundleManifest {
        schema: REPORT_BUNDLE_SCHEMA,
        producer: ManifestProducer {
            product: "Termivar",
            version: env!("CARGO_PKG_VERSION"),
        },
        assessment,
        files,
    };
    let mut rendered = serde_json::to_vec_pretty(&document)?;
    rendered.push(b'\n');
    if rendered.len() > MAX_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "report bundle manifest exceeds the byte limit",
        )
        .into());
    }
    Ok(rendered)
}

fn manifest_file<'a>(
    name: &'a str,
    format: ReportFormat,
    bytes: &[u8],
) -> Result<ManifestFile<'a>, io::Error> {
    let digest = Sha256::digest(bytes);
    Ok(ManifestFile {
        name,
        format: format.as_str(),
        media_type: format.media_type(),
        byte_length: u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "report byte length cannot be represented in the manifest",
            )
        })?,
        sha256: format!("{digest:x}"),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationStage {
    HtmlWrite,
    HtmlSync,
    HtmlLink,
    HtmlTempCleanup,
    JsonWrite,
    JsonSync,
    JsonLink,
    JsonTempCleanup,
    PayloadDirectorySync,
    ManifestWrite,
    ManifestSync,
    ManifestLink,
    ManifestTempCleanup,
    CommittedDirectorySync,
}

trait PublicationHook {
    fn check(&mut self, stage: PublicationStage) -> io::Result<()>;
}

struct NoopPublicationHook;

impl PublicationHook for NoopPublicationHook {
    fn check(&mut self, _stage: PublicationStage) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct OwnedFilePaths {
    identity: Option<Handle>,
    temporary: bool,
    final_path: bool,
}

#[derive(Default)]
struct OwnedBundlePaths {
    html: OwnedFilePaths,
    json: OwnedFilePaths,
    manifest: OwnedFilePaths,
}

/// Exclusive ownership of a newly created report-bundle directory.
pub(crate) struct ReportBundleReservation {
    path: PathBuf,
    identity: Option<Handle>,
    owned: OwnedBundlePaths,
    committed: bool,
    released: bool,
}

impl fmt::Debug for ReportBundleReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReportBundleReservation")
            .field("identity_retained", &self.identity.is_some())
            .field("committed", &self.committed)
            .field("released", &self.released)
            .finish_non_exhaustive()
    }
}

/// Validates and exclusively reserves a new bundle directory.
pub(crate) fn reserve_report_bundle(
    path: Option<&Path>,
) -> io::Result<Option<ReportBundleReservation>> {
    path.map(ReportBundleReservation::reserve).transpose()
}

impl ReportBundleReservation {
    fn reserve(path: &Path) -> io::Result<Self> {
        validate_destination(path)?;
        create_private_directory(path).map_err(|error| {
            let message = if error.kind() == io::ErrorKind::AlreadyExists {
                "report bundle destination already exists"
            } else {
                "report bundle destination could not be reserved"
            };
            io::Error::new(error.kind(), message)
        })?;
        let identity = match Handle::from_path(path) {
            Ok(identity) => identity,
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    "report bundle directory identity could not be retained; cleanup was not attempted and the uncommitted directory may remain",
                ));
            },
        };
        Ok(Self {
            path: path.to_owned(),
            identity: Some(identity),
            owned: OwnedBundlePaths::default(),
            committed: false,
            released: false,
        })
    }

    /// Publishes both payloads and commits the manifest last.
    pub(crate) fn publish(
        self,
        bundle: &RenderedReportBundle,
    ) -> Result<(), ReportBundlePublicationError> {
        let mut hook = NoopPublicationHook;
        self.publish_with_hook(bundle, &mut hook)
    }

    fn publish_with_hook(
        mut self,
        bundle: &RenderedReportBundle,
        hook: &mut impl PublicationHook,
    ) -> Result<(), ReportBundlePublicationError> {
        let result = self.publish_inner(bundle, hook);
        match result {
            Ok(()) => {
                self.released = true;
                Ok(())
            },
            Err(source) if self.committed => {
                self.released = true;
                Err(ReportBundlePublicationError {
                    source,
                    cleanup: None,
                    committed: true,
                })
            },
            Err(source) => {
                let cleanup = self.cleanup_precommit().err();
                self.released = cleanup.is_none();
                Err(ReportBundlePublicationError {
                    source,
                    cleanup,
                    committed: false,
                })
            },
        }
    }

    /// Removes only tracked files from an uncommitted owned directory.
    pub(crate) fn abort(mut self) -> io::Result<()> {
        let result = self.cleanup_precommit();
        self.released = result.is_ok();
        result
    }

    fn publish_inner(
        &mut self,
        bundle: &RenderedReportBundle,
        hook: &mut impl PublicationHook,
    ) -> io::Result<()> {
        validate_bundle_sizes(bundle)?;
        self.publish_file(
            FilePublication {
                temporary_name: HTML_TEMP_NAME,
                final_name: ASSESSMENT_HTML_NAME,
                bytes: &bundle.html,
                write_stage: PublicationStage::HtmlWrite,
                sync_stage: PublicationStage::HtmlSync,
                link_stage: PublicationStage::HtmlLink,
                cleanup_stage: PublicationStage::HtmlTempCleanup,
                kind: FileKind::Html,
            },
            hook,
        )?;
        self.publish_file(
            FilePublication {
                temporary_name: JSON_TEMP_NAME,
                final_name: ASSESSMENT_JSON_NAME,
                bytes: &bundle.json,
                write_stage: PublicationStage::JsonWrite,
                sync_stage: PublicationStage::JsonSync,
                link_stage: PublicationStage::JsonLink,
                cleanup_stage: PublicationStage::JsonTempCleanup,
                kind: FileKind::Json,
            },
            hook,
        )?;
        hook.check(PublicationStage::PayloadDirectorySync)?;
        sync_directory(&self.path)?;
        self.publish_file(
            FilePublication {
                temporary_name: MANIFEST_TEMP_NAME,
                final_name: MANIFEST_NAME,
                bytes: &bundle.manifest,
                write_stage: PublicationStage::ManifestWrite,
                sync_stage: PublicationStage::ManifestSync,
                link_stage: PublicationStage::ManifestLink,
                cleanup_stage: PublicationStage::ManifestTempCleanup,
                kind: FileKind::Manifest,
            },
            hook,
        )?;
        hook.check(PublicationStage::CommittedDirectorySync)?;
        sync_directory(&self.path)
    }

    fn publish_file(
        &mut self,
        publication: FilePublication<'_>,
        hook: &mut impl PublicationHook,
    ) -> io::Result<()> {
        if publication.bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to publish an empty report bundle file",
            ));
        }
        let temporary = self.path.join(publication.temporary_name);
        let final_path = self.path.join(publication.final_name);
        let mut file = create_private_file(&temporary)?;
        self.owned_file_mut(publication.kind).temporary = true;
        let identity = Handle::from_file(file.try_clone()?).map_err(|error| {
            io::Error::new(
                error.kind(),
                "report bundle file identity could not be retained",
            )
        })?;
        self.owned_file_mut(publication.kind).identity = Some(identity);
        hook.check(publication.write_stage)?;
        file.write_all(publication.bytes)?;
        hook.check(publication.sync_stage)?;
        file.sync_all()?;
        drop(file);
        hook.check(publication.link_stage)?;
        self.verify_owned_path(publication.kind, &temporary)?;
        fs::hard_link(&temporary, &final_path)?;
        if publication.kind == FileKind::Manifest {
            self.committed = true;
        }
        self.owned_file_mut(publication.kind).final_path = true;
        self.verify_owned_path(publication.kind, &final_path)?;
        hook.check(publication.cleanup_stage)?;
        self.verify_owned_path(publication.kind, &temporary)?;
        fs::remove_file(&temporary)?;
        self.owned_file_mut(publication.kind).temporary = false;
        Ok(())
    }

    fn owned_file(&self, kind: FileKind) -> &OwnedFilePaths {
        match kind {
            FileKind::Html => &self.owned.html,
            FileKind::Json => &self.owned.json,
            FileKind::Manifest => &self.owned.manifest,
        }
    }

    fn owned_file_mut(&mut self, kind: FileKind) -> &mut OwnedFilePaths {
        match kind {
            FileKind::Html => &mut self.owned.html,
            FileKind::Json => &mut self.owned.json,
            FileKind::Manifest => &mut self.owned.manifest,
        }
    }

    fn verify_owned_path(&self, kind: FileKind, path: &Path) -> io::Result<()> {
        let expected = self
            .owned_file(kind)
            .identity
            .as_ref()
            .ok_or_else(|| io::Error::other("report bundle file ownership is unavailable"))?;
        let current = Handle::from_path(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                "report bundle file ownership could not be verified",
            )
        })?;
        if current != *expected {
            return Err(io::Error::other(
                "report bundle file ownership changed; residuals retained",
            ));
        }
        Ok(())
    }

    fn cleanup_precommit(&mut self) -> io::Result<()> {
        if self.committed || self.released {
            return Ok(());
        }
        self.verify_directory_identity()?;
        let tracked = [
            (
                FileKind::Manifest,
                MANIFEST_TEMP_NAME,
                self.owned.manifest.temporary,
            ),
            (
                FileKind::Manifest,
                MANIFEST_NAME,
                self.owned.manifest.final_path,
            ),
            (FileKind::Json, JSON_TEMP_NAME, self.owned.json.temporary),
            (
                FileKind::Json,
                ASSESSMENT_JSON_NAME,
                self.owned.json.final_path,
            ),
            (FileKind::Html, HTML_TEMP_NAME, self.owned.html.temporary),
            (
                FileKind::Html,
                ASSESSMENT_HTML_NAME,
                self.owned.html.final_path,
            ),
        ];
        for (kind, name, owned) in tracked {
            if !owned {
                continue;
            }
            let path = self.path.join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => self.verify_owned_path(kind, &path)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        "report bundle cleanup ownership could not be verified",
                    ));
                },
            }
        }
        let mut first_error = None;
        for (kind, name, owned) in tracked {
            if !owned {
                continue;
            }
            let path = self.path.join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => self.verify_owned_path(kind, &path)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        "report bundle cleanup ownership could not be verified",
                    ));
                },
            }
            if let Err(error) = fs::remove_file(path) {
                if error.kind() != io::ErrorKind::NotFound && first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(io::Error::new(
                error.kind(),
                "report bundle cleanup was incomplete",
            ));
        }
        fs::remove_dir(&self.path).map_err(|error| {
            io::Error::new(error.kind(), "report bundle cleanup was incomplete")
        })?;
        self.identity = None;
        self.released = true;
        Ok(())
    }

    fn verify_directory_identity(&self) -> io::Result<()> {
        let original = self
            .identity
            .as_ref()
            .ok_or_else(|| io::Error::other("report bundle directory ownership is unavailable"))?;
        let current = Handle::from_path(&self.path).map_err(|error| {
            io::Error::new(
                error.kind(),
                "report bundle directory ownership could not be verified",
            )
        })?;
        if current != *original {
            return Err(io::Error::other(
                "report bundle directory ownership changed; residuals retained",
            ));
        }
        Ok(())
    }
}

impl Drop for ReportBundleReservation {
    fn drop(&mut self) {
        if !self.committed && !self.released {
            let _ = self.cleanup_precommit();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileKind {
    Html,
    Json,
    Manifest,
}

struct FilePublication<'a> {
    temporary_name: &'static str,
    final_name: &'static str,
    bytes: &'a [u8],
    write_stage: PublicationStage,
    sync_stage: PublicationStage,
    link_stage: PublicationStage,
    cleanup_stage: PublicationStage,
    kind: FileKind,
}

/// A publication failure distinguishes a pre-commit error from housekeeping
/// after the manifest commit point.
#[derive(Debug)]
pub(crate) struct ReportBundlePublicationError {
    source: io::Error,
    cleanup: Option<io::Error>,
    committed: bool,
}

impl ReportBundlePublicationError {
    #[cfg(test)]
    fn committed(&self) -> bool {
        self.committed
    }

    #[cfg(test)]
    fn cleanup_incomplete(&self) -> bool {
        self.cleanup.is_some()
    }
}

impl fmt::Display for ReportBundlePublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.committed {
            formatter
                .write_str("report bundle committed, but post-commit housekeeping was incomplete")
        } else if self.cleanup.is_some() {
            formatter.write_str("report bundle publication failed and cleanup was incomplete")
        } else {
            formatter.write_str("report bundle publication failed before manifest commit")
        }
    }
}

impl Error for ReportBundlePublicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

fn validate_destination(path: &Path) -> io::Result<()> {
    let final_component = path.components().next_back();
    if !matches!(final_component, Some(Component::Normal(name)) if valid_final_name(name)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report bundle destination must have a valid final directory name",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "report bundle destination already exists",
            ));
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                "report bundle destination state could not be inspected",
            ));
        },
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_link_metadata = fs::symlink_metadata(parent)
        .map_err(|error| io::Error::new(error.kind(), "report bundle parent is unavailable"))?;
    if metadata_is_link_like(&parent_link_metadata) || !parent_link_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report bundle parent must be a trusted non-link directory",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn metadata_is_link_like(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn metadata_is_link_like(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn valid_final_name(name: &OsStr) -> bool {
    !name.is_empty() && name != OsStr::new(".") && name != OsStr::new("..")
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read as _,
        net::{TcpListener, TcpStream},
        sync::{Arc, Barrier},
    };
    use termivar_scanner::web_runtime::{
        ScanProfileV1, WebAssessmentCompletion, WebAssessmentRuntime,
    };
    use url::Url;

    struct FailingHook {
        stage: PublicationStage,
    }

    impl PublicationHook for FailingHook {
        fn check(&mut self, stage: PublicationStage) -> io::Result<()> {
            if stage == self.stage {
                Err(io::Error::other("injected publication failure"))
            } else {
                Ok(())
            }
        }
    }

    struct ReplaceAtStageHook {
        stage: PublicationStage,
        path: PathBuf,
        return_error: bool,
    }

    impl PublicationHook for ReplaceAtStageHook {
        fn check(&mut self, stage: PublicationStage) -> io::Result<()> {
            if stage != self.stage {
                return Ok(());
            }
            fs::remove_file(&self.path)?;
            fs::write(&self.path, b"foreign replacement")?;
            if self.return_error {
                Err(io::Error::other("injected failure after replacement"))
            } else {
                Ok(())
            }
        }
    }

    struct RemoveThenFailHook {
        stage: PublicationStage,
        path: PathBuf,
    }

    impl PublicationHook for RemoveThenFailHook {
        fn check(&mut self, stage: PublicationStage) -> io::Result<()> {
            if stage == self.stage {
                fs::remove_file(&self.path)?;
                return Err(io::Error::other("injected failure after removal"));
            }
            Ok(())
        }
    }

    fn reserve_in(parent: &Path, name: &str) -> ReportBundleReservation {
        reserve_report_bundle(Some(&parent.join(name)))
            .unwrap()
            .unwrap()
    }

    fn respond_to_fixture_request(stream: &mut TcpStream) {
        let mut request = [0_u8; 16 * 1024];
        let _ = stream.read(&mut request);
        let body = b"<main>typed bundle fixture</main>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        stream.flush().unwrap();
    }

    fn fail_html_render(
        _report: &AssessmentRunReport,
        format: ReportFormat,
    ) -> Result<String, Box<dyn Error>> {
        match format {
            ReportFormat::Html => Err(io::Error::other("injected HTML render failure").into()),
            _ => Ok("not reached".to_owned()),
        }
    }

    fn fail_json_render(
        _report: &AssessmentRunReport,
        format: ReportFormat,
    ) -> Result<String, Box<dyn Error>> {
        match format {
            ReportFormat::Html => Ok("<html>complete</html>".to_owned()),
            ReportFormat::Json => Err(io::Error::other("injected JSON render failure").into()),
            _ => Err(io::Error::other("unexpected bundle report format").into()),
        }
    }

    #[tokio::test]
    async fn one_typed_assessment_supplies_both_exact_existing_renderings() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = std::thread::spawn(move || {
            for stream in listener.incoming().take(3) {
                respond_to_fixture_request(&mut stream.unwrap());
            }
        });
        let profile = ScanProfileV1::web_review().unwrap();
        let mut builder =
            WebAssessmentRuntime::builder(Url::parse(&format!("http://{address}/")).unwrap())
                .limits(profile.web_assessment_limits());
        if profile.capabilities().low_risk_differential_review() {
            builder = builder.enable_low_risk_differential_review();
        }
        let mut runtime = builder.build().unwrap();
        let runtime_report = runtime.analyze().await.unwrap();
        assert_eq!(
            *runtime_report.completion(),
            WebAssessmentCompletion::Complete
        );
        let report = ReportGenerator::compose_assessment(runtime_report, profile).unwrap();
        let direct_html = ReportGenerator::generate_assessment(&report, ReportFormat::Html)
            .unwrap()
            .into_bytes();
        let direct_json = ReportGenerator::generate_assessment(&report, ReportFormat::Json)
            .unwrap()
            .into_bytes();

        let bundle = render_report_bundle(&report).unwrap();
        assert_eq!(bundle.html, direct_html);
        assert_eq!(bundle.json, direct_json);
        fixture.join().unwrap();
    }

    #[tokio::test]
    async fn completed_zero_item_assessment_is_bundled_without_a_security_claim() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = std::thread::spawn(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut request = [0_u8; 16 * 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            stream.flush().unwrap();
        });
        let profile = ScanProfileV1::web_review().unwrap();
        let mut runtime =
            WebAssessmentRuntime::builder(Url::parse(&format!("http://{address}/")).unwrap())
                .limits(profile.web_assessment_limits())
                .build()
                .unwrap();
        let runtime_report = runtime.analyze().await.unwrap();
        let report = ReportGenerator::compose_assessment(runtime_report, profile).unwrap();
        assert_eq!(report.item_count(), 0);

        let bundle = render_report_bundle(&report).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&bundle.manifest).unwrap();
        assert_eq!(manifest["assessment"]["status"], "complete");
        assert_eq!(manifest["assessment"]["item_count"], 0);
        assert!(!String::from_utf8_lossy(&bundle.manifest).contains("secure"));

        for (name, renderer) in [
            ("html", fail_html_render as AssessmentRenderer),
            ("json", fail_json_render as AssessmentRenderer),
        ] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join(format!("{name}-render-failure"));
            let reservation = reserve_report_bundle(Some(&destination)).unwrap().unwrap();
            let error = render_report_bundle_with(&report, renderer).unwrap_err();
            assert!(error.to_string().contains("render failure"));
            reservation.abort().unwrap();
            assert!(
                !destination.exists(),
                "{name} render failure left an uncommitted directory"
            );
        }
        fixture.join().unwrap();
    }

    #[test]
    fn manifest_is_bounded_deterministic_and_hashes_exact_bytes() {
        let bundle = RenderedReportBundle::from_test_bytes(
            "<html>kanıt</html>".as_bytes(),
            r#"{"ölçüm":true}"#.as_bytes(),
        );
        let manifest: serde_json::Value = serde_json::from_slice(&bundle.manifest).unwrap();
        let sorted_keys = |value: &serde_json::Value| {
            let mut keys = value
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            keys.sort_unstable();
            keys
        };
        assert_eq!(
            sorted_keys(&manifest),
            ["assessment", "files", "producer", "schema"]
        );
        assert_eq!(sorted_keys(&manifest["producer"]), ["product", "version"]);
        assert_eq!(
            sorted_keys(&manifest["assessment"]),
            ["item_count", "profile", "status", "subject_count"]
        );
        assert_eq!(manifest["schema"], REPORT_BUNDLE_SCHEMA);
        assert_eq!(manifest["producer"]["product"], "Termivar");
        assert_eq!(manifest["producer"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(manifest["assessment"]["profile"], "web-review");
        assert_eq!(manifest["assessment"]["status"], "complete");
        assert_eq!(manifest["assessment"]["subject_count"], 0);
        assert_eq!(manifest["assessment"]["item_count"], 0);
        let files = manifest["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0]["name"], ASSESSMENT_HTML_NAME);
        assert_eq!(files[1]["name"], ASSESSMENT_JSON_NAME);
        assert!(files.iter().all(|file| file["name"] != MANIFEST_NAME));
        assert!(!String::from_utf8_lossy(&bundle.manifest).contains("secure"));
        for (entry, bytes) in files.iter().zip([&bundle.html, &bundle.json]) {
            assert_eq!(
                sorted_keys(entry),
                ["byte_length", "format", "media_type", "name", "sha256"]
            );
            let digest = Sha256::digest(bytes);
            assert_eq!(entry["byte_length"], bytes.len() as u64);
            assert_eq!(entry["sha256"], format!("{digest:x}"));
        }
        assert!(bundle.manifest.len() <= MAX_MANIFEST_BYTES);
        assert!(bundle.total_len().unwrap() <= MAX_REPORT_BUNDLE_BYTES);
    }

    #[test]
    fn reservation_is_exclusive_and_never_reuses_existing_paths() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("bundle");
        let reservation = reserve_report_bundle(Some(&destination)).unwrap().unwrap();
        let error = reserve_report_bundle(Some(&destination)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        reservation.abort().unwrap();

        fs::write(&destination, b"foreign").unwrap();
        let error = reserve_report_bundle(Some(&destination)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).unwrap(), b"foreign");
    }

    #[test]
    fn competing_reservations_have_exactly_one_owner() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("bundle");
        let start = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let destination = destination.clone();
            let start = Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                start.wait();
                reserve_report_bundle(Some(&destination))
            }));
        }
        start.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .filter(|error| error.kind() == io::ErrorKind::AlreadyExists)
                .count(),
            1
        );
        drop(results);
        assert!(!destination.exists());
    }

    #[test]
    fn complete_publication_leaves_exactly_three_files_with_manifest_last() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("bundle");
        let reservation = reserve_report_bundle(Some(&destination)).unwrap().unwrap();
        let bundle = RenderedReportBundle::from_test_bytes(b"<html>ok</html>", br#"{"ok":true}"#);
        reservation.publish(&bundle).unwrap();
        let mut names = fs::read_dir(&destination)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            [ASSESSMENT_HTML_NAME, ASSESSMENT_JSON_NAME, MANIFEST_NAME]
        );
        assert_eq!(
            fs::read(destination.join(ASSESSMENT_HTML_NAME)).unwrap(),
            bundle.html
        );
        assert_eq!(
            fs::read(destination.join(ASSESSMENT_JSON_NAME)).unwrap(),
            bundle.json
        );
        assert_eq!(
            fs::read(destination.join(MANIFEST_NAME)).unwrap(),
            bundle.manifest
        );
    }

    #[test]
    fn every_precommit_failure_cleans_only_the_owned_directory() {
        let stages = [
            PublicationStage::HtmlWrite,
            PublicationStage::HtmlSync,
            PublicationStage::HtmlLink,
            PublicationStage::HtmlTempCleanup,
            PublicationStage::JsonWrite,
            PublicationStage::JsonSync,
            PublicationStage::JsonLink,
            PublicationStage::JsonTempCleanup,
            PublicationStage::PayloadDirectorySync,
            PublicationStage::ManifestWrite,
            PublicationStage::ManifestSync,
            PublicationStage::ManifestLink,
        ];
        for (index, stage) in stages.into_iter().enumerate() {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join(format!("bundle-{index}"));
            let reservation = reserve_report_bundle(Some(&destination)).unwrap().unwrap();
            let bundle = RenderedReportBundle::from_test_bytes(b"html", b"json");
            let error = reservation
                .publish_with_hook(&bundle, &mut FailingHook { stage })
                .unwrap_err();
            assert!(!error.committed(), "stage {stage:?} committed unexpectedly");
            assert!(
                !destination.exists(),
                "stage {stage:?} left an owned directory"
            );
        }
    }

    #[test]
    fn postcommit_failure_retains_the_valid_committed_bundle() {
        for stage in [
            PublicationStage::ManifestTempCleanup,
            PublicationStage::CommittedDirectorySync,
        ] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join(format!("bundle-{stage:?}"));
            let reservation = reserve_report_bundle(Some(&destination)).unwrap().unwrap();
            let bundle = RenderedReportBundle::from_test_bytes(b"html", b"json");
            let error = reservation
                .publish_with_hook(&bundle, &mut FailingHook { stage })
                .unwrap_err();
            assert!(error.committed());
            assert!(!error.cleanup_incomplete());
            assert_eq!(
                fs::read(destination.join(ASSESSMENT_HTML_NAME)).unwrap(),
                b"html"
            );
            assert_eq!(
                fs::read(destination.join(ASSESSMENT_JSON_NAME)).unwrap(),
                b"json"
            );
            assert!(destination.join(MANIFEST_NAME).is_file());
        }
    }

    #[test]
    fn foreign_file_makes_cleanup_incomplete_without_broad_deletion() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("bundle");
        let reservation = reserve_in(parent.path(), "bundle");
        fs::write(destination.join("foreign.txt"), b"preserve me").unwrap();
        let error = reservation.abort().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::DirectoryNotEmpty);
        assert_eq!(
            fs::read(destination.join("foreign.txt")).unwrap(),
            b"preserve me"
        );
    }

    #[test]
    fn publication_preserves_primary_failure_and_reports_incomplete_cleanup() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("bundle");
        let reservation = reserve_in(parent.path(), "bundle");
        fs::write(destination.join("foreign.txt"), b"preserve me").unwrap();
        let bundle = RenderedReportBundle::from_test_bytes(b"html", b"json");
        let error = reservation
            .publish_with_hook(
                &bundle,
                &mut FailingHook {
                    stage: PublicationStage::HtmlWrite,
                },
            )
            .unwrap_err();
        assert!(!error.committed());
        assert!(error.cleanup_incomplete());
        assert_eq!(error.source.to_string(), "injected publication failure");
        assert_eq!(
            fs::read(destination.join("foreign.txt")).unwrap(),
            b"preserve me"
        );
        assert!(!destination.join(MANIFEST_NAME).exists());
    }

    #[test]
    fn same_name_replacements_are_never_published_or_removed_as_owned_files() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("temporary-replacement");
        let reservation = reserve_in(parent.path(), "temporary-replacement");
        let bundle = RenderedReportBundle::from_test_bytes(b"html", b"json");
        let temporary = destination.join(HTML_TEMP_NAME);
        let error = reservation
            .publish_with_hook(
                &bundle,
                &mut ReplaceAtStageHook {
                    stage: PublicationStage::HtmlLink,
                    path: temporary.clone(),
                    return_error: false,
                },
            )
            .unwrap_err();
        assert!(!error.committed());
        assert!(error.cleanup_incomplete());
        assert_eq!(fs::read(&temporary).unwrap(), b"foreign replacement");
        assert!(!destination.join(ASSESSMENT_HTML_NAME).exists());
        assert!(!destination.join(MANIFEST_NAME).exists());

        let destination = parent.path().join("final-replacement");
        let reservation = reserve_in(parent.path(), "final-replacement");
        let final_path = destination.join(ASSESSMENT_HTML_NAME);
        let error = reservation
            .publish_with_hook(
                &bundle,
                &mut ReplaceAtStageHook {
                    stage: PublicationStage::JsonWrite,
                    path: final_path.clone(),
                    return_error: true,
                },
            )
            .unwrap_err();
        assert!(!error.committed());
        assert!(error.cleanup_incomplete());
        assert_eq!(fs::read(&final_path).unwrap(), b"foreign replacement");
        assert!(!destination.join(MANIFEST_NAME).exists());
    }

    #[test]
    fn already_removed_owned_path_does_not_prevent_safe_cleanup() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("removed-path");
        let reservation = reserve_in(parent.path(), "removed-path");
        let bundle = RenderedReportBundle::from_test_bytes(b"html", b"json");
        let temporary = destination.join(HTML_TEMP_NAME);
        let error = reservation
            .publish_with_hook(
                &bundle,
                &mut RemoveThenFailHook {
                    stage: PublicationStage::HtmlLink,
                    path: temporary,
                },
            )
            .unwrap_err();
        assert!(!error.committed());
        assert!(!error.cleanup_incomplete());
        assert!(!destination.exists());
    }

    #[test]
    fn per_document_and_total_bounds_are_enforced_before_publication() {
        let oversized = vec![b'x'; MAX_RENDERED_REPORT_BYTES + 1];
        let bundle = RenderedReportBundle {
            html: oversized,
            json: b"{}".to_vec(),
            manifest: b"{}".to_vec(),
        };
        assert_eq!(
            validate_bundle_sizes(&bundle).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("bundle");
        let reservation = reserve_report_bundle(Some(&destination)).unwrap().unwrap();
        let error = reservation.publish(&bundle).unwrap_err();
        assert!(!error.committed());
        assert!(!destination.exists());
    }

    #[test]
    fn empty_payloads_and_oversized_manifests_fail_before_commit() {
        for (index, bundle) in [
            RenderedReportBundle::from_test_bytes(b"", b"{}"),
            RenderedReportBundle::from_test_bytes(b"<html></html>", b""),
        ]
        .into_iter()
        .enumerate()
        {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join(format!("empty-{index}"));
            let reservation = reserve_report_bundle(Some(&destination)).unwrap().unwrap();
            let error = reservation.publish(&bundle).unwrap_err();
            assert!(!error.committed());
            assert!(!error.cleanup_incomplete());
            assert_eq!(error.source.kind(), io::ErrorKind::InvalidInput);
            assert!(!destination.exists());
        }

        let oversized_profile = "p".repeat(MAX_MANIFEST_BYTES);
        let error = build_manifest(
            b"<html></html>",
            b"{}",
            ManifestAssessment {
                profile: &oversized_profile,
                status: "complete",
                subject_count: 0,
                item_count: 0,
            },
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("manifest exceeds the byte limit"));
    }

    #[test]
    fn publication_errors_distinguish_commit_and_cleanup_states() {
        let source_only = ReportBundlePublicationError {
            source: io::Error::other("private source detail"),
            cleanup: None,
            committed: false,
        };
        assert_eq!(
            source_only.to_string(),
            "report bundle publication failed before manifest commit"
        );
        assert_eq!(
            Error::source(&source_only).unwrap().to_string(),
            "private source detail"
        );

        let cleanup_incomplete = ReportBundlePublicationError {
            source: io::Error::other("primary"),
            cleanup: Some(io::Error::other("cleanup")),
            committed: false,
        };
        assert_eq!(
            cleanup_incomplete.to_string(),
            "report bundle publication failed and cleanup was incomplete"
        );

        let committed = ReportBundlePublicationError {
            source: io::Error::other("housekeeping"),
            cleanup: None,
            committed: true,
        };
        assert_eq!(
            committed.to_string(),
            "report bundle committed, but post-commit housekeeping was incomplete"
        );
    }

    #[test]
    fn invalid_destinations_and_missing_or_link_parents_are_rejected() {
        assert!(reserve_report_bundle(None).unwrap().is_none());
        let parent = tempfile::tempdir().unwrap();
        for path in [
            Path::new(""),
            Path::new("."),
            Path::new(".."),
            Path::new("/"),
        ] {
            assert_eq!(
                reserve_report_bundle(Some(path)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let missing = parent.path().join("missing").join("bundle");
        assert_eq!(
            reserve_report_bundle(Some(&missing)).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        let regular_parent = parent.path().join("regular-parent");
        fs::write(&regular_parent, b"not a directory").unwrap();
        assert_eq!(
            reserve_report_bundle(Some(&regular_parent.join("bundle")))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let real = parent.path().join("real");
            let linked = parent.path().join("linked");
            fs::create_dir(&real).unwrap();
            symlink(&real, &linked).unwrap();
            assert_eq!(
                reserve_report_bundle(Some(&linked.join("bundle")))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );

            let broken = parent.path().join("broken");
            symlink(parent.path().join("absent"), &broken).unwrap();
            assert_eq!(
                reserve_report_bundle(Some(&broken)).unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
            assert!(fs::symlink_metadata(&broken)
                .unwrap()
                .file_type()
                .is_symlink());
        }
    }
}
