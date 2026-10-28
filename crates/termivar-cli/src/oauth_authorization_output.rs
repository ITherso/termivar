//! CLI-owned, create-only sensitive authorization-URI handoff.
//!
//! Only a bounded writer is transferred to the runtime. This file is not a
//! report-bundle member and never contains the PKCE verifier. Unix creation uses
//! mode 0600; Windows inherits the operator's directory ACL without claiming a
//! new ACL guarantee. Trusted, quiescent ancestors remain an explicit assumption:
//! final-component checks and identity checks are not an atomic path snapshot.

use same_file::Handle;
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
};

pub(crate) struct PreparedAuthorizationOutput {
    path: PathBuf,
    parent: PathBuf,
    parent_identity: Handle,
}

impl PreparedAuthorizationOutput {
    /// Read-only preflight. No output is reserved until every policy and
    /// composition check has succeeded and the report reservation is complete.
    pub(crate) fn prepare(
        path: &Path,
        report_output: Option<&Path>,
        report_directory: Option<&Path>,
    ) -> io::Result<Self> {
        crate::auth_input::validate_local_file_path(path)
            .map_err(|_| invalid("OAuth authorization output must be a local regular-file path"))?;
        let path = prospective_file(path)?;
        let parent = path
            .parent()
            .expect("a resolved output has a parent")
            .to_owned();
        if report_output
            .map(prospective_file)
            .transpose()?
            .as_ref()
            .is_some_and(|report| same_path(report, &path))
        {
            return Err(invalid(
                "OAuth authorization output must be separate from report output",
            ));
        }
        if report_directory
            .map(prospective_file)
            .transpose()?
            .is_some_and(|directory| path_beneath(&path, &directory))
        {
            return Err(invalid(
                "OAuth authorization output must remain outside the report bundle",
            ));
        }
        require_absent(&path)?;
        let parent_identity = Handle::from_path(&parent)
            .map_err(|_| invalid("OAuth authorization output parent identity is unavailable"))?;
        Ok(Self {
            path,
            parent,
            parent_identity,
        })
    }

    pub(crate) fn reserve(self) -> io::Result<AuthorizationOutput> {
        verify_directory(&self.parent, &self.parent_identity)?;
        require_absent(&self.path)?;
        let file = create_private_file(&self.path).map_err(|error| {
            io::Error::new(
                error.kind(),
                "OAuth authorization output could not be reserved",
            )
        })?;
        if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
            return Err(invalid(
                "OAuth authorization output is not a regular file; residual retained",
            ));
        }
        let identity = file.try_clone().and_then(Handle::from_file).map_err(|_| {
            invalid("OAuth authorization output identity is unavailable; residual retained")
        })?;
        Ok(AuthorizationOutput {
            path: self.path,
            parent: self.parent,
            parent_identity: self.parent_identity,
            identity: Some(identity),
            file: Some(file),
            cleanup_attempted: false,
        })
    }
}

impl fmt::Debug for PreparedAuthorizationOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedAuthorizationOutput(<redacted>)")
    }
}

pub(crate) struct AuthorizationOutput {
    path: PathBuf,
    parent: PathBuf,
    parent_identity: Handle,
    identity: Option<Handle>,
    file: Option<File>,
    cleanup_attempted: bool,
}

impl AuthorizationOutput {
    pub(crate) fn writer(&self) -> io::Result<File> {
        self.verify_owned_file()?;
        self.file
            .as_ref()
            .ok_or_else(|| invalid("OAuth authorization writer is unavailable"))?
            .try_clone()
            .map_err(|_| invalid("OAuth authorization writer could not be retained"))
    }

    /// Remove only the still-verified file created by this invocation. A
    /// replacement, link or changed parent is retained, never blindly unlinked.
    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        if std::mem::replace(&mut self.cleanup_attempted, true) {
            return Ok(());
        }
        verify_directory(&self.parent, &self.parent_identity)?;
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.file = None;
                self.identity = None;
                return Ok(());
            },
            Err(_) => {
                return Err(invalid(
                    "OAuth authorization cleanup state is unavailable; residual retained",
                ))
            },
            Ok(_) => self.verify_owned_file()?,
        }
        self.file = None;
        self.identity = None;
        fs::remove_file(&self.path).map_err(|error| {
            io::Error::new(
                error.kind(),
                "OAuth authorization cleanup was incomplete; residual retained",
            )
        })
    }

    fn verify_owned_file(&self) -> io::Result<()> {
        verify_directory(&self.parent, &self.parent_identity)?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|_| invalid("OAuth authorization file ownership is unavailable"))?;
        if link_like(&metadata) || !metadata.is_file() {
            return Err(invalid(
                "OAuth authorization file ownership changed; residual retained",
            ));
        }
        let current = Handle::from_path(&self.path)
            .map_err(|_| invalid("OAuth authorization file identity is unavailable"))?;
        if self.identity.as_ref() != Some(&current) {
            return Err(invalid(
                "OAuth authorization file identity changed; residual retained",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for AuthorizationOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationOutput(<redacted>)")
    }
}

impl Drop for AuthorizationOutput {
    fn drop(&mut self) {
        if !self.cleanup_attempted && self.cleanup().is_err() {
            // Static warning only. Never mask the original scan/input failure
            // or print a path, URI, state, code, response or OS error detail.
            eprintln!("OAuth authorization output cleanup was incomplete; inspect the private destination");
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn same_path(first: &Path, second: &Path) -> bool {
    first.components().count() == second.components().count() && path_beneath(first, second)
}

fn path_beneath(path: &Path, parent: &Path) -> bool {
    let mut components = path.components();
    parent.components().all(|expected| {
        components.next().is_some_and(|actual| {
            #[cfg(windows)]
            {
                actual.as_os_str().to_string_lossy().to_uppercase()
                    == expected.as_os_str().to_string_lossy().to_uppercase()
            }
            #[cfg(not(windows))]
            {
                actual == expected
            }
        })
    })
}

fn prospective_file(path: &Path) -> io::Result<PathBuf> {
    if !matches!(path.components().next_back(), Some(Component::Normal(name)) if !name.is_empty()) {
        return Err(invalid("OAuth authorization output must name a file"));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)
        .map_err(|_| invalid("OAuth authorization output parent is unavailable"))?;
    if link_like(&metadata) || !metadata.is_dir() {
        return Err(invalid(
            "OAuth authorization output requires a trusted non-link parent directory",
        ));
    }
    let parent = fs::canonicalize(parent)
        .map_err(|_| invalid("OAuth authorization output parent cannot be resolved"))?;
    Ok(parent.join(path.file_name().expect("the final component was checked")))
}

fn require_absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "OAuth authorization output already exists",
        )),
        Err(_) => Err(invalid("OAuth authorization output state is unavailable")),
    }
}

fn verify_directory(path: &Path, expected: &Handle) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| invalid("OAuth authorization output parent is unavailable"))?;
    if link_like(&metadata) || !metadata.is_dir() {
        return Err(invalid(
            "OAuth authorization output parent changed; residual retained",
        ));
    }
    let current = Handle::from_path(path)
        .map_err(|_| invalid("OAuth authorization output parent identity is unavailable"))?;
    if &current != expected {
        return Err(invalid(
            "OAuth authorization output parent identity changed; residual retained",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn link_like(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
fn link_like(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn private_handoff_is_create_only_separate_and_owned_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("handoff.txt");
        let report = directory.path().join("report.json");
        let prepared = PreparedAuthorizationOutput::prepare(&path, Some(&report), None).unwrap();
        assert!(!path.exists(), "preflight must not reserve output");
        assert_eq!(
            format!("{prepared:?}"),
            "PreparedAuthorizationOutput(<redacted>)"
        );
        let mut output = prepared.reserve().unwrap();
        let mut writer = output.writer().unwrap();
        writer.write_all(b"SYNTHETIC-PRIVATE-HANDOFF\n").unwrap();
        writer.flush().unwrap();
        assert!(PreparedAuthorizationOutput::prepare(&path, None, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"SYNTHETIC-PRIVATE-HANDOFF\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(writer);
        output.cleanup().unwrap();
        assert!(!path.exists());
        output.cleanup().unwrap();
        assert!(!report.exists());
    }

    #[test]
    fn handoff_rejects_report_collision_and_bundle_membership_before_creation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("same.json");
        assert!(PreparedAuthorizationOutput::prepare(&path, Some(&path), None).is_err());
        let bundle = directory.path().join("bundle");
        fs::create_dir(&bundle).unwrap();
        let child = bundle.join("handoff.txt");
        assert!(PreparedAuthorizationOutput::prepare(&child, None, Some(&bundle)).is_err());
        assert!(!path.exists() && !child.exists());
        assert_eq!(fs::read_dir(&bundle).unwrap().count(), 0);
    }

    #[test]
    fn output_race_and_replacement_are_not_overwritten_or_removed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("handoff.txt");
        let prepared = PreparedAuthorizationOutput::prepare(&path, None, None).unwrap();
        fs::write(&path, b"SYNTHETIC-CONCURRENT-FILE").unwrap();
        assert!(prepared.reserve().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"SYNTHETIC-CONCURRENT-FILE");
        fs::remove_file(&path).unwrap();
        let mut output = PreparedAuthorizationOutput::prepare(&path, None, None)
            .unwrap()
            .reserve()
            .unwrap();
        let retained = directory.path().join("retained-original.txt");
        fs::rename(&path, &retained).unwrap();
        fs::write(&path, b"SYNTHETIC-REPLACEMENT").unwrap();
        assert!(output.cleanup().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"SYNTHETIC-REPLACEMENT");
        assert!(retained.exists());
    }

    #[test]
    fn drop_cleans_only_the_created_handoff_and_errors_are_path_free() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("PRIVATE-PATH-SENTINEL.txt");
        {
            let output = PreparedAuthorizationOutput::prepare(&path, None, None)
                .unwrap()
                .reserve()
                .unwrap();
            assert_eq!(format!("{output:?}"), "AuthorizationOutput(<redacted>)");
            assert!(path.exists());
        }
        assert!(!path.exists());
        fs::write(&path, b"existing").unwrap();
        let error = PreparedAuthorizationOutput::prepare(&path, None, None).unwrap_err();
        assert!(!format!("{error:?}: {error}").contains("PRIVATE-PATH-SENTINEL"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_output_or_parent_cannot_authorize_cleanup() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("unrelated.txt");
        fs::write(&target, b"SYNTHETIC-UNRELATED").unwrap();
        let path = directory.path().join("handoff.txt");
        symlink(&target, &path).unwrap();
        assert!(PreparedAuthorizationOutput::prepare(&path, None, None).is_err());
        fs::remove_file(&path).unwrap();
        let mut output = PreparedAuthorizationOutput::prepare(&path, None, None)
            .unwrap()
            .reserve()
            .unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        assert!(output.cleanup().is_err());
        assert_eq!(fs::read(&target).unwrap(), b"SYNTHETIC-UNRELATED");
    }
}
