use super::LuaRegistrationError;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

pub(super) fn read_registered_source(
    script_path: &Path,
    approved_root: &Path,
    max_source_bytes: usize,
) -> Result<String, LuaRegistrationError> {
    let absolute_root =
        std::path::absolute(approved_root).map_err(|_| LuaRegistrationError::InvalidPath)?;
    let absolute_candidate = if script_path.is_absolute() {
        std::path::absolute(script_path).map_err(|_| LuaRegistrationError::InvalidPath)?
    } else {
        absolute_root.join(script_path)
    };
    let relative = absolute_candidate
        .strip_prefix(&absolute_root)
        .map_err(|_| LuaRegistrationError::OutsideApprovedRoot)?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(LuaRegistrationError::InvalidPath);
    }
    if absolute_candidate
        .extension()
        .and_then(|value| value.to_str())
        != Some("lua")
    {
        return Err(LuaRegistrationError::InvalidPath);
    }
    reject_symlink_components(&absolute_root, relative)?;
    let canonical_root = absolute_root
        .canonicalize()
        .map_err(|_| LuaRegistrationError::InvalidPath)?;
    let canonical_candidate = absolute_candidate
        .canonicalize()
        .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(LuaRegistrationError::OutsideApprovedRoot);
    }
    let path_metadata = canonical_candidate
        .metadata()
        .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    if !path_metadata.is_file() {
        return Err(LuaRegistrationError::NotRegularFile);
    }
    if path_metadata.len() > max_source_bytes as u64 {
        return Err(LuaRegistrationError::SourceTooLarge);
    }
    let mut file =
        File::open(&canonical_candidate).map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    let before = file
        .metadata()
        .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    let read_limit = u64::try_from(max_source_bytes)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(LuaRegistrationError::SourceTooLarge)?;
    let initial_capacity =
        usize::try_from(path_metadata.len()).map_err(|_| LuaRegistrationError::SourceTooLarge)?;
    let mut bytes = Vec::with_capacity(initial_capacity);
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    if bytes.len() > max_source_bytes {
        return Err(LuaRegistrationError::SourceTooLarge);
    }
    let after = file
        .metadata()
        .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    let canonical_after = absolute_candidate
        .canonicalize()
        .map_err(|_| LuaRegistrationError::SourceChangedDuringRegistration)?;
    reject_symlink_components(&absolute_root, relative)?;
    let path_after = canonical_after
        .metadata()
        .map_err(|_| LuaRegistrationError::SourceChangedDuringRegistration)?;
    if canonical_after != canonical_candidate
        || !same_file_metadata(&before, &after)
        || !same_file_metadata(&after, &path_after)
        || after.len() != bytes.len() as u64
    {
        return Err(LuaRegistrationError::SourceChangedDuringRegistration);
    }
    String::from_utf8(bytes).map_err(|_| LuaRegistrationError::SourceNotUtf8)
}

fn reject_symlink_components(
    absolute_root: &Path,
    relative: &Path,
) -> Result<(), LuaRegistrationError> {
    let root_metadata = absolute_root
        .symlink_metadata()
        .map_err(|_| LuaRegistrationError::InvalidPath)?;
    if root_metadata.file_type().is_symlink() {
        return Err(LuaRegistrationError::SymlinkRejected);
    }
    let mut current = PathBuf::from(absolute_root);
    for component in relative.components() {
        if let Component::Normal(component) = component {
            current.push(component);
            let metadata = current
                .symlink_metadata()
                .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
            if metadata.file_type().is_symlink() {
                return Err(LuaRegistrationError::SymlinkRejected);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

#[cfg(not(unix))]
fn same_file_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

pub(super) fn validate_identifier(value: &str, max_bytes: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(());
    }
    Ok(())
}

pub(super) fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn stable_script_id(name: &str, version: &str, source_digest: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"venom-lua-script/v1\0");
    digest.update(name.as_bytes());
    digest.update(b"\0");
    digest.update(version.as_bytes());
    digest.update(b"\0");
    digest.update(source_digest);
    let digest: [u8; 32] = digest.finalize().into();
    let mut id = String::with_capacity(68);
    id.push_str("lua:");
    id.push_str(&hex_digest(&digest));
    id
}
