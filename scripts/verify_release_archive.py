#!/usr/bin/env python3
"""Inspect one locally downloaded alpha.1 archive; optionally extract it.

Requires Python 3.12.4+. This is not an installer: it never downloads, builds,
executes a binary, changes PATH, or bypasses platform security controls.
Checksum agreement is not independent authentication, code signing, or an audit.
The caller must obtain SHA256SUMS through a trusted channel and use a trusted,
already-existing parent directory for any fresh extraction directory.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import zipfile
import zlib


RELEASE_TAG = "v0.10.0-alpha.1"
ARCHIVES = {
    f"termivar-{RELEASE_TAG}-x86_64-unknown-linux-gnu.tar.gz": "termivar",
    f"termivar-{RELEASE_TAG}-x86_64-apple-darwin.tar.gz": "termivar",
    f"termivar-{RELEASE_TAG}-aarch64-apple-darwin.tar.gz": "termivar",
    f"termivar-{RELEASE_TAG}-x86_64-pc-windows-msvc.zip": "termivar.exe",
}
MAX_MANIFEST_BYTES = 4096
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_TAR_BYTES = MAX_BINARY_BYTES + 64 * 1024
MAX_ZIP_DIRECTORY_BYTES = 64 * 1024
MANIFEST_ENTRY = re.compile(r"([0-9a-fA-F]{64}) [ *]([^\s]+)", re.ASCII)


class VerificationError(ValueError):
    """A static, credential-free local verification failure."""


def _read_snapshot(path: Path, limit: int) -> bytes:
    # Hash and parse this same bounded snapshot; later pathname replacement or
    # in-place archive edits cannot substitute bytes between these operations.
    with path.open("rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise VerificationError("input must be a regular local file")
        data = source.read(limit + 1)
    if len(data) > limit:
        raise VerificationError("input exceeds the compiled byte limit")
    return data


def _selected_digest(manifest: bytes, archive_name: str) -> str:
    if archive_name not in ARCHIVES:
        raise VerificationError("archive basename is not an exact supported alpha.1 asset")
    if len(manifest) > MAX_MANIFEST_BYTES:
        raise VerificationError("checksum manifest exceeds the compiled byte limit")
    try:
        text = manifest.decode("ascii")
    except UnicodeDecodeError as error:
        raise VerificationError("checksum manifest must be ASCII") from error
    entries: dict[str, str] = {}
    lines = text.replace("\r\n", "\n").split("\n")
    if lines[-1] == "":
        lines.pop()
    for line in lines:
        match = MANIFEST_ENTRY.fullmatch(line)
        if match is None:
            raise VerificationError("checksum manifest contains a malformed entry")
        digest, name = match.groups()
        if name not in ARCHIVES:
            raise VerificationError("checksum manifest contains an unexpected asset name")
        if name in entries:
            raise VerificationError("checksum manifest contains a duplicate filename")
        entries[name] = digest.lower()
    if archive_name not in entries:
        raise VerificationError("checksum manifest is missing the selected filename")
    return entries[archive_name]


def _tar_binary(snapshot: bytes, expected_name: str) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(snapshot), mode="rb") as compressed:
        content = compressed.read(MAX_TAR_BYTES + 1)
    if len(content) > MAX_TAR_BYTES:
        raise VerificationError("tar decompression exceeds the compiled byte limit")
    if len(content) < 3 * tarfile.BLOCKSIZE or len(content) % tarfile.BLOCKSIZE:
        raise VerificationError("tar must contain one complete entry and zero end blocks")
    # The published flat archives need exactly one ordinary header. Reject PAX,
    # GNU long-name/sparse records and links rather than interpreting alternate
    # names or asking extractall to apply archive-controlled filesystem metadata.
    member = tarfile.TarInfo.frombuf(content[:512], "utf-8", "strict")
    if member.name != expected_name:
        raise VerificationError("tar entry name is not the exact expected binary")
    if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
        raise VerificationError("tar entry must be an ordinary regular file, not a link")
    if not member.mode & 0o111 or member.mode & 0o7000:
        raise VerificationError("tar binary must be executable without special permission bits")
    if not 0 < member.size <= MAX_BINARY_BYTES:
        raise VerificationError("tar binary size is empty or exceeds the compiled byte limit")
    padded_end = 512 + ((member.size + 511) // 512) * 512
    if len(content) < padded_end + 1024 or any(content[512 + member.size:]):
        raise VerificationError("tar contains extra entries, nonzero padding, or missing end blocks")
    return content[512:512 + member.size]


def _zip_binary(snapshot: bytes, expected_name: str) -> bytes:
    # Check the bounded, single-entry central directory before ZipFile builds
    # an entry list. ZIP64, split archives, prefixes and archive comments are
    # outside the shape of the four published release assets.
    if len(snapshot) < 22 or snapshot[-22:-18] != b"PK\x05\x06":
        raise VerificationError("zip must have a complete comment-free end record")
    _, disk, directory_disk, disk_count, count, directory_size, offset, comment = (
        struct.unpack("<4s4H2LH", snapshot[-22:])
    )
    if disk or directory_disk or disk_count != 1 or count != 1 or comment:
        raise VerificationError("zip must contain exactly one entry on one disk")
    if (not 46 <= directory_size <= MAX_ZIP_DIRECTORY_BYTES
            or offset + directory_size != len(snapshot) - 22
            or snapshot[offset:offset + 4] != b"PK\x01\x02"):
        raise VerificationError("zip central directory is malformed or exceeds its byte limit")
    name_size, extra_size, comment_size = struct.unpack_from("<3H", snapshot, offset + 28)
    if 46 + name_size + extra_size + comment_size != directory_size:
        raise VerificationError("zip central directory contains unexpected entries")
    with zipfile.ZipFile(io.BytesIO(snapshot), "r") as archive:
        members = archive.infolist()
        if len(members) != 1:
            raise VerificationError("zip must contain exactly one entry")
        member = members[0]
        if member.orig_filename != expected_name or member.filename != expected_name:
            raise VerificationError("zip entry name is not the exact expected binary")
        unix_type = stat.S_IFMT(member.external_attr >> 16)
        if (member.is_dir() or unix_type not in (0, stat.S_IFREG)
                or member.external_attr & (0x10 | 0x400)):
            raise VerificationError("zip entry must be an ordinary regular file, not a link")
        if member.flag_bits & 1 or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise VerificationError("zip encryption or compression method is unsupported")
        if not 0 < member.file_size <= MAX_BINARY_BYTES:
            raise VerificationError("zip binary size is empty or exceeds the compiled byte limit")
        if member.header_offset != 0 or snapshot[:4] != b"PK\x03\x04":
            raise VerificationError("zip has an unexpected prefix or local entry")
        local_name, local_extra = struct.unpack_from("<2H", snapshot, 26)
        gap = offset - (30 + local_name + local_extra + member.compress_size)
        if gap not in ((12, 16) if member.flag_bits & 8 else (0,)):
            raise VerificationError("zip has unexpected bytes between its entry and directory")
        with archive.open(member, "r") as source:
            binary = source.read(MAX_BINARY_BYTES + 1)
        if len(binary) != member.file_size or len(binary) > MAX_BINARY_BYTES:
            raise VerificationError("zip binary length does not match its bounded entry")
        return binary


def _extract_fresh(directory: Path, name: str, binary: bytes) -> None:
    # No recursive creation or overwrite. 0700 is implemented as an owner/admin
    # ACL on Windows by Python 3.12.4+; parents must already exist and be trusted.
    directory.mkdir(mode=0o700)
    destination = directory / name
    created = False
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as output:
            output.write(binary)
        if os.name != "nt":
            destination.chmod(0o700)
    except BaseException:
        # Remove only the file/directory this invocation created, never a tree.
        if created:
            destination.unlink(missing_ok=True)
        directory.rmdir()
        raise


def verify_archive(archive_path: Path, checksums_path: Path, extract_to: Path | None = None) -> dict:
    """Validate local bytes and return a deterministic, path-free inspection."""
    if sys.version_info < (3, 12, 4):
        raise VerificationError("Python 3.12.4 or newer is required")
    manifest = _read_snapshot(checksums_path, MAX_MANIFEST_BYTES)
    expected_digest = _selected_digest(manifest, archive_path.name)
    snapshot = _read_snapshot(archive_path, MAX_ARCHIVE_BYTES)
    digest = hashlib.sha256(snapshot).hexdigest()
    if digest != expected_digest:
        raise VerificationError("archive SHA-256 does not match the selected manifest entry")
    expected_name = ARCHIVES[archive_path.name]
    try:
        binary = (_zip_binary(snapshot, expected_name) if archive_path.name.endswith(".zip")
                  else _tar_binary(snapshot, expected_name))
    except (OSError, EOFError, UnicodeError, tarfile.TarError, zipfile.BadZipFile, zlib.error,
            NotImplementedError, struct.error) as error:
        raise VerificationError("archive is malformed or outside the supported release shape") from error
    if extract_to is not None:
        _extract_fresh(extract_to, expected_name, binary)
    return {
        "schema": "termivar-release-archive-inspection-v1",
        "release_tag": RELEASE_TAG,
        "archive": archive_path.name,
        "archive_bytes": len(snapshot),
        "archive_sha256": digest,
        "checksums_sha256": hashlib.sha256(manifest).hexdigest(),
        "entry_count": 1,
        "member": expected_name,
        "member_bytes": len(binary),
        "member_sha256": hashlib.sha256(binary).hexdigest(),
        "extracted": extract_to is not None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True, help="one exact alpha.1 platform archive")
    parser.add_argument("--checksums", type=Path, required=True, help="local SHA256SUMS from the exact release")
    parser.add_argument("--extract-to", type=Path, help="explicitly extract after verification into a new directory")
    args = parser.parse_args(argv)
    try:
        result = verify_archive(args.archive, args.checksums, args.extract_to)
    except VerificationError as error:
        print(f"verification refused: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("verification refused: local input/output unavailable or destination already exists", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
