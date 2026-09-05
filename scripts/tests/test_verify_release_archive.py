"""Local synthetic archive checks; no released executable or network is used."""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "verify_release_archive.py"
SPEC = importlib.util.spec_from_file_location("verify_release_archive", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)
TAR_NAME = "termivar-v0.10.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz"
ZIP_NAME = "termivar-v0.10.0-alpha.1-x86_64-pc-windows-msvc.zip"
PAYLOAD = b"benign archive verification fixture; not an executable\n"


def tar_bytes(name="termivar", kind=tarfile.REGTYPE, mode=0o755, extra=False, payload=PAYLOAD):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.mode = mode
        member.linkname = "untrusted-link-destination" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
        member.size = len(payload) if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
        archive.addfile(member, io.BytesIO(payload) if member.size else None)
        if extra:
            other = tarfile.TarInfo("unexpected")
            other.size = 1
            archive.addfile(other, io.BytesIO(b"x"))
    return output.getvalue()


def zip_bytes(name="termivar.exe", external_attr=0, extra=False, compression=zipfile.ZIP_DEFLATED, payload=PAYLOAD):
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # intentional duplicate-entry fixture
        with zipfile.ZipFile(output, "w", compression=compression) as archive:
            member = zipfile.ZipInfo(name)
            member.create_system = 0
            member.external_attr = external_attr
            member.compress_type = compression
            archive.writestr(member, payload)
            if extra:
                archive.writestr(name, b"duplicate")
    return output.getvalue()


class ReleaseArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def local_files(self, data, name=TAR_NAME):
        archive = self.root / name
        archive.write_bytes(data)
        manifest = self.root / "SHA256SUMS"
        lines = []
        for asset in verifier.ARCHIVES:
            digest = hashlib.sha256(data).hexdigest() if asset == name else "0" * 64
            lines.append(f"{digest}  {asset}\n")
        manifest.write_text("".join(lines), encoding="ascii")
        return archive, manifest

    def test_one_download_works_with_the_four_platform_manifest(self):
        for name in verifier.ARCHIVES:
            with self.subTest(name=name):
                data = zip_bytes() if name.endswith(".zip") else tar_bytes()
                archive, manifest = self.local_files(data, name)
                before = set(self.root.iterdir())
                self.assertEqual(before, {archive, manifest})
                result = verifier.verify_archive(archive, manifest)
                self.assertEqual(set(self.root.iterdir()), before)
                self.assertEqual(result["archive"], name)
                self.assertEqual(result["archive_sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(result["member_sha256"], hashlib.sha256(PAYLOAD).hexdigest())
                self.assertEqual(result["checksums_sha256"], hashlib.sha256(manifest.read_bytes()).hexdigest())
                self.assertEqual(result["member_bytes"], len(PAYLOAD))
                self.assertEqual(result["entry_count"], 1)
                self.assertFalse(result["extracted"])
                self.assertNotIn(str(self.root), json.dumps(result))
                archive.unlink()

    def test_manifest_accepts_only_exact_unique_well_formed_entries(self):
        digest = "A" * 64
        for separator, ending in [("  ", "\n"), (" *", "\r\n"), ("  ", "")]:
            self.assertEqual(verifier._selected_digest(
                f"{digest}{separator}{TAR_NAME}{ending}".encode(), TAR_NAME), digest.lower())
        valid = f"{digest}  {TAR_NAME}\n".encode()
        bad = [
            b"", valid + valid, valid + b"\n", b"\n" + valid,
            valid.replace(digest.encode(), b"A" * 63),
            valid.replace(digest.encode(), b"A" * 65),
            valid.replace(digest.encode(), b"g" * 64),
            valid.replace(b"  ", b"\t"),
            valid.replace(b"  ", b" "),
            valid.replace(TAR_NAME.encode(), b"../" + TAR_NAME.encode()),
            valid.replace(TAR_NAME.encode(), b"/" + TAR_NAME.encode()),
            valid.replace(TAR_NAME.encode(), b"C:\\" + TAR_NAME.encode()),
            valid.replace(TAR_NAME.encode(), b"unrelated.tar.gz"),
            valid + f"{'0' * 64}  {ZIP_NAME}\nmalformed\n".encode(),
            valid.replace(b"\n", b"\r"), valid.replace(b"\n", b"\v"),
            valid + b"\xff", valid.rstrip(b"\n") + b" \n",
        ]
        for manifest in bad:
            with self.subTest(manifest=manifest[:80]):
                with self.assertRaises(verifier.VerificationError):
                    verifier._selected_digest(manifest, TAR_NAME)
        with self.assertRaisesRegex(verifier.VerificationError, "missing"):
            verifier._selected_digest(f"{'0' * 64}  {ZIP_NAME}\n".encode(), TAR_NAME)
        with self.assertRaisesRegex(verifier.VerificationError, "basename"):
            verifier._selected_digest(valid, "renamed.tar.gz")
        with self.assertRaisesRegex(verifier.VerificationError, "byte limit"):
            verifier._selected_digest(b"x" * (verifier.MAX_MANIFEST_BYTES + 1), TAR_NAME)

    def test_hash_mismatch_precedes_parsing_and_any_output_creation(self):
        archive, manifest = self.local_files(b"not an archive")
        archive.write_bytes(b"different bytes")
        output = self.root / "new-output"
        with mock.patch.object(verifier, "_tar_binary") as parse:
            with self.assertRaisesRegex(verifier.VerificationError, "SHA-256"):
                verifier.verify_archive(archive, manifest, output)
        parse.assert_not_called()
        self.assertFalse(output.exists())

    def test_tar_rejects_names_links_special_files_and_extra_entries(self):
        cases = [tar_bytes(name=name) for name in [
            "./termivar", "../termivar", "/termivar", "C:/termivar", "folder/termivar",
            "folder\\termivar", "termivar.exe", "Termivar",
        ]]
        cases += [tar_bytes(kind=kind) for kind in [
            tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE,
            tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_SPARSE,
        ]]
        cases += [tar_bytes(mode=0o644), tar_bytes(mode=0o4755), tar_bytes(extra=True), tar_bytes(payload=b"")]
        for index, data in enumerate(cases):
            with self.subTest(case=index):
                archive, manifest = self.local_files(data)
                output = self.root / "new-output"
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_archive(archive, manifest, output)
                self.assertFalse(output.exists())

    def test_tar_rejects_truncation_bad_compression_and_nonzero_padding(self):
        valid = tar_bytes()
        unpacked = gzip.decompress(valid)
        damaged = bytearray(unpacked)
        damaged[512 + len(PAYLOAD)] = 1
        for data in [b"", b"not gzip", valid[:-5], gzip.compress(unpacked[:1024]),
                     gzip.compress(unpacked[:-1]), gzip.compress(damaged)]:
            with self.subTest(length=len(data)):
                archive, manifest = self.local_files(data)
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_archive(archive, manifest)

    def test_zip_rejects_names_links_special_files_and_extra_entries(self):
        cases = [zip_bytes(name=name) for name in [
            "./termivar.exe", "../termivar.exe", "/termivar.exe", "C:/termivar.exe",
            "folder\\termivar.exe", "termivar.exe/", "termivar", "Termivar.exe",
        ]]
        cases += [zip_bytes(external_attr=attributes) for attributes in [
            (stat.S_IFLNK | 0o777) << 16, (stat.S_IFIFO | 0o600) << 16,
            (stat.S_IFDIR | 0o700) << 16, 0x10, 0x400,
        ]]
        cases += [zip_bytes(extra=True), zip_bytes(compression=zipfile.ZIP_BZIP2), zip_bytes(payload=b"")]
        for index, data in enumerate(cases):
            with self.subTest(case=index):
                archive, manifest = self.local_files(data, ZIP_NAME)
                output = self.root / "new-output"
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_archive(archive, manifest, output)
                self.assertFalse(output.exists())

    def test_zip_rejects_malformed_directory_prefix_encryption_and_crc(self):
        valid = zip_bytes(compression=zipfile.ZIP_STORED)
        split = bytearray(valid)
        struct.pack_into("<H", split, len(split) - 18, 1)
        count = bytearray(valid)
        struct.pack_into("<H", count, len(count) - 12, 2)
        encrypted = bytearray(valid)
        directory = encrypted.index(b"PK\x01\x02")
        struct.pack_into("<H", encrypted, directory + 8, 1)
        struct.pack_into("<H", encrypted, 6, 1)
        corrupted = valid.replace(PAYLOAD, b"x" + PAYLOAD[1:])
        for data in [b"", valid[:-1], valid + b"comment", bytes(split), bytes(count),
                     bytes(encrypted), corrupted, b"prefix" + valid]:
            with self.subTest(length=len(data)):
                archive, manifest = self.local_files(data, ZIP_NAME)
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_archive(archive, manifest)

    def test_byte_limits_are_enforced_before_unbounded_retention(self):
        for name, data in [(TAR_NAME, tar_bytes()), (ZIP_NAME, zip_bytes())]:
            archive, manifest = self.local_files(data, name)
            with mock.patch.object(verifier, "MAX_ARCHIVE_BYTES", len(data) - 1):
                with self.assertRaisesRegex(verifier.VerificationError, "byte limit"):
                    verifier.verify_archive(archive, manifest)
            with mock.patch.object(verifier, "MAX_BINARY_BYTES", len(PAYLOAD) - 1):
                with self.assertRaisesRegex(verifier.VerificationError, "byte limit"):
                    verifier.verify_archive(archive, manifest)
        archive, manifest = self.local_files(tar_bytes())
        with mock.patch.object(verifier, "MAX_TAR_BYTES", 1024):
            with self.assertRaisesRegex(verifier.VerificationError, "decompression"):
                verifier.verify_archive(archive, manifest)
        archive, manifest = self.local_files(zip_bytes(), ZIP_NAME)
        with mock.patch.object(verifier, "MAX_ZIP_DIRECTORY_BYTES", 46):
            with self.assertRaisesRegex(verifier.VerificationError, "directory"):
                verifier.verify_archive(archive, manifest)
        manifest.write_bytes(b"x" * (verifier.MAX_MANIFEST_BYTES + 1))
        with self.assertRaisesRegex(verifier.VerificationError, "byte limit"):
            verifier.verify_archive(archive, manifest)

    def test_explicit_extraction_is_private_flat_and_never_overwrites(self):
        for name, data in [(TAR_NAME, tar_bytes()), (ZIP_NAME, zip_bytes())]:
            with self.subTest(name=name):
                archive, manifest = self.local_files(data, name)
                output = self.root / ("zip-output" if name.endswith(".zip") else "tar-output")
                result = verifier.verify_archive(archive, manifest, output)
                binary = output / verifier.ARCHIVES[name]
                self.assertTrue(result["extracted"])
                self.assertEqual(list(output.iterdir()), [binary])
                self.assertEqual(binary.read_bytes(), PAYLOAD)
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                    self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o700)
                original = hashlib.sha256(binary.read_bytes()).hexdigest()
                with self.assertRaises(FileExistsError):
                    verifier.verify_archive(archive, manifest, output)
                self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), original)
        existing_file = self.root / "existing-file"
        existing_file.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            verifier.verify_archive(archive, manifest, existing_file)
        self.assertEqual(existing_file.read_bytes(), b"preserve")
        with self.assertRaises(FileNotFoundError):
            verifier.verify_archive(archive, manifest, self.root / "absent-parent" / "new")
        self.assertFalse((self.root / "absent-parent").exists())

    def test_extraction_uses_the_same_snapshot_that_was_hashed(self):
        archive, manifest = self.local_files(zip_bytes(), ZIP_NAME)
        original_parser = verifier._zip_binary
        def replace_path_after_snapshot(snapshot, name):
            archive.write_bytes(b"changed after snapshot")
            return original_parser(snapshot, name)
        output = self.root / "new-output"
        with mock.patch.object(verifier, "_zip_binary", side_effect=replace_path_after_snapshot):
            result = verifier.verify_archive(archive, manifest, output)
        self.assertEqual((output / "termivar.exe").read_bytes(), PAYLOAD)
        self.assertNotEqual(result["archive_sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_interruption_removes_only_the_new_partial_output(self):
        output = self.root / "new-output"
        original_fdopen = os.fdopen
        class InterruptedOutput:
            def __init__(self, descriptor, mode):
                self.file = original_fdopen(descriptor, mode)
            def __enter__(self):
                return self
            def write(self, data):
                self.file.write(data[:1])
                raise KeyboardInterrupt
            def __exit__(self, *_):
                self.file.close()
        sentinel = self.root / "untouched"
        sentinel.write_bytes(b"preserve")
        with mock.patch.object(verifier.os, "fdopen", side_effect=InterruptedOutput):
            with self.assertRaises(KeyboardInterrupt):
                verifier._extract_fresh(output, "termivar", PAYLOAD)
        self.assertFalse(output.exists())
        self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_cli_json_and_failure_status_do_not_run_the_binary(self):
        archive, manifest = self.local_files(tar_bytes())
        arguments = ["--archive", str(archive), "--checksums", str(manifest)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = verifier.main(arguments)
        self.assertEqual(status, 0)
        self.assertFalse(json.loads(stdout.getvalue())["extracted"])
        self.assertEqual(stderr.getvalue(), "")
        archive.write_bytes(b"wrong")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = verifier.main(arguments)
        self.assertEqual(status, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("SHA-256", stderr.getvalue())
        archive.unlink()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(verifier.main(arguments), 2)
        with mock.patch.object(verifier.sys, "version_info", (3, 12, 3)):
            with self.assertRaisesRegex(verifier.VerificationError, "3.12.4"):
                verifier.verify_archive(archive, manifest)


if __name__ == "__main__":
    unittest.main()
