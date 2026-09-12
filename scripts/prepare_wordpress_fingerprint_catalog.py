#!/usr/bin/env python3
"""Prepare a finite WordPress asset-fingerprint catalogue from explicit local files.

This development helper reads only the source manifest and the regular, non-link
asset files named by that manifest. It never crawls a directory, contacts a
network, or overwrites an existing output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit


SOURCE_SCHEMA = "termivar-test.wordpress-asset-fingerprint-catalog-source/v1"
CATALOG_SCHEMA = "security.wordpress-asset-fingerprint-catalog/v1"
REPRESENTATION_PROFILE = "identity-content-bytes/v1"
MAX_SOURCE_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_ASSET_BYTES = 512 * 1024
MAX_TOTAL_ASSET_BYTES = 16 * 1024 * 1024
MAX_COMPONENTS = 16
MAX_RELEASES_PER_COMPONENT = 128
MAX_FILES_PER_RELEASE = 32
MAX_FILES = 16_384
MAX_TEXT_BYTES = 4 * 1024
MAX_PATH_BYTES = 256

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}\Z", re.ASCII)
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z", re.ASCII)
PATH_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)


class PreparationError(ValueError):
    """The explicit source declaration cannot produce a bounded catalogue."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PreparationError("source manifest contains a duplicate object key")
        result[key] = value
    return result


def _exact_object(
    value: object,
    label: str,
    required: tuple[str, ...],
    optional: tuple[str, ...] = (),
) -> dict[str, object]:
    require(isinstance(value, dict), f"{label} must be an object")
    keys = set(value)
    required_keys = set(required)
    optional_keys = set(optional)
    require(required_keys <= keys, f"{label} is missing a required field")
    require(keys <= required_keys | optional_keys, f"{label} contains an unknown field")
    return value


def _bounded_text(value: object, label: str, maximum: int = MAX_TEXT_BYTES) -> str:
    require(isinstance(value, str), f"{label} must be a string")
    try:
        encoded = value.encode("ascii", "strict")
    except UnicodeEncodeError as error:
        raise PreparationError(f"{label} must be ASCII") from error
    require(0 < len(encoded) <= maximum, f"{label} is empty or exceeds its byte limit")
    require(all(0x20 <= byte <= 0x7E for byte in encoded),
            f"{label} contains a control character")
    return value


def _identifier(value: object, label: str) -> str:
    text = _bounded_text(value, label, 128)
    require(IDENTIFIER.fullmatch(text) is not None, f"{label} is invalid")
    return text


def _reference(value: object, label: str) -> str:
    text = _bounded_text(value, label, 2048)
    parsed = urlsplit(text)
    require(parsed.scheme in {"http", "https"} and parsed.hostname is not None,
            f"{label} must be an absolute HTTP(S) reference")
    require(parsed.username is None and parsed.password is None,
            f"{label} must not contain user information")
    require(
        parsed.query == "" and parsed.fragment == "",
        f"{label} must not contain a query or fragment",
    )
    return text


def _relative_path(value: object, label: str) -> str:
    text = _bounded_text(value, label, MAX_PATH_BYTES)
    require("\\" not in text and "%" not in text and "?" not in text and "#" not in text,
            f"{label} contains an unsupported delimiter")
    require(not text.startswith("/") and ":" not in text, f"{label} must be relative")
    segments = text.split("/")
    require(all(segment not in {"", ".", ".."} for segment in segments),
            f"{label} contains an unsafe segment")
    require(all(PATH_SEGMENT.fullmatch(segment) is not None for segment in segments),
            f"{label} contains an unsupported segment")
    require(text.endswith((".js", ".css")), f"{label} must name a .js or .css file")
    return text


def _read_regular_file(path: Path, limit: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PreparationError(f"{label} is unavailable") from error
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(),
            f"{label} must be a regular non-link file")
    try:
        with path.open("rb") as source:
            data = source.read(limit + 1)
    except OSError as error:
        raise PreparationError(f"{label} could not be read") from error
    require(0 < len(data) <= limit, f"{label} is empty or exceeds its byte limit")
    return data


def _source_asset(source_root: Path, declared: object, label: str) -> tuple[Path, bytes]:
    relative = _relative_path(declared, label)
    candidate = source_root.joinpath(*relative.split("/"))
    resolved_root = source_root.resolve(strict=True)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise PreparationError(f"{label} is unavailable") from error
    require(resolved.is_relative_to(resolved_root), f"{label} escapes the source directory")

    current = source_root
    for segment in relative.split("/")[:-1]:
        current = current / segment
        try:
            metadata = current.lstat()
        except OSError as error:
            raise PreparationError(f"{label} parent is unavailable") from error
        require(stat.S_ISDIR(metadata.st_mode) and not current.is_symlink(),
                f"{label} parent must be a regular non-link directory")
    return resolved, _read_regular_file(resolved, MAX_ASSET_BYTES, label)


def _parse_source(path: Path) -> dict[str, object]:
    raw = _read_regular_file(path, MAX_SOURCE_BYTES, "source manifest")
    try:
        document = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_object_without_duplicates
        )
    except PreparationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreparationError("source manifest is not one strict UTF-8 JSON document") from error
    return _exact_object(document, "source manifest", ("schema", "catalog", "components"))


def _prepare_provenance(value: object) -> dict[str, object]:
    provenance = _exact_object(value, "catalog provenance", ("reference", "revision", "notices"))
    notices = provenance["notices"]
    require(isinstance(notices, list) and len(notices) <= 16,
            "catalog notices must be a bounded array")
    prepared = []
    notice_ids: set[str] = set()
    for index, value in enumerate(notices):
        notice = _exact_object(
            value,
            f"catalog notice {index}",
            ("id", "party", "notice", "license", "license_reference"),
        )
        notice_id = _identifier(notice["id"], f"catalog notice {index} id")
        require(notice_id not in notice_ids, "catalog notice ids must be unique")
        notice_ids.add(notice_id)
        prepared.append({
            "id": notice_id,
            "party": _bounded_text(notice["party"], f"catalog notice {index} party"),
            "notice": _bounded_text(notice["notice"], f"catalog notice {index} text"),
            "license": _bounded_text(notice["license"], f"catalog notice {index} license"),
            "license_reference": _reference(
                notice["license_reference"], f"catalog notice {index} license reference"
            ),
        })
    prepared.sort(key=lambda notice: notice["id"])
    return {
        "reference": _reference(provenance["reference"], "catalog provenance reference"),
        "revision": _identifier(provenance["revision"], "catalog provenance revision"),
        "notices": prepared,
    }


def build_catalog(source_path: Path) -> tuple[dict[str, object], dict[str, int]]:
    document = _parse_source(source_path)
    require(document["schema"] == SOURCE_SCHEMA, "source manifest schema is unsupported")
    catalog = _exact_object(
        document["catalog"],
        "catalog declaration",
        ("id", "revision", "source_namespace", "provenance"),
    )
    provenance = _prepare_provenance(catalog["provenance"])
    known_notice_ids = {notice["id"] for notice in provenance["notices"]}

    components = document["components"]
    require(isinstance(components, list) and 0 < len(components) <= MAX_COMPONENTS,
            "components must be a nonempty bounded array")
    prepared_components = []
    component_ids: set[tuple[str, str]] = set()
    file_count = 0
    total_asset_bytes = 0
    source_root = source_path.parent
    for component_index, value in enumerate(components):
        component = _exact_object(
            value, f"component {component_index}", ("kind", "slug", "releases")
        )
        kind = _bounded_text(component["kind"], f"component {component_index} kind", 16)
        require(kind in {"plugin", "theme"}, f"component {component_index} kind is unsupported")
        slug = _bounded_text(component["slug"], f"component {component_index} slug", 64)
        require(SLUG.fullmatch(slug) is not None, f"component {component_index} slug is invalid")
        identity = (kind, slug)
        require(identity not in component_ids, "component identities must be unique")
        component_ids.add(identity)

        releases = component["releases"]
        require(isinstance(releases, list) and 0 < len(releases) <= MAX_RELEASES_PER_COMPONENT,
                f"component {component_index} releases must be a nonempty bounded array")
        prepared_releases = []
        release_ids: set[str] = set()
        for release_index, value in enumerate(releases):
            release = _exact_object(
                value,
                f"component {component_index} release {release_index}",
                ("release_id", "version", "source", "files"),
                ("build_variant",),
            )
            release_id = _identifier(
                release["release_id"], f"component {component_index} release id"
            )
            require(release_id not in release_ids, "release ids must be unique per component")
            release_ids.add(release_id)
            prepared_release: dict[str, object] = {
                "release_id": release_id,
                "version": _bounded_text(
                    release["version"], f"component {component_index} release version", 64
                ),
            }
            if "build_variant" in release:
                prepared_release["build_variant"] = _identifier(
                    release["build_variant"],
                    f"component {component_index} release build variant",
                )

            source = _exact_object(
                release["source"],
                f"component {component_index} release source",
                ("reference", "revision", "notice_ids"),
            )
            notice_ids = source["notice_ids"]
            require(isinstance(notice_ids, list) and len(notice_ids) <= 16,
                    "release notice_ids must be a bounded array")
            normalized_notice_ids = []
            for notice_id in notice_ids:
                normalized = _identifier(notice_id, "release notice id")
                require(normalized in known_notice_ids, "release references an unknown notice id")
                require(normalized not in normalized_notice_ids,
                        "release notice ids must be unique")
                normalized_notice_ids.append(normalized)
            prepared_release["source"] = {
                "reference": _reference(source["reference"], "release source reference"),
                "revision": _identifier(source["revision"], "release source revision"),
                "notice_ids": sorted(normalized_notice_ids),
            }

            files = release["files"]
            require(isinstance(files, list) and 0 < len(files) <= MAX_FILES_PER_RELEASE,
                    "release files must be a nonempty bounded array")
            prepared_files = []
            asset_paths: set[str] = set()
            for file_index, value in enumerate(files):
                record = _exact_object(
                    value,
                    f"component {component_index} release {release_index} file {file_index}",
                    ("path", "local_file", "representation_profile"),
                )
                asset_path = _relative_path(record["path"], "catalog asset path")
                require(asset_path not in asset_paths,
                        "asset paths must be unique within a release")
                asset_paths.add(asset_path)
                require(record["representation_profile"] == REPRESENTATION_PROFILE,
                        "asset representation profile is unsupported")
                _, data = _source_asset(source_root, record["local_file"], "local asset file")
                file_count += 1
                require(file_count <= MAX_FILES, "catalog source exceeds the file-count limit")
                total_asset_bytes += len(data)
                require(total_asset_bytes <= MAX_TOTAL_ASSET_BYTES,
                        "catalog source exceeds the aggregate asset-byte limit")
                prepared_files.append({
                    "path": asset_path,
                    "byte_length": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "representation_profile": REPRESENTATION_PROFILE,
                })
            prepared_files.sort(key=lambda record: record["path"])
            prepared_release["files"] = prepared_files
            prepared_releases.append(prepared_release)
        prepared_releases.sort(key=lambda release: release["release_id"])
        prepared_components.append({
            "kind": kind,
            "slug": slug,
            "releases": prepared_releases,
        })
    prepared_components.sort(key=lambda component: (component["kind"], component["slug"]))

    result = {
        "schema": CATALOG_SCHEMA,
        "catalog": {
            "id": _identifier(catalog["id"], "catalog id"),
            "revision": _identifier(catalog["revision"], "catalog revision"),
            "source_namespace": _identifier(
                catalog["source_namespace"], "catalog source namespace"
            ),
            "provenance": provenance,
        },
        "components": prepared_components,
    }
    return result, {
        "components": len(prepared_components),
        "releases": sum(len(component["releases"]) for component in prepared_components),
        "files": file_count,
        "reference_bytes": total_asset_bytes,
    }


def encode_catalog(catalog: dict[str, object]) -> bytes:
    encoded = (json.dumps(catalog, indent=2, sort_keys=True) + "\n").encode("utf-8")
    require(len(encoded) <= MAX_OUTPUT_BYTES, "prepared catalogue exceeds its byte limit")
    return encoded


def write_fresh(path: Path, data: bytes) -> None:
    require(path.name not in {"", ".", ".."}, "output must name a file")
    parent = path.parent
    try:
        metadata = parent.lstat()
    except OSError as error:
        raise PreparationError("output parent is unavailable") from error
    require(stat.S_ISDIR(metadata.st_mode) and not parent.is_symlink(),
            "output parent must be a regular non-link directory")
    require(not os.path.lexists(path), "output already exists")
    created = False
    try:
        with path.open("xb") as output:
            created = True
            require(output.write(data) == len(data), "catalogue output write was incomplete")
    except BaseException:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise


def prepare(source: Path, output: Path) -> dict[str, int | str]:
    catalog, counts = build_catalog(source)
    encoded = encode_catalog(catalog)
    write_fresh(output, encoded)
    return {
        "schema": CATALOG_SCHEMA,
        **counts,
        "output_bytes": len(encoded),
        "output_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path,
                        help="strict source manifest with explicit local asset files")
    parser.add_argument("--output", required=True, type=Path,
                        help="fresh catalogue output path; existing files are refused")
    args = parser.parse_args(argv)
    try:
        summary = prepare(args.source, args.output)
    except (PreparationError, OSError):
        print("wordpress-fingerprint-catalog: preparation failed", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
