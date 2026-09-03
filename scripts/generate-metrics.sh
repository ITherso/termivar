#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if ! python3 -c 'import json; from pathlib import Path' >/dev/null 2>&1; then
  echo "python3 is required to read Cargo metadata" >&2
  exit 1
fi

metadata_file=$(mktemp)
trap 'rm -f "$metadata_file"' EXIT
cargo metadata --locked --no-deps --format-version 1 > "$metadata_file"

# Cargo owns the package inventory. Python only converts Cargo's JSON paths to
# repository-relative pathspecs; git remains the authority for tracked files.
mapfile -t workspace_package_roots < <(
  python3 - "$metadata_file" <<'PY'
import json
from pathlib import Path
import sys

with open(sys.argv[1], encoding="utf-8") as metadata_file:
    metadata = json.load(metadata_file)

workspace_root = Path(metadata["workspace_root"]).resolve()
workspace_members = set(metadata["workspace_members"])
package_roots = {
    Path(package["manifest_path"]).resolve().parent.relative_to(workspace_root).as_posix() or "."
    for package in metadata["packages"]
    if package["id"] in workspace_members
}

for package_root in sorted(package_roots):
    print(package_root)
PY
)

if ((${#workspace_package_roots[@]} == 0)); then
  echo "cargo metadata returned no workspace package roots" >&2
  exit 1
fi

rust_pathspecs=()
for package_root in "${workspace_package_roots[@]}"; do
  rust_pathspecs+=("$package_root/*.rs" "$package_root/**/*.rs")
done

# Count only tracked Rust files below package roots returned by locked Cargo
# metadata. Sorting also removes duplicates if package roots ever overlap.
mapfile -t rust_files < <(
  git ls-files --cached -- "${rust_pathspecs[@]}" |
    while IFS= read -r file; do
      if [[ -f "$file" ]]; then
        printf '%s\n' "$file"
      fi
    done |
    sort -u
)

source_files=()
test_files=()
benchmark_files=()

for file in "${rust_files[@]}"; do
  case "$file" in
    */tests/*|*_tests.rs) test_files+=("$file") ;;
    */benches/*) benchmark_files+=("$file") ;;
    *) source_files+=("$file") ;;
  esac
done

sum_lines() {
  local total=0
  local file
  for file in "$@"; do
    total=$((total + $(wc -l < "$file")))
  done
  printf '%d' "$total"
}

source_lines=$(sum_lines "${source_files[@]}")
test_lines=$(sum_lines "${test_files[@]}")
benchmark_lines=$(sum_lines "${benchmark_files[@]}")
total_lines=$((source_lines + test_lines + benchmark_lines))

cat <<EOF
# Termivar workspace Rust metrics

| Metric | Value |
| --- | ---: |
| Workspace source lines | $source_lines |
| Workspace test lines | $test_lines |
| Workspace benchmark lines | $benchmark_lines |
| Total tracked workspace Rust lines | $total_lines |
| Workspace source files | ${#source_files[@]} |
| Workspace test files | ${#test_files[@]} |
| Workspace benchmark files | ${#benchmark_files[@]} |

Generated from tracked Rust files below package roots discovered through
\`cargo metadata --locked --no-deps\`. The virtual workspace root has no source
target and is excluded by construction. These counts describe repository size,
not product quality or test coverage.
EOF
