#!/usr/bin/env bash
set -euo pipefail

# Count only tracked Rust files owned by the workspace packages declared in
# Cargo.toml. Keep these pathspecs aligned with the architecture allowlist.
mapfile -t rust_files < <(
  git ls-files -- \
    'crates/**/*.rs' \
    'examples/**/*.rs' \
    'xtask/**/*.rs'
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
# Venom workspace Rust metrics

| Metric | Value |
| --- | ---: |
| Workspace source lines | $source_lines |
| Workspace test lines | $test_lines |
| Workspace benchmark lines | $benchmark_lines |
| Total tracked workspace Rust lines | $total_lines |
| Workspace source files | ${#source_files[@]} |
| Workspace test files | ${#test_files[@]} |
| Workspace benchmark files | ${#benchmark_files[@]} |

Generated from tracked Rust files under \`crates/\`, \`examples/\`, and
\`xtask/\`. The virtual workspace root has no source target and is excluded by
construction. These counts describe repository size, not product quality or
test coverage.
EOF
