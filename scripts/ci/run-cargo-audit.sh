#!/usr/bin/env bash
set -euo pipefail

readonly CARGO_AUDIT_VERSION="0.22.2"
readonly CARGO_AUDIT_TOOLCHAIN="1.88.0"

workspace_root="$(git rev-parse --show-toplevel)"
cd -- "$workspace_root"

if [[ ! -f Cargo.lock || -L Cargo.lock ]]; then
  echo "Cargo.lock must be a regular, non-symlinked file" >&2
  exit 1
fi
git ls-files --error-unmatch -- Cargo.lock >/dev/null

lock_fingerprint="$(git hash-object -- Cargo.lock)"
tool_root="$(mktemp -d "${TMPDIR:-/tmp}/termivar-cargo-audit.XXXXXX")"
trap 'rm -rf -- "$tool_root"' EXIT

cargo +"$CARGO_AUDIT_TOOLCHAIN" install \
  cargo-audit \
  --version "$CARGO_AUDIT_VERSION" \
  --locked \
  --root "$tool_root" \
  --no-track

audit_bin="$tool_root/bin/cargo-audit"
expected_version="cargo-audit $CARGO_AUDIT_VERSION"
actual_version="$("$audit_bin" --version)"
if [[ "$actual_version" != "$expected_version" ]]; then
  echo "installed cargo-audit version did not match the reviewed version" >&2
  exit 1
fi
printf '%s\n' "$actual_version"

audit_home="$tool_root/audit-home"
audit_worktree="$tool_root/audit-worktree"
mkdir -p -- "$audit_home/.cargo" "$audit_worktree"
(
  cd -- "$audit_worktree"
  HOME="$audit_home" \
    CARGO_HOME="$audit_home/.cargo" \
    "$audit_bin" audit --file "$workspace_root/Cargo.lock"
)

if [[ "$(git hash-object -- Cargo.lock)" != "$lock_fingerprint" ]]; then
  echo "cargo-audit modified the committed Cargo.lock" >&2
  exit 1
fi
