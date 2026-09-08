#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository_root=$(cd -- "${script_dir}/.." && pwd -P)

probe=
binary=
output_dir=
source_ref=
expected_version=

usage() {
  cat <<'EOF'
Usage: scripts/run-wordpress-resource-acceptance.sh [options]

Required options:
  --probe PATH             Compiled wordpress_acceptance_corpus test executable
  --binary PATH            Compiled termivar executable with wordpress-review
  --output-dir DIRECTORY   Fresh evidence directory (existing parent required)
  --source-ref SHA         Exact lowercase 40-character source commit
  --expect-version VERSION Exact CLI package version

The runner owns only a new private work directory and the new evidence directory.
It uses GNU time to measure one fresh child per synthetic case. It never accepts
a target or vendor-export path and performs no public-network operation.
EOF
}

while (($# > 0)); do
  case "$1" in
    --probe)
      (($# >= 2)) || { echo "--probe requires a value" >&2; exit 2; }
      probe=$2
      shift 2
      ;;
    --binary)
      (($# >= 2)) || { echo "--binary requires a value" >&2; exit 2; }
      binary=$2
      shift 2
      ;;
    --output-dir)
      (($# >= 2)) || { echo "--output-dir requires a value" >&2; exit 2; }
      output_dir=$2
      shift 2
      ;;
    --source-ref)
      (($# >= 2)) || { echo "--source-ref requires a value" >&2; exit 2; }
      source_ref=$2
      shift 2
      ;;
    --expect-version)
      (($# >= 2)) || { echo "--expect-version requires a value" >&2; exit 2; }
      expected_version=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "${probe}" && -n "${binary}" && -n "${output_dir}" && -n "${source_ref}" && -n "${expected_version}" ]] || {
  echo "every required option must be supplied" >&2
  usage >&2
  exit 2
}
[[ -x /usr/bin/time ]] || { echo "GNU /usr/bin/time is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
  echo "Python 3.11 or newer is required" >&2
  exit 2
}
[[ "${source_ref}" =~ ^[0-9a-f]{40}$ ]] || { echo "--source-ref must be a lowercase full Git SHA" >&2; exit 2; }
[[ "${expected_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$ ]] || {
  echo "--expect-version is invalid" >&2
  exit 2
}

probe=$(cd -- "$(dirname -- "${probe}")" && printf '%s/%s\n' "$(pwd -P)" "$(basename -- "${probe}")")
binary=$(cd -- "$(dirname -- "${binary}")" && printf '%s/%s\n' "$(pwd -P)" "$(basename -- "${binary}")")
[[ -f "${probe}" && -x "${probe}" ]] || { echo "--probe must be an executable regular file" >&2; exit 2; }
[[ -f "${binary}" && -x "${binary}" ]] || { echo "--binary must be an executable regular file" >&2; exit 2; }

temporary_parent=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || {
  echo "temporary parent must be an existing regular directory" >&2
  exit 2
}
temporary_parent=$(cd -- "${temporary_parent}" && pwd -P)
temporary_dir=$(mktemp -d "${temporary_parent}/termivar-wordpress-resource.XXXXXX")
chmod 700 "${temporary_dir}"
cleanup() {
  case "${temporary_dir}" in
    "${temporary_parent}"/termivar-wordpress-resource.*)
      rm -rf -- "${temporary_dir}"
      ;;
    *)
      echo "refusing to remove unexpected temporary path" >&2
      ;;
  esac
}
trap cleanup EXIT

output_parent=$(dirname -- "${output_dir}")
output_name=$(basename -- "${output_dir}")
[[ -d "${output_parent}" && ! -L "${output_parent}" ]] || {
  echo "--output-dir parent must be an existing regular directory" >&2
  exit 2
}
[[ -n "${output_name}" && "${output_name}" != "." && "${output_name}" != ".." ]] || {
  echo "--output-dir must have an ordinary final component" >&2
  exit 2
}
output_parent=$(cd -- "${output_parent}" && pwd -P)
output_dir="${output_parent}/${output_name}"
if ! mkdir -m 700 -- "${output_dir}"; then
  echo "--output-dir must be fresh and exclusively creatable" >&2
  exit 2
fi

cd "${repository_root}"
set +e
python3 scripts/wordpress_resource_acceptance.py \
  --probe "${probe}" \
  --binary "${binary}" \
  --work-dir "${temporary_dir}" \
  --source-ref "${source_ref}" \
  --expect-version "${expected_version}" \
  --json-output "${output_dir}/wordpress-resource-acceptance.json" \
  --markdown-output "${output_dir}/wordpress-resource-acceptance.md"
acceptance_status=$?
set -e

for evidence in wordpress-resource-acceptance.json wordpress-resource-acceptance.md; do
  [[ -f "${output_dir}/${evidence}" && ! -L "${output_dir}/${evidence}" ]] || {
    echo "acceptance did not produce the complete bounded evidence pair" >&2
    exit 1
  }
done
[[ $(find "${output_dir}" -mindepth 1 -maxdepth 1 | wc -l) -eq 2 ]] || {
  echo "acceptance evidence directory contains an unexpected entry" >&2
  exit 1
}

if ((acceptance_status != 0)); then
  echo "WordPress resource acceptance failed; bounded evidence was retained" >&2
  exit "${acceptance_status}"
fi

echo "WordPress resource acceptance JSON: ${output_dir}/wordpress-resource-acceptance.json"
echo "WordPress resource acceptance Markdown: ${output_dir}/wordpress-resource-acceptance.md"
