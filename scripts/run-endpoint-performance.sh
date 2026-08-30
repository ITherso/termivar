#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "${script_dir}/.." && pwd)
cd "${repository_root}"

workload=all
warmups=1
samples=3
output_dir=target/endpoint-performance

usage() {
  cat <<'EOF'
Usage: scripts/run-endpoint-performance.sh [options]

Options:
  --workload all|100|1000|10000  Fixed local workload selection (default: all)
  --warmups 1|2|3                 Warmup count (default: 1)
  --samples 3..10                 Measured sample count (default: 3)
  --output-dir PATH               Final JSON/Markdown directory
  --help                          Show this help

The benchmark owns its 127.0.0.1 fixture. There is deliberately no target option.
EOF
}

while (($# > 0)); do
  case "$1" in
    --workload)
      (($# >= 2)) || { echo "--workload requires a value" >&2; exit 2; }
      workload=$2
      shift 2
      ;;
    --warmups)
      (($# >= 2)) || { echo "--warmups requires a value" >&2; exit 2; }
      warmups=$2
      shift 2
      ;;
    --samples)
      (($# >= 2)) || { echo "--samples requires a value" >&2; exit 2; }
      samples=$2
      shift 2
      ;;
    --output-dir)
      (($# >= 2)) || { echo "--output-dir requires a value" >&2; exit 2; }
      output_dir=$2
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

case "${workload}" in
  all|100|1000|10000) ;;
  *) echo "--workload must be all, 100, 1000, or 10000" >&2; exit 2 ;;
esac
[[ "${warmups}" =~ ^[1-3]$ ]] || { echo "--warmups must be within 1..3" >&2; exit 2; }
[[ "${samples}" =~ ^([3-9]|10)$ ]] || { echo "--samples must be within 3..10" >&2; exit 2; }
[[ -n "${output_dir}" ]] || { echo "--output-dir must not be empty" >&2; exit 2; }
[[ -x /usr/bin/time ]] || { echo "GNU /usr/bin/time is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }
command -v lscpu >/dev/null || { echo "lscpu is required" >&2; exit 2; }
worktree_state=$(git status --porcelain=v1 --untracked-files=all)
[[ -z "${worktree_state}" ]] || {
  echo "endpoint performance evidence requires a clean worktree" >&2
  exit 2
}

temporary_parent=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
temporary_parent=$(cd -- "${temporary_parent}" && pwd -P)
temporary_dir=$(mktemp -d "${temporary_parent}/venom-endpoint-performance.XXXXXX")
cleanup() {
  case "${temporary_dir}" in
    "${temporary_parent}"/venom-endpoint-performance.*) rm -rf -- "${temporary_dir}" ;;
    *) echo "refusing to remove unexpected temporary path: ${temporary_dir}" >&2 ;;
  esac
}
trap cleanup EXIT
artifact_stream="${temporary_dir}/cargo-artifacts.jsonl"
raw_report="${temporary_dir}/raw-endpoint-performance.json"
resource_report="${temporary_dir}/gnu-time.txt"

cargo bench --locked -p venom-scanner --bench endpoint_assessment --no-run \
  --message-format=json > "${artifact_stream}"
benchmark_executable=$(python3 - "${artifact_stream}" <<'PY'
import json
from pathlib import Path
import sys

executables = []
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    value = json.loads(line)
    target = value.get("target", {})
    if (
        value.get("reason") == "compiler-artifact"
        and target.get("name") == "endpoint_assessment"
        and "bench" in target.get("kind", [])
        and value.get("executable")
    ):
        executables.append(value["executable"])
if len(executables) != 1:
    raise SystemExit(f"expected one endpoint_assessment executable, observed {len(executables)}")
print(executables[0])
PY
)
[[ -x "${benchmark_executable}" ]] || { echo "benchmark executable was not produced" >&2; exit 1; }

cpu_model=$(LC_ALL=C lscpu | awk -F: '/^Model name:/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}')
[[ -n "${cpu_model}" ]] || { echo "could not determine CPU model" >&2; exit 1; }
memory_kib=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)
[[ "${memory_kib}" =~ ^[0-9]+$ ]] || { echo "could not determine total memory" >&2; exit 1; }

export VENOM_PERF_COMMIT_SHA
VENOM_PERF_COMMIT_SHA=$(git rev-parse --verify HEAD)
export VENOM_PERF_RUST_VERSION
VENOM_PERF_RUST_VERSION=$(rustc --version --verbose | tr '\n' ' ' | sed 's/[[:space:]]\+$//')
export VENOM_PERF_OS
VENOM_PERF_OS=$(uname -srvmo)
export VENOM_PERF_BUILD_PROFILE=bench
export VENOM_PERF_CPU_MODEL="${cpu_model}"
export VENOM_PERF_TOTAL_MEMORY_BYTES=$((memory_kib * 1024))

# The production broker honors standard proxy variables. This active-security
# harness must connect only to its own loopback listener, so clear every proxy
# spelling after Cargo has finished and pin the bypass list before execution.
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost

LC_ALL=C /usr/bin/time \
  --format=$'user_seconds=%U\nsystem_seconds=%S\ncpu_percent=%P\npeak_rss_kib=%M' \
  --output="${resource_report}" \
  "${benchmark_executable}" \
  --workload "${workload}" \
  --warmups "${warmups}" \
  --samples "${samples}" \
  --output "${raw_report}"

mkdir -p -- "${output_dir}"
python3 scripts/endpoint_performance_report.py \
  --input "${raw_report}" \
  --gnu-time "${resource_report}" \
  --json-output "${output_dir}/endpoint-performance.json" \
  --markdown-output "${output_dir}/endpoint-performance.md"

echo "Endpoint performance JSON: ${output_dir}/endpoint-performance.json"
echo "Endpoint performance Markdown: ${output_dir}/endpoint-performance.md"
