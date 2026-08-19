#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/fuzz-campaign.sh [options]

Runs RASP Shield cargo-fuzz targets with artifact replay and a text report.

Options:
  --targets CSV              Comma-separated target list.
  --seconds SECONDS          Max fuzzing seconds per target. Default: 300.
  --runs RUNS                Fixed libFuzzer runs per target instead of time.
  --rss-limit-mb MB          libFuzzer RSS limit. Default: 4096.
  --toolchain TOOLCHAIN      Rust toolchain for cargo-fuzz. Default: nightly.
  --report-dir PATH          Report/log output directory.
  --skip-replay              Skip committed regression and local artifact replay.
  --replay-only              Replay regressions/artifacts without fuzzing.
  -h, --help                 Show this help.

Environment:
  RASP_FUZZ_TARGETS          Default target CSV.
  RASP_FUZZ_SECONDS          Default seconds per target.
  RASP_FUZZ_RUNS             Default fixed runs per target.
  RASP_FUZZ_RSS_LIMIT_MB     Default RSS limit.
  RASP_FUZZ_TOOLCHAIN        Default Rust toolchain.
  RASP_FUZZ_REPORT_DIR       Default report directory.
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
known_targets=(
  axml_parse
  axml_provider_injection
  apk_inspect
  apk_rewrite
)

targets_csv="${RASP_FUZZ_TARGETS:-}"
seconds="${RASP_FUZZ_SECONDS:-300}"
runs="${RASP_FUZZ_RUNS:-}"
rss_limit_mb="${RASP_FUZZ_RSS_LIMIT_MB:-4096}"
toolchain="${RASP_FUZZ_TOOLCHAIN:-nightly}"
report_dir="${RASP_FUZZ_REPORT_DIR:-${root_dir}/target/fuzz-campaign/$(date -u +%Y%m%dT%H%M%SZ)}"
replay=true
campaign=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --targets)
      targets_csv="${2:?missing value for --targets}"
      shift 2
      ;;
    --seconds)
      seconds="${2:?missing value for --seconds}"
      shift 2
      ;;
    --runs)
      runs="${2:?missing value for --runs}"
      shift 2
      ;;
    --rss-limit-mb)
      rss_limit_mb="${2:?missing value for --rss-limit-mb}"
      shift 2
      ;;
    --toolchain)
      toolchain="${2:?missing value for --toolchain}"
      shift 2
      ;;
    --report-dir)
      report_dir="${2:?missing value for --report-dir}"
      shift 2
      ;;
    --skip-replay)
      replay=false
      shift
      ;;
    --replay-only)
      campaign=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ "${seconds}" =~ ^[0-9]+$ ]] || die "--seconds must be a non-negative integer"
[[ "${rss_limit_mb}" =~ ^[0-9]+$ ]] || die "--rss-limit-mb must be a non-negative integer"
if [[ -n "${runs}" ]]; then
  [[ "${runs}" =~ ^[0-9]+$ ]] || die "--runs must be a non-negative integer"
fi
if [[ "${campaign}" == true && -n "${runs}" && "${runs}" -eq 0 ]]; then
  die "--runs must be greater than zero unless --replay-only is used"
fi
if [[ "${campaign}" == true && -z "${runs}" && "${seconds}" -eq 0 ]]; then
  die "--seconds must be greater than zero unless --runs is set or --replay-only is used"
fi

if [[ -z "${targets_csv}" ]]; then
  selected_targets=("${known_targets[@]}")
else
  IFS=',' read -r -a selected_targets <<<"${targets_csv}"
fi

is_known_target() {
  local target="$1"
  local known=""
  for known in "${known_targets[@]}"; do
    if [[ "${target}" == "${known}" ]]; then
      return 0
    fi
  done
  return 1
}

trim_target() {
  local target="$1"
  target="${target//[[:space:]]/}"
  printf '%s\n' "${target}"
}

for index in "${!selected_targets[@]}"; do
  selected_targets[$index]="$(trim_target "${selected_targets[$index]}")"
  [[ -n "${selected_targets[$index]}" ]] || die "empty fuzz target in --targets"
  is_known_target "${selected_targets[$index]}" || die "unknown fuzz target: ${selected_targets[$index]}"
done

command -v cargo >/dev/null 2>&1 || die "cargo not found on PATH"
cargo "+${toolchain}" fuzz --version >/dev/null 2>&1 \
  || die "cargo-fuzz with Rust toolchain '${toolchain}' is not available"

mkdir -p "${report_dir}"
summary_file="${report_dir}/summary.txt"
: >"${summary_file}"

log() {
  printf '%s\n' "$*" | tee -a "${summary_file}"
}

print_command() {
  printf '$'
  local arg=""
  for arg in "$@"; do
    printf ' %q' "${arg}"
  done
  printf '\n'
}

run_logged() {
  local log_file="$1"
  shift
  print_command "$@" | tee -a "${summary_file}"
  set +e
  "$@" 2>&1 | tee "${log_file}"
  local status="${PIPESTATUS[0]}"
  set -e
  if [[ "${status}" -eq 0 ]]; then
    log "status: PASS (${log_file})"
  else
    log "status: FAIL ${status} (${log_file})"
  fi
  return "${status}"
}

replay_inputs_for_target() {
  local target="$1"
  local failed=0
  local found=0
  local input=""
  local source_dir=""
  local label=""

  for source_dir in "${root_dir}/fuzz/regressions/${target}" "${root_dir}/fuzz/artifacts/${target}"; do
    [[ -d "${source_dir}" ]] || continue
    label="$(basename "$(dirname "${source_dir}")")"
    for input in "${source_dir}"/*; do
      [[ -f "${input}" ]] || continue
      case "${source_dir}" in
        */artifacts/*)
          case "$(basename "${input}")" in
            crash-*|timeout-*|oom-*|leak-*) ;;
            *) continue ;;
          esac
          ;;
      esac
      found=1
      local safe_name
      safe_name="$(basename "${input}")"
      if ! run_logged \
        "${report_dir}/${target}.${label}.${safe_name}.log" \
        cargo "+${toolchain}" fuzz run "${target}" "${input}" -- -runs=1; then
        failed=1
      fi
    done
  done

  if [[ "${found}" -eq 0 ]]; then
    log "${target}: no committed regressions or local artifacts to replay"
  fi
  return "${failed}"
}

run_campaign_for_target() {
  local target="$1"
  local args=("-rss_limit_mb=${rss_limit_mb}" "-print_final_stats=1")
  if [[ -n "${runs}" ]]; then
    args+=("-runs=${runs}")
  else
    args+=("-max_total_time=${seconds}")
  fi

  run_logged \
    "${report_dir}/${target}.campaign.log" \
    cargo "+${toolchain}" fuzz run "${target}" -- "${args[@]}"
}

log "fuzz_campaign_report: ${report_dir}"
log "toolchain: ${toolchain}"
log "targets: ${selected_targets[*]}"
log "artifact_replay: ${replay}"
if [[ -n "${runs}" ]]; then
  log "runs_per_target: ${runs}"
else
  log "seconds_per_target: ${seconds}"
fi
log "rss_limit_mb: ${rss_limit_mb}"

failed=0
for target in "${selected_targets[@]}"; do
  log "target: ${target}"
  if [[ "${replay}" == true ]]; then
    replay_inputs_for_target "${target}" || failed=1
  fi
  if [[ "${campaign}" == true ]]; then
    run_campaign_for_target "${target}" || failed=1
  fi
done

if [[ "${failed}" -eq 0 ]]; then
  log "result: PASS"
else
  log "result: FAIL"
fi

exit "${failed}"
