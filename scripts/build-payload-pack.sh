#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/build-payload-pack.sh [options]

Builds the Android bootstrap DEX and native libsecurity.so artifacts, then
packages and signs them as a RASP Shield payload pack.

Options:
  --output PATH                 Output payload-pack directory.
  --payload-version VERSION     Payload version written to manifest.json.
  --abis CSV                    Comma-separated ABIs to build.
  --android-min-sdk API         Android API level for D8 and NDK builds.
  --signing-key-env NAME        Environment variable containing 32-byte Ed25519 seed hex.
  --minimum-cli-version VERSION Minimum compatible CLI version.
  --maximum-cli-version VERSION Maximum compatible CLI version.
  -h, --help                    Show this help.

Environment:
  ANDROID_HOME or ANDROID_SDK_ROOT  Android SDK location.
  ANDROID_NDK_HOME                  Optional Android NDK location.
  RASP_PAYLOAD_SIGNING_KEY_HEX      Default signing key environment variable.
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${RASP_PAYLOAD_PACK_OUTPUT:-${root_dir}/target/payload-pack/android-dev}"
payload_version="${RASP_PAYLOAD_VERSION:-0.1.0-dev}"
abis_csv="${RASP_PAYLOAD_ABIS:-arm64-v8a}"
android_min_sdk="${RASP_ANDROID_MIN_SDK:-23}"
signing_key_env="${RASP_PAYLOAD_SIGNING_KEY_ENV:-RASP_PAYLOAD_SIGNING_KEY_HEX}"
minimum_cli_version="${RASP_PAYLOAD_MINIMUM_CLI_VERSION:-}"
maximum_cli_version="${RASP_PAYLOAD_MAXIMUM_CLI_VERSION:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output="${2:?missing value for --output}"
      shift 2
      ;;
    --payload-version)
      payload_version="${2:?missing value for --payload-version}"
      shift 2
      ;;
    --abis)
      abis_csv="${2:?missing value for --abis}"
      shift 2
      ;;
    --android-min-sdk)
      android_min_sdk="${2:?missing value for --android-min-sdk}"
      shift 2
      ;;
    --signing-key-env)
      signing_key_env="${2:?missing value for --signing-key-env}"
      shift 2
      ;;
    --minimum-cli-version)
      minimum_cli_version="${2:?missing value for --minimum-cli-version}"
      shift 2
      ;;
    --maximum-cli-version)
      maximum_cli_version="${2:?missing value for --maximum-cli-version}"
      shift 2
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

[[ -n "${!signing_key_env:-}" ]] || die "set ${signing_key_env} to a 64-character Ed25519 signing seed hex value"
[[ "${android_min_sdk}" =~ ^[0-9]+$ ]] || die "--android-min-sdk must be a number"

android_sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "${android_sdk}" && -d "${HOME}/Library/Android/sdk" ]]; then
  android_sdk="${HOME}/Library/Android/sdk"
fi
[[ -n "${android_sdk}" && -d "${android_sdk}" ]] || die "Android SDK not found; set ANDROID_HOME"

version_score() {
  local name="${1##*/}"
  name="${name%%-*}"
  local major=0
  local minor=0
  local patch=0
  IFS='.' read -r major minor patch _ <<<"${name}"
  printf '%03d%03d%03d' "${major:-0}" "${minor:-0}" "${patch:-0}"
}

latest_dir_with_file() {
  local base="$1"
  local relative_file="$2"
  local best=""
  local best_score=""
  local candidate=""
  while IFS= read -r candidate; do
    if [[ -f "${candidate}/${relative_file}" ]]; then
      local score
      score="$(version_score "${candidate}")"
      if [[ -z "${best_score}" || "${score}" > "${best_score}" ]]; then
        best="${candidate}"
        best_score="${score}"
      fi
    fi
  done < <(find "${base}" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort)
  printf '%s\n' "${best}"
}

latest_android_jar() {
  local best=""
  local best_api=-1
  local candidate=""
  while IFS= read -r candidate; do
    local platform
    platform="$(basename "$(dirname "${candidate}")")"
    local api="${platform#android-}"
    api="${api%%-*}"
    if [[ "${api}" =~ ^[0-9]+$ && "${api}" -gt "${best_api}" ]]; then
      best="${candidate}"
      best_api="${api}"
    fi
  done < <(find "${android_sdk}/platforms" -maxdepth 2 -type f -name android.jar 2>/dev/null | sort)
  printf '%s\n' "${best}"
}

android_jar="$(latest_android_jar)"
build_tools_dir="$(latest_dir_with_file "${android_sdk}/build-tools" d8)"
ndk_dir="${ANDROID_NDK_HOME:-}"
if [[ -z "${ndk_dir}" ]]; then
  ndk_dir="$(latest_dir_with_file "${android_sdk}/ndk" build/cmake/android.toolchain.cmake)"
fi

[[ -n "${android_jar}" && -f "${android_jar}" ]] || die "android.jar not found under ${android_sdk}/platforms"
[[ -n "${build_tools_dir}" && -x "${build_tools_dir}/d8" ]] || die "d8 not found under ${android_sdk}/build-tools"
[[ -n "${ndk_dir}" && -f "${ndk_dir}/build/cmake/android.toolchain.cmake" ]] || die "Android NDK CMake toolchain not found"
command -v javac >/dev/null 2>&1 || die "javac not found on PATH"
command -v cmake >/dev/null 2>&1 || die "cmake not found on PATH"

build_root="${root_dir}/target/payload-pack-build/${payload_version}-$$"
classes_dir="${build_root}/classes"
dex_dir="${build_root}/dex"
pack_input_dir="${build_root}/pack-input"
mkdir -p "${classes_dir}" "${dex_dir}" "${pack_input_dir}"

printf 'Compiling Android bootstrap provider...\n'
javac \
  -Xlint:-options \
  -source 8 \
  -target 8 \
  -cp "${android_jar}" \
  -d "${classes_dir}" \
  "${root_dir}/payload/android-bootstrap/src/main/java/com/rasp/runtime/bootstrap/RaspInitProvider.java"

class_files=()
while IFS= read -r -d '' class_file; do
  class_files+=("${class_file}")
done < <(find "${classes_dir}" -type f -name '*.class' -print0)
[[ "${#class_files[@]}" -gt 0 ]] || die "javac did not produce any class files"

printf 'Converting bootstrap classes to DEX...\n'
"${build_tools_dir}/d8" \
  --min-api "${android_min_sdk}" \
  --lib "${android_jar}" \
  --output "${dex_dir}" \
  "${class_files[@]}"
[[ -f "${dex_dir}/classes.dex" ]] || die "d8 did not produce classes.dex"
cp "${dex_dir}/classes.dex" "${pack_input_dir}/bootstrap.dex"

strip_tool=""
while IFS= read -r candidate; do
  strip_tool="${candidate}"
  break
done < <(find "${ndk_dir}/toolchains/llvm/prebuilt" -type f -path '*/bin/llvm-strip' 2>/dev/null | sort)

IFS=',' read -r -a abis <<<"${abis_csv}"
native_args=()
for abi in "${abis[@]}"; do
  abi="${abi//[[:space:]]/}"
  [[ -n "${abi}" ]] || continue
  case "${abi}" in
    arm64-v8a|armeabi-v7a|x86_64) ;;
    *) die "unsupported ABI: ${abi}" ;;
  esac

  native_build_dir="${build_root}/native/${abi}"
  printf 'Building native payload for %s...\n' "${abi}"
  cmake \
    -S "${root_dir}/payload/android-native" \
    -B "${native_build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE="${ndk_dir}/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="${abi}" \
    -DANDROID_PLATFORM="android-${android_min_sdk}"
  cmake --build "${native_build_dir}" --target security --config Release

  built_library="${native_build_dir}/libsecurity.so"
  [[ -f "${built_library}" ]] || die "native build did not produce ${built_library}"
  mkdir -p "${pack_input_dir}/${abi}"
  cp "${built_library}" "${pack_input_dir}/${abi}/libsecurity.so"
  if [[ -n "${strip_tool}" ]]; then
    "${strip_tool}" --strip-unneeded "${pack_input_dir}/${abi}/libsecurity.so" >/dev/null 2>&1 || true
  fi
  native_args+=(--native-lib "${abi}=${pack_input_dir}/${abi}/libsecurity.so")
done
[[ "${#native_args[@]}" -gt 0 ]] || die "no ABIs selected"

cargo_args=(
  run -q -p rasp-cli --
  build-payload-pack
  --output "${output}"
  --bootstrap-dex "${pack_input_dir}/bootstrap.dex"
  --payload-version "${payload_version}"
  --payload-signing-key-env "${signing_key_env}"
)
if [[ -n "${minimum_cli_version}" ]]; then
  cargo_args+=(--minimum-cli-version "${minimum_cli_version}")
fi
if [[ -n "${maximum_cli_version}" ]]; then
  cargo_args+=(--maximum-cli-version "${maximum_cli_version}")
fi
cargo_args+=("${native_args[@]}")

printf 'Writing signed payload pack...\n'
(
  cd "${root_dir}"
  cargo "${cargo_args[@]}"
)
