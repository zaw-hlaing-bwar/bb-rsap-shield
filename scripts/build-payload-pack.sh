#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/build-payload-pack.sh [options]

Builds the Android bootstrap loader/runtime DEX and native libsecurity.so
artifacts, then packages and signs them as a RASP Shield payload pack.

Options:
  --output PATH                 Output payload-pack directory.
  --payload-version VERSION     Payload version written to manifest.json.
  --abis CSV                    Comma-separated ABIs to build.
  --android-min-sdk API         Android API level for D8 and NDK builds.
  --bootstrap-shrinker MODE     Bootstrap DEX backend: auto, d8, or r8.
  --r8-jar PATH                 Optional R8 jar used when MODE is r8 or auto.
  --dex-protector PATH          External secondary-runtime DEX protector adapter.
  --native-protector PATH       External native protector adapter.
  --require-external-protectors Fail unless both protector adapters are configured.
  --signing-key-env NAME        Environment variable containing 32-byte Ed25519 seed hex.
  --minimum-cli-version VERSION Minimum compatible CLI version.
  --maximum-cli-version VERSION Maximum compatible CLI version.
  -h, --help                    Show this help.

Environment:
  ANDROID_HOME or ANDROID_SDK_ROOT  Android SDK location.
  ANDROID_NDK_HOME                  Optional Android NDK location.
  RASP_PAYLOAD_SIGNING_KEY_HEX      Default signing key environment variable.
  RASP_BOOTSTRAP_SHRINKER           Bootstrap DEX backend: auto, d8, or r8.
  RASP_R8_JAR                       Optional path to R8 jar.
  RASP_DEX_PROTECTOR                Optional DEX protector adapter path.
  RASP_NATIVE_PROTECTOR             Optional native protector adapter path.
  RASP_REQUIRE_EXTERNAL_PROTECTORS  Set to 1 to require both adapters.
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
bootstrap_shrinker="${RASP_BOOTSTRAP_SHRINKER:-auto}"
r8_jar="${RASP_R8_JAR:-}"
dex_protector="${RASP_DEX_PROTECTOR:-}"
native_protector="${RASP_NATIVE_PROTECTOR:-}"
require_external_protectors="${RASP_REQUIRE_EXTERNAL_PROTECTORS:-0}"

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
    --bootstrap-shrinker)
      bootstrap_shrinker="${2:?missing value for --bootstrap-shrinker}"
      shift 2
      ;;
    --r8-jar)
      r8_jar="${2:?missing value for --r8-jar}"
      shift 2
      ;;
    --dex-protector)
      dex_protector="${2:?missing value for --dex-protector}"
      shift 2
      ;;
    --native-protector)
      native_protector="${2:?missing value for --native-protector}"
      shift 2
      ;;
    --require-external-protectors)
      require_external_protectors=1
      shift
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

case "${bootstrap_shrinker}" in
  auto|d8|r8) ;;
  *) die "--bootstrap-shrinker must be auto, d8, or r8" ;;
esac
if [[ -n "${r8_jar}" && ! -f "${r8_jar}" ]]; then
  die "--r8-jar must point to an existing file"
fi
case "${require_external_protectors}" in
  0|1) ;;
  *) die "RASP_REQUIRE_EXTERNAL_PROTECTORS must be 0 or 1" ;;
esac
if [[ "${require_external_protectors}" == "1" ]]; then
  [[ -n "${dex_protector}" ]] || die "external protection requires --dex-protector"
  [[ -n "${native_protector}" ]] || die "external protection requires --native-protector"
fi
if [[ -n "${dex_protector}" && ! -x "${dex_protector}" ]]; then
  die "--dex-protector must point to an executable adapter"
fi
if [[ -n "${native_protector}" && ! -x "${native_protector}" ]]; then
  die "--native-protector must point to an executable adapter"
fi
[[ "${android_min_sdk}" =~ ^[0-9]+$ ]] || die "--android-min-sdk must be a number"
[[ -n "${!signing_key_env:-}" ]] || die "set ${signing_key_env} to a 64-character Ed25519 signing seed hex value"

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

check_native_patch_marker() {
  local library="$1"
  python3 -c '
from pathlib import Path
import sys

library = Path(sys.argv[1])
needle = b"com/rasp/runtime/bootstrap/RaspRuntimeEntry"
key_marker = bytes([0x71, 0x49, 0x5A, 0xC5, 0x2D])
detector_key_marker = bytes([0x29, 0x73, 0x5A, 0xB6, 0x4C])
bootstrap_methods = [
    b"nativeInitialize",
    b"nativeMonitorScan",
    b"nativeLastActionCode",
    b"nativeLastReportJson",
]
detector_tokens = [
    b"frida",
    b"gum-js-loop",
    b"frida-agent",
    b"xposed",
    b"generic",
    b"sdk_gphone",
    b"LD_PRELOAD",
    b"de/robv/android/xposed/XposedBridge",
]
report_strings = [
    b"instrumentation.frida_library",
    b"root.su_binary",
    b"emulator.qemu_property",
    b"payload integrity mismatch",
    b"java hook bridge",
    b"ALLOW",
    b"REPORT",
    b"WARN",
    b"LOCK_STARTUP",
    b"TERMINATE",
    b"{\"detector_version\":",
    b",\"risk_score\":",
    b",\"action\":",
    b",\"action_reason\":",
    b",\"signals\":[",
    b"{\"id\":",
    b",\"category\":",
    b",\"confidence\":",
    b",\"severity\":",
    b",\"weight\":",
    b",\"evidence\":",
    b"/proc/self/status",
    b"/proc/self/maps",
    b"/proc/self/task",
    b"/proc/self/fd",
    b"/proc/net/tcp",
    b"/proc/net/tcp6",
    b"/proc/net/unix",
    b"/proc/self/environ",
    b"(Landroid/content/Context;IIIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;IIIIIIIIIIIIII)I",
    b"(IIIILjava/lang/String;Ljava/lang/String;IIIIIIIIIII)I",
    b"()Ljava/lang/String;",
    b"Ljava/lang/String;",
    b"%llx-%llx %4s",
    b"%llx-%llx %4s %llx %15s %llu %511[^\n]",
    b"[vdso]",
    b"[vvar]",
    b"dalvik",
    b"boot.oat",
    b"boot.art",
    b"(deleted)",
    b"00:00",
    b"memfd:",
    b"%s/%s",
    b"%s/%s/comm",
    b"%s=%s",
    b"%127s %127s %63s %255s",
    b"\\u%04x",
]
probe_strings = [
    b"/data/adb/magisk",
    b"ro.kernel.qemu",
    b"/dev/qemu_pipe",
    b"/proc/mounts",
    b"/proc/cpuinfo",
    b"android/os/Build",
    b"BOOTLOADER",
]
plaintext_forbidden_detector_tokens = [
    b"gum-js-loop",
    b"frida-agent",
    b"sdk_gphone",
    b"LD_PRELOAD",
    b"de/robv/android/xposed/XposedBridge",
]
def native_mask(key, index, length):
    position = (index + 1) & 0xFF
    span = length & 0xFF
    mix = (0x9D + ((position * 0x3D) & 0xFF) + ((span * 0x11) & 0xFF)) & 0xFF
    rotated = ((position << 3) | (position >> 5)) & 0xFF
    return key ^ mix ^ rotated

def native_encode(value, key=0x5A):
    return bytes(byte ^ native_mask(key, index, len(value)) for index, byte in enumerate(value))

encoded = native_encode(needle)
data = library.read_bytes()
if needle in data:
    print(f"{library}: contains plaintext bootstrap runtime class", file=sys.stderr)
    sys.exit(1)
if encoded not in data:
    print(f"{library}: missing encoded bootstrap runtime patch marker", file=sys.stderr)
    sys.exit(1)
key_marker_count = data.count(key_marker)
if key_marker_count != 1:
    print(
        f"{library}: expected one bootstrap string key marker, found {key_marker_count}",
        file=sys.stderr,
    )
    sys.exit(1)
detector_key_marker_count = data.count(detector_key_marker)
if detector_key_marker_count != 1:
    print(
        f"{library}: expected one detector string key marker, found {detector_key_marker_count}",
        file=sys.stderr,
    )
    sys.exit(1)
for method in bootstrap_methods:
    if method in data:
        print(f"{library}: contains plaintext bootstrap method {method.decode()}", file=sys.stderr)
        sys.exit(1)
    method_encoded = native_encode(method)
    if method_encoded not in data:
        print(
            f"{library}: missing encoded bootstrap method patch marker {method.decode()}",
            file=sys.stderr,
        )
        sys.exit(1)
for token in plaintext_forbidden_detector_tokens:
    if token in data:
        print(f"{library}: contains plaintext detector token {token.decode()}", file=sys.stderr)
        sys.exit(1)
for token in detector_tokens:
    token_encoded = native_encode(token)
    if token_encoded not in data:
        print(
            f"{library}: missing encoded detector token patch marker {token.decode()}",
            file=sys.stderr,
        )
        sys.exit(1)
for report_string in report_strings:
    if report_string in data:
        print(
            f"{library}: contains plaintext report string {report_string.decode()}",
            file=sys.stderr,
        )
        sys.exit(1)
    report_string_encoded = native_encode(report_string)
    if report_string_encoded not in data:
        print(
            f"{library}: missing encoded report string patch marker {report_string.decode()}",
            file=sys.stderr,
        )
        sys.exit(1)
for probe_string in probe_strings:
    if probe_string in data:
        print(
            f"{library}: contains plaintext probe string {probe_string.decode()}",
            file=sys.stderr,
        )
        sys.exit(1)
    probe_string_encoded = native_encode(probe_string)
    if probe_string_encoded not in data:
        print(
            f"{library}: missing encoded probe string patch marker {probe_string.decode()}",
            file=sys.stderr,
        )
        sys.exit(1)
' "${library}" || die "native library failed bootstrap runtime patch-marker validation: ${library}"
}

check_bootstrap_loader_strings() {
  local loader_dex="$1"
  python3 -c '
from pathlib import Path
import sys

loader_dex = Path(sys.argv[1])
data = loader_dex.read_bytes()
forbidden = [
    b"rasp-shield/integrity-manifest.json",
    b"XOR_SHA256_STREAM_V1",
    b"RASP_SHIELD_BOOTSTRAP_RUNTIME_V1",
    b"onProviderCreate",
    b"startup_budget_ms",
    b"startup_payload_tampering_action",
    b"policy",
    b"payload",
    b"encrypted_runtime",
    b"build_id",
    b"asset_path",
    b"class_name",
    b"sha256",
    b"encryption",
    b"encrypted runtime digest mismatch",
    b"RASP Shield locked startup",
]
encoded_markers = forbidden + [b"runtime"]
for token in forbidden:
    if token in data:
        print(
            f"{loader_dex}: contains plaintext bootstrap loader string {token.decode()}",
            file=sys.stderr,
        )
        sys.exit(1)
def native_mask(key, index, length):
    position = (index + 1) & 0xFF
    span = length & 0xFF
    mix = (0x9D + ((position * 0x3D) & 0xFF) + ((span * 0x11) & 0xFF)) & 0xFF
    rotated = ((position << 3) | (position >> 5)) & 0xFF
    return key ^ mix ^ rotated

def native_encode(value, key=0x5A):
    return bytes(byte ^ native_mask(key, index, len(value)) for index, byte in enumerate(value))

def dex_int_array_encoded(value):
    return b"".join(int(byte).to_bytes(4, "little") for byte in native_encode(value))

for token in encoded_markers:
    if dex_int_array_encoded(token) not in data:
        print(
            f"{loader_dex}: missing encoded bootstrap loader patch marker {token.decode()}",
            file=sys.stderr,
        )
        sys.exit(1)
' "${loader_dex}" || die "bootstrap loader DEX failed static string validation: ${loader_dex}"
}

check_runtime_dex_protector_output() {
  local runtime_dex="$1"
  python3 -c '
from pathlib import Path
import sys

runtime_dex = Path(sys.argv[1])
data = runtime_dex.read_bytes()
if len(data) < 112 or not data.startswith(b"dex\n"):
    print(f"{runtime_dex}: protector output is not a valid DEX container", file=sys.stderr)
    sys.exit(1)
runtime_class = b"com/rasp/runtime/bootstrap/RaspRuntimeEntry"
if runtime_class not in data:
    print(
        f"{runtime_dex}: protector removed or renamed the required runtime entry class",
        file=sys.stderr,
    )
    sys.exit(1)
' "${runtime_dex}" || die "secondary runtime DEX failed protector compatibility validation"
}

check_native_protector_output() {
  local library="$1"
  local abi="$2"
  local readelf_tool="$3"

  python3 -c '
from pathlib import Path
import sys

library = Path(sys.argv[1])
data = library.read_bytes()
if len(data) < 64 or not data.startswith(b"\x7fELF"):
    print(f"{library}: protector output is not an ELF shared object", file=sys.stderr)
    sys.exit(1)
' "${library}" || die "native protector produced an invalid ELF for ${abi}"

  "${readelf_tool}" --dyn-syms "${library}" | awk '
    $NF == "JNI_OnLoad" { found = 1 }
    END { exit(found ? 0 : 1) }
  ' || die "native protector did not preserve the JNI_OnLoad export for ${abi}"
  check_native_patch_marker "${library}"
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
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"
if [[ -n "${r8_jar}" ]]; then
  command -v java >/dev/null 2>&1 || die "java not found on PATH"
fi

r8_command=()
if [[ "${bootstrap_shrinker}" != "d8" ]]; then
  if [[ -n "${r8_jar}" ]]; then
    r8_command=(java -cp "${r8_jar}" com.android.tools.r8.R8)
  elif [[ -x "${build_tools_dir}/r8" ]]; then
    r8_command=("${build_tools_dir}/r8")
  elif [[ -f "${build_tools_dir}/r8.jar" ]]; then
    command -v java >/dev/null 2>&1 || die "java not found on PATH"
    r8_command=(java -cp "${build_tools_dir}/r8.jar" com.android.tools.r8.R8)
  fi
fi
if [[ "${bootstrap_shrinker}" == "r8" && "${#r8_command[@]}" -eq 0 ]]; then
  die "R8 requested but no R8 command was found; pass --r8-jar or use --bootstrap-shrinker d8"
fi

build_root="${root_dir}/target/payload-pack-build/${payload_version}-$$"
classes_dir="${build_root}/classes"
loader_dex_dir="${build_root}/dex-loader"
runtime_dex_dir="${build_root}/dex-runtime"
pack_input_dir="${build_root}/pack-input"
mkdir -p "${classes_dir}" "${loader_dex_dir}" "${runtime_dex_dir}" "${pack_input_dir}"

printf 'Compiling Android bootstrap loader and runtime...\n'
javac \
  -Xlint:-options \
  -g:none \
  -source 8 \
  -target 8 \
  -cp "${android_jar}" \
  -d "${classes_dir}" \
  "${root_dir}/payload/android-bootstrap/src/main/java/com/rasp/runtime/bootstrap/RaspInitProvider.java" \
  "${root_dir}/payload/android-bootstrap/src/main/java/com/rasp/runtime/bootstrap/RaspRuntimeEntry.java"

provider_class_files=()
while IFS= read -r -d '' class_file; do
  provider_class_files+=("${class_file}")
done < <(find "${classes_dir}/com/rasp/runtime/bootstrap" -type f -name 'RaspInitProvider*.class' -print0)
[[ "${#provider_class_files[@]}" -gt 0 ]] || die "javac did not produce provider class files"

runtime_class_files=()
while IFS= read -r -d '' class_file; do
  runtime_class_files+=("${class_file}")
done < <(find "${classes_dir}/com/rasp/runtime/bootstrap" -type f -name 'RaspRuntimeEntry*.class' -print0)
[[ "${#runtime_class_files[@]}" -gt 0 ]] || die "javac did not produce runtime class files"

dex_bootstrap_artifact() {
  local label="$1"
  local output_dir="$2"
  shift 2
  local input_files=("$@")

  if [[ "${#r8_command[@]}" -gt 0 ]]; then
    printf 'Shrinking and converting %s classes with R8...\n' "${label}"
    "${r8_command[@]}" \
      --release \
      --min-api "${android_min_sdk}" \
      --lib "${android_jar}" \
      --classpath "${classes_dir}" \
      --pg-conf "${root_dir}/payload/android-bootstrap/r8-rules.pro" \
      --output "${output_dir}" \
      "${input_files[@]}"
    [[ -f "${output_dir}/classes.dex" ]] || die "R8 did not produce ${label} classes.dex"
  else
    printf 'Converting %s classes to DEX with D8...\n' "${label}"
    "${build_tools_dir}/d8" \
      --release \
      --min-api "${android_min_sdk}" \
      --lib "${android_jar}" \
      --classpath "${classes_dir}" \
      --output "${output_dir}" \
      "${input_files[@]}"
    [[ -f "${output_dir}/classes.dex" ]] || die "D8 did not produce ${label} classes.dex"
  fi
}

dex_bootstrap_artifact "bootstrap loader" "${loader_dex_dir}" "${provider_class_files[@]}"
dex_bootstrap_artifact "bootstrap runtime" "${runtime_dex_dir}" "${runtime_class_files[@]}"
cp "${loader_dex_dir}/classes.dex" "${pack_input_dir}/bootstrap.dex"
cp "${runtime_dex_dir}/classes.dex" "${pack_input_dir}/bootstrap-runtime.dex"
check_bootstrap_loader_strings "${pack_input_dir}/bootstrap.dex"
check_runtime_dex_protector_output "${pack_input_dir}/bootstrap-runtime.dex"

if [[ -n "${dex_protector}" ]]; then
  protected_runtime_dex="${build_root}/protected-bootstrap-runtime.dex"
  printf 'Protecting secondary runtime DEX with external adapter...\n'
  "${dex_protector}" \
    --input "${pack_input_dir}/bootstrap-runtime.dex" \
    --output "${protected_runtime_dex}" \
    --min-sdk "${android_min_sdk}" \
    --keep-class "com.rasp.runtime.bootstrap.RaspRuntimeEntry"
  [[ -f "${protected_runtime_dex}" ]] || die "DEX protector did not produce its declared output"
  check_runtime_dex_protector_output "${protected_runtime_dex}"
  cp "${protected_runtime_dex}" "${pack_input_dir}/bootstrap-runtime.dex"
fi

strip_tool=""
while IFS= read -r candidate; do
  if [[ -x "${candidate}" ]]; then
    strip_tool="${candidate}"
    break
  fi
done < <(find "${ndk_dir}/toolchains/llvm/prebuilt" \( -type f -o -type l \) -path '*/bin/llvm-strip' 2>/dev/null | sort)
[[ -n "${strip_tool}" ]] || die "llvm-strip not found under ${ndk_dir}/toolchains/llvm/prebuilt"

readelf_tool=""
while IFS= read -r candidate; do
  if [[ -x "${candidate}" ]]; then
    readelf_tool="${candidate}"
    break
  fi
done < <(find "${ndk_dir}/toolchains/llvm/prebuilt" \( -type f -o -type l \) -path '*/bin/llvm-readelf' 2>/dev/null | sort)
[[ -n "${readelf_tool}" ]] || die "llvm-readelf not found under ${ndk_dir}/toolchains/llvm/prebuilt"

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
  "${strip_tool}" --strip-all "${pack_input_dir}/${abi}/libsecurity.so" >/dev/null 2>&1 \
    || die "failed to strip native library for ${abi}"
  if [[ -n "${native_protector}" ]]; then
    protected_library="${native_build_dir}/libsecurity.protected.so"
    printf 'Protecting native payload for %s with external adapter...\n' "${abi}"
    "${native_protector}" \
      --input "${pack_input_dir}/${abi}/libsecurity.so" \
      --output "${protected_library}" \
      --abi "${abi}" \
      --preserve-export "JNI_OnLoad"
    [[ -f "${protected_library}" ]] || die "native protector did not produce output for ${abi}"
    check_native_protector_output "${protected_library}" "${abi}" "${readelf_tool}"
    cp "${protected_library}" "${pack_input_dir}/${abi}/libsecurity.so"
  else
    check_native_protector_output "${pack_input_dir}/${abi}/libsecurity.so" "${abi}" "${readelf_tool}"
  fi
  native_args+=(--native-lib "${abi}=${pack_input_dir}/${abi}/libsecurity.so")
done
[[ "${#native_args[@]}" -gt 0 ]] || die "no ABIs selected"

cargo_args=(
  run -q -p rasp-cli --
  build-payload-pack
  --output "${output}"
  --bootstrap-dex "${pack_input_dir}/bootstrap.dex"
  --bootstrap-runtime-dex "${pack_input_dir}/bootstrap-runtime.dex"
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
