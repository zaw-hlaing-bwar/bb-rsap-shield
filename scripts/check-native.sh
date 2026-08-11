#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${TMPDIR:-/tmp}/rasp-shield-native-check"
mkdir -p "${build_dir}"

cc \
  -std=c11 \
  -DRASP_SECURITY_TEST=1 \
  -I"${root_dir}/payload/android-native/include" \
  -fvisibility=hidden \
  -fstack-protector-strong \
  -Wall \
  -Wextra \
  -Werror \
  "${root_dir}/payload/android-native/tests/test_security.c" \
  "${root_dir}/payload/android-native/src/security.c" \
  -o "${build_dir}/rasp_security_tests"

"${build_dir}/rasp_security_tests"
