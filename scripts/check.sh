#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash -n scripts/check.sh scripts/check-native.sh scripts/build-payload-pack.sh
for json_file in schemas/*.json fixtures/*.json; do
  python3 -m json.tool "${json_file}" >/dev/null
done
bash scripts/check-native.sh
