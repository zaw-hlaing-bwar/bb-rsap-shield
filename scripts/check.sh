#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
bash -n scripts/check.sh scripts/check-native.sh scripts/build-payload-pack.sh scripts/fuzz-campaign.sh
for json_file in schemas/*.json fixtures/*.json; do
  python3 -m json.tool "${json_file}" >/dev/null
done
python3 scripts/validate-json-schemas.py
bash scripts/check-native.sh
