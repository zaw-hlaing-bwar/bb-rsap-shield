#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash -n scripts/check.sh scripts/check-native.sh scripts/build-payload-pack.sh
bash scripts/check-native.sh
