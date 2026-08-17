# Fuzzing

The fuzz crate is intentionally isolated from the main workspace so normal
builds do not require `cargo-fuzz`. `scripts/check.sh` still compile-checks all
fuzz targets with stable Rust.

Targets:

- `axml_parse`: raw and mutated binary Android manifest parsing.
- `axml_provider_injection`: provider injection, duplicate-provider rejection,
  and parse-after-mutation behavior.
- `apk_inspect`: raw APK bytes plus generated APK ZIPs with risky paths,
  duplicates, signature metadata, symlink-mode entries, DEX files, native
  libraries, React Native assets, and Flutter assets.
- `apk_rewrite`: unsigned APK rewrite with payload insertion, manifest
  mutation, signature stripping, collision handling, and inspect-after-rewrite
  checks.

Run a short local campaign:

```sh
cargo install cargo-fuzz
cargo fuzz run axml_parse -- -max_total_time=60
cargo fuzz run axml_provider_injection -- -max_total_time=60
cargo fuzz run apk_inspect -- -max_total_time=60
cargo fuzz run apk_rewrite -- -max_total_time=60
```

Compile-check without running libFuzzer:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
```

Crash artifacts are written under `fuzz/artifacts/`. Add minimized regressions
to the relevant crate tests before deleting the artifact.
