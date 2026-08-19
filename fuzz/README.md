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

Run a local campaign with artifact replay:

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
scripts/fuzz-campaign.sh --seconds 300
```

The campaign script replays committed inputs from `fuzz/regressions/<target>/`
and local libFuzzer crash artifacts from `fuzz/artifacts/<target>/` before
running each selected target. Logs are written under `target/fuzz-campaign/` by
default. To run a deterministic smoke pass without spending time fuzzing:

```sh
scripts/fuzz-campaign.sh --runs 1
```

To run only high-risk parser and rewrite targets:

```sh
scripts/fuzz-campaign.sh --targets axml_parse,apk_rewrite --seconds 1800
```

Compile-check without running libFuzzer:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
```

Crash artifacts are written under `fuzz/artifacts/`. Reproduce each artifact
with `scripts/fuzz-campaign.sh --replay-only --targets <target>`, minimize it,
then either add a focused crate test or commit the minimized input under
`fuzz/regressions/<target>/`. Local generated corpus state is written under
`fuzz/corpus/` and is intentionally ignored; promote only curated seeds or
regression tests into source control.

The scheduled GitHub workflow in `.github/workflows/fuzz.yml` runs the same
script nightly and can also be started manually with a custom seconds-per-target
budget. Its logs and libFuzzer artifacts are uploaded as workflow artifacts.
