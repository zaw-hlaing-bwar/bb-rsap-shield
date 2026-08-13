# RASP Shield CLI

RASP Shield CLI is a post-build Android APK hardening tool. It inspects an
already-built APK, injects a signed runtime protection payload, prepares the APK
for signing, verifies the hardened output, and can run a basic ADB smoke test on
a connected device.

The current release line is focused on Android React Native and Flutter APKs.
It works after your normal app build has produced an APK; it does not replace
Gradle, Metro, Flutter, Play signing, or your release pipeline.

## What It Provides

`rasp-cli` provides these capabilities:

- APK inspection: ZIP safety checks, manifest metadata, package/version/SDK
  details, DEX/native library inventory, ABI detection, React Native and Flutter
  indicators, signing scheme detection, signing certificate SHA-256 digests, and
  existing security-product markers.
- APK shielding: injects a bootstrap DEX as the next available `classesN.dex`,
  injects `libsecurity.so` for each payload ABI, adds a private
  `ContentProvider`, writes an internal integrity manifest, and removes stale
  APK signature metadata from the unsigned output.
- Runtime startup bootstrap: `com.rasp.runtime.bootstrap.RaspInitProvider`
  loads the native runtime before the host `Application.onCreate()` path.
- Runtime policy embedding: stores expected package name, expected signing
  certificate digests, payload digests, protected asset digests, APK inventory
  digests, risk thresholds, and runtime monitoring settings inside
  `assets/rasp-shield/integrity-manifest.json`.
- Runtime detection MVP: debugger attachment, Frida/Gum indicators, Frida ports
  and sockets, Xposed/LSPosed/EdXposed, Substrate, Zygisk/Riru/Magisk traces,
  suspicious writable/executable mappings, hook-related environment variables,
  native hook frameworks such as Dobby, ShadowHook, xHook, Whale, HookZz, and
  libhooker, plus native runtime self-checksum monitoring.
- Integrity checks: startup package/certificate validation, startup payload
  self-integrity, bounded startup hashing for small protected JavaScript assets,
  deferred monitor hashing for larger JavaScript and Flutter assets, and APK
  inventory verification to detect added executable entries.
- Signing support: external signing workflow artifacts, or local signing through
  Android SDK `zipalign` and `apksigner`.
- Verification reports: static checks for the injected provider, integrity
  manifest, protected asset digests, APK inventory, payload digests, and optional
  signing certificate match.
- Payload-pack creation: signs a payload-pack manifest with Ed25519 and includes
  payload SBOM/license metadata.
- Runtime smoke testing: installs and launches a signed APK through ADB, checks
  that the target process remains running, and optionally writes a JSON report.

## Support Matrix

| Area | Current support |
| --- | --- |
| Input artifact | Android `.apk` only |
| App frameworks | React Native APKs and Flutter APKs |
| Unsupported artifacts | `.aab`, `.ipa`, `.xcarchive`, and unknown file types |
| Android minimum SDK | `23` or higher |
| Target SDK compatibility warning range | `33` through `36` |
| Payload ABIs | `arm64-v8a`, `armeabi-v7a`, `x86_64` |
| Bootstrap mechanism | Private Android `ContentProvider` |
| Signing modes | `external` and `local` |
| Host OS checked by `doctor` | macOS `aarch64`/`x86_64`, Linux `x86_64` |

## Install

### Prerequisites

Install these tools before building or using the full Android pipeline:

- Rust stable with Cargo. This workspace requires Rust `1.77` or newer and uses
  `rust-toolchain.toml` with `rustfmt` and `clippy`.
- Android SDK build tools containing `zipalign`, `apksigner`, and `d8`.
- `ANDROID_HOME` or `ANDROID_SDK_ROOT` pointing at the Android SDK. On macOS,
  the CLI also checks `$HOME/Library/Android/sdk`.
- Java/JDK with `javac`.
- CMake and Android NDK when building payload packs from the included native
  source.
- `adb` when using `runtime-smoke`.

### Build From Source

```sh
git clone <repo-url>
cd bb-rsap-shield
cargo build --release -p rasp-cli
./target/release/rasp-cli --help
```

Optional local install:

```sh
cargo install --path crates/rasp-cli
rasp-cli --help
```

Check host dependencies:

```sh
rasp-cli doctor
```

Run repository checks:

```sh
bash scripts/check.sh
```

## Quick Start

### 1. Inspect The Input APK

```sh
rasp-cli inspect \
  --input build/app-release.apk
```

JSON output is useful for CI and for capturing the signing certificate digest:

```sh
rasp-cli inspect \
  --input build/app-release.apk \
  --format json \
  --output build/app-release.inspection.json
```

Use the printed `Signing certificate SHA-256` value as the
`--expected-cert-sha256` argument in shielding and verification commands.

### 2. Create A Config File

Start from the example:

```sh
cp fixtures/rasp.config.example.json rasp.config.json
```

Edit at least these values:

- `application.expected_package_name`: exact APK package name, for example
  `com.example.mobile`.
- `android.certificate_sha256`: either a literal 64-character certificate
  SHA-256 digest or `CURRENT_SIGNING_CERTIFICATE_SHA256`.
- `protections.javascript_bundle_integrity.paths`: APK entry paths to protect
  for React Native, for example `assets/index.android.bundle`.
- `protections.flutter_integrity`: enable for Flutter apps. If enabled with an
  empty `paths` list, the CLI auto-protects detected `libapp.so`,
  `libflutter.so`, and `assets/flutter_assets/*` entries.

### 3. Build A Payload Pack

Generate or provide a 32-byte Ed25519 signing seed as 64 lowercase or uppercase
hex characters:

```sh
export RASP_PAYLOAD_SIGNING_KEY_HEX="$(openssl rand -hex 32)"
```

Build the bootstrap DEX and native runtime from this repository:

```sh
bash scripts/build-payload-pack.sh \
  --output target/payload-pack/android-release \
  --payload-version 0.1.0 \
  --abis arm64-v8a,armeabi-v7a
```

The command prints `payload_signing_public_key_hex`. Pass that public key to
`rasp-cli shield --payload-signing-public-key-hex` whenever you consume the
payload pack.

### 4. Shield With External Signing

Use this when your release pipeline signs APKs outside `rasp-cli`, for example
through CI, Play App Signing, or another signing service.

```sh
rasp-cli shield \
  --input build/app-release.apk \
  --output build/app-release.hardened.unsigned.apk \
  --config rasp.config.json \
  --signing-mode external \
  --expected-cert-sha256 <64-hex-release-cert-sha256> \
  --payload-pack target/payload-pack/android-release \
  --payload-signing-public-key-hex <payload-public-key-hex>
```

This writes:

- `build/app-release.hardened.unsigned.apk`
- `build/app-release.hardened.unsigned.signing-request.json`
- `build/app-release.hardened.unsigned.verification-template.json`

Sign the unsigned APK with your release process, then verify the signed result:

```sh
rasp-cli verify \
  --input build/app-release.hardened.unsigned.signed.apk \
  --expected-cert-sha256 <64-hex-release-cert-sha256> \
  --report build/app-release.hardened.verify.json
```

### 5. Shield With Local Signing

Use this when `rasp-cli` should run `zipalign` and `apksigner` directly.

```sh
export KEYSTORE_PASSWORD='<keystore-password>'
export KEY_PASSWORD='<key-password>'

rasp-cli shield \
  --input build/app-release.apk \
  --output build/app-release.hardened.signed.apk \
  --config rasp.config.json \
  --signing-mode local \
  --keystore release.keystore \
  --keystore-alias release \
  --keystore-password-env KEYSTORE_PASSWORD \
  --key-password-env KEY_PASSWORD \
  --expected-cert-sha256 <64-hex-release-cert-sha256> \
  --payload-pack target/payload-pack/android-release \
  --payload-signing-public-key-hex <payload-public-key-hex>
```

`--expected-cert-sha256` is required when the config uses
`CURRENT_SIGNING_CERTIFICATE_SHA256`; otherwise it is optional for local signing
but recommended so the CLI verifies the final certificate.

### 6. Runtime Smoke Test

Run this only against a signed APK on a connected Android device or emulator:

```sh
rasp-cli runtime-smoke \
  --input build/app-release.hardened.signed.apk \
  --report build/runtime-smoke.json
```

If the package or launch activity cannot be decoded from the APK, pass them
explicitly:

```sh
rasp-cli runtime-smoke \
  --input build/app-release.hardened.signed.apk \
  --package com.example.mobile \
  --activity .MainActivity \
  --device-serial <adb-serial>
```

## Commands And Options

### `rasp-cli inspect`

Inspects an APK without modifying it.

```text
Usage: rasp-cli inspect [OPTIONS] --input <INPUT>
```

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `--input <INPUT>` | Yes | | APK path to inspect. The input must be a regular file and must not be a symlink. |
| `--format <FORMAT>` | No | `text` | Output format. Possible values: `text`, `json`. |
| `--output <OUTPUT>` | No | stdout | File path for JSON output. Text output is always printed to stdout. |

Text output includes package metadata, SDK values, React Native/Flutter
indicators, DEX/native counts, supported ABIs, signing schemes, certificate
SHA-256 digests, ZIP entry counts, compatibility warnings, and generic warnings.

### `rasp-cli shield`

Hardens an APK by injecting the verified runtime payload.

```text
Usage: rasp-cli shield [OPTIONS] --input <INPUT> --output <OUTPUT> --config <CONFIG>
```

Common options:

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `--input <INPUT>` | Yes | | Source APK to harden. |
| `--output <OUTPUT>` | Yes | | Output APK path. Must be different from `--input`. In external mode this is unsigned; in local mode this is signed. |
| `--config <CONFIG>` | Yes | | RASP Shield JSON config. See `schemas/rasp-config.schema.json`. |
| `--signing-mode <SIGNING_MODE>` | No | `external` | `external` writes an unsigned APK and signing request. `local` signs with `zipalign` and `apksigner`. |
| `--expected-cert-sha256 <EXPECTED_CERT_SHA256>` | Depends | | 64-character signing certificate SHA-256 digest. Required for external signing and required whenever config uses `CURRENT_SIGNING_CERTIFICATE_SHA256`. |
| `--payload-pack <PAYLOAD_PACK>` | Yes | | Signed payload-pack directory. Bundled payloads are not implemented yet, so this is currently required. |
| `--payload-signing-public-key-hex <PAYLOAD_SIGNING_PUBLIC_KEY_HEX>` | Yes | | 32-byte Ed25519 public key as 64 hex characters. Used to verify `payload-pack/signature.ed25519`. |
| `--keep-workdir` | No | `false` | In local signing mode, keep temporary unsigned and aligned APKs and print their paths. |

External signing options:

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `--signing-request <SIGNING_REQUEST>` | No | `<output-stem>.signing-request.json` | Path for the JSON request describing the unsigned APK and expected signing certificate. |
| `--verification-template <VERIFICATION_TEMPLATE>` | No | `<output-stem>.verification-template.json` | Path for a JSON template describing the expected signed APK and payload metadata. |

Local signing options:

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `--keystore <KEYSTORE>` | Yes for `local` | | Existing Android keystore file. |
| `--keystore-alias <KEYSTORE_ALIAS>` | Yes for `local` | | Key alias passed to `apksigner --ks-key-alias`. |
| `--keystore-password-env <KEYSTORE_PASSWORD_ENV>` | Yes for `local` | | Environment variable name containing the keystore password. Pass the variable name, not the secret value. |
| `--key-password-env <KEY_PASSWORD_ENV>` | Yes for `local` | | Environment variable name containing the key password. Pass the variable name, not the secret value. |

Injected APK entries:

- `classesN.dex`: bootstrap DEX, where `N` is the next available DEX number.
- `lib/<abi>/libsecurity.so`: native runtime library for each payload ABI.
- `assets/rasp-shield/integrity-manifest.json`: internal policy and digest
  manifest.

### `rasp-cli verify`

Verifies a hardened APK and optionally writes a JSON report.

```text
Usage: rasp-cli verify [OPTIONS] --input <INPUT>
```

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `--input <INPUT>` | Yes | | Hardened APK to verify. |
| `--report <REPORT>` | No | stdout | JSON verification report path. |
| `--expected-cert-sha256 <EXPECTED_CERT_SHA256>` | No | | 64-character signing certificate SHA-256 digest to require in the APK. If omitted, the signing certificate check is skipped with a warning. |

Verification checks include APK inspection, ZIP safety, internal integrity
manifest presence, package metadata, private bootstrap provider, protected asset
digests, bootstrap DEX, native payload libraries, payload digest manifest, APK
inventory, optional Flutter protected assets, and optional signing certificate
matching.

### `rasp-cli runtime-smoke`

Installs and launches a signed APK on a connected Android device through ADB.

```text
Usage: rasp-cli runtime-smoke [OPTIONS] --input <INPUT>
```

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `--input <INPUT>` | Yes | | Signed APK to install and launch. |
| `--package <PACKAGE>` | No | decoded package | Package name. Required if inspection cannot decode it. If provided and inspection decodes a different package, the command fails. |
| `--activity <ACTIVITY>` | No | decoded main activity or launcher monkey | Activity to launch. Accepts `.MainActivity`, `MainActivity`, or full `package/activity` component syntax. |
| `--device-serial <DEVICE_SERIAL>` | No | default ADB device | Serial passed to `adb -s`. |
| `--wait-after-launch-ms <WAIT_AFTER_LAUNCH_MS>` | No | `1500` | Milliseconds to wait after launch before checking `pidof`. |
| `--no-uninstall` | No | `false` | Leave the APK installed after the test. |
| `--report <REPORT>` | No | none | JSON runtime smoke-test report path. |

The smoke test checks ADB device state, installs with `adb install -r -t`,
launches the app, checks that the process is running, and uninstalls unless
`--no-uninstall` is passed.

### `rasp-cli build-payload-pack`

Builds a signed payload-pack directory from precompiled payload artifacts.

```text
Usage: rasp-cli build-payload-pack [OPTIONS] --output <OUTPUT> --bootstrap-dex <BOOTSTRAP_DEX> --payload-version <PAYLOAD_VERSION> --payload-signing-key-env <PAYLOAD_SIGNING_KEY_ENV>
```

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `--output <OUTPUT>` | Yes | | Output payload-pack directory. Must not be an existing file. |
| `--bootstrap-dex <BOOTSTRAP_DEX>` | Yes | | Existing DEX file. Must have DEX magic. |
| `--native-lib <ABI=PATH>` | Yes, one or more | | Native `libsecurity.so` for an ABI. Repeat for multiple ABIs. ABI must be `arm64-v8a`, `armeabi-v7a`, or `x86_64`. |
| `--payload-version <PAYLOAD_VERSION>` | Yes | | Payload version written to `manifest.json`. |
| `--payload-signing-key-env <PAYLOAD_SIGNING_KEY_ENV>` | Yes | | Environment variable name containing a 32-byte Ed25519 signing seed as 64 hex characters. |
| `--minimum-cli-version <MINIMUM_CLI_VERSION>` | No | current CLI version | Minimum compatible CLI version written to the payload manifest. |
| `--maximum-cli-version <MAXIMUM_CLI_VERSION>` | No | current CLI major as `<major>.x` | Maximum compatible CLI version written to the payload manifest. |

Payload-pack layout:

```text
payload-pack/
  manifest.json
  signature.ed25519
  bootstrap.dex
  arm64-v8a/libsecurity.so
  armeabi-v7a/libsecurity.so
  x86_64/libsecurity.so
  sbom.json
  licenses/NOTICE.txt
```

Only the ABI directories you provide are written. `manifest.json` contains
SHA-256 digests for every payload file, and `signature.ed25519` signs the raw
manifest bytes.

### `rasp-cli doctor`

Checks host dependencies needed by the Android pipeline.

Required checks:

- Java runtime
- `zipalign`
- `apksigner`
- temporary directory write permission
- supported host architecture

Optional check:

- `adb`

### `rasp-cli version`

Prints CLI, schema, build target, and git commit metadata.

## Payload-Pack Build Script

For development payloads, the repository includes
`scripts/build-payload-pack.sh`. It compiles the Java bootstrap provider with
`javac`, converts it to DEX with Android SDK `d8`, builds native
`libsecurity.so` with CMake and the Android NDK, then calls
`rasp-cli build-payload-pack`.

```text
Usage: scripts/build-payload-pack.sh [options]
```

| Option | Default | Description |
| --- | --- | --- |
| `--output PATH` | `target/payload-pack/android-dev` | Output payload-pack directory. |
| `--payload-version VERSION` | `0.1.0-dev` | Payload version. |
| `--abis CSV` | `arm64-v8a` | Comma-separated ABIs to build. Supported: `arm64-v8a`, `armeabi-v7a`, `x86_64`. |
| `--android-min-sdk API` | `23` | Android API level for `d8` and NDK builds. |
| `--signing-key-env NAME` | `RASP_PAYLOAD_SIGNING_KEY_HEX` | Environment variable containing a 32-byte Ed25519 signing seed as 64 hex characters. |
| `--minimum-cli-version VERSION` | omitted | Minimum compatible CLI version. |
| `--maximum-cli-version VERSION` | omitted | Maximum compatible CLI version. |
| `-h`, `--help` | | Show script help. |

Environment variables accepted by the script:

- `ANDROID_HOME` or `ANDROID_SDK_ROOT`: Android SDK location.
- `ANDROID_NDK_HOME`: optional Android NDK location. If omitted, the script
  searches under the SDK.
- `RASP_PAYLOAD_SIGNING_KEY_HEX`: default payload signing seed variable.
- `RASP_PAYLOAD_PACK_OUTPUT`, `RASP_PAYLOAD_VERSION`,
  `RASP_PAYLOAD_ABIS`, `RASP_ANDROID_MIN_SDK`,
  `RASP_PAYLOAD_SIGNING_KEY_ENV`, `RASP_PAYLOAD_MINIMUM_CLI_VERSION`, and
  `RASP_PAYLOAD_MAXIMUM_CLI_VERSION`: defaults for matching script options.

## Configuration Reference

The config file is strict JSON. Unknown fields are rejected. See
`fixtures/rasp.config.example.json` for a complete example and
`schemas/rasp-config.schema.json` for the JSON schema.

### Top-Level Fields

| Field | Required | Description |
| --- | --- | --- |
| `schema_version` | Yes | Must be `1`. |
| `application` | Yes | Application identity and environment labels. |
| `protections` | Yes | Protection rules and weights. Missing child rules default to disabled. |
| `risk_policy` | Yes | Risk thresholds and configured responses. |
| `runtime` | Yes | Runtime monitoring settings. |
| `android` | Yes | Android-specific package, ABI, SDK, and signing expectations. |
| `telemetry` | No | Reserved telemetry configuration. Defaults to disabled. |
| `output` | No | Reserved output preferences. Command flags currently control report paths. |

### `application`

| Field | Required | Description |
| --- | --- | --- |
| `profile` | Yes | Non-empty profile label, for example `banking-strict`. |
| `expected_package_name` | Yes | Exact Android package name expected in `AndroidManifest.xml`. |
| `build_environment` | Yes | Non-empty environment label, for example `production`. |

### `protections`

Most protection entries use this shape:

```json
{ "enabled": true, "weight": 60 }
```

`weight` must be from `0` through `100`.

| Field | Description |
| --- | --- |
| `application_signature` | Enables certificate/package identity policy data in the integrity manifest. |
| `payload_integrity` | Enables payload integrity policy data in the integrity manifest. |
| `javascript_bundle_integrity` | Protects configured React Native JavaScript bundle paths. Shape: `{ "enabled": bool, "weight": 0-100, "paths": ["apk/entry/path"] }`. |
| `flutter_integrity` | Protects Flutter app libraries, engine libraries, and assets. If enabled with `paths: []`, detected Flutter entries are selected automatically. |
| `debugger_detection` | Runtime debugger detection policy weight. |
| `instrumentation_detection` | Runtime hook/instrumentation detection policy weight. |
| `memory_integrity` | Runtime memory-integrity policy weight. |
| `root_detection` | Accepted policy field for root-detection weighting. The current native MVP focuses on instrumentation/debugger/memory signals. |
| `emulator_detection` | Accepted policy field for emulator-detection weighting. The current native MVP focuses on instrumentation/debugger/memory signals. |

### `risk_policy`

| Field | Required | Description |
| --- | --- | --- |
| `thresholds.report` | Yes | Risk score threshold for report behavior. |
| `thresholds.warn` | Yes | Risk score threshold for warning behavior. |
| `thresholds.restrict` | Yes | Risk score threshold for restricted behavior. |
| `thresholds.terminate` | Yes | Risk score threshold for terminate behavior. |
| `startup_signature_mismatch` | Yes | Action for startup package/certificate mismatch. |
| `startup_payload_tampering` | Yes | Action for startup payload or protected asset tampering. |
| `runtime_high_risk` | Yes | Action for high-risk runtime detection. |
| `offline_behavior` | Yes | Offline behavior policy. |

Thresholds must be from `0` through `100` and strictly increasing:
`report < warn < restrict < terminate`.

Risk actions:

- `ALLOW`
- `REPORT`
- `WARN`
- `LOCK_STARTUP`
- `TERMINATE`

Offline behavior values:

- `CONTINUE_WITH_LOCAL_POLICY`
- `FAIL_CLOSED`

### `runtime`

| Field | Required | Default in code | Description |
| --- | --- | --- | --- |
| `startup_budget_ms` | Yes | `50` | Startup budget in milliseconds. |
| `monitoring_enabled` | Yes | `true` | Enables runtime monitor scans. |
| `scan_interval_ms.minimum` | Yes | `5000` | Minimum scan interval. Must be greater than `0`. |
| `scan_interval_ms.maximum` | Yes | `15000` | Maximum scan interval. Must be greater than or equal to minimum. |
| `deep_scan_on_suspicion` | Yes | `true` | Run broader scans after suspicious signals. |
| `monitor_background_state` | Yes | `false` | Continue monitoring while the app is backgrounded. |

### `android`

| Field | Required | Description |
| --- | --- | --- |
| `initializer` | Yes | Must be `CONTENT_PROVIDER`. |
| `supported_abis` | Yes | ABI list. Supported values: `arm64-v8a`, `armeabi-v7a`, `x86_64`. |
| `initialize_processes` | Yes | Process labels accepted by the config schema. The current bootstrap provider is injected at the APK manifest level. |
| `minimum_sdk` | Yes | Must be at least `23`. |
| `certificate_sha256` | Yes | One or more expected signing certificate digests. Each value must be a 64-character SHA-256 hex digest or `CURRENT_SIGNING_CERTIFICATE_SHA256`. |
| `preserve_signature_lineage` | No | Included in external signing request metadata. Defaults to `false`. |

### `telemetry`

Telemetry is disabled by default. If `telemetry.enabled` is `true`,
`telemetry.endpoint` must be non-empty. `telemetry.include_raw_memory` must stay
`false`.

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Enables telemetry configuration. |
| `endpoint` | `null` | Telemetry endpoint. Required when enabled. |
| `connect_timeout_ms` | `3000` | Connect timeout. |
| `request_timeout_ms` | `5000` | Request timeout. |
| `include_device_identifiers` | `false` | Whether device identifiers may be included. |
| `include_raw_memory` | `false` | Must remain `false`. |
| `queue_capacity` | `100` | Queue capacity. |

### `output`

| Field | Default | Description |
| --- | --- | --- |
| `generate_report` | `true` | Reserved output preference. |
| `generate_sbom` | `true` | Reserved output preference; payload-pack SBOM is currently generated by the payload-pack builder. |
| `preserve_timestamps` | `false` | Reserved output preference. |
| `fail_on_warning` | `false` | Reserved output preference. |

## Schemas And Reports

JSON schemas are stored in `schemas/`:

- `schemas/rasp-config.schema.json`
- `schemas/inspection-result.schema.json`
- `schemas/payload-manifest.schema.json`
- `schemas/payload-sbom.schema.json`
- `schemas/signing-request.schema.json`
- `schemas/verification-template.schema.json`
- `schemas/verification-report.schema.json`
- `schemas/runtime-smoke-report.schema.json`
- `schemas/integrity-manifest.schema.json`

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | General processing failure |
| `2` | Invalid CLI arguments |
| `3` | Invalid configuration |
| `4` | Unsupported artifact |
| `5` | Artifact inspection failure |
| `6` | Payload injection failure |
| `7` | Package reconstruction failure |
| `8` | Alignment failure |
| `9` | Signing failure |
| `10` | Verification failure |
| `11` | Compatibility validation failure |
| `12` | Payload signature failure |
| `13` | Missing external dependency |
| `14` | Security policy violation |
| `15` | Runtime smoke-test failure |

## Development Notes

Useful local checks:

```sh
bash scripts/check.sh
bash scripts/check-native.sh
```

Architecture and planning docs:

- `docs/architecture.md`
- `docs/threat-model.md`
- `docs/implementation-plan.md`
- `docs/release-checklist.md`
