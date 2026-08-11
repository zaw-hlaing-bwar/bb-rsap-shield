# RASP Shield CLI Implementation Plan

Source specification: `RASP Shield CLI Product Specification v1.0.pdf`

## Scope

This plan targets Release 1.0 only:

- Android APK input and APK output.
- React Native Android applications using Hermes or JavaScriptCore.
- Flutter Android APKs for static detection and runtime integrity coverage of
  packaged Flutter assets and native app/engine libraries.
- Rust CLI and artifact transformation.
- C/C++ Android native payload built with the Android NDK.
- Bootstrap through a private Android `ContentProvider`.
- Precompiled bootstrap DEX injection.
- Local and external signing flows.
- Static verification, JSON reports, and optional ADB runtime smoke tests.

Out of scope for the first release:

- AAB transformation.
- iOS/XCArchive transformation.
- Dynamic feature modules.
- Remote policy updates.
- Runtime code download.
- Automatic backend transaction blocking.

## Current Repository State

The Rust workspace, crate layout, schemas, payload directories, fixtures, docs, and CI skeleton have
been created. Local Rust formatting, lint, and unit-test checks pass through `scripts/check.sh`.

## Implementation Strategy

Build the product in vertical slices. The first slice should transform a known-good React Native APK and
produce a verifiable output. Security sophistication should increase only after the packaging pipeline is
reliable, because signing, alignment, ZIP handling, and manifest mutation are hard failure boundaries.

The critical path is:

1. Inspect APK metadata without mutation.
2. Validate configuration.
3. Inject bootstrap DEX and native library placeholders.
4. Inject the manifest provider.
5. Rebuild, align, sign, and verify the APK.
6. Replace placeholder payload behavior with real runtime checks.
7. Add compatibility, fuzzing, performance, and CI coverage.

## Proposed Repository Layout

```text
rasp-shield/
  Cargo.toml
  crates/
    rasp-cli/
    rasp-core/
    rasp-config/
    rasp-report/
    artifact-inspector/
    android-axml/
    android-dex/
    android-apk/
    android-signing/
    payload-pack/
    runtime-test/
  payload/
    android-bootstrap/
    android-native/
      CMakeLists.txt
      include/
      src/
      tests/
    payload-packaging/
  schemas/
    rasp-config.schema.json
    verification-report.schema.json
    payload-manifest.schema.json
    integrity-manifest.schema.json
    runtime-smoke-report.schema.json
    signing-request.schema.json
    verification-template.schema.json
  fixtures/
    react-native-hermes/
    react-native-jsc/
    multidex/
    extract-native-libs-false/
    malformed-apks/
  integration-tests/
  fuzz/
  ci/
  docs/
  scripts/
```

## Phase 0: Project Bootstrap

Goal: create a buildable workspace with stable boundaries.

- Initialize a Rust workspace.
- Add `rasp-cli` binary crate with `inspect`, `shield`, `verify`, `doctor`, and `version` commands.
- Add library crates matching the module boundaries in the specification.
- Add JSON schemas for configuration, verification report, and payload manifest.
- Add basic CI jobs for Rust format, lint, tests, and build.
- Add a test fixture policy for how APK fixtures are stored or generated.
- Add `docs/` files for architecture decisions, threat model, and release checklist.

Exit criteria:

- `cargo build` succeeds.
- `rasp-cli version` works.
- CI skeleton runs local unit tests.
- Schemas are committed and loadable by tests.

## Phase 1: Configuration and CLI Contract

Goal: make the user-facing command surface stable before deep APK mutation work.

- Implement POSIX-compatible CLI parsing.
- Implement structured error handling mapped to the specified exit codes.
- Implement secret-safe logging and diagnostics.
- Implement `rasp.config.json` parsing.
- Validate:
  - Required `schema_version`.
  - No unknown top-level properties.
  - No unknown protection names.
  - Risk weights from 0 to 100.
  - Monotonically increasing thresholds.
  - Android package-name syntax.
  - Signing certificate requirements.
  - Telemetry disabled by default.
  - Raw memory collection disabled by default.
  - No password values in environment-variable-name fields.
- Add golden tests for valid and invalid configuration files.

Exit criteria:

- Invalid config returns exit code `3`.
- Invalid CLI arguments return exit code `2`.
- Password values never appear in process arguments, logs, or generated reports.

## Phase 2: APK Inspection

Goal: produce immutable APK inspection results without changing the artifact.

- Implement safe input path handling:
  - Existing regular file check.
  - Symlink traversal rejection.
  - SHA-256 digest calculation.
- Implement ZIP reader:
  - Duplicate path detection.
  - ZIP-slip path rejection.
  - Maximum extracted-size protection.
  - Maximum entry-count protection.
  - Compression metadata capture.
- Implement binary Android manifest parsing sufficient for:
  - Package name.
  - Version code and version name.
  - Minimum SDK and target SDK.
  - Application class.
  - Providers.
  - Main activity detection for smoke tests.
  - `extractNativeLibs`.
- Inventory:
  - `classes*.dex`.
  - Native libraries and ABIs.
  - React Native JavaScript bundle paths.
  - Hermes/JSC indicators.
  - Flutter indicators: `libapp.so`, `libflutter.so`, and
    `assets/flutter_assets/*`.
  - Existing signature certificates.
  - Compatibility warnings and blocking conditions.
- Implement `rasp-cli inspect --format text|json`.

Exit criteria:

- Inspection works on Hermes, JSC, multidex, and malformed APK fixtures.
- Unsupported artifacts return exit code `4` or `5` as appropriate.
- Inspection results are deterministic and serializable.

## Phase 3: Payload Pack MVP

Goal: define the payload-pack contract early, even if runtime checks are initially minimal.

- Define payload-pack manifest schema.
- Implement payload-pack loading.
- Verify file digests.
- Add Ed25519 signature verification.
- Enforce CLI version and platform compatibility.
- Select ABI-specific libraries from the pack.
- Package:
  - `bootstrap.dex`.
  - `arm64-v8a/libsecurity.so`.
  - `armeabi-v7a/libsecurity.so` later in Phase 8 if sequencing requires it.
  - `sbom.json`.
  - `licenses/`.
  - `signature.ed25519`.
- Create a development payload pack for integration tests.

Exit criteria:

- Invalid signature or digest returns exit code `12`.
- Missing payload files fail before APK mutation.
- Offline development payload pack can be used in integration tests.

## Phase 4: APK Transformation MVP

Goal: produce a structurally valid transformed APK before implementing all security behavior.

- Create private temporary workspaces:
  - Restrictive permissions.
  - Random directory names.
  - Automatic cleanup.
  - Optional `--keep-workdir`.
- Implement DEX insertion:
  - Insert bootstrap as the next `classesN.dex`.
  - Reject class-name collision with existing bootstrap package.
- Implement native library insertion:
  - Add `lib/arm64-v8a/libsecurity.so`.
  - Preserve compression policy based on source APK behavior.
  - Preserve unknown ZIP entries.
- Implement binary manifest provider injection:
  - Add `com.rasp.runtime.bootstrap.RaspInitProvider`.
  - Generate authority as `<package>.rasp.<first-eight-build-id-chars>`.
  - Set exported false.
  - Set init order.
  - Avoid intent filters and URI grants.
  - Do not patch `MainApplication.smali`.
- Generate internal integrity manifest with build ID, protected assets, policy digest, expected certificate digests, app-owned React Native/Flutter asset digests, and APK entry inventory digests.
- Reconstruct APK with deterministic entry order where practical.

Exit criteria:

- `rasp-cli shield --signing-mode external` produces an unsigned transformed APK and signing request.
- Output APK contains bootstrap DEX, provider, native library, and integrity manifest.
- Original resources, assets, DEX files, and unknown entries are preserved.

## Phase 5: Alignment, Signing, and Verification

Goal: enforce the packaging rules that determine whether output is actually usable.

- Integrate `zipalign`:
  - Run alignment before signing.
  - Use `zipalign -P 16 -f -v 4`.
  - Verify with `zipalign -c -P 16 -v 4`.
- Integrate `apksigner` for local signing:
  - Use keystore path and alias arguments.
  - Read passwords only from environment variables, stdin, or secure descriptors.
  - Preserve signing lineage only when explicitly configured.
- Implement external signing artifacts:
  - `signing-request.json`.
  - `verification-template.json`.
- Implement final static verifier:
  - ZIP validity.
  - Duplicate entries.
  - Manifest provider presence and safety.
  - Bootstrap DEX presence.
  - Native payload presence for configured ABIs.
  - ELF architecture.
  - 16 KiB ELF compatibility checks.
  - APK alignment.
  - APK signature.
  - Expected signing certificate digest.
- Implement JSON verification reports.

Exit criteria:

- Signing, alignment, or final verification failure never returns success.
- Local signing produces installable APKs.
- External signing flow can be verified after operator signing.
- Verification report validates against schema.

## Phase 6: Android Bootstrap and Native Payload MVP

Goal: prove runtime initialization happens before `Application.onCreate()`.

- Build Android bootstrap project that outputs a precompiled DEX.
- Implement `RaspInitProvider`.
- Load `libsecurity.so`.
- Pass package and application context metadata to JNI.
- Keep provider startup work within the 50 ms target path.
- Build native payload with:
  - Hidden symbol visibility.
  - Position-independent code.
  - Release symbol stripping.
  - 16 KiB page-size compatibility.
  - Minimal JNI surface.
  - Signed payload version descriptor.
- Implement native startup checks:
  - Policy-signature verification.
  - Payload self-integrity placeholder, then real check.
  - Package-name verification.
  - Certificate verification.
  - Basic debugger state.
  - JavaScript bundle hash check when small enough for startup.

Exit criteria:

- Runtime smoke test confirms payload initializes before app startup.
- Clean supported APK launches after transformation.
- Startup overhead remains within the specified budget on test devices.

## Phase 7: Runtime Risk Engine and Signals

Goal: implement Release 1.0 defensive behavior without overreacting to low-confidence signals.

- Implement signal model:
  - ID.
  - Category.
  - Confidence.
  - Severity.
  - Weight.
  - Evidence digest.
  - Timestamp.
  - Detector version.
- Implement risk calculation as `min(100, sum(active_signal_weights))`.
- Implement responses:
  - `ALLOW`.
  - `REPORT`.
  - `WARN`.
  - `LOCK_STARTUP`.
  - `TERMINATE`.
- Implement default policy:
  - Signature mismatch terminates.
  - Payload integrity mismatch terminates.
  - JavaScript bundle mismatch locks startup.
  - Debugger-only signal reports.
  - Root-only signal reports.
- Implement detectors:
  - Debugger indicators.
  - Suspicious memory maps.
  - Instrumentation indicators.
  - Root risk indicators.
  - Emulator indicators only when enabled.
- Implement randomized monitoring scheduler with bounded CPU and memory behavior.

Exit criteria:

- Root signal alone does not terminate by default.
- String-name instrumentation detection alone is not sufficient for high-risk action.
- Multiple high-confidence instrumentation indicators raise risk.
- Detector failure does not crash the host application.

## Phase 8: Compatibility and Production Readiness

Goal: broaden from a working path to a release-quality tool.

- Add `armeabi-v7a` production payload support.
- Add optional `x86_64` test payload support.
- Add `extractNativeLibs=false` compatibility tests.
- Add multidex compatibility tests.
- Add 16 KiB device and emulator testing.
- Add large-APK streaming tests.
- Add malformed APK tests.
- Add ZIP-slip and decompression-bomb tests.
- Add fuzzing for ZIP, AXML, and manifest mutation code.
- Add SBOM generation.
- Add GitHub Actions, Jenkins, and Bitrise examples.
- Add operational documentation.
- Run privacy review for telemetry and reports.
- Run security review and penetration test before release.

Exit criteria:

- Acceptance criteria from the specification pass.
- No unresolved critical parser crashes from fuzzing.
- CLI memory remains bounded for large APKs.
- Payload size remains below 1.5 MB per production ABI.
- Compatibility test fleet does not show material crash-rate increase.

## Suggested Milestones

### Milestone 1: Buildable Scaffold

Deliverables:

- Rust workspace.
- CLI command skeletons.
- Config schema and validation tests.
- Empty report schema.
- CI baseline.

### Milestone 2: Inspect-Only CLI

Deliverables:

- `rasp-cli inspect`.
- APK ZIP safety checks.
- Android manifest parser.
- React Native engine and bundle detection.
- Signature certificate extraction.

Current status:

- APK ZIP safety checks and artifact inventory are implemented.
- Android manifest parsing is implemented for common binary AXML metadata.
- Main activity detection and `extractNativeLibs` parsing are implemented.
- APK Signature Scheme v2/v3 certificate SHA-256 digest extraction is implemented.
- v1 JAR signature entries are detected and DER certificate SHA-256 digest extraction is implemented for PKCS#7/CMS signature blocks.

### Milestone 3: Unsigned Shielded APK

Deliverables:

- Payload-pack loader.
- Bootstrap DEX insertion.
- Native library insertion.
- Manifest provider injection.
- APK reconstruction.
- External signing output artifacts.

Current status:

- Payload-pack manifest loading is implemented.
- Declared payload file SHA-256 digest verification is implemented.
- Ed25519 payload-pack signature verification is implemented over raw `manifest.json` bytes.
- Signed payload-pack creation is implemented through `rasp-cli build-payload-pack`, including
  DEX/ELF artifact validation, manifest generation, SHA-256 file digests, and Ed25519 signing.
- Source-based Android payload assembly is implemented through `scripts/build-payload-pack.sh`,
  which compiles `RaspInitProvider.java` with `javac`/`d8`, builds `libsecurity.so` with the
  Android NDK through CMake, and emits a verified payload pack.
- Payload-pack SBOM and license notice artifacts are generated as `sbom.json` and
  `licenses/NOTICE.txt`; both are included in the signed manifest digest inventory and enforced by
  the payload-pack loader.
- Platform, ABI layout, and CLI version compatibility checks are implemented.
- `rasp-cli shield --payload-pack` validates payload packs and requires `--payload-signing-public-key-hex` before transformation.
- Unsigned APK ZIP reconstruction is implemented for the external-signing path.
- Bootstrap DEX insertion is implemented as the next available `classesN.dex`.
- Native payload library insertion is implemented under `lib/<abi>/libsecurity.so`.
- v1 JAR signature metadata is stripped during reconstruction, and v2/v3 signing blocks are discarded by the fresh ZIP rewrite.
- External signing-request artifact generation is implemented as `<output-stem>.signing-request.json`.
- External verification-template artifact generation is implemented as `<output-stem>.verification-template.json`.
- Binary manifest provider injection is implemented for the external-signing path, including
  `com.rasp.runtime.bootstrap.RaspInitProvider`, generated authority, `exported=false`, and init order.
- Internal integrity manifest generation is implemented as
  `assets/rasp-shield/integrity-manifest.json`, including build ID, package metadata, policy digest,
  expected certificate digests, provider metadata, payload file digests, and protected asset digests.
- End-to-end smoke testing confirms the unsigned output contains the injected provider, bootstrap DEX,
  native payload library, internal integrity manifest, and no detected signing schemes.

### Milestone 4: Signed and Verified APK

Deliverables:

- `zipalign` integration.
- `apksigner` integration.
- `rasp-cli verify`.
- Verification report.
- Hermes fixture transforms and installs.

Current status:

- Static `rasp-cli verify` is implemented for APK inspection, ZIP safety, bootstrap provider
  presence, internal integrity manifest parsing, protected asset digest checks, bootstrap DEX
  presence, native payload library presence, and optional signing certificate SHA-256 matching.
- Verification reports now emit `PASS` or `FAIL` with structured input, application, payload,
  signing, check, and warning sections.
- `zipalign` integration is implemented with `zipalign -P 16 -f -v 4` and verification through
  `zipalign -c -P 16 -v 4`.
- Local `apksigner` signing is implemented for `--signing-mode local`, using keystore password
  environment-variable references and `apksigner verify --verbose --print-certs` after signing.
- SDK build tools are discovered from `ANDROID_HOME`, `ANDROID_SDK_ROOT`, or the standard local
  Android SDK build-tools directory before falling back to `PATH`.
- Local signing smoke testing passes with the Android debug keystore.
- ADB install/launch/process runtime smoke automation is implemented as `rasp-cli runtime-smoke`.
  It installs the APK with `adb install -r -t`, launches either the decoded main activity or launcher
  intent, checks `pidof <package>`, optionally uninstalls, and can emit a JSON report.
- No Android device is currently attached in this local environment, so a real-device install/launch
  run was not executed.

### Milestone 5: Runtime Payload MVP

Deliverables:

- Native payload loaded by bootstrap provider.
- Package and certificate verification.
- JavaScript bundle and Flutter app-owned asset integrity checks.
- Basic debugger signal.
- Runtime smoke test.

Current status:

- Native detector API and report model are implemented in `payload/android-native`.
- Runtime hook/instrumentation signals are implemented for Frida/Gum library and thread traces,
  Frida file descriptors, default Frida TCP ports, Xposed/LSPosed/EdXposed, Substrate, and
  Zygisk/Riru/Magisk map indicators.
- Additional hook indicators are implemented for Frida UNIX sockets, suspicious hook-related
  environment variables, and native hook frameworks such as Dobby, ShadowHook, xHook, Whale,
  HookZz, and libhooker.
- Basic debugger detection is implemented through `/proc/self/status` `TracerPid`.
- Suspicious writable/executable memory map detection is implemented as a low-confidence memory signal.
- Native self-defense now attempts `PR_SET_DUMPABLE=0` where available to reduce ptrace
  attachability, and monitor scans checksum the `libsecurity.so` executable mapping to detect
  post-startup patches to the detector itself.
- The detector computes capped risk as `min(100, sum(active_signal_weights))` and keeps the latest
  report available as JSON.
- The generated integrity manifest now carries the runtime response policy summary, including
  thresholds, `runtime_high_risk_action`, `startup_integrity_action`, and
  `startup_payload_tampering_action`.
- The native payload resolves detector results to `ALLOW`, `REPORT`, `WARN`, `LOCK_STARTUP`, or
  `TERMINATE`, using conservative defaults when policy parsing fails.
- Bootstrap `RaspInitProvider` Java source now loads `libsecurity.so` and calls the native detector
  during provider startup, reads the integrity manifest from assets, and applies configured
  lock-startup or terminate responses.
- Startup package-name and signing-certificate checks are implemented in the bootstrap provider.
  Mismatches are reported to native as startup integrity signals and default to `TERMINATE`.
- Startup payload self-integrity checks are implemented for protected bootstrap DEX and native
  library APK entries. Digest mismatches are reported to native as payload tampering signals.
- Startup APK inventory checks are implemented for non-signature ZIP entries and executable
  entry paths. Added or removed APK entries are reported to native as payload tampering signals,
  which catches common repackaging/code-injection attempts such as adding a new `classesN.dex`
  or native library.
- Small JavaScript protected assets are hashed at startup when they fit the bounded startup budget.
- Large protected JavaScript bundles and Flutter app-owned protected entries are deferred into the
  runtime monitor: normal scans rotate through one deferred asset per interval, and deep scans verify
  all deferred app-owned assets before applying the configured payload tampering action.
- Runtime monitoring scheduler is implemented in the bootstrap provider. It uses randomized bounded
  intervals from the integrity manifest, can run one immediate confirmation scan on suspicion, and
  skips background scans when `monitor_background_state=false` and lifecycle callbacks are available.
- Host-runnable native detector tests are implemented through `scripts/check-native.sh` and are
  included in `scripts/check.sh`.
- Development payload-pack assembly from current source is implemented and can replace the old
  placeholder smoke pack. Release-grade payload-pack production hardening still needs CI release
  packaging and production key custody/signing procedures.

### Milestone 6: Release Candidate

Deliverables:

- Full P0 backlog complete.
- P1 critical security checks complete.
- CI integration tests.
- Malformed APK and fuzzing coverage.
- Documentation and release checklist.

## Initial Engineering Decisions

- Treat binary AXML parsing and mutation as a high-risk subsystem with focused tests and fuzzing.
- Keep the APK transformer streaming-oriented where possible to avoid loading large APKs fully into memory.
- Do not sign or mutate the original input APK in place.
- Model every external tool invocation as a typed operation with redacted logs.
- Keep payload pack verification mandatory, including development packs.
- Make runtime telemetry compileable but disabled by default until privacy review is complete.
- Prefer explicit compatibility failures over best-effort mutation when the APK structure is unsupported.

## First Implementation Sprint

Recommended first sprint:

1. Initialize the Rust workspace and crate layout.
2. Implement CLI skeleton and exit-code mapping.
3. Implement configuration schema and validation.
4. Implement safe APK ZIP reader with duplicate path and ZIP-slip detection.
5. Implement `inspect --format json` with partial metadata.
6. Add unit tests for config validation and ZIP safety.
7. Add a CI workflow or local script that runs format, lint, and tests.

This sprint gives the project a stable command contract and catches malformed input before mutation
work begins.
