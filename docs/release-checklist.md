# Release Checklist

## Packaging

- Build signed payload pack from source using `.github/workflows/release-payload-pack.yml`
  or an equivalent approved release runner.
- Payload pack contains `sbom.json`.
- Payload pack contains `licenses/NOTICE.txt`.
- Payload manifest includes digests for SBOM and license notice.
- Payload pack verifies with `rasp-cli verify-payload-pack` and the release public key.
- Payload-pack archive SHA-256 is published with the release artifacts.
- Transform React Native Hermes APK.
- Transform React Native JSC APK.
- Transform multidex APK.
- Transform APK with `extractNativeLibs=false`.
- Preserve original resources and unknown ZIP entries.
- Install and launch transformed APK.

## Security

- Payload loads before `Application.onCreate()`.
- Package name verification passes.
- Final signing certificate verification passes.
- JavaScript bundle modification is detected.
- Payload policy modification is detected.
- Debugger attachment produces a signal.
- Root-only signal reports without default termination.

## Signing

- Payload signing seed is supplied only through a secret environment variable.
- Production payload signing follows `docs/payload-signing.md`.
- Payload signing public key is published with the release artifacts.
- Release notes record the workflow run ID, commit SHA, tag, payload version,
  public key, and archive SHA-256.
- APK alignment verified before signing.
- APK signature verification passes.
- Expected certificate digest verification passes.
- Post-signing mutation fails verification.
- Secrets do not appear in output or reports.

## Quality

- Unit tests pass.
- Integration tests pass.
- Malformed APK tests pass.
- ZIP-slip and decompression-bomb tests pass.
- Verification report validates against JSON Schema.
- `scripts/fuzz-campaign.sh` completes artifact replay and the approved
  seconds-per-target campaign without unresolved crashes.
- Fuzz crash artifacts are triaged into focused tests or committed minimized
  inputs under `fuzz/regressions/<target>/`.
- Nightly fuzz workflow artifacts are reviewed before release sign-off.
