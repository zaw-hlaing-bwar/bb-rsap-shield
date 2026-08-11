# Release Checklist

## Packaging

- Build signed payload pack from source.
- Payload pack contains `sbom.json`.
- Payload pack contains `licenses/NOTICE.txt`.
- Payload manifest includes digests for SBOM and license notice.
- Payload pack verifies with the release public key.
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
- Payload signing public key is published with the release artifacts.
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
