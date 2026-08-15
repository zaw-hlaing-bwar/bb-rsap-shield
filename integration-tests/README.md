# Integration Tests

This package contains workspace-level integration tests that generate minimal APK
fixtures at test time. The generated fixtures avoid external Android SDK tooling
while still exercising public crate APIs across inspection, manifest mutation,
APK rewrite, and malformed APK rejection.

Current coverage:

- React Native Hermes inspection.
- React Native JSC inspection.
- Multidex ordering.
- Flutter library and asset inspection.
- Unsigned APK rewrite with bootstrap DEX, native payload, manifest provider,
  integrity manifest, and signature metadata stripping.
- Fail-closed handling for missing manifests and ZIP-slip paths.

Future device-backed tests should cover alignment, signing, installation, and
startup smoke behavior with real Android SDK tools and emulators.
