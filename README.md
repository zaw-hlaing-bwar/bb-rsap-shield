# RASP Shield CLI

RASP Shield CLI is a post-build Android APK hardening tool. Release 1.0 targets
React Native and Flutter Android APKs and injects a native runtime protection
payload through a private Android `ContentProvider`.

## Current Status

Implementation has progressed through the unsigned APK transformation path:

- Rust workspace layout.
- CLI command skeleton.
- Configuration types and validation.
- APK inspection for ZIP safety, artifact inventory, React Native indicators,
  and Flutter indicators.
- APK signing-scheme and certificate digest inspection.
- Payload-pack manifest, digest, and Ed25519 signature validation.
- Signed payload-pack assembly from the current bootstrap Java and native C
  runtime sources through `scripts/build-payload-pack.sh` and
  `rasp-cli build-payload-pack`.
- Payload-pack SBOM and license notice generation, with both metadata files
  covered by signed manifest digests.
- Unsigned APK ZIP rewrite with bootstrap DEX, private manifest provider, native payload,
  and internal integrity manifest insertion.
- External signing request and verification template generation.
- Static `rasp-cli verify` checks for provider, integrity manifest, protected payload digests,
  and optional signing certificate match.
- Local signing path using SDK `zipalign` and `apksigner`.
- ADB runtime smoke-test automation through `rasp-cli runtime-smoke`.
- Native runtime hook/instrumentation detector MVP for Frida, Xposed/LSPosed,
  Substrate, Zygisk/Riru/Magisk traces, debugger attachment, suspicious RWX
  mappings, default Frida ports, Frida UNIX sockets, suspicious hook-related
  environment variables, and common native hook frameworks such as Dobby,
  ShadowHook, xHook, Whale, and libhooker.
- Native runtime self-defense for reducing ptrace attachability through
  `PR_SET_DUMPABLE=0` where available, plus runtime checksum monitoring for
  post-startup patches to the `libsecurity.so` executable mapping.
- Runtime response policy summary embedded in the integrity manifest, with
  report/warn/high-risk threshold evaluation in the native payload.
- Startup package-name and signing-certificate verification from the integrity
  manifest, with mismatch signals resolved through the configured startup
  integrity action.
- Startup payload self-integrity for injected bootstrap DEX/native library APK
  entries, plus bounded startup hashing for small protected JavaScript assets,
  with mismatches resolved through the configured payload tampering action.
- Startup APK inventory verification for non-signature ZIP entries and
  executable entry paths, so repackaging that adds injected DEX/native/code
  payload entries is reported as payload tampering.
- Runtime monitoring scheduler driven by integrity-manifest settings, including
  randomized scan intervals, optional deep scan on suspicion, and foreground
  gating when background monitoring is disabled.
- Deferred runtime integrity checks for large protected JavaScript bundles and
  Flutter app assets/native libraries: normal monitor scans rotate through
  protected app-owned assets, and deep scans verify all deferred assets when
  suspicion is raised.
- Flutter integrity configuration through `protections.flutter_integrity`; when
  enabled with an empty `paths` list, the CLI auto-protects detected
  `libapp.so`, `libflutter.so`, and `assets/flutter_assets/*` entries.
- Bootstrap `RaspInitProvider` source that loads `libsecurity.so` and calls the
  native detector during provider startup, then applies configured
  lock-startup/terminate actions.
- Host dependency checks through `rasp-cli doctor`.
- Shared exit-code definitions.
- JSON schema files.
- CI and local check script.

## Local Checks

```sh
bash scripts/check.sh
```

The current development environment must have a Rust toolchain installed with
`cargo`, `rustfmt`, `clippy`, and a C compiler available as `cc`.

To build a development Android payload pack from source, provide a 32-byte
Ed25519 signing seed as hex and run:

```sh
export RASP_PAYLOAD_SIGNING_KEY_HEX=<64 hex characters>
bash scripts/build-payload-pack.sh
```

The command prints `payload_signing_public_key_hex`; pass that value to
`rasp-cli shield --payload-signing-public-key-hex` with the generated pack.

## Specification

See [docs/implementation-plan.md](docs/implementation-plan.md) for the
implementation roadmap derived from the product specification.
