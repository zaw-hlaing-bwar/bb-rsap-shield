# Payload Packaging

Payload packs are signed directories consumed by `rasp-cli shield`. The current
development builder compiles the plaintext bootstrap provider, encrypted-at-
insertion runtime DEX, and native runtime from source, writes SBOM/license
metadata, writes the payload manifest, signs `manifest.json` with Ed25519, and
prints the public verification key.

```text
payload-pack/
  manifest.json
  bootstrap.dex
  bootstrap-runtime.dex
  arm64-v8a/libsecurity.so
  armeabi-v7a/libsecurity.so
  licenses/
  sbom.json
  signature.ed25519
```

`manifest.json` must include SHA-256 digests for every payload artifact,
including `sbom.json` and `licenses/NOTICE.txt`. The Ed25519 signature covers
the raw `manifest.json` bytes, so metadata changes are detected before APK
mutation.

Payload packs keep native artifacts at stable paths such as
`arm64-v8a/libsecurity.so`. During APK shielding, the CLI copies that library
into the APK under a build-derived load name, patches the bootstrap provider
class and runtime entry class to build-derived names, encrypts the runtime DEX
under a build-derived asset path, writes the integrity manifest at a
build-derived asset path, rotates native bootstrap and detector string encoding
keys from the shield build ID, re-encodes native marker, report taxonomy, and
static probe strings with the rolling mask, including action names, report JSON
fields, `/proc` paths, JNI signatures, parser formats, and runtime-map markers,
re-encodes bootstrap-loader runtime-binding strings with a build-derived key,
and records the final APK payload digests in the integrity manifest.
Development builds also reject bootstrap loader DEX output that exposes
sensitive loader metadata, runtime-binding, or fallback policy strings in
plaintext, require the source-key encoded patch markers that shielding later
re-keys, and reject native artifacts that expose or omit the protected static
markers.

## Development Build

Set `RASP_PAYLOAD_SIGNING_KEY_HEX` to a 64-character Ed25519 seed hex value and
run:

```sh
bash scripts/build-payload-pack.sh
```

Defaults:

- Output: `target/payload-pack/android-dev`
- Payload version: `0.1.0-dev`
- ABI: `arm64-v8a`
- Android min SDK: `23`
- Bootstrap shrinker: `auto` (R8 when available, D8 fallback)
- External DEX/native protectors: disabled unless adapter paths are configured
- Signing key variable: `RASP_PAYLOAD_SIGNING_KEY_HEX`

Useful options:

```sh
bash scripts/build-payload-pack.sh \
  --output target/payload-pack/android-release-candidate \
  --payload-version 0.1.0-rc1 \
  --abis arm64-v8a,armeabi-v7a,x86_64 \
  --signing-key-env RASP_PAYLOAD_SIGNING_KEY_HEX
```

The script requires `javac`, `cmake`, Android SDK build tools with `d8`, and an
Android NDK with `build/cmake/android.toolchain.cmake`. Pass
`--bootstrap-shrinker r8 --r8-jar /path/to/r8.jar` to require R8 shrinking for
the bootstrap DEX. The provider class itself must remain in a loadable DEX so
Android can instantiate the startup `ContentProvider`; the larger Java runtime
is emitted separately and encrypted during APK shielding.

Licensed DEX and native protection products can be connected through
`--dex-protector` and `--native-protector`. Add
`--require-external-protectors` for a fail-closed release build. The executable
adapter contract is documented in `docs/external-protectors.md`; protected DEX
and ELF output is validated before payload-pack signing.

For precompiled artifacts, call the CLI builder directly:

```sh
rasp-cli build-payload-pack \
  --output target/payload-pack/android-dev \
  --bootstrap-dex /path/to/bootstrap.dex \
  --bootstrap-runtime-dex /path/to/bootstrap-runtime.dex \
  --native-lib arm64-v8a=/path/to/libsecurity.so \
  --payload-version 0.1.0-dev \
  --payload-signing-key-env RASP_PAYLOAD_SIGNING_KEY_HEX
```
