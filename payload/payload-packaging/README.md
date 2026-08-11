# Payload Packaging

Payload packs are signed directories consumed by `rasp-cli shield`. The current
development builder compiles the bootstrap provider and native runtime from
source, writes SBOM/license metadata, writes the payload manifest, signs
`manifest.json` with Ed25519, and prints the public verification key.

```text
payload-pack/
  manifest.json
  bootstrap.dex
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
Android NDK with `build/cmake/android.toolchain.cmake`.

For precompiled artifacts, call the CLI builder directly:

```sh
rasp-cli build-payload-pack \
  --output target/payload-pack/android-dev \
  --bootstrap-dex /path/to/bootstrap.dex \
  --native-lib arm64-v8a=/path/to/libsecurity.so \
  --payload-version 0.1.0-dev \
  --payload-signing-key-env RASP_PAYLOAD_SIGNING_KEY_HEX
```
