# External DEX and Native Protectors

RASP Shield can pass the secondary runtime DEX and each stripped native runtime
library through executable adapters before building and signing a payload pack.
The adapters are intended to wrap licensed DEX obfuscators, native control-flow
transformers, or virtualization products without placing vendor credentials or
vendor-specific command lines in the repository.

The plaintext bootstrap provider is deliberately excluded. Android must be able
to instantiate that provider directly from an installed DEX before the encrypted
secondary runtime can be loaded.

## Strict Build

Configure both adapters and require them for a release build:

```sh
bash scripts/build-payload-pack.sh \
  --dex-protector /opt/rasp-adapters/protect-dex \
  --native-protector /opt/rasp-adapters/protect-native \
  --require-external-protectors
```

The equivalent environment variables are `RASP_DEX_PROTECTOR`,
`RASP_NATIVE_PROTECTOR`, and `RASP_REQUIRE_EXTERNAL_PROTECTORS=1`. The strict
switch fails before compilation when either adapter is missing.

## DEX Adapter Contract

The build invokes the DEX adapter as:

```text
ADAPTER --input INPUT --output OUTPUT --min-sdk API \
  --keep-class com.rasp.runtime.bootstrap.RaspRuntimeEntry
```

The adapter must write a new DEX file to `OUTPUT`, propagate vendor failures
through a nonzero exit code, and preserve the named runtime entry class. Methods
and implementation classes may be renamed, virtualized, or transformed. The
build rejects non-DEX output and output that removes or renames the entry class.
The resulting runtime DEX is encrypted under a build-derived asset name during
APK shielding.

## Native Adapter Contract

The build invokes the native adapter once per ABI:

```text
ADAPTER --input INPUT --output OUTPUT --abi ABI \
  --preserve-export JNI_OnLoad
```

The adapter must write a new ELF shared object to `OUTPUT`, preserve the
`JNI_OnLoad` dynamic export, and preserve the encoded bootstrap and detector
marker byte regions. Those regions are re-keyed for each shielded APK after the
payload pack is loaded. The build validates ELF magic, the required export, all
re-key markers, and the absence of protected plaintext strings before signing.

Control-flow virtualization and function-level transformations are compatible
when they preserve those contracts. A whole-file packer that encrypts or removes
the marker regions is not compatible with the current payload-pack stage; that
kind of product needs a later integration point after per-build native re-keying.

## Operational Requirements

Keep vendor licenses and credentials in the protected build environment. The
adapter should use a fixed vendor policy file, pin the protector version, emit
its own transformation report, and fail closed when licensing or protection is
unavailable. Passing the compatibility checks proves that the artifact remains
loadable by RASP Shield; it does not independently prove the strength of a
vendor's virtualization.
