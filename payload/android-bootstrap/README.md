# Android Bootstrap

This directory contains the Android bootstrap source for the precompiled DEX.
The source provider class is `com.rasp.runtime.bootstrap.RaspInitProvider`; APK
shielding patches the loader DEX class descriptor to a build-derived provider
name. The source runtime class is
`com.rasp.runtime.bootstrap.RaspRuntimeEntry`; shielding patches it to a
build-derived runtime class, encrypts the runtime DEX, and inserts it under
`assets/r/<build-id-prefix>/d`.

The provider class remains loadable from an installed plaintext DEX so Android
can instantiate it at startup. It then reads the integrity manifest path from
provider metadata, verifies and decrypts the encrypted secondary runtime DEX,
loads it, and invokes the runtime entrypoint. Sensitive loader constants such
as the encrypted runtime metadata keys, runtime key domain, entrypoint method,
fallback policy actions, and diagnostics are stored with a rolling string
encoding instead of plaintext DEX string-pool entries. Runtime-binding loader
strings are emitted as source-key encoded DEX markers in the payload pack and
are re-encoded with a build-derived key during APK shielding.

Release 1.0 must inject this DEX as the next available `classesN.dex` and must
not patch `MainApplication.smali`.

The runtime loads the configured native library name and calls the native
detector before the host `Application.onCreate()` path. The APK library
filename, provider name, runtime class name, and runtime asset path can be
build-derived while the payload pack still stores the native artifact as
`libsecurity.so`.

Startup keeps JavaScript hashing bounded by checking only small protected
bundles. Larger protected JavaScript assets are verified by the runtime monitor:
regular scans rotate through one protected JS asset per interval, while deep
scans hash every protected JS asset before applying the configured payload
tampering action.
