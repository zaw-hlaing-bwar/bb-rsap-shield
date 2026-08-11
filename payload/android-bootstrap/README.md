# Android Bootstrap

This directory contains the Android bootstrap source for the precompiled DEX
containing `com.rasp.runtime.bootstrap.RaspInitProvider`.

Release 1.0 must inject this DEX as the next available `classesN.dex` and must
not patch `MainApplication.smali`.

`RaspInitProvider` loads `libsecurity.so` and calls the native detector from
`ContentProvider.onCreate()`, before the host `Application.onCreate()` path.

Startup keeps JavaScript hashing bounded by checking only small protected
bundles. Larger protected JavaScript assets are verified by the runtime monitor:
regular scans rotate through one protected JS asset per interval, while deep
scans hash every protected JS asset before applying the configured payload
tampering action.
