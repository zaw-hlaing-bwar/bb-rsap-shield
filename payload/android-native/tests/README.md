# Native Payload Tests

`test_security.c` covers the current detector MVP:

- Frida/Gum, Xposed/LSPosed, Substrate, and Zygisk/Riru/Magisk map indicators.
- Frida-like thread names.
- Debugger `TracerPid`.
- Suspicious writable/executable mappings.
- Default Frida TCP ports.
- JSON report emission and capped risk scoring.
- Runtime response action selection.
- Startup package/certificate identity mismatch precedence.
- Startup payload/protected-asset tamper response precedence.

Run the native test slice with:

```sh
bash scripts/check-native.sh
```

Policy loading and startup payload self-integrity checks now happen in the
Android bootstrap provider. Broader crash-safety boundaries and background
monitoring are still pending.
