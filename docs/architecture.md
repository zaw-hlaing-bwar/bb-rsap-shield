# Architecture Notes

Release 1.0 is split into focused crates so APK handling, Android manifest
mutation, signing, configuration, reporting, and runtime-test support can be
tested independently.

The first implementation slice intentionally keeps mutation out of the `inspect`
path. Inspection should produce immutable artifact metadata and compatibility
findings. Later transformation stages consume that metadata and fail closed when
the input APK has unsupported structure.

External tools such as `zipalign`, `apksigner`, and `adb` should be wrapped in
typed operations that redact secrets and map failures to the public exit-code
contract.
