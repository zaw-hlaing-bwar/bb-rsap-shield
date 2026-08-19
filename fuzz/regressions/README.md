# Fuzz Regressions

Put minimized, committed fuzz regression inputs under:

```text
fuzz/regressions/<target>/<short-name>
```

`scripts/fuzz-campaign.sh` replays these files before each campaign. Prefer a
focused crate-level unit test when the failure can be expressed clearly in
normal test code; use this directory for binary parser inputs that are only
practical to preserve as raw bytes.
