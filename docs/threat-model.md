# Threat Model

## Defensive Scope

The CLI is intended to process applications owned by, or explicitly authorized
by, the operator. The runtime payload protects the host application against
tampering, debugging, instrumentation, and risky environment signals.

## Non-Goals

- Injecting into third-party applications without authorization.
- Disabling platform security controls.
- Bypassing Android signing requirements.
- Embedding reusable backend secrets.
- Downloading executable code after application installation.

## Initial Assumptions

- APK input can be malformed or intentionally hostile.
- ZIP, AXML, DEX, and ELF parsing must fail safely.
- Runtime detections can be noisy, so low-confidence signals must contribute to
  risk scoring rather than causing automatic termination.
- Signing and alignment failures are hard failures and must never return success.
