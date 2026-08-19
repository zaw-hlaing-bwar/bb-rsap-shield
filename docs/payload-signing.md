# Payload Signing

RASP Shield payload packs are signed with an Ed25519 key. The private material is
a 32-byte signing seed encoded as 64 hex characters and supplied only through the
`RASP_PAYLOAD_SIGNING_KEY_HEX` environment variable.

## Key Custody

- Store the production seed in a protected CI secret or external secret manager.
- Do not commit the seed, paste it into config files, or pass it as a command
  argument.
- Restrict release workflow execution to protected version tags or manually
  approved runs.
- Require review before updating the production signing secret.
- Treat `payload_signing_public_key_hex` as public release metadata. Consumers
  must pass it to `rasp-cli shield --payload-signing-public-key-hex` and
  `rasp-cli verify-payload-pack --payload-signing-public-key-hex`.

## Key Generation

Generate the seed on a trusted machine or in the approved secret-management
system:

```sh
umask 077
openssl rand -hex 32 > payload-signing-seed.hex
```

Load the seed into the protected secret named `RASP_PAYLOAD_SIGNING_KEY_HEX`.
Remove temporary local copies after the secret is stored and verified.

## Release Procedure

1. Run the normal repository checks with `bash scripts/check.sh`.
2. Run the approved fuzz campaign and triage any artifacts.
3. Start `.github/workflows/release-payload-pack.yml` manually or by pushing a
   protected `v*` tag.
4. Confirm the workflow built `target/payload-pack/android-release`, printed
   `payload_signing_public_key_hex`, and passed `rasp-cli verify-payload-pack`.
5. Publish the payload-pack archive, archive SHA-256, `manifest.json`,
   `signature.ed25519`, `sbom.json`, and public key together.
6. Record the workflow run ID, commit SHA, tag, payload version, public key, and
   archive SHA-256 in the release notes.

## Rotation

Rotate the production payload signing seed when key exposure is suspected, access
policy changes materially, or on the scheduled rotation cadence.

1. Generate and store a new seed.
2. Build a new payload pack and publish its new public key.
3. Update downstream shielding jobs to require the new public key.
4. Keep the old public key available only for verification of historical release
   artifacts.
5. Revoke access to the old seed and record the rotation in release notes.
