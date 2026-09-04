#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from hashlib import sha256


REQUIRED_PAYLOAD_FILES = {
    "bootstrap.dex",
    "bootstrap-runtime.dex",
    "sbom.json",
    "licenses/NOTICE.txt",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify release payload-pack digests and write provenance JSON.",
    )
    parser.add_argument("--payload-pack", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--public-key-hex", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sha256-output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload_pack = args.payload_pack
    archive = args.archive
    public_key_hex = args.public_key_hex.strip().lower()

    if not payload_pack.is_dir():
        raise SystemExit(f"payload pack directory does not exist: {payload_pack}")
    if not archive.is_file():
        raise SystemExit(f"payload-pack archive does not exist: {archive}")
    if len(public_key_hex) != 64 or any(c not in "0123456789abcdef" for c in public_key_hex):
        raise SystemExit("--public-key-hex must be a 64-character lowercase hex value")

    manifest_path = payload_pack / "manifest.json"
    signature_path = payload_pack / "signature.ed25519"
    if not manifest_path.is_file():
        raise SystemExit(f"payload pack is missing {manifest_path}")
    if not signature_path.is_file():
        raise SystemExit(f"payload pack is missing {signature_path}")

    manifest = read_json(manifest_path)
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise SystemExit("manifest.json files must be an object")

    missing = sorted(path for path in REQUIRED_PAYLOAD_FILES if path not in files)
    if missing:
        raise SystemExit(f"manifest.json is missing required file entries: {', '.join(missing)}")

    computed_file_digests: dict[str, str] = {}
    for relative_path, expected_digest in files.items():
        if not isinstance(relative_path, str) or not isinstance(expected_digest, str):
            raise SystemExit("manifest.json files must map string paths to string digests")
        if not is_safe_relative_path(relative_path):
            raise SystemExit(f"manifest.json contains unsafe file path: {relative_path}")
        if not is_sha256(expected_digest):
            raise SystemExit(f"manifest.json digest for {relative_path} is not SHA-256 hex")

        path = payload_pack / relative_path
        if not path.is_file():
            raise SystemExit(f"manifest.json references missing file: {relative_path}")

        actual_digest = sha256_file(path)
        if actual_digest != expected_digest.lower():
            raise SystemExit(
                f"digest mismatch for {relative_path}: expected {expected_digest}, got {actual_digest}"
            )
        computed_file_digests[relative_path] = actual_digest

    sbom_path = payload_pack / "sbom.json"
    sbom = read_json(sbom_path)
    validate_sbom_components(sbom, computed_file_digests)

    archive_sha256 = sha256_file(archive)
    provenance = {
        "schema_version": 1,
        "artifact_type": "RASP_SHIELD_PAYLOAD_RELEASE_PROVENANCE",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository": env("GITHUB_REPOSITORY"),
        "commit_sha": env("GITHUB_SHA"),
        "git_ref": env("GITHUB_REF"),
        "workflow": env("GITHUB_WORKFLOW"),
        "workflow_run_id": env("GITHUB_RUN_ID"),
        "workflow_run_attempt": env("GITHUB_RUN_ATTEMPT"),
        "payload_version": require_string(manifest, "payload_version"),
        "minimum_cli_version": require_string(manifest, "minimum_cli_version"),
        "maximum_cli_version": require_string(manifest, "maximum_cli_version"),
        "supported_platform": require_string(manifest, "supported_platform"),
        "supported_abis": require_string_array(manifest, "supported_abis"),
        "payload_signing_public_key_hex": public_key_hex,
        "archive": {
            "path": archive.name,
            "sha256": archive_sha256,
        },
        "payload_pack": {
            "manifest_sha256": sha256_file(manifest_path),
            "signature_sha256": sha256_file(signature_path),
            "sbom_sha256": computed_file_digests["sbom.json"],
            "notice_sha256": computed_file_digests["licenses/NOTICE.txt"],
            "files": computed_file_digests,
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    if args.sha256_output is not None:
        args.sha256_output.write_text(f"{archive_sha256}  {archive.name}\n")

    print(f"payload_release_provenance: {args.output}")
    print(f"payload_archive_sha256: {archive_sha256}")
    return 0


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise SystemExit(f"failed to parse {path}: {error}") from error


def validate_sbom_components(sbom: Any, file_digests: dict[str, str]) -> None:
    if not isinstance(sbom, dict):
        raise SystemExit("sbom.json must be an object")
    components = sbom.get("components")
    if not isinstance(components, list):
        raise SystemExit("sbom.json components must be an array")

    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise SystemExit(f"sbom.json component {index} must be an object")
        path = component.get("path")
        digest = component.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str):
            raise SystemExit(f"sbom.json component {index} must include path and sha256")
        manifest_digest = file_digests.get(path)
        if manifest_digest is None:
            raise SystemExit(f"sbom.json component {index} references non-manifest path {path}")
        if manifest_digest != digest.lower():
            raise SystemExit(
                f"sbom.json component {index} digest mismatch for {path}: "
                f"manifest has {manifest_digest}, sbom has {digest}"
            )


def require_string(value: dict[str, Any], name: str) -> str:
    result = value.get(name)
    if not isinstance(result, str) or not result:
        raise SystemExit(f"manifest.json {name} must be a non-empty string")
    return result


def require_string_array(value: dict[str, Any], name: str) -> list[str]:
    result = value.get(name)
    if not isinstance(result, list) or not result or not all(isinstance(item, str) for item in result):
        raise SystemExit(f"manifest.json {name} must be a non-empty string array")
    return result


def env(name: str) -> str | None:
    value = os.environ.get(name)
    return value if value else None


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_sha256(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)


def is_safe_relative_path(value: str) -> bool:
    if not value or value.startswith("/") or value.startswith("\\") or "\\" in value:
        return False
    return all(segment not in {"", ".", ".."} for segment in value.split("/"))


if __name__ == "__main__":
    raise SystemExit(main())
