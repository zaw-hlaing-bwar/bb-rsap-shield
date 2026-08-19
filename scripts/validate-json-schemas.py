#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_FIXTURES = [
    ("schemas/rasp-config.schema.json", "fixtures/rasp.config.example.json"),
    ("schemas/inspection-result.schema.json", "fixtures/inspection-result.example.json"),
    ("schemas/verification-report.schema.json", "fixtures/verification-report.example.json"),
    ("schemas/verification-template.schema.json", "fixtures/verification-template.example.json"),
    ("schemas/signing-request.schema.json", "fixtures/signing-request.example.json"),
    ("schemas/runtime-smoke-report.schema.json", "fixtures/runtime-smoke-report.example.json"),
    ("schemas/payload-manifest.schema.json", "fixtures/payload-manifest.example.json"),
    ("schemas/payload-sbom.schema.json", "fixtures/payload-sbom.example.json"),
    ("schemas/integrity-manifest.schema.json", "fixtures/integrity-manifest.example.json"),
]

SUPPORTED_KEYWORDS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "allOf",
    "anyOf",
    "const",
    "default",
    "description",
    "enum",
    "items",
    "maximum",
    "maxItems",
    "maxLength",
    "minItems",
    "minimum",
    "minLength",
    "minProperties",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "title",
    "type",
    "uniqueItems",
}


class SchemaSupportError(Exception):
    pass


class Validator:
    def __init__(self, schema: Any) -> None:
        self.schema = schema

    def validate(self, instance: Any) -> list[str]:
        return list(self._errors(instance, self.schema, "$"))

    def _errors(self, instance: Any, schema: Any, path: str) -> list[str]:
        if schema is True:
            return []
        if schema is False:
            return [f"{path}: boolean schema false rejects all values"]
        if not isinstance(schema, dict):
            return [f"{path}: invalid schema node {schema!r}"]

        errors: list[str] = []

        if "$ref" in schema:
            errors.extend(self._errors(instance, self._resolve_ref(schema["$ref"]), path))
            schema = {keyword: value for keyword, value in schema.items() if keyword != "$ref"}
            if not schema:
                return errors

        for keyword in ("allOf", "anyOf", "oneOf"):
            if keyword in schema:
                errors.extend(self._validate_combiner(keyword, schema[keyword], instance, path))

        if "const" in schema and instance != schema["const"]:
            errors.append(f"{path}: expected constant {schema['const']!r}, got {instance!r}")

        if "enum" in schema and instance not in schema["enum"]:
            errors.append(f"{path}: expected one of {schema['enum']!r}, got {instance!r}")

        if "type" in schema and not self._matches_type(instance, schema["type"]):
            errors.append(f"{path}: expected type {schema['type']!r}, got {json_type(instance)}")
            return errors

        if isinstance(instance, dict):
            errors.extend(self._validate_object(instance, schema, path))
        elif isinstance(instance, list):
            errors.extend(self._validate_array(instance, schema, path))
        elif isinstance(instance, str):
            errors.extend(self._validate_string(instance, schema, path))
        elif isinstance(instance, (int, float)) and not isinstance(instance, bool):
            errors.extend(self._validate_number(instance, schema, path))

        return errors

    def _resolve_ref(self, ref: str) -> Any:
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise SchemaSupportError(f"only internal JSON Pointer refs are supported, got {ref!r}")

        node = self.schema
        for raw_part in ref[2:].split("/"):
            part = raw_part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                raise SchemaSupportError(f"unresolved schema ref {ref!r}")
            node = node[part]
        return node

    def _validate_combiner(
        self,
        keyword: str,
        subschemas: Any,
        instance: Any,
        path: str,
    ) -> list[str]:
        if not isinstance(subschemas, list) or not subschemas:
            raise SchemaSupportError(f"{path}: {keyword} must be a non-empty array")

        if keyword == "allOf":
            errors = []
            for subschema in subschemas:
                errors.extend(self._errors(instance, subschema, path))
            return errors

        matches = []
        first_errors = []
        for index, subschema in enumerate(subschemas):
            errors = self._errors(instance, subschema, path)
            if errors:
                first_errors.append(f"option {index}: {errors[0]}")
            else:
                matches.append(index)

        if keyword == "anyOf":
            if matches:
                return []
            return [f"{path}: does not match anyOf ({'; '.join(first_errors)})"]

        if len(matches) == 1:
            return []
        if matches:
            return [f"{path}: matches multiple oneOf branches {matches!r}"]
        return [f"{path}: does not match oneOf ({'; '.join(first_errors)})"]

    def _validate_object(self, instance: dict[str, Any], schema: dict[str, Any], path: str) -> list[str]:
        errors: list[str] = []

        min_properties = schema.get("minProperties")
        if min_properties is not None and len(instance) < min_properties:
            errors.append(f"{path}: expected at least {min_properties} properties")

        for name in schema.get("required", []):
            if name not in instance:
                errors.append(f"{path}: missing required property {name!r}")

        properties = schema.get("properties", {})
        if properties is not None and not isinstance(properties, dict):
            raise SchemaSupportError(f"{path}: properties must be an object")

        for name, property_schema in properties.items():
            if name in instance:
                errors.extend(self._errors(instance[name], property_schema, child_path(path, name)))

        additional = schema.get("additionalProperties", True)
        known_properties = set(properties)
        for name, value in instance.items():
            if name in known_properties:
                continue
            value_path = child_path(path, name)
            if additional is False:
                errors.append(f"{value_path}: additional property is not allowed")
            elif additional is not True:
                errors.extend(self._errors(value, additional, value_path))

        return errors

    def _validate_array(self, instance: list[Any], schema: dict[str, Any], path: str) -> list[str]:
        errors: list[str] = []

        min_items = schema.get("minItems")
        if min_items is not None and len(instance) < min_items:
            errors.append(f"{path}: expected at least {min_items} items")

        max_items = schema.get("maxItems")
        if max_items is not None and len(instance) > max_items:
            errors.append(f"{path}: expected at most {max_items} items")

        if schema.get("uniqueItems") is True:
            seen = set()
            for index, item in enumerate(instance):
                encoded = json.dumps(item, sort_keys=True, separators=(",", ":"))
                if encoded in seen:
                    errors.append(f"{child_path(path, index)}: duplicate array item")
                    break
                seen.add(encoded)

        if "items" in schema:
            for index, item in enumerate(instance):
                errors.extend(self._errors(item, schema["items"], child_path(path, index)))

        return errors

    def _validate_string(self, instance: str, schema: dict[str, Any], path: str) -> list[str]:
        errors: list[str] = []

        min_length = schema.get("minLength")
        if min_length is not None and len(instance) < min_length:
            errors.append(f"{path}: expected string length at least {min_length}")

        max_length = schema.get("maxLength")
        if max_length is not None and len(instance) > max_length:
            errors.append(f"{path}: expected string length at most {max_length}")

        pattern = schema.get("pattern")
        if pattern is not None and re.search(pattern, instance) is None:
            errors.append(f"{path}: value {instance!r} does not match pattern {pattern!r}")

        return errors

    def _validate_number(self, instance: int | float, schema: dict[str, Any], path: str) -> list[str]:
        errors: list[str] = []

        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            errors.append(f"{path}: expected value >= {minimum}")

        maximum = schema.get("maximum")
        if maximum is not None and instance > maximum:
            errors.append(f"{path}: expected value <= {maximum}")

        return errors

    def _matches_type(self, instance: Any, expected_type: Any) -> bool:
        if isinstance(expected_type, list):
            return any(self._matches_type(instance, item) for item in expected_type)

        if expected_type == "object":
            return isinstance(instance, dict)
        if expected_type == "array":
            return isinstance(instance, list)
        if expected_type == "string":
            return isinstance(instance, str)
        if expected_type == "integer":
            return isinstance(instance, int) and not isinstance(instance, bool)
        if expected_type == "number":
            return isinstance(instance, (int, float)) and not isinstance(instance, bool)
        if expected_type == "boolean":
            return isinstance(instance, bool)
        if expected_type == "null":
            return instance is None

        raise SchemaSupportError(f"unsupported JSON Schema type {expected_type!r}")


def assert_supported_schema(schema: Any, path: str) -> None:
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise SchemaSupportError(f"{path}: schema node must be an object or boolean")

    for keyword in schema:
        if keyword not in SUPPORTED_KEYWORDS:
            raise SchemaSupportError(f"{path}: unsupported schema keyword {keyword!r}")

    ref = schema.get("$ref")
    if ref is not None and (not isinstance(ref, str) or not ref.startswith("#/")):
        raise SchemaSupportError(f"{path}: only internal JSON Pointer refs are supported")

    for keyword in ("allOf", "anyOf", "oneOf"):
        if keyword in schema:
            subschemas = schema[keyword]
            if not isinstance(subschemas, list):
                raise SchemaSupportError(f"{path}.{keyword}: must be an array")
            for index, subschema in enumerate(subschemas):
                assert_supported_schema(subschema, f"{path}.{keyword}[{index}]")

    properties = schema.get("properties", {})
    if properties is not None:
        if not isinstance(properties, dict):
            raise SchemaSupportError(f"{path}.properties: must be an object")
        for name, property_schema in properties.items():
            assert_supported_schema(property_schema, f"{path}.properties[{name!r}]")

    defs = schema.get("$defs", {})
    if defs is not None:
        if not isinstance(defs, dict):
            raise SchemaSupportError(f"{path}.$defs: must be an object")
        for name, def_schema in defs.items():
            assert_supported_schema(def_schema, f"{path}.$defs[{name!r}]")

    additional = schema.get("additionalProperties")
    if isinstance(additional, dict) or isinstance(additional, bool):
        assert_supported_schema(additional, f"{path}.additionalProperties")
    elif additional is not None:
        raise SchemaSupportError(f"{path}.additionalProperties: must be a schema or boolean")

    if "items" in schema:
        assert_supported_schema(schema["items"], f"{path}.items")


def json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return type(value).__name__


def child_path(path: str, child: str | int) -> str:
    if isinstance(child, int):
        return f"{path}[{child}]"
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", child):
        return f"{path}.{child}"
    return f"{path}[{child!r}]"


def load_json(relative_path: str) -> Any:
    path = ROOT / relative_path
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    errors: list[str] = []
    schema_paths = sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / "schemas").glob("*.json"))
    mapped_schema_paths = {schema for schema, _fixture in SCHEMA_FIXTURES}

    for schema_path in schema_paths:
        try:
            assert_supported_schema(load_json(schema_path), schema_path)
        except (OSError, json.JSONDecodeError, SchemaSupportError) as error:
            errors.append(f"{schema_path}: {error}")

    for schema_path in sorted(set(schema_paths) - mapped_schema_paths):
        errors.append(f"{schema_path}: no fixture mapped for schema validation")

    for schema_path, fixture_path in SCHEMA_FIXTURES:
        try:
            schema = load_json(schema_path)
            fixture = load_json(fixture_path)
            validation_errors = Validator(schema).validate(fixture)
        except (OSError, json.JSONDecodeError, SchemaSupportError) as error:
            errors.append(f"{fixture_path}: {error}")
            continue

        for error in validation_errors:
            errors.append(f"{fixture_path} against {schema_path}: {error}")

    if errors:
        print("JSON Schema validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"Validated {len(SCHEMA_FIXTURES)} JSON fixtures against {len(schema_paths)} schemas.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
