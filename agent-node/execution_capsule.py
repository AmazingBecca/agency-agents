#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SCHEMA = "execution-capsule/v1"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
MAX_SECONDS = 900
MAX_OUTPUT_BYTES = 1_000_000


class CapsuleError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise CapsuleError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def parse(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CapsuleError(f"invalid capsule JSON: {exc}") from exc
    if canonical(value) != raw:
        raise CapsuleError("capsule must use canonical JSON encoding")
    verify(value)
    return value


def verify(value: dict[str, Any]) -> None:
    expected = {
        "schema", "capsule_id", "repository", "head", "tree", "source_bundle_sha256",
        "operation", "network_access", "max_seconds", "max_output_bytes", "required_tools",
        "advisory_only", "promotion_authorized", "completion_authorized", "capsule_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise CapsuleError("capsule schema drift")
    if value["schema"] != SCHEMA:
        raise CapsuleError("unsupported capsule schema")
    if not isinstance(value["capsule_id"], str) or not value["capsule_id"].strip():
        raise CapsuleError("capsule_id is required")
    repo = value["repository"]
    if not isinstance(repo, str) or repo.count("/") != 1:
        raise CapsuleError("repository must be owner/name")
    if not SHA40.fullmatch(value["head"] or "") or not SHA40.fullmatch(value["tree"] or ""):
        raise CapsuleError("head/tree must be lowercase Git SHA-1")
    if not SHA64.fullmatch(value["source_bundle_sha256"] or ""):
        raise CapsuleError("invalid source_bundle_sha256")
    op = value["operation"]
    if not isinstance(op, dict) or set(op) != {"kind", "selector"}:
        raise CapsuleError("operation schema drift")
    if op["kind"] != "python_unittest":
        raise CapsuleError("unsupported operation kind")
    selector = op["selector"]
    if not isinstance(selector, str) or not selector or any(ch.isspace() for ch in selector):
        raise CapsuleError("selector must be one exact non-whitespace token")
    if value["network_access"] != "none":
        raise CapsuleError("capsule network access must remain disabled")
    if not isinstance(value["max_seconds"], int) or isinstance(value["max_seconds"], bool) or not (1 <= value["max_seconds"] <= MAX_SECONDS):
        raise CapsuleError("max_seconds outside bound")
    if not isinstance(value["max_output_bytes"], int) or isinstance(value["max_output_bytes"], bool) or not (1 <= value["max_output_bytes"] <= MAX_OUTPUT_BYTES):
        raise CapsuleError("max_output_bytes outside bound")
    tools = value["required_tools"]
    if not isinstance(tools, list) or not tools or tools != sorted(tools, key=lambda x: x.get("name", "")):
        raise CapsuleError("required_tools must be non-empty and sorted")
    names = set()
    for tool in tools:
        if not isinstance(tool, dict) or set(tool) != {"name", "version"}:
            raise CapsuleError("tool requirement schema drift")
        name, version = tool["name"], tool["version"]
        if not isinstance(name, str) or not name or name in names:
            raise CapsuleError("tool names must be unique non-empty strings")
        if not isinstance(version, str) or not version:
            raise CapsuleError("tool version is required")
        names.add(name)
    if "python" not in names:
        raise CapsuleError("python tool requirement is mandatory")
    if value["advisory_only"] is not True or value["promotion_authorized"] is not False or value["completion_authorized"] is not False:
        raise CapsuleError("capsule authority boundary weakened")
    provided = value["capsule_sha256"]
    if not SHA64.fullmatch(provided or ""):
        raise CapsuleError("invalid capsule_sha256")
    expected_hash = digest({k: v for k, v in value.items() if k != "capsule_sha256"})
    if provided != expected_hash:
        raise CapsuleError("capsule hash mismatch")


def build(**kwargs: Any) -> bytes:
    value = dict(kwargs)
    value["schema"] = SCHEMA
    value["advisory_only"] = True
    value["promotion_authorized"] = False
    value["completion_authorized"] = False
    value["required_tools"] = sorted(value["required_tools"], key=lambda x: x["name"])
    value["capsule_sha256"] = digest(value)
    raw = canonical(value)
    parse(raw)
    return raw
