#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
EXECUTOR = re.compile(r"^[a-z][a-z0-9-]{1,47}$")
TEST = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")
EXECUTION_KEYS = {
    "execution_id",
    "repository",
    "head",
    "base",
    "merge",
    "executor",
    "production_mutation",
    "attempted_paths",
    "tests",
}


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def load_canonical(path: pathlib.Path):
    raw = path.read_bytes()
    value = json.loads(raw)
    if canonical_bytes(value) != raw:
        raise ValueError(f"{path} is not canonical JSON")
    return value


def _path(value: object) -> str:
    if not isinstance(value, str) or not value or value.startswith(("/", "~")) or "\\" in value:
        raise ValueError("executed path must be repository-relative POSIX path")
    parts = pathlib.PurePosixPath(value).parts
    if not parts or any(part in {"", ".", ".."} for part in parts) or value.endswith("/"):
        raise ValueError("executed path must be normalized")
    return value


def _under(path: str, allowed: str) -> bool:
    return path == allowed or path.startswith(allowed.rstrip("/") + "/")


def verify_manifest(manifest: dict) -> str:
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    if manifest.get("schema") != "amazingbecca.predator-compiler.v1":
        raise ValueError("unsupported manifest schema")
    execution_id = manifest.get("execution_id")
    if not isinstance(execution_id, str) or not SHA64.fullmatch(execution_id):
        raise ValueError("invalid execution_id")
    core = dict(manifest)
    core.pop("execution_id", None)
    if hashlib.sha256(canonical_bytes(core)).hexdigest() != execution_id:
        raise ValueError("manifest execution_id mismatch")
    if manifest.get("status") != "READY":
        raise ValueError("manifest is not executable")
    if manifest.get("production_mutation") is not False:
        raise ValueError("production mutation is forbidden")
    for field in ("head", "base", "merge"):
        if not isinstance(manifest.get(field), str) or not SHA40.fullmatch(manifest[field]):
            raise ValueError(f"invalid manifest {field}")
    return execution_id


def issue_receipt(manifest: dict, execution: dict) -> dict:
    execution_id = verify_manifest(manifest)
    if not isinstance(execution, dict):
        raise ValueError("execution report must be an object")
    if set(execution) != EXECUTION_KEYS:
        raise ValueError("execution report fields must match the exact authority schema")
    for field in ("execution_id", "repository", "head", "base", "merge"):
        if execution.get(field) != manifest.get(field):
            raise ValueError(f"execution {field} does not match manifest")
    executor = execution.get("executor")
    if not isinstance(executor, str) or not EXECUTOR.fullmatch(executor):
        raise ValueError("invalid executor identity")
    if execution.get("production_mutation", False) is not False:
        raise ValueError("executor attempted production mutation")

    allowed = manifest.get("allowed_paths", [])
    if not isinstance(allowed, list) or not all(isinstance(x, str) for x in allowed):
        raise ValueError("invalid manifest allowed_paths")
    attempted = execution.get("attempted_paths", [])
    if not isinstance(attempted, list):
        raise ValueError("invalid attempted_paths")
    normalized = sorted({_path(value) for value in attempted})
    for path in normalized:
        if not any(_under(path, root) for root in allowed):
            raise ValueError(f"executor path outside manifest: {path}")

    results = execution.get("tests")
    if not isinstance(results, list) or not results:
        raise ValueError("execution must report tests")
    observed = {}
    for result in results:
        if not isinstance(result, dict) or set(result) != {"name", "status"}:
            raise ValueError("test result must contain only name/status")
        name, status = result["name"], result["status"]
        if not isinstance(name, str) or not TEST.fullmatch(name):
            raise ValueError("invalid test name")
        if name in observed:
            raise ValueError("duplicate test result")
        if status not in {"PASS", "FAIL", "SKIP"}:
            raise ValueError("invalid test status")
        observed[name] = status
    required = manifest.get("required_tests", [])
    if not isinstance(required, list) or not all(isinstance(x, str) for x in required):
        raise ValueError("invalid manifest required_tests")
    missing = sorted(set(required) - set(observed))
    if missing:
        raise ValueError(f"missing required tests: {','.join(missing)}")
    bad = sorted(name for name in required if observed[name] != "PASS")
    if bad:
        raise ValueError(f"required tests not passing: {','.join(bad)}")

    execution_core = {
        "schema": "amazingbecca.predator-execution-report.v1",
        "execution_id": execution_id,
        "repository": manifest["repository"],
        "head": manifest["head"],
        "base": manifest["base"],
        "merge": manifest["merge"],
        "executor": executor,
        "production_mutation": False,
        "attempted_paths": normalized,
        "tests": [{"name": name, "status": observed[name]} for name in sorted(observed)],
    }
    report_sha256 = hashlib.sha256(canonical_bytes(execution_core)).hexdigest()
    receipt_core = {
        "schema": "amazingbecca.predator-executor-receipt.v1",
        "execution_id": execution_id,
        "manifest_sha256": hashlib.sha256(canonical_bytes(manifest)).hexdigest(),
        "execution_report_sha256": report_sha256,
        "repository": manifest["repository"],
        "head": manifest["head"],
        "base": manifest["base"],
        "merge": manifest["merge"],
        "executor": executor,
        "status": "PASS",
    }
    return {**receipt_core, "receipt_id": hashlib.sha256(canonical_bytes(receipt_core)).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--execution", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        receipt = issue_receipt(load_canonical(args.manifest), load_canonical(args.execution))
        args.output.write_bytes(canonical_bytes(receipt))
    except Exception as exc:
        print(f"executor receipt rejected input: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
