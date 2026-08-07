#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import stat
import sys

import executor_receipt as er

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
EXPECTATION_KEYS = {
    "schema", "source", "compiler_repository", "compiler_head",
    "repository", "head", "base", "merge", "execution_id",
}


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _inside(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _secure_root(root: pathlib.Path) -> pathlib.Path:
    if root.is_symlink():
        raise ValueError("trusted expectation root must not be a symlink")
    resolved = root.resolve(strict=True)
    info = os.stat(resolved, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("trusted expectation root must be a directory")
    if info.st_uid not in {0, os.geteuid()}:
        raise ValueError("trusted expectation root owner is not trusted")
    if info.st_mode & 0o022:
        raise ValueError("trusted expectation root must not be group/world writable")
    return resolved


def _read_regular(path: pathlib.Path, label: str) -> tuple[bytes, os.stat_result, pathlib.Path]:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    resolved = path.resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(resolved, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if info.st_nlink != 1:
            raise ValueError(f"{label} must have exactly one hard link")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), info, resolved
    finally:
        os.close(fd)


def _load_canonical_bytes(raw: bytes, label: str):
    value = json.loads(raw)
    if _canonical(value) != raw:
        raise ValueError(f"{label} is not canonical JSON")
    return value


def load_expectation(
    expectation_path: pathlib.Path,
    manifest_path: pathlib.Path,
    execution_path: pathlib.Path,
    trusted_root: pathlib.Path,
) -> dict:
    root = _secure_root(trusted_root)
    expectation_raw, expectation_info, expectation_resolved = _read_regular(expectation_path, "trusted expectation")
    manifest_raw, manifest_info, manifest_resolved = _read_regular(manifest_path, "manifest")
    execution_raw, execution_info, execution_resolved = _read_regular(execution_path, "execution report")

    if not _inside(expectation_resolved, root):
        raise ValueError("trusted expectation must come from the trusted expectation root")
    if _inside(manifest_resolved, root) or _inside(execution_resolved, root):
        raise ValueError("candidate manifest/execution inputs must remain outside the trusted expectation root")

    identities = {
        (expectation_info.st_dev, expectation_info.st_ino),
        (manifest_info.st_dev, manifest_info.st_ino),
        (execution_info.st_dev, execution_info.st_ino),
    }
    if len(identities) != 3:
        raise ValueError("trusted expectation, manifest, and execution report must be distinct file objects")
    if expectation_info.st_uid not in {0, os.geteuid()} or expectation_info.st_mode & 0o022:
        raise ValueError("trusted expectation file ownership/mode is not trusted")

    expectation = _load_canonical_bytes(expectation_raw, "trusted expectation")
    if not isinstance(expectation, dict) or set(expectation) != EXPECTATION_KEYS:
        raise ValueError("trusted expectation fields must match the exact channel schema")
    if expectation.get("schema") != "amazingbecca.predator-execution-expectation.v1":
        raise ValueError("unsupported trusted expectation schema")
    if expectation.get("source") != "predator-compiler-control":
        raise ValueError("unexpected trusted expectation source")
    for field in ("compiler_repository", "repository"):
        if not isinstance(expectation.get(field), str) or not REPOSITORY.fullmatch(expectation[field]):
            raise ValueError(f"invalid trusted expectation {field}")
    for field in ("compiler_head", "head", "base", "merge"):
        if not isinstance(expectation.get(field), str) or not SHA40.fullmatch(expectation[field]):
            raise ValueError(f"invalid trusted expectation {field}")
    if not isinstance(expectation.get("execution_id"), str) or not SHA64.fullmatch(expectation["execution_id"]):
        raise ValueError("invalid trusted expectation execution_id")

    return {
        "expectation": expectation,
        "manifest": _load_canonical_bytes(manifest_raw, "manifest"),
        "execution": _load_canonical_bytes(execution_raw, "execution report"),
    }


def issue_receipt_from_files(
    expectation_path: pathlib.Path,
    manifest_path: pathlib.Path,
    execution_path: pathlib.Path,
    trusted_root: pathlib.Path,
) -> dict:
    bound = load_expectation(expectation_path, manifest_path, execution_path, trusted_root)
    expectation, manifest, execution = bound["expectation"], bound["manifest"], bound["execution"]
    for field in ("repository", "head", "base", "merge"):
        if expectation[field] != manifest.get(field):
            raise ValueError(f"trusted expectation {field} does not match manifest")
    return er.issue_receipt(manifest, execution, expectation["execution_id"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expectation", type=pathlib.Path, required=True)
    parser.add_argument("--trusted-expectation-root", type=pathlib.Path, required=True)
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--execution", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        receipt = issue_receipt_from_files(args.expectation, args.manifest, args.execution, args.trusted_expectation_root)
        er.materialize_receipt(receipt, args.output)
    except Exception as exc:
        print(f"executor expectation channel rejected input: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
