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
    "repository", "head", "base", "merge", "execution_id", "candidate_uid",
}


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _inside(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _absolute(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def _open_trusted_root(root: pathlib.Path) -> tuple[int, os.stat_result, pathlib.Path]:
    root_abs = _absolute(root)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(root_abs, flags)
    except OSError as exc:
        raise ValueError(f"trusted expectation root is unavailable: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("trusted expectation root must be a directory")
        if info.st_mode & 0o022:
            raise ValueError("trusted expectation root must not be group/world writable")
        if info.st_uid != os.geteuid():
            raise ValueError("trusted expectation verifier must run as trusted root owner")
        resolved = pathlib.Path(os.path.realpath(root_abs))
        return fd, info, resolved
    except Exception:
        os.close(fd)
        raise


def _direct_child_leaf(path: pathlib.Path, root: pathlib.Path, label: str) -> str:
    path_abs = _absolute(path)
    root_abs = _absolute(root)
    if path_abs.parent != root_abs:
        raise ValueError(f"{label} must be a direct child of the trusted expectation root")
    leaf = path_abs.name
    if not leaf or leaf in {".", ".."} or "/" in leaf or "\\" in leaf:
        raise ValueError(f"{label} leaf is invalid")
    return leaf


def _expectation_leaf(expectation_path: pathlib.Path, trusted_root: pathlib.Path) -> str:
    return _direct_child_leaf(expectation_path, trusted_root, "trusted expectation")


def _read_regular_at(parent_fd: int, leaf: str, label: str, required_uid: int) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(leaf, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise ValueError(f"{label} is unavailable: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if info.st_nlink != 1:
            raise ValueError(f"{label} must have exactly one hard link")
        if info.st_uid != required_uid:
            raise ValueError(f"{label} owner does not match trusted expectation root")
        if info.st_mode & 0o022:
            raise ValueError(f"{label} must not be group/world writable")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), info
    finally:
        os.close(fd)


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


def _validate_expectation(expectation: object, root_uid: int) -> dict:
    if not isinstance(expectation, dict) or set(expectation) != EXPECTATION_KEYS:
        raise ValueError("trusted expectation fields must match the exact channel schema")
    if expectation.get("schema") != "amazingbecca.predator-execution-expectation.v2":
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
    candidate_uid = expectation.get("candidate_uid")
    if isinstance(candidate_uid, bool) or not isinstance(candidate_uid, int) or candidate_uid <= 0 or candidate_uid > 0xFFFFFFFF:
        raise ValueError("trusted expectation candidate_uid must identify a non-root account")
    if candidate_uid == root_uid:
        raise ValueError("trusted expectation root must be owned by an authority uid distinct from candidate uid")
    return expectation


def load_expectation(
    expectation_path: pathlib.Path,
    manifest_path: pathlib.Path,
    execution_path: pathlib.Path,
    trusted_root: pathlib.Path,
) -> dict:
    root_fd, root_info, root_resolved = _open_trusted_root(trusted_root)
    try:
        leaf = _expectation_leaf(expectation_path, trusted_root)
        expectation_raw, expectation_info = _read_regular_at(
            root_fd, leaf, "trusted expectation", root_info.st_uid
        )
        expectation = _validate_expectation(
            _load_canonical_bytes(expectation_raw, "trusted expectation"),
            root_info.st_uid,
        )
        manifest_raw, manifest_info, manifest_resolved = _read_regular(manifest_path, "manifest")
        execution_raw, execution_info, execution_resolved = _read_regular(execution_path, "execution report")

        candidate_uid = expectation["candidate_uid"]
        if manifest_info.st_uid != candidate_uid or execution_info.st_uid != candidate_uid:
            raise ValueError("candidate manifest/execution owner does not match trusted candidate uid")
        if manifest_info.st_mode & 0o022 or execution_info.st_mode & 0o022:
            raise ValueError("candidate manifest/execution inputs must not be group/world writable")

        if _inside(manifest_resolved, root_resolved) or _inside(execution_resolved, root_resolved):
            raise ValueError("candidate manifest/execution inputs must remain outside the trusted expectation root")

        identities = {
            (expectation_info.st_dev, expectation_info.st_ino),
            (manifest_info.st_dev, manifest_info.st_ino),
            (execution_info.st_dev, execution_info.st_ino),
        }
        if len(identities) != 3:
            raise ValueError("trusted expectation, manifest, and execution report must be distinct file objects")

        return {
            "expectation": expectation,
            "manifest": _load_canonical_bytes(manifest_raw, "manifest"),
            "execution": _load_canonical_bytes(execution_raw, "execution report"),
        }
    finally:
        os.close(root_fd)


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


def materialize_trusted_receipt(
    receipt: dict,
    output: pathlib.Path,
    trusted_root: pathlib.Path,
) -> str:
    _direct_child_leaf(output, trusted_root, "executor receipt output")
    return er.materialize_receipt(receipt, output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expectation", type=pathlib.Path, required=True)
    parser.add_argument("--trusted-expectation-root", type=pathlib.Path, required=True)
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--execution", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        receipt = issue_receipt_from_files(
            args.expectation,
            args.manifest,
            args.execution,
            args.trusted_expectation_root,
        )
        materialize_trusted_receipt(receipt, args.output, args.trusted_expectation_root)
    except Exception as exc:
        print(f"executor expectation channel rejected input: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
