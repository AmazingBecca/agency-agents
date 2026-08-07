#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
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
TRUSTED_COMPILER_REPOSITORY = "AmazingBecca/agency-agents"
EXPECTATION_KEYS = {
    "schema", "source", "compiler_repository", "compiler_head",
    "repository", "head", "base", "merge", "execution_id", "candidate_uid",
}
TRUSTED_RECEIPT_KEYS = {
    "schema", "execution_id", "manifest_sha256", "execution_report_sha256",
    "repository", "head", "base", "merge", "executor", "status",
    "compiler_repository", "compiler_head", "expectation_sha256",
    "verifier_receipt_sha256", "receipt_id",
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


def _require_expected_compiler_head(value: object) -> str:
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        raise ValueError("trusted expected compiler head must be a lowercase 40-character Git SHA")
    return value


def _validate_expectation(expectation: object, root_uid: int, expected_compiler_head: str) -> dict:
    expected_compiler_head = _require_expected_compiler_head(expected_compiler_head)
    if not isinstance(expectation, dict) or set(expectation) != EXPECTATION_KEYS:
        raise ValueError("trusted expectation fields must match the exact channel schema")
    if expectation.get("schema") != "amazingbecca.predator-execution-expectation.v2":
        raise ValueError("unsupported trusted expectation schema")
    if expectation.get("source") != "predator-compiler-control":
        raise ValueError("unexpected trusted expectation source")
    if expectation.get("compiler_repository") != TRUSTED_COMPILER_REPOSITORY:
        raise ValueError("trusted expectation compiler repository does not match trusted compiler authority")
    compiler_head = expectation.get("compiler_head")
    if not isinstance(compiler_head, str) or not SHA40.fullmatch(compiler_head):
        raise ValueError("invalid trusted expectation compiler_head")
    if compiler_head != expected_compiler_head:
        raise ValueError("trusted expectation compiler head does not match trusted expected compiler head")
    repository = expectation.get("repository")
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        raise ValueError("invalid trusted expectation repository")
    for field in ("head", "base", "merge"):
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


def _finalize_trusted_receipt(base_receipt: dict, expectation: dict, expectation_sha256: str) -> dict:
    if not isinstance(expectation_sha256, str) or not SHA64.fullmatch(expectation_sha256):
        raise ValueError("invalid trusted expectation digest")
    verifier_receipt_sha256 = hashlib.sha256(er.canonical_bytes(base_receipt)).hexdigest()
    core = {
        "schema": "amazingbecca.predator-executor-receipt.v2",
        "execution_id": base_receipt["execution_id"],
        "manifest_sha256": base_receipt["manifest_sha256"],
        "execution_report_sha256": base_receipt["execution_report_sha256"],
        "repository": base_receipt["repository"],
        "head": base_receipt["head"],
        "base": base_receipt["base"],
        "merge": base_receipt["merge"],
        "executor": base_receipt["executor"],
        "status": base_receipt["status"],
        "compiler_repository": expectation["compiler_repository"],
        "compiler_head": expectation["compiler_head"],
        "expectation_sha256": expectation_sha256,
        "verifier_receipt_sha256": verifier_receipt_sha256,
    }
    return {**core, "receipt_id": hashlib.sha256(_canonical(core)).hexdigest()}


def verify_trusted_receipt(receipt: object) -> str:
    if not isinstance(receipt, dict) or set(receipt) != TRUSTED_RECEIPT_KEYS:
        raise ValueError("trusted executor receipt fields must match the exact authority schema")
    if receipt.get("schema") != "amazingbecca.predator-executor-receipt.v2":
        raise ValueError("unsupported trusted executor receipt schema")
    if receipt.get("status") != "PASS":
        raise ValueError("trusted executor receipt is not PASS")
    if receipt.get("compiler_repository") != TRUSTED_COMPILER_REPOSITORY:
        raise ValueError("trusted executor receipt compiler repository mismatch")
    if not isinstance(receipt.get("compiler_head"), str) or not SHA40.fullmatch(receipt["compiler_head"]):
        raise ValueError("invalid trusted executor receipt compiler_head")
    repository = receipt.get("repository")
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        raise ValueError("invalid trusted executor receipt repository")
    for field in ("head", "base", "merge"):
        if not isinstance(receipt.get(field), str) or not SHA40.fullmatch(receipt[field]):
            raise ValueError(f"invalid trusted executor receipt {field}")
    for field in (
        "execution_id", "manifest_sha256", "execution_report_sha256",
        "expectation_sha256", "verifier_receipt_sha256", "receipt_id",
    ):
        if not isinstance(receipt.get(field), str) or not SHA64.fullmatch(receipt[field]):
            raise ValueError(f"invalid trusted executor receipt {field}")
    executor = receipt.get("executor")
    if not isinstance(executor, str) or not er.EXECUTOR.fullmatch(executor):
        raise ValueError("invalid trusted executor receipt executor")
    core = dict(receipt)
    receipt_id = core.pop("receipt_id")
    if hashlib.sha256(_canonical(core)).hexdigest() != receipt_id:
        raise ValueError("trusted executor receipt digest mismatch")
    return receipt_id


def load_expectation(
    expectation_path: pathlib.Path,
    manifest_path: pathlib.Path,
    execution_path: pathlib.Path,
    trusted_root: pathlib.Path,
    expected_compiler_head: str,
) -> dict:
    expected_compiler_head = _require_expected_compiler_head(expected_compiler_head)
    root_fd, root_info, root_resolved = _open_trusted_root(trusted_root)
    try:
        leaf = _expectation_leaf(expectation_path, trusted_root)
        expectation_raw, expectation_info = _read_regular_at(
            root_fd, leaf, "trusted expectation", root_info.st_uid
        )
        expectation = _validate_expectation(
            _load_canonical_bytes(expectation_raw, "trusted expectation"),
            root_info.st_uid,
            expected_compiler_head,
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
            "expectation_sha256": hashlib.sha256(expectation_raw).hexdigest(),
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
    expected_compiler_head: str,
) -> dict:
    bound = load_expectation(
        expectation_path,
        manifest_path,
        execution_path,
        trusted_root,
        expected_compiler_head,
    )
    expectation, manifest, execution = bound["expectation"], bound["manifest"], bound["execution"]
    for field in ("repository", "head", "base", "merge"):
        if expectation[field] != manifest.get(field):
            raise ValueError(f"trusted expectation {field} does not match manifest")
    base_receipt = er.issue_receipt(manifest, execution, expectation["execution_id"])
    return _finalize_trusted_receipt(
        base_receipt,
        expectation,
        bound["expectation_sha256"],
    )


def materialize_trusted_receipt(
    receipt: dict,
    output: pathlib.Path,
    trusted_root: pathlib.Path,
) -> str:
    verify_trusted_receipt(receipt)
    _direct_child_leaf(output, trusted_root, "executor receipt output")
    return er.materialize_receipt(receipt, output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expectation", type=pathlib.Path, required=True)
    parser.add_argument("--trusted-expectation-root", type=pathlib.Path, required=True)
    parser.add_argument("--expected-compiler-head", required=True)
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
            args.expected_compiler_head,
        )
        materialize_trusted_receipt(receipt, args.output, args.trusted_expectation_root)
    except Exception as exc:
        print(f"executor expectation channel rejected input: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
