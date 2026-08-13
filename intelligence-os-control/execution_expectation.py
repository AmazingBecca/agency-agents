#!/usr/bin/env python3
from __future__ import annotations

import hashlib as _bootstrap_hashlib
import os as _bootstrap_os
import pathlib as _bootstrap_pathlib
import stat as _bootstrap_stat

_CORE_FILENAME = "execution_expectation_v3.inc"
_CORE_SHA256 = "023931bb6813b2804d607e4d34c3c88c7e421a96ed73d7ea29fb954f3f4a80cb"
_CORE_MAX_BYTES = 1 << 16
_ENTRYPOINT_NAME = __name__
_ENTRYPOINT_FILE = __file__


def _bootstrap_snapshot(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_uid,
        _bootstrap_stat.S_IFMT(info.st_mode),
        _bootstrap_stat.S_IMODE(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _load_exact_core() -> bytes:
    core_path = _bootstrap_pathlib.Path(_ENTRYPOINT_FILE).resolve().with_name(_CORE_FILENAME)
    flags = _bootstrap_os.O_RDONLY | getattr(_bootstrap_os, "O_CLOEXEC", 0) | getattr(_bootstrap_os, "O_NOFOLLOW", 0)
    fd = _bootstrap_os.open(core_path, flags)
    try:
        before = _bootstrap_os.fstat(fd)
        if not _bootstrap_stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("trusted execution-expectation core must be a single-link regular file")
        if before.st_size > _CORE_MAX_BYTES:
            raise RuntimeError("trusted execution-expectation core exceeds bootstrap size bound")
        chunks = []
        total = 0
        while True:
            remaining = _CORE_MAX_BYTES + 1 - total
            chunk = _bootstrap_os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _CORE_MAX_BYTES:
                raise RuntimeError("trusted execution-expectation core exceeds bootstrap size bound")
        after = _bootstrap_os.fstat(fd)
        if _bootstrap_snapshot(after) != _bootstrap_snapshot(before) or after.st_size != total:
            raise RuntimeError("trusted execution-expectation core changed during bootstrap read")
        raw = b"".join(chunks)
        if _bootstrap_hashlib.sha256(raw).hexdigest() != _CORE_SHA256:
            raise RuntimeError("trusted execution-expectation core digest mismatch")
        return raw
    finally:
        _bootstrap_os.close(fd)


_CORE_BYTES = _load_exact_core()
globals()["__name__"] = "execution_expectation_v3_core"
exec(compile(_CORE_BYTES, str(_bootstrap_pathlib.Path(_ENTRYPOINT_FILE).with_name(_CORE_FILENAME)), "exec"), globals(), globals())
globals()["__name__"] = _ENTRYPOINT_NAME
globals()["__file__"] = _ENTRYPOINT_FILE

MAX_CONTROL_INPUT_BYTES = 1 << 20


def _stat_snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_uid,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_bounded_fd(fd: int, before: os.stat_result, label: str) -> bytes:
    if before.st_size > MAX_CONTROL_INPUT_BYTES:
        raise ValueError(f"{label} exceeds maximum size")
    chunks = []
    total = 0
    while True:
        remaining = MAX_CONTROL_INPUT_BYTES + 1 - total
        chunk = os.read(fd, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_CONTROL_INPUT_BYTES:
            raise ValueError(f"{label} exceeds maximum size")
    after = os.fstat(fd)
    if _stat_snapshot(after) != _stat_snapshot(before) or after.st_size != total:
        raise ValueError(f"{label} changed during read")
    return b"".join(chunks)


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
        return _read_bounded_fd(fd, info, label), info
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
        return _read_bounded_fd(fd, info, label), info, resolved
    finally:
        os.close(fd)


def verify_trusted_receipt_from_root(
    receipt_path: pathlib.Path,
    expectation_path: pathlib.Path,
    trusted_root: pathlib.Path,
    expected_compiler_head: str,
) -> str:
    """Verify a materialized receipt against the authority-owned expectation channel.

    ``verify_trusted_receipt`` validates receipt structure and its self-digest. This
    verifier additionally requires both the receipt and expectation to be direct,
    authority-owned children of the trusted root, binds the receipt to the exact
    expectation bytes, and rechecks every authority field carried by the receipt.
    """
    expected_compiler_head = _require_expected_compiler_head(expected_compiler_head)
    root_fd, root_info, _ = _open_trusted_root(trusted_root)
    try:
        expectation_leaf = _expectation_leaf(expectation_path, trusted_root)
        receipt_leaf = _direct_child_leaf(receipt_path, trusted_root, "trusted executor receipt")
        if receipt_leaf == expectation_leaf:
            raise ValueError("trusted expectation and executor receipt must be distinct files")

        expectation_raw, expectation_info = _read_regular_at(
            root_fd,
            expectation_leaf,
            "trusted expectation",
            root_info.st_uid,
        )
        receipt_raw, receipt_info = _read_regular_at(
            root_fd,
            receipt_leaf,
            "trusted executor receipt",
            root_info.st_uid,
        )
        if stat.S_IMODE(receipt_info.st_mode) != 0o600:
            raise ValueError("trusted executor receipt must have mode 0600")
        if (expectation_info.st_dev, expectation_info.st_ino) == (receipt_info.st_dev, receipt_info.st_ino):
            raise ValueError("trusted expectation and executor receipt must be distinct file objects")

        expectation = _validate_expectation(
            _load_canonical_bytes(expectation_raw, "trusted expectation"),
            root_info.st_uid,
            expected_compiler_head,
        )
        receipt = _load_canonical_bytes(receipt_raw, "trusted executor receipt")
        receipt_id = verify_trusted_receipt(receipt)

        expected_expectation_sha256 = hashlib.sha256(expectation_raw).hexdigest()
        if receipt.get("expectation_sha256") != expected_expectation_sha256:
            raise ValueError("trusted executor receipt expectation digest mismatch")

        bindings = {
            "compiler_repository": expectation["compiler_repository"],
            "compiler_head": expectation["compiler_head"],
            "repository": expectation["repository"],
            "head": expectation["head"],
            "base": expectation["base"],
            "merge": expectation["merge"],
            "execution_id": expectation["execution_id"],
            "candidate_uid": expectation["candidate_uid"],
            "executor_uid": expectation["executor_uid"],
            "executor": expectation["executor"],
        }
        for field, expected in bindings.items():
            if receipt.get(field) != expected:
                raise ValueError(f"trusted executor receipt {field} does not match trusted expectation")
        return receipt_id
    finally:
        os.close(root_fd)


if _ENTRYPOINT_NAME == "__main__":
    raise SystemExit(main())
