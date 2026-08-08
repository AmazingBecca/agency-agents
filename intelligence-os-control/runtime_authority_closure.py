from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import sysconfig
from dataclasses import dataclass

_SCHEMA = "amazingbecca.runtime-authority-closure.v1"
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_FILES = 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class RuntimeFileSnapshot:
    path: pathlib.Path
    sha256: str
    total_bytes: int
    mode: int
    identity: tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True)
class RuntimeClosureSnapshot:
    schema: str
    python_executable: pathlib.Path
    sha256: str
    file_count: int
    total_bytes: int
    entries: tuple[RuntimeFileSnapshot, ...]


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _canonical_json(payload: object) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _stable_file(path: pathlib.Path) -> RuntimeFileSnapshot:
    resolved = path.resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(resolved, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError(f"runtime closure member must be a regular single-link file: {resolved}")
        if before.st_size < 1 or before.st_size > _MAX_FILE_BYTES:
            raise RuntimeError(f"runtime closure member size is outside policy: {resolved}")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_FILE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_FILE_BYTES:
                raise RuntimeError(f"runtime closure member size is outside policy: {resolved}")
            digest.update(chunk)
        after = os.fstat(descriptor)
        before_identity = _identity(before)
        if before_identity != _identity(after) or total != before.st_size:
            raise RuntimeError(f"runtime closure member changed during authority read: {resolved}")
        return RuntimeFileSnapshot(
            path=resolved,
            sha256=digest.hexdigest(),
            total_bytes=total,
            mode=stat.S_IMODE(before.st_mode),
            identity=before_identity,
        )
    finally:
        os.close(descriptor)


def _stdlib_roots() -> tuple[pathlib.Path, ...]:
    roots: set[pathlib.Path] = set()
    for key in ("stdlib", "platstdlib"):
        value = sysconfig.get_path(key)
        if value:
            roots.add(pathlib.Path(value).resolve(strict=True))
    if not roots:
        raise RuntimeError("Python standard-library roots are unavailable")
    return tuple(sorted(roots, key=lambda item: item.as_posix()))


def _site_roots() -> tuple[pathlib.Path, ...]:
    roots: set[pathlib.Path] = set()
    for key in ("purelib", "platlib"):
        value = sysconfig.get_path(key)
        if value:
            try:
                roots.add(pathlib.Path(value).resolve(strict=True))
            except FileNotFoundError:
                continue
    return tuple(sorted(roots, key=lambda item: item.as_posix()))


def _within(path: pathlib.Path, root: pathlib.Path) -> bool:
    return path == root or root in path.parents


def _loaded_stdlib_paths() -> set[pathlib.Path]:
    stdlib_roots = _stdlib_roots()
    site_roots = _site_roots()
    paths: set[pathlib.Path] = set()
    for module in tuple(sys.modules.values()):
        raw = getattr(module, "__file__", None)
        if not isinstance(raw, str) or not raw:
            continue
        try:
            path = pathlib.Path(raw).resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError):
            continue
        if not any(_within(path, root) for root in stdlib_roots):
            continue
        if any(_within(path, root) for root in site_roots):
            continue
        if path.is_file():
            paths.add(path)
    return paths


def _mapped_runtime_paths() -> set[pathlib.Path]:
    if sys.platform != "linux":
        raise RuntimeError("runtime mapping closure is currently defined only for Linux")
    maps = pathlib.Path("/proc/self/maps").read_text(encoding="utf-8")
    paths: set[pathlib.Path] = set()
    for line in maps.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6:
            continue
        permissions = fields[1]
        if "x" not in permissions:
            continue
        raw = fields[5]
        if raw.endswith(" (deleted)"):
            raise RuntimeError("an executable mapped runtime authority file was deleted")
        if not raw.startswith("/"):
            continue
        try:
            path = pathlib.Path(raw).resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError) as exc:
            raise RuntimeError("executable mapped runtime authority path is unavailable") from exc
        if path.is_file():
            paths.add(path)
    return paths


def snapshot_runtime_closure(python_executable: pathlib.Path) -> RuntimeClosureSnapshot:
    selected = python_executable.resolve(strict=True)
    control_runtime = pathlib.Path(sys.executable).resolve(strict=True)
    if selected != control_runtime:
        raise RuntimeError(
            "sandboxed candidate Python must equal the verifier runtime before runtime closure can be trusted"
        )

    paths = {selected}
    paths.update(_mapped_runtime_paths())
    paths.update(_loaded_stdlib_paths())
    if len(paths) > _MAX_FILES:
        raise RuntimeError("runtime closure file count is outside policy")

    entries: list[RuntimeFileSnapshot] = []
    total_bytes = 0
    for path in sorted(paths, key=lambda item: item.as_posix()):
        snapshot = _stable_file(path)
        total_bytes += snapshot.total_bytes
        if total_bytes > _MAX_TOTAL_BYTES:
            raise RuntimeError("runtime closure total size is outside policy")
        entries.append(snapshot)

    if not entries or selected not in {entry.path for entry in entries}:
        raise RuntimeError("runtime closure omitted the selected Python executable")

    manifest = {
        "schema": _SCHEMA,
        "python_executable": str(selected),
        "entries": [
            {
                "path": str(entry.path),
                "sha256": entry.sha256,
                "bytes": entry.total_bytes,
                "mode": entry.mode,
            }
            for entry in entries
        ],
    }
    digest = hashlib.sha256(_canonical_json(manifest)).hexdigest()
    if _DIGEST_RE.fullmatch(digest) is None:
        raise RuntimeError("runtime closure digest is malformed")
    return RuntimeClosureSnapshot(
        schema=_SCHEMA,
        python_executable=selected,
        sha256=digest,
        file_count=len(entries),
        total_bytes=total_bytes,
        entries=tuple(entries),
    )


def _identity_can_mutate(metadata: os.stat_result, *, uid: int, gid: int) -> bool:
    if metadata.st_uid == uid:
        return True
    if metadata.st_gid == gid and metadata.st_mode & stat.S_IWGRP:
        return True
    return bool(metadata.st_mode & stat.S_IWOTH)


def assert_closure_not_writable_by_identity(
    snapshot: RuntimeClosureSnapshot,
    *,
    uid: int,
    gid: int,
) -> None:
    checked: set[pathlib.Path] = set()
    for entry in snapshot.entries:
        current = entry.path
        while current not in checked:
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError("runtime closure authority path became a symlink")
            if _identity_can_mutate(metadata, uid=uid, gid=gid):
                raise RuntimeError(
                    "runtime closure authority is replaceable or owner-mutable by sandbox principal"
                )
            checked.add(current)
            if current == pathlib.Path("/"):
                break
            current = current.parent


def render_manifest(snapshot: RuntimeClosureSnapshot) -> list[dict[str, object]]:
    return [
        {
            "path": str(entry.path),
            "sha256": entry.sha256,
            "bytes": entry.total_bytes,
            "mode": entry.mode,
        }
        for entry in snapshot.entries
    ]
