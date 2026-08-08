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
_MAX_FILES = 8192
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_CONTROL_SOURCE_ROOT = pathlib.Path(__file__).resolve(strict=True).parent


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
        if before.st_size > _MAX_FILE_BYTES:
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


def _runtime_prefixes() -> tuple[pathlib.Path, ...]:
    roots: set[pathlib.Path] = set()
    for raw in (sys.prefix, sys.exec_prefix, sys.base_prefix, sys.base_exec_prefix):
        if not isinstance(raw, str) or not raw:
            continue
        roots.add(pathlib.Path(raw).resolve(strict=True))
    if not roots:
        raise RuntimeError("Python runtime prefixes are unavailable")
    return tuple(sorted(roots, key=lambda item: item.as_posix()))


def _runtime_import_roots() -> tuple[pathlib.Path, ...]:
    prefixes = _runtime_prefixes()
    roots: set[pathlib.Path] = set(_stdlib_roots())
    roots.update(_site_roots())

    for raw in tuple(sys.path):
        if not isinstance(raw, str) or not raw:
            continue
        try:
            resolved = pathlib.Path(raw).resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError):
            continue
        if _within(resolved, _CONTROL_SOURCE_ROOT):
            continue
        if not any(_within(resolved, prefix) for prefix in prefixes):
            raise RuntimeError(f"Python runtime import search path escaped sealed runtime authority: {resolved}")
        roots.add(resolved)

    for root in roots:
        if not any(_within(root, prefix) for prefix in prefixes):
            raise RuntimeError(f"Python runtime import root escaped sealed runtime authority: {root}")
    return tuple(sorted(roots, key=lambda item: item.as_posix()))


def _runtime_import_paths() -> set[pathlib.Path]:
    prefixes = _runtime_prefixes()
    paths: set[pathlib.Path] = set()
    visited_directories: set[pathlib.Path] = set()
    stack = list(reversed(_runtime_import_roots()))

    while stack:
        candidate = stack.pop()
        try:
            resolved = candidate.resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError) as exc:
            raise RuntimeError("runtime import authority path is unavailable") from exc
        if not any(_within(resolved, prefix) for prefix in prefixes):
            raise RuntimeError(f"runtime import authority escaped sealed runtime prefix: {resolved}")

        metadata = resolved.stat()
        if stat.S_ISREG(metadata.st_mode):
            paths.add(resolved)
            if len(paths) > _MAX_FILES:
                raise RuntimeError("runtime closure file count is outside policy")
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"runtime import authority is not a regular file or directory: {resolved}")
        if resolved in visited_directories:
            continue
        visited_directories.add(resolved)

        try:
            with os.scandir(resolved) as iterator:
                children = sorted(iterator, key=lambda item: item.name, reverse=True)
        except OSError as exc:
            raise RuntimeError(f"runtime import authority directory is unreadable: {resolved}") from exc
        for child in children:
            child_path = pathlib.Path(child.path)
            try:
                child_metadata = child_path.lstat()
            except OSError as exc:
                raise RuntimeError(f"runtime import authority member is unavailable: {child_path}") from exc
            if stat.S_ISLNK(child_metadata.st_mode):
                try:
                    target = child_path.resolve(strict=True)
                except (FileNotFoundError, OSError, RuntimeError) as exc:
                    raise RuntimeError(f"runtime import authority symlink is unresolved: {child_path}") from exc
                if not any(_within(target, prefix) for prefix in prefixes):
                    raise RuntimeError(f"runtime import authority symlink escaped sealed runtime prefix: {child_path}")
                stack.append(target)
                continue
            if stat.S_ISDIR(child_metadata.st_mode) or stat.S_ISREG(child_metadata.st_mode):
                stack.append(child_path)
                continue
            raise RuntimeError(f"runtime import authority contains an unsupported filesystem object: {child_path}")

    return paths


def _loaded_stdlib_paths() -> set[pathlib.Path]:
    # Kept for compatibility with focused callers; the closure no longer relies
    # on load state and instead binds the complete runtime import authority tree.
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
    paths.update(_runtime_import_paths())
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
                raise RuntimeError(f"runtime closure authority path became a symlink: {current}")
            if _identity_can_mutate(metadata, uid=uid, gid=gid):
                raise RuntimeError(
                    "runtime closure authority is replaceable or owner-mutable by sandbox principal: "
                    f"{current} owner={metadata.st_uid}:{metadata.st_gid} mode={stat.S_IMODE(metadata.st_mode):04o} "
                    f"sandbox={uid}:{gid}"
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
