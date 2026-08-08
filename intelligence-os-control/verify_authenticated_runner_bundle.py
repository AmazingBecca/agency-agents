from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from dataclasses import dataclass

import verify_bound_candidate_test_authority as bound

_SCHEMA = "amazingbecca.authenticated-runner-bundle.v1"
_AUTHORITY_LEVEL = "diagnostic-bundle-bound-not-terminal"
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_MAX_BUNDLE_FILES = 128
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_BUNDLE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class BundleSnapshot:
    root: pathlib.Path
    sha256: str
    file_count: int
    total_bytes: int
    entries: tuple[dict[str, object], ...]


def _canonical_json(payload: object) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


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


def _stable_file(path: pathlib.Path) -> tuple[str, int, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("runner bundle members must be regular single-link files")
        if before.st_size < 1 or before.st_size > _MAX_FILE_BYTES:
            raise RuntimeError("runner bundle member size is outside policy")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_FILE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_FILE_BYTES:
                raise RuntimeError("runner bundle member size is outside policy")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after) or total != before.st_size:
            raise RuntimeError("runner bundle member changed during authority read")
        return digest.hexdigest(), total, stat.S_IMODE(before.st_mode)
    finally:
        os.close(descriptor)


def snapshot_bundle(root: pathlib.Path) -> BundleSnapshot:
    resolved_root = root.resolve(strict=True)
    root_metadata = resolved_root.lstat()
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise RuntimeError("runner bundle root must be one real directory")

    entries: list[dict[str, object]] = []
    total_bytes = 0
    stack = [resolved_root]
    while stack:
        directory = stack.pop()
        directory_metadata = directory.lstat()
        if stat.S_ISLNK(directory_metadata.st_mode) or not stat.S_ISDIR(directory_metadata.st_mode):
            raise RuntimeError("runner bundle directories must be real directories")
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            child_path = pathlib.Path(child.path)
            metadata = child_path.lstat()
            relative = child_path.relative_to(resolved_root).as_posix()
            if not relative or relative.startswith("../") or relative.startswith("/"):
                raise RuntimeError("runner bundle member escaped its root")
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError("runner bundle may not contain symlinks")
            if stat.S_ISDIR(metadata.st_mode):
                stack.append(child_path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError("runner bundle may contain only regular files and directories")

            sha256, size, mode = _stable_file(child_path)
            total_bytes += size
            if total_bytes > _MAX_BUNDLE_BYTES:
                raise RuntimeError("runner bundle total size is outside policy")
            entries.append(
                {
                    "path": relative,
                    "sha256": sha256,
                    "bytes": size,
                    "mode": mode,
                }
            )
            if len(entries) > _MAX_BUNDLE_FILES:
                raise RuntimeError("runner bundle file count is outside policy")

    if not entries:
        raise RuntimeError("runner bundle is empty")
    entries.sort(key=lambda item: str(item["path"]))
    payload = {
        "schema": _SCHEMA,
        "entries": entries,
    }
    digest = hashlib.sha256(_canonical_json(payload)).hexdigest()
    return BundleSnapshot(
        root=resolved_root,
        sha256=digest,
        file_count=len(entries),
        total_bytes=total_bytes,
        entries=tuple(entries),
    )


def verify_authenticated_bundle(
    *,
    runner_root: pathlib.Path,
    entrypoint: str,
    python_executable: pathlib.Path,
    expected_runner_sha256: str,
    expected_bundle_sha256: str,
    repository: str,
    head_sha: str,
    base_sha: str,
    merge_sha: str,
    timeout_seconds: int = 20,
    sandbox_user: str | None = "nobody",
) -> dict[str, object]:
    if _DIGEST_RE.fullmatch(expected_bundle_sha256) is None:
        raise RuntimeError("expected bundle SHA-256 must be 64 lowercase hex characters")

    before = snapshot_bundle(runner_root)
    if before.sha256 != expected_bundle_sha256:
        raise RuntimeError("runner bundle SHA-256 does not match authenticated expectation")

    relative_entrypoint = pathlib.PurePosixPath(entrypoint).as_posix()
    bundle_paths = {str(entry["path"]) for entry in before.entries}
    if relative_entrypoint not in bundle_paths:
        raise RuntimeError("runner entrypoint is not present in authenticated bundle")

    inner = bound.verify_bound(
        runner_root=before.root,
        entrypoint=entrypoint,
        python_executable=python_executable,
        expected_runner_sha256=expected_runner_sha256,
        repository=repository,
        head_sha=head_sha,
        base_sha=base_sha,
        merge_sha=merge_sha,
        timeout_seconds=timeout_seconds,
        sandbox_user=sandbox_user,
    )

    after = snapshot_bundle(before.root)
    if (
        after.root != before.root
        or after.sha256 != before.sha256
        or after.file_count != before.file_count
        or after.total_bytes != before.total_bytes
        or after.entries != before.entries
    ):
        raise RuntimeError("runner bundle authority changed during external verification")

    report = dict(inner)
    report.update(
        {
            "bundle_schema": _SCHEMA,
            "authority_level": _AUTHORITY_LEVEL,
            "bundle_sha256": before.sha256,
            "bundle_file_count": before.file_count,
            "bundle_bytes": before.total_bytes,
            "bundle_files": [dict(entry) for entry in before.entries],
        }
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner-root", type=pathlib.Path, required=True)
    parser.add_argument("--entrypoint", default="isolated_unittest_runner.py")
    parser.add_argument("--python", dest="python_executable", type=pathlib.Path, default=pathlib.Path(sys.executable))
    parser.add_argument("--expected-runner-sha256", required=True)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--merge-sha", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=20)
    parser.add_argument("--sandbox-user", default="nobody")
    args = parser.parse_args(argv)

    try:
        report = verify_authenticated_bundle(
            runner_root=args.runner_root,
            entrypoint=args.entrypoint,
            python_executable=args.python_executable,
            expected_runner_sha256=args.expected_runner_sha256,
            expected_bundle_sha256=args.expected_bundle_sha256,
            repository=args.repository,
            head_sha=args.head_sha,
            base_sha=args.base_sha,
            merge_sha=args.merge_sha,
            timeout_seconds=args.timeout_seconds,
            sandbox_user=args.sandbox_user,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    sys.stdout.write(_canonical_json(report).decode("utf-8"))
    return 0 if report.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
