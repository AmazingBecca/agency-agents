from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tempfile
import textwrap

import verify_candidate_test_authority as diagnostic

_SCHEMA = "amazingbecca.bound-candidate-test-authority.v1"
_AUTHORITY_LEVEL = "diagnostic-bound-not-terminal"
_MAX_RUNNER_BYTES = 4 * 1024 * 1024
_SHA_RE = re.compile(r"[0-9a-f]{40}")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_INSTANCE_DISPATCH_CASE = "instance-calltestmethod-shadow"
_GETATTRIBUTE_DISPATCH_CASE = "getattribute-calltestmethod-shadow"


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def _validate_identity(repository: str, head_sha: str, base_sha: str, merge_sha: str) -> None:
    if _REPOSITORY_RE.fullmatch(repository) is None:
        raise RuntimeError("repository identity is malformed")
    for label, value in (
        ("head SHA", head_sha),
        ("base SHA", base_sha),
        ("merge SHA", merge_sha),
    ):
        if _SHA_RE.fullmatch(value) is None:
            raise RuntimeError(f"{label} must be one lowercase 40-character SHA")


def _stable_runner_digest(root: pathlib.Path, entrypoint: str) -> tuple[pathlib.Path, str, int]:
    resolved_root = root.resolve(strict=True)
    root_metadata = resolved_root.lstat()
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise RuntimeError("runner root must be a regular directory")

    candidate = resolved_root / entrypoint
    try:
        entry_metadata = candidate.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError("runner entrypoint is missing") from exc
    if stat.S_ISLNK(entry_metadata.st_mode):
        raise RuntimeError("runner entrypoint must not be a symlink")

    resolved = candidate.resolve(strict=True)
    if resolved_root not in resolved.parents:
        raise RuntimeError("runner entrypoint escaped its bundle root")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(resolved, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("runner entrypoint must be one regular non-hard-linked file")
        if before.st_size < 1 or before.st_size > _MAX_RUNNER_BYTES:
            raise RuntimeError("runner entrypoint size is outside policy")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_RUNNER_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_RUNNER_BYTES:
                raise RuntimeError("runner entrypoint size is outside policy")
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(before) != identity(after) or total != before.st_size:
            raise RuntimeError("runner entrypoint changed during authority read")
        return resolved, digest.hexdigest(), total
    finally:
        os.close(descriptor)


def _run_dispatch_attack(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
    case_name: str,
    fixture_name: str,
    source: str,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix=f"bound-{case_name}-") as directory:
        project = pathlib.Path(directory)
        tests = project / "tests"
        tests.mkdir(parents=True)
        fixture = tests / fixture_name
        fixture.write_text(source, encoding="utf-8")
        fixture.chmod(0o444)
        tests.chmod(0o555)
        project.chmod(0o555)
        returncode, output, errors, elapsed = diagnostic._bounded_run(
            [
                str(python_executable),
                "-I",
                str(runner),
                "--project-root",
                str(project),
                "--pattern",
                "test*.py",
            ],
            cwd=project,
            timeout_seconds=timeout_seconds,
        )

    return {
        "name": case_name,
        "expected_zero": False,
        "returncode": returncode,
        "passed": returncode != 0,
        "stdout_bytes": len(output),
        "stderr_bytes": len(errors),
        "elapsed_ms": int(elapsed * 1000),
    }


def _run_instance_dispatch_attack(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, object]:
    nonce = os.urandom(8).hex()
    source = textwrap.dedent(
        f"""
        import unittest

        class InstanceDispatch{nonce}(unittest.TestCase):
            def setUp(self):
                self._callTestMethod = lambda method: None

            def test_must_fail(self):
                self.fail("mandatory instance-dispatch failure {nonce}")
        """
    ).lstrip()
    return _run_dispatch_attack(
        runner=runner,
        python_executable=python_executable,
        timeout_seconds=timeout_seconds,
        case_name=_INSTANCE_DISPATCH_CASE,
        fixture_name="test_instance_dispatch_authority.py",
        source=source,
    )


def _run_getattribute_dispatch_attack(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, object]:
    nonce = os.urandom(8).hex()
    source = textwrap.dedent(
        f"""
        import unittest

        class GetattributeDispatch{nonce}(unittest.TestCase):
            def __getattribute__(self, name):
                if name == "_callTestMethod":
                    return lambda method: None
                return super().__getattribute__(name)

            def test_must_fail(self):
                self.fail("mandatory getattribute-dispatch failure {nonce}")
        """
    ).lstrip()
    return _run_dispatch_attack(
        runner=runner,
        python_executable=python_executable,
        timeout_seconds=timeout_seconds,
        case_name=_GETATTRIBUTE_DISPATCH_CASE,
        fixture_name="test_getattribute_dispatch_authority.py",
        source=source,
    )


def verify_bound(
    *,
    runner_root: pathlib.Path,
    entrypoint: str,
    python_executable: pathlib.Path,
    expected_runner_sha256: str,
    repository: str,
    head_sha: str,
    base_sha: str,
    merge_sha: str,
    timeout_seconds: int = 20,
) -> dict[str, object]:
    _validate_identity(repository, head_sha, base_sha, merge_sha)
    if _DIGEST_RE.fullmatch(expected_runner_sha256) is None:
        raise RuntimeError("expected runner SHA-256 must be 64 lowercase hex characters")

    runner, before_digest, runner_bytes = _stable_runner_digest(runner_root, entrypoint)
    if before_digest != expected_runner_sha256:
        raise RuntimeError("runner SHA-256 does not match authenticated expectation")

    diagnostic_report = diagnostic.verify(
        runner_root=runner_root,
        entrypoint=entrypoint,
        python_executable=python_executable,
        timeout_seconds=timeout_seconds,
    )
    if diagnostic_report.get("schema") != "amazingbecca.candidate-test-authority-matrix.v1":
        raise RuntimeError("candidate authority diagnostic schema is unexpected")
    if not isinstance(diagnostic_report.get("passed"), bool):
        raise RuntimeError("candidate authority diagnostic decision is malformed")
    if not isinstance(diagnostic_report.get("case_count"), int):
        raise RuntimeError("candidate authority diagnostic case count is malformed")

    python_executable = python_executable.resolve(strict=True)
    sidecars = [
        _run_instance_dispatch_attack(
            runner=runner,
            python_executable=python_executable,
            timeout_seconds=timeout_seconds,
        ),
        _run_getattribute_dispatch_attack(
            runner=runner,
            python_executable=python_executable,
            timeout_seconds=timeout_seconds,
        ),
    ]

    after_runner, after_digest, after_bytes = _stable_runner_digest(runner_root, entrypoint)
    if after_runner != runner or after_digest != before_digest or after_bytes != runner_bytes:
        raise RuntimeError("runner authority changed during external verification")

    accepted_attacks = list(diagnostic_report.get("accepted_attacks", []))
    rejected_clean = list(diagnostic_report.get("rejected_clean", []))
    if any(not isinstance(item, str) for item in accepted_attacks + rejected_clean):
        raise RuntimeError("candidate authority diagnostic case inventory is malformed")
    for sidecar in sidecars:
        if not sidecar["passed"]:
            accepted_attacks.append(str(sidecar["name"]))

    passed = bool(diagnostic_report["passed"]) and all(bool(sidecar["passed"]) for sidecar in sidecars)
    return {
        "schema": _SCHEMA,
        "authority_level": _AUTHORITY_LEVEL,
        "repository": repository,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "merge_sha": merge_sha,
        "runner_entrypoint": entrypoint,
        "runner_sha256": before_digest,
        "runner_bytes": runner_bytes,
        "diagnostic_schema": diagnostic_report["schema"],
        "diagnostic_case_count": diagnostic_report["case_count"],
        "sidecar_case_count": len(sidecars),
        "total_case_count": int(diagnostic_report["case_count"]) + len(sidecars),
        "accepted_attacks": sorted(set(accepted_attacks)),
        "rejected_clean": sorted(set(rejected_clean)),
        "passed": passed,
        "sidecar": sidecars[0],
        "sidecars": sidecars,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner-root", type=pathlib.Path, required=True)
    parser.add_argument("--entrypoint", default="isolated_unittest_runner.py")
    parser.add_argument("--python", dest="python_executable", type=pathlib.Path, default=pathlib.Path(sys.executable))
    parser.add_argument("--expected-runner-sha256", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--merge-sha", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=20)
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args(argv)

    try:
        report = verify_bound(
            runner_root=args.runner_root,
            entrypoint=args.entrypoint,
            python_executable=args.python_executable,
            expected_runner_sha256=args.expected_runner_sha256,
            repository=args.repository,
            head_sha=args.head_sha,
            base_sha=args.base_sha,
            merge_sha=args.merge_sha,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    rendered = _canonical_json(report)
    if args.report is not None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(args.report, flags, 0o600)
        try:
            os.write(descriptor, rendered.encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    sys.stdout.write(rendered)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
