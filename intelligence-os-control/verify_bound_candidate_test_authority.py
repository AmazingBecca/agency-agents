from __future__ import annotations

import contextlib
import hashlib
import os
import pathlib
import pwd
import re
import secrets
import stat
import sys
import tempfile
import textwrap
from typing import Iterator

import distinct_principal_boundary as boundary
import verify_candidate_test_authority as diagnostic

_SCHEMA = "amazingbecca.bound-candidate-test-authority.v1"
_AUTHORITY_LEVEL = "diagnostic-bound-not-terminal"
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_SHA_RE = re.compile(r"[0-9a-f]{40}")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_INSTANCE_DISPATCH_CASE = "instance-calltestmethod-dispatch-forgery"
_GETATTRIBUTE_DISPATCH_CASE = "getattribute-calltestmethod-dispatch-forgery"
_CLEAN_POSITION_DECOY_CASE = "clean-position-decoy"
_CLEAN_SOURCE_SHAPE_DECOY_CASE = "clean-source-shape-decoy"
_ATTACK_SOURCE_SHAPE_DECOY_CASE = "attack-source-shape-decoy"
_CONTROL_SOURCE_VISIBILITY_CASE = "control-source-visibility"


def _validate_identity(repository: str, head_sha: str, base_sha: str, merge_sha: str) -> None:
    if _REPOSITORY_RE.fullmatch(repository) is None:
        raise RuntimeError("repository identity must be owner/name")
    for name, value in (
        ("head_sha", head_sha),
        ("base_sha", base_sha),
        ("merge_sha", merge_sha),
    ):
        if _SHA_RE.fullmatch(value) is None:
            raise RuntimeError(f"{name} must be 40 lowercase hex characters")
    if len({head_sha, base_sha, merge_sha}) != 3:
        raise RuntimeError("candidate head, base, and synthetic merge identities must be distinct")


def _stable_runner_digest(root: pathlib.Path, entrypoint: str) -> tuple[pathlib.Path, str, int]:
    resolved_root = root.resolve(strict=True)
    relative = pathlib.PurePosixPath(entrypoint)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise RuntimeError("runner entrypoint must stay inside authenticated bundle")
    runner = (resolved_root / pathlib.Path(*relative.parts)).resolve(strict=True)
    if runner.parent != resolved_root and resolved_root not in runner.parents:
        raise RuntimeError("runner entrypoint escaped authenticated bundle")
    metadata = runner.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError("runner entrypoint must be one regular single-link file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(runner, flags)
    try:
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or total != before.st_size:
            raise RuntimeError("runner entrypoint changed during authority read")
        return runner, digest.hexdigest(), total
    finally:
        os.close(descriptor)


def _assert_sandbox_runner_access(runner: pathlib.Path) -> None:
    current = runner.parent
    while True:
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError("runner ancestry may not contain symlinks")
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("runner ancestry must contain directories")
        if not metadata.st_mode & stat.S_IXOTH:
            raise RuntimeError("sandbox principal cannot traverse runner authority path")
        if current == pathlib.Path("/"):
            break
        current = current.parent
    if not runner.stat().st_mode & stat.S_IROTH:
        raise RuntimeError("sandbox principal cannot read runner entrypoint")


def _shuffle_by_control_entropy(items: list[object]) -> None:
    for index in range(len(items) - 1, 0, -1):
        other = secrets.randbelow(index + 1)
        items[index], items[other] = items[other], items[index]


def _raw_case_supplier() -> list[tuple[str, str, bool]]:
    supplier = getattr(diagnostic, "_CASES", None)
    if not isinstance(supplier, list) or not supplier:
        raise RuntimeError("diagnostic case supplier is unavailable")
    cases: list[tuple[str, str, bool]] = []
    for item in supplier:
        if not isinstance(item, tuple) or len(item) != 3:
            raise RuntimeError("diagnostic case supplier is malformed")
        name, source, expected_zero = item
        if not isinstance(name, str) or not isinstance(source, str) or not isinstance(expected_zero, bool):
            raise RuntimeError("diagnostic case supplier values are malformed")
        cases.append((name, source, expected_zero))
    _shuffle_by_control_entropy(cases)
    return cases


def _make_private_fixture(
    root: pathlib.Path,
    *,
    source: str,
) -> pathlib.Path:
    project = root / f"run-{secrets.token_hex(16)}"
    tests = project / "tests"
    project.mkdir(mode=0o755)
    tests.mkdir(mode=0o755)
    package = tests / "__init__.py"
    fixture = tests / f"test_{secrets.token_hex(16)}.py"
    package.write_text("", encoding="utf-8")
    fixture.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    package.chmod(0o444)
    fixture.chmod(0o444)
    tests.chmod(0o555)
    project.chmod(0o555)
    return project


def _invoke_runner(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    project: pathlib.Path,
    timeout_seconds: int,
) -> tuple[int, str, str, float]:
    return diagnostic._bounded_run(
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


def _run_diagnostic_matrix(
    *,
    runner_root: pathlib.Path,
    entrypoint: str,
    python_executable: pathlib.Path,
    timeout_seconds: int,
    sandboxed: bool,
) -> dict[str, object]:
    del sandboxed
    runner, _digest, _bytes = _stable_runner_digest(runner_root, entrypoint)
    cases = _raw_case_supplier()
    by_name: dict[str, dict[str, object]] = {}
    with tempfile.TemporaryDirectory(prefix="bound-candidate-authority-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o711)
        for name, source, expected_zero in cases:
            project = _make_private_fixture(root, source=source)
            returncode, output, errors, elapsed = _invoke_runner(
                runner=runner,
                python_executable=python_executable,
                project=project,
                timeout_seconds=timeout_seconds,
            )
            by_name[name] = {
                "name": name,
                "expected_zero": expected_zero,
                "returncode": returncode,
                "passed": (returncode == 0) == expected_zero,
                "stdout_bytes": len(output),
                "stderr_bytes": len(errors),
                "elapsed_ms": int(elapsed * 1000),
            }
    canonical = [name for name, _source, _expected_zero in diagnostic._CASES]
    ordered = [by_name[name] for name in canonical]
    rejected_clean = [str(case["name"]) for case in ordered if case["expected_zero"] and not case["passed"]]
    accepted_attacks = [str(case["name"]) for case in ordered if not case["expected_zero"] and not case["passed"]]
    return {
        "schema": "amazingbecca.candidate-test-authority-matrix.v1",
        "case_count": len(ordered),
        "accepted_attacks": accepted_attacks,
        "rejected_clean": rejected_clean,
        "cases": ordered,
        "passed": not accepted_attacks and not rejected_clean,
    }


@contextlib.contextmanager
def _sandboxed_candidate_execution(sandbox_user: str | None) -> Iterator[dict[str, object] | None]:
    if sandbox_user is None:
        yield None
        return

    identity = boundary.resolve_identity(sandbox_user)
    with tempfile.TemporaryDirectory(prefix="bound-candidate-sandbox-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o755)
        probe = root / "probe.py"
        probe.write_text("raise SystemExit(0)\n", encoding="utf-8")
        probe.chmod(0o444)
        report = boundary.prove_boundary(
            sandbox_user=sandbox_user,
            command=[sys.executable, "-I", str(probe)],
            hidden_paths=(),
        )
        if report.get("passed") is not True:
            raise RuntimeError("distinct-principal candidate boundary is unavailable")
        if report.get("sandbox_uid") != identity.uid or report.get("sandbox_gid") != identity.gid:
            raise RuntimeError("distinct-principal boundary identity drifted")
        yield report


def _run_instance_dispatch_attack(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, object]:
    source = r"""
        import unittest

        class InstanceDispatchAttack(unittest.TestCase):
            def setUp(self):
                self._callTestMethod = lambda method: None

            def test_must_fail(self):
                self.fail("mandatory failure")
    """
    with tempfile.TemporaryDirectory(prefix="instance-dispatch-authority-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o711)
        project = _make_private_fixture(root, source=source)
        returncode, output, errors, elapsed = _invoke_runner(
            runner=runner,
            python_executable=python_executable,
            project=project,
            timeout_seconds=timeout_seconds,
        )
    return {
        "name": _INSTANCE_DISPATCH_CASE,
        "expected_zero": False,
        "returncode": returncode,
        "passed": returncode != 0,
        "stdout_bytes": len(output),
        "stderr_bytes": len(errors),
        "elapsed_ms": int(elapsed * 1000),
    }


def _run_getattribute_dispatch_attack(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, object]:
    source = r"""
        import unittest

        class GetattributeDispatchAttack(unittest.TestCase):
            def __getattribute__(self, name):
                if name == "_callTestMethod":
                    return lambda method: None
                return super().__getattribute__(name)

            def test_must_fail(self):
                self.fail("mandatory failure")
    """
    with tempfile.TemporaryDirectory(prefix="getattribute-dispatch-authority-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o711)
        project = _make_private_fixture(root, source=source)
        returncode, output, errors, elapsed = _invoke_runner(
            runner=runner,
            python_executable=python_executable,
            project=project,
            timeout_seconds=timeout_seconds,
        )
    return {
        "name": _GETATTRIBUTE_DISPATCH_CASE,
        "expected_zero": False,
        "returncode": returncode,
        "passed": returncode != 0,
        "stdout_bytes": len(output),
        "stderr_bytes": len(errors),
        "elapsed_ms": int(elapsed * 1000),
    }


def _run_clean_position_decoy(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, object]:
    source = r"""
        import unittest

        class MandatoryFailure(unittest.TestCase):
            def test_must_fail(self):
                self.assertEqual(2 + 2, 4)
    """
    with tempfile.TemporaryDirectory(prefix="clean-position-decoy-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o711)
        project = _make_private_fixture(root, source=source)
        returncode, output, errors, elapsed = _invoke_runner(
            runner=runner,
            python_executable=python_executable,
            project=project,
            timeout_seconds=timeout_seconds,
        )
    return {
        "name": _CLEAN_POSITION_DECOY_CASE,
        "expected_zero": True,
        "returncode": returncode,
        "passed": returncode == 0,
        "stdout_bytes": len(output),
        "stderr_bytes": len(errors),
        "elapsed_ms": int(elapsed * 1000),
    }


def _run_clean_source_shape_decoy(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, object]:
    source = r"""
        import unittest

        class MandatoryFailure(unittest.TestCase):
            def test_must_fail(self):
                if False:
                    self.fail("LEXICAL_ATTACK_DECOY")
                self.assertEqual(2 + 2, 4)
    """
    with tempfile.TemporaryDirectory(prefix="clean-source-shape-decoy-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o711)
        project = _make_private_fixture(root, source=source)
        returncode, output, errors, elapsed = _invoke_runner(
            runner=runner,
            python_executable=python_executable,
            project=project,
            timeout_seconds=timeout_seconds,
        )
    return {
        "name": _CLEAN_SOURCE_SHAPE_DECOY_CASE,
        "expected_zero": True,
        "returncode": returncode,
        "passed": returncode == 0,
        "stdout_bytes": len(output),
        "stderr_bytes": len(errors),
        "elapsed_ms": int(elapsed * 1000),
    }


def _run_attack_source_shape_decoy(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, object]:
    source = r"""
        import unittest

        class Clean(unittest.TestCase):
            def test_pass(self):
                if False:
                    self.assertEqual(2 + 2, 4)
                self.assertEqual(2 + 2, 5)
    """
    with tempfile.TemporaryDirectory(prefix="attack-source-shape-decoy-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o711)
        project = _make_private_fixture(root, source=source)
        returncode, output, errors, elapsed = _invoke_runner(
            runner=runner,
            python_executable=python_executable,
            project=project,
            timeout_seconds=timeout_seconds,
        )
    return {
        "name": _ATTACK_SOURCE_SHAPE_DECOY_CASE,
        "expected_zero": False,
        "returncode": returncode,
        "passed": returncode != 0,
        "stdout_bytes": len(output),
        "stderr_bytes": len(errors),
        "elapsed_ms": int(elapsed * 1000),
    }


def _run_control_source_visibility_attack(
    *,
    python_executable: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, object]:
    target = pathlib.Path(__file__).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="control-source-visibility-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o711)
        project = root / "project"
        project.mkdir(mode=0o755)
        probe = project / "probe.py"
        probe.write_text(
            textwrap.dedent(
                """
                import pathlib
                import sys

                target = pathlib.Path(sys.argv[1])
                try:
                    target.read_bytes()
                except OSError:
                    raise SystemExit(7)
                raise SystemExit(0)
                """
            ).lstrip(),
            encoding="utf-8",
        )
        probe.chmod(0o444)
        returncode, output, errors, elapsed = diagnostic._bounded_run(
            [
                str(python_executable),
                "-I",
                str(probe),
                str(target),
            ],
            cwd=project,
            timeout_seconds=timeout_seconds,
        )

    return {
        "name": _CONTROL_SOURCE_VISIBILITY_CASE,
        "expected_zero": False,
        "returncode": returncode,
        "passed": returncode != 0,
        "stdout_bytes": len(output),
        "stderr_bytes": len(errors),
        "elapsed_ms": int(elapsed * 1000),
    }


def _run_sidecars(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
    sandboxed: bool,
) -> list[dict[str, object]]:
    invocations = [
        (
            _INSTANCE_DISPATCH_CASE,
            lambda: _run_instance_dispatch_attack(
                runner=runner,
                python_executable=python_executable,
                timeout_seconds=timeout_seconds,
            ),
        ),
        (
            _GETATTRIBUTE_DISPATCH_CASE,
            lambda: _run_getattribute_dispatch_attack(
                runner=runner,
                python_executable=python_executable,
                timeout_seconds=timeout_seconds,
            ),
        ),
        (
            _CLEAN_POSITION_DECOY_CASE,
            lambda: _run_clean_position_decoy(
                runner=runner,
                python_executable=python_executable,
                timeout_seconds=timeout_seconds,
            ),
        ),
        (
            _CLEAN_SOURCE_SHAPE_DECOY_CASE,
            lambda: _run_clean_source_shape_decoy(
                runner=runner,
                python_executable=python_executable,
                timeout_seconds=timeout_seconds,
            ),
        ),
        (
            _ATTACK_SOURCE_SHAPE_DECOY_CASE,
            lambda: _run_attack_source_shape_decoy(
                runner=runner,
                python_executable=python_executable,
                timeout_seconds=timeout_seconds,
            ),
        ),
    ]
    canonical_names = [
        _INSTANCE_DISPATCH_CASE,
        _GETATTRIBUTE_DISPATCH_CASE,
        _CLEAN_POSITION_DECOY_CASE,
        _CLEAN_SOURCE_SHAPE_DECOY_CASE,
        _ATTACK_SOURCE_SHAPE_DECOY_CASE,
    ]
    if sandboxed:
        invocations.append(
            (
                _CONTROL_SOURCE_VISIBILITY_CASE,
                lambda: _run_control_source_visibility_attack(
                    python_executable=python_executable,
                    timeout_seconds=timeout_seconds,
                ),
            )
        )
        canonical_names.append(_CONTROL_SOURCE_VISIBILITY_CASE)

    _shuffle_by_control_entropy(invocations)
    by_name: dict[str, dict[str, object]] = {}
    for expected_name, invoke in invocations:
        report = invoke()
        if report.get("name") != expected_name:
            raise RuntimeError("sidecar authority case identity drifted")
        by_name[expected_name] = report
    return [by_name[name] for name in canonical_names]


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
    sandbox_user: str | None = None,
) -> dict[str, object]:
    _validate_identity(repository, head_sha, base_sha, merge_sha)
    if _DIGEST_RE.fullmatch(expected_runner_sha256) is None:
        raise RuntimeError("expected runner SHA-256 must be 64 lowercase hex characters")

    runner, before_digest, runner_bytes = _stable_runner_digest(runner_root, entrypoint)
    if before_digest != expected_runner_sha256:
        raise RuntimeError("runner SHA-256 does not match authenticated expectation")
    if sandbox_user is not None:
        _assert_sandbox_runner_access(runner)

    with _sandboxed_candidate_execution(sandbox_user) as boundary_report:
        diagnostic_report = _run_diagnostic_matrix(
            runner_root=runner_root,
            entrypoint=entrypoint,
            python_executable=python_executable,
            timeout_seconds=timeout_seconds,
            sandboxed=sandbox_user is not None,
        )
        if diagnostic_report.get("schema") != "amazingbecca.candidate-test-authority-matrix.v1":
            raise RuntimeError("candidate authority diagnostic schema is unexpected")
        if not isinstance(diagnostic_report.get("passed"), bool):
            raise RuntimeError("candidate authority diagnostic decision is malformed")
        if not isinstance(diagnostic_report.get("case_count"), int):
            raise RuntimeError("candidate authority diagnostic case count is malformed")

        python_executable = python_executable.resolve(strict=True)
        sidecars = _run_sidecars(
            runner=runner,
            python_executable=python_executable,
            timeout_seconds=timeout_seconds,
            sandboxed=sandbox_user is not None,
        )

    after_runner, after_digest, after_bytes = _stable_runner_digest(runner_root, entrypoint)
    if after_runner != runner or after_digest != before_digest or after_bytes != runner_bytes:
        raise RuntimeError("runner authority changed during external verification")

    accepted_attacks = list(diagnostic_report.get("accepted_attacks", []))
    rejected_clean = list(diagnostic_report.get("rejected_clean", []))
    if any(not isinstance(item, str) for item in accepted_attacks + rejected_clean):
        raise RuntimeError("candidate authority diagnostic case inventory is malformed")
    for sidecar in sidecars:
        if sidecar["passed"]:
            continue
        if sidecar["expected_zero"]:
            rejected_clean.append(str(sidecar["name"]))
        else:
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
        "sandbox_user": sandbox_user,
        "sandbox_boundary": boundary_report,
        "passed": passed,
        "sidecar": sidecars[0],
        "sidecars": sidecars,
    }


def main(argv: list[str] | None = None) -> int:
    del argv
    print(
        "ERROR: direct entrypoint-only verification is disabled; "
        "use verify_terminal_candidate_authority.py",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
