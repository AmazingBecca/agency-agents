from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tempfile
import textwrap

import distinct_principal_boundary as boundary
import verify_candidate_test_authority as diagnostic

_SCHEMA = "amazingbecca.bound-candidate-test-authority.v1"
_AUTHORITY_LEVEL = "diagnostic-bound-not-terminal"
_MAX_RUNNER_BYTES = 4 * 1024 * 1024
_SHA_RE = re.compile(r"[0-9a-f]{40}")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_INSTANCE_DISPATCH_CASE = "instance-calltestmethod-shadow"
_GETATTRIBUTE_DISPATCH_CASE = "getattribute-calltestmethod-shadow"
_CLEAN_POSITION_DECOY_CASE = "clean-position-decoy"
_CLEAN_SOURCE_SHAPE_DECOY_CASE = "clean-source-shape-decoy"
_ATTACK_SOURCE_SHAPE_DECOY_CASE = "attack-source-shape-decoy"
_CONTROL_SOURCE_VISIBILITY_CASE = "trusted-control-source-read"
_TRUSTED_CONTROL_ROOT = pathlib.Path(__file__).resolve(strict=True).parent.parent


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


def _assert_sandbox_runner_access(runner: pathlib.Path) -> None:
    metadata = runner.stat()
    if not metadata.st_mode & stat.S_IROTH:
        raise RuntimeError("runner entrypoint is not readable by the sandbox principal")
    for parent in runner.parents:
        if parent == pathlib.Path("/"):
            break
        parent_metadata = parent.stat()
        if not parent_metadata.st_mode & stat.S_IXOTH:
            raise RuntimeError("runner path is not traversable by the sandbox principal")


@contextlib.contextmanager
def _sandboxed_candidate_execution(sandbox_user: str | None):
    if sandbox_user is None:
        yield None
        return

    control_metadata = _TRUSTED_CONTROL_ROOT.lstat()
    if stat.S_ISLNK(control_metadata.st_mode) or not stat.S_ISDIR(control_metadata.st_mode):
        raise RuntimeError("trusted control checkout must be one real directory")

    boundary_report = boundary.verify_boundary(sandbox_user=sandbox_user)
    sandbox_identity = boundary.resolve_identity(sandbox_user)
    original_bounded_run = diagnostic._bounded_run

    def sandboxed_bounded_run(
        command: list[str],
        *,
        cwd: pathlib.Path,
        timeout_seconds: int,
    ) -> tuple[int, bytes, bytes, float]:
        return original_bounded_run(
            boundary.wrap_command(
                command,
                sandbox_identity,
                hidden_paths=(_TRUSTED_CONTROL_ROOT,),
            ),
            cwd=cwd,
            timeout_seconds=timeout_seconds,
        )

    diagnostic._bounded_run = sandboxed_bounded_run
    try:
        yield boundary_report
    finally:
        diagnostic._bounded_run = original_bounded_run


def _shuffle_by_control_entropy(items: list[object]) -> None:
    items.sort(key=lambda _item: os.urandom(32))


@contextlib.contextmanager
def _opaque_diagnostic_case_identity():
    original_bounded_run = diagnostic._bounded_run
    original_fixture_cases = diagnostic._fixture_cases

    def shuffled_fixture_cases():
        cases = list(original_fixture_cases())
        _shuffle_by_control_entropy(cases)
        return tuple(cases)

    def opaque_bounded_run(
        command: list[str],
        *,
        cwd: pathlib.Path,
        timeout_seconds: int,
    ) -> tuple[int, bytes, bytes, float]:
        rewritten = list(command)
        try:
            root_index = rewritten.index("--project-root") + 1
        except (ValueError, IndexError):
            return original_bounded_run(
                rewritten,
                cwd=cwd,
                timeout_seconds=timeout_seconds,
            )

        project = pathlib.Path(rewritten[root_index])
        if project != cwd:
            raise RuntimeError("diagnostic project root and working directory diverged")
        tests = project / "tests"
        fixtures = sorted(tests.glob("test*.py"))
        if len(fixtures) != 1:
            raise RuntimeError("diagnostic case must expose exactly one test fixture")

        opaque_project = project.parent / f"run-{os.urandom(16).hex()}"
        if opaque_project.exists():
            raise RuntimeError("opaque diagnostic project identity collided")
        opaque_fixture_name = f"test_{os.urandom(16).hex()}.py"
        fixture = fixtures[0]
        tests.chmod(0o755)
        project.chmod(0o755)
        fixture.rename(tests / opaque_fixture_name)
        project.rename(opaque_project)
        (opaque_project / "tests").chmod(0o555)
        opaque_project.chmod(0o555)
        rewritten[root_index] = str(opaque_project)
        return original_bounded_run(
            rewritten,
            cwd=opaque_project,
            timeout_seconds=timeout_seconds,
        )

    diagnostic._fixture_cases = shuffled_fixture_cases
    diagnostic._bounded_run = opaque_bounded_run
    try:
        yield
    finally:
        diagnostic._bounded_run = original_bounded_run
        diagnostic._fixture_cases = original_fixture_cases


def _run_diagnostic_matrix(
    *,
    runner_root: pathlib.Path,
    entrypoint: str,
    python_executable: pathlib.Path,
    timeout_seconds: int,
    sandboxed: bool,
) -> dict[str, object]:
    original_tempdir = tempfile.TemporaryDirectory

    class TraversableTemporaryDirectory:
        def __init__(self, *args, **kwargs):
            self._inner = original_tempdir(*args, **kwargs)

        def __enter__(self):
            directory = self._inner.__enter__()
            pathlib.Path(directory).chmod(0o711)
            return directory

        def __exit__(self, exc_type, exc, traceback):
            return self._inner.__exit__(exc_type, exc, traceback)

    if sandboxed:
        tempfile.TemporaryDirectory = TraversableTemporaryDirectory
    try:
        with _opaque_diagnostic_case_identity():
            return diagnostic.verify(
                runner_root=runner_root,
                entrypoint=entrypoint,
                python_executable=python_executable,
                timeout_seconds=timeout_seconds,
            )
    finally:
        tempfile.TemporaryDirectory = original_tempdir


def _run_dispatch_attack(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
    case_name: str,
    fixture_name: str,
    source: str,
    expected_zero: bool = False,
) -> dict[str, object]:
    del fixture_name
    with tempfile.TemporaryDirectory(prefix="bound-case-") as directory:
        project = pathlib.Path(directory)
        tests = project / "tests"
        tests.mkdir(parents=True)
        fixture = tests / f"test_{os.urandom(16).hex()}.py"
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

    observed_zero = returncode == 0
    return {
        "name": case_name,
        "expected_zero": expected_zero,
        "returncode": returncode,
        "passed": observed_zero == expected_zero,
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


def _run_clean_position_decoy(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, object]:
    nonce = os.urandom(8).hex()
    source = textwrap.dedent(
        f"""
        import unittest

        class Clean{nonce}(unittest.TestCase):
            def test_pass(self):
                self.assertEqual(2 + 2, 4)
        """
    ).lstrip()
    with tempfile.TemporaryDirectory(prefix="bound-case-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o711)
        project = root / f"run-{os.urandom(16).hex()}"
        tests = project / "tests"
        tests.mkdir(parents=True)
        fixture = tests / f"test_{os.urandom(16).hex()}.py"
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
    nonce = os.urandom(8).hex()
    source = textwrap.dedent(
        f"""
        import unittest

        LEXICAL_ATTACK_DECOY = "self.fail("

        class Mandatory{nonce}(unittest.TestCase):
            def test_must_fail(self):
                self.assertEqual(2 + 2, 4)
        """
    ).lstrip()
    return _run_dispatch_attack(
        runner=runner,
        python_executable=python_executable,
        timeout_seconds=timeout_seconds,
        case_name=_CLEAN_SOURCE_SHAPE_DECOY_CASE,
        fixture_name="test_clean_source_shape_decoy.py",
        source=source,
        expected_zero=True,
    )


def _run_attack_source_shape_decoy(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, object]:
    nonce = os.urandom(8).hex()
    source = textwrap.dedent(
        f"""
        import unittest

        LEXICAL_CLEAN_DECOY = "class Clean{nonce}(unittest.TestCase):\\n    def test_pass(self):\\n        self.assertEqual(2 + 2, 4)"

        class Mandatory{nonce}(unittest.TestCase):
            def test_must_fail(self):
                self.assertEqual(2 + 2, 5)
        """
    ).lstrip()
    return _run_dispatch_attack(
        runner=runner,
        python_executable=python_executable,
        timeout_seconds=timeout_seconds,
        case_name=_ATTACK_SOURCE_SHAPE_DECOY_CASE,
        fixture_name="test_attack_source_shape_decoy.py",
        source=source,
    )


def _run_control_source_visibility_attack(
    *,
    python_executable: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, object]:
    target = pathlib.Path(__file__).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="bound-control-source-") as directory:
        project = pathlib.Path(directory)
        project.chmod(0o711)
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
