from __future__ import annotations

import os
import pathlib
import stat
import tempfile
import textwrap

import verify_candidate_test_authority as diagnostic

_SCHEMA = "amazingbecca.nested-suite-dispatch-authority.v1"
_AUTHORITY_LEVEL = "diagnostic-bound-not-terminal"


def _write_case(project: pathlib.Path, *, attack: bool) -> None:
    tests = project / "tests"
    tests.mkdir(parents=True)
    package = tests / "__init__.py"
    package.write_text("", encoding="utf-8")
    nonce = os.urandom(8).hex()

    if attack:
        arm_body = textwrap.dedent(
            f"""
            import unittest

            class ArmNestedSuiteDispatch{nonce}(unittest.TestCase):
                def test_00_arm_nested_suite_dispatch(self):
                    def forged_suite_call(suite, result, debug=False):
                        for item in suite:
                            if isinstance(item, unittest.TestSuite):
                                forged_suite_call(item, result, debug)
                                continue
                            result.startTest(item)
                            try:
                                result.addSuccess(item)
                            finally:
                                result.stopTest(item)
                        return result

                    setattr(unittest.TestSuite, "__" + "call__", forged_suite_call)
            """
        ).lstrip()
        later_body = textwrap.dedent(
            f"""
            import unittest

            class MandatoryNestedSuiteFailure{nonce}(unittest.TestCase):
                def test_99_must_fail(self):
                    self.fail("mandatory later-module failure {nonce}")
            """
        ).lstrip()
    else:
        arm_body = textwrap.dedent(
            f"""
            import unittest

            class ArmNestedSuiteDispatch{nonce}(unittest.TestCase):
                def test_00_arm_nested_suite_dispatch(self):
                    self.assertTrue(True)
            """
        ).lstrip()
        later_body = textwrap.dedent(
            f"""
            import unittest

            class MandatoryNestedSuiteFailure{nonce}(unittest.TestCase):
                def test_99_must_fail(self):
                    self.assertEqual(2 + 2, 4)
            """
        ).lstrip()

    first = tests / f"test_00_{os.urandom(8).hex()}.py"
    second = tests / f"test_99_{os.urandom(8).hex()}.py"
    first.write_text(arm_body, encoding="utf-8")
    second.write_text(later_body, encoding="utf-8")
    package.chmod(0o444)
    first.chmod(0o444)
    second.chmod(0o444)
    tests.chmod(0o555)
    project.chmod(0o555)


def _run_case(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int,
    attack: bool,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="nested-suite-authority-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o711)
        project = root / f"run-{os.urandom(16).hex()}"
        project.mkdir()
        _write_case(project, attack=attack)
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

    expected_zero = not attack
    return {
        "name": "nested-suite-post-discovery-forgery" if attack else "nested-suite-clean-control",
        "expected_zero": expected_zero,
        "returncode": returncode,
        "passed": (returncode == 0) == expected_zero,
        "stdout_bytes": len(output),
        "stderr_bytes": len(errors),
        "elapsed_ms": int(elapsed * 1000),
    }


def verify(
    *,
    runner: pathlib.Path,
    python_executable: pathlib.Path,
    timeout_seconds: int = 20,
) -> dict[str, object]:
    runner = runner.resolve(strict=True)
    python_executable = python_executable.resolve(strict=True)
    metadata = runner.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("runner must be one real regular file")

    clean = _run_case(
        runner=runner,
        python_executable=python_executable,
        timeout_seconds=timeout_seconds,
        attack=False,
    )
    attack = _run_case(
        runner=runner,
        python_executable=python_executable,
        timeout_seconds=timeout_seconds,
        attack=True,
    )
    rejected_clean = [] if clean["passed"] else [str(clean["name"])]
    accepted_attacks = [] if attack["passed"] else [str(attack["name"])]
    return {
        "schema": _SCHEMA,
        "authority_level": _AUTHORITY_LEVEL,
        "case_count": 2,
        "accepted_attacks": accepted_attacks,
        "rejected_clean": rejected_clean,
        "cases": [clean, attack],
        "passed": bool(clean["passed"] and attack["passed"]),
    }
