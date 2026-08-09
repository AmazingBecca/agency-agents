from __future__ import annotations

import os
import pathlib
import stat
import tempfile
import textwrap

import verify_candidate_test_authority as diagnostic

_SCHEMA = "amazingbecca.nested-suite-dispatch-authority.v1"
_AUTHORITY_LEVEL = "diagnostic-bound-not-terminal"


def _write_case(project: pathlib.Path, *, attack_kind: str | None) -> None:
    tests = project / "tests"
    tests.mkdir(parents=True)
    package = tests / "__init__.py"
    package.write_text("", encoding="utf-8")
    nonce = os.urandom(8).hex()

    if attack_kind == "call":
        arm_body = textwrap.dedent(
            f"""
            import unittest

            class ArmNestedSuiteCallDispatch{nonce}(unittest.TestCase):
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
    elif attack_kind == "run":
        arm_body = textwrap.dedent(
            f"""
            import unittest

            class ArmNestedSuiteRunDispatch{nonce}(unittest.TestCase):
                def test_00_arm_nested_suite_dispatch(self):
                    def forged_suite_run(suite, result, debug=False):
                        for item in suite:
                            if isinstance(item, unittest.TestSuite):
                                forged_suite_run(item, result, debug)
                                continue
                            result.startTest(item)
                            try:
                                result.addSuccess(item)
                            finally:
                                result.stopTest(item)
                        return result

                    setattr(unittest.TestSuite, "r" + "un", forged_suite_run)
            """
        ).lstrip()
    elif attack_kind == "result-add-error":
        arm_body = textwrap.dedent(
            f"""
            import unittest

            class ArmResultAddErrorDispatch{nonce}(unittest.TestCase):
                def test_00_arm_result_dispatch(self):
                    original_add_error = unittest.TextTestResult.addError

                    def forged_result_add_error(result, test, error):
                        del error
                        unittest.TextTestResult.addError = original_add_error
                        result.addSuccess(test)

                    unittest.TextTestResult.addError = forged_result_add_error
            """
        ).lstrip()
    elif attack_kind is None:
        arm_body = textwrap.dedent(
            f"""
            import unittest

            class ArmNestedSuiteDispatch{nonce}(unittest.TestCase):
                def test_00_arm_nested_suite_dispatch(self):
                    self.assertTrue(True)
            """
        ).lstrip()
    else:
        raise ValueError(f"unsupported attack kind: {attack_kind!r}")

    if attack_kind is None:
        later_body = textwrap.dedent(
            f"""
            import unittest

            class MandatoryNestedSuiteFailure{nonce}(unittest.TestCase):
                def test_99_must_fail(self):
                    self.assertEqual(2 + 2, 4)
            """
        ).lstrip()
    elif attack_kind == "result-add-error":
        later_body = textwrap.dedent(
            f"""
            import unittest

            class MandatoryNestedSuiteFailure{nonce}(unittest.TestCase):
                def test_99_must_fail(self):
                    raise RuntimeError("mandatory later-module error {nonce}")
            """
        ).lstrip()
    else:
        later_body = textwrap.dedent(
            f"""
            import unittest

            class MandatoryNestedSuiteFailure{nonce}(unittest.TestCase):
                def test_99_must_fail(self):
                    self.fail("mandatory later-module failure {nonce}")
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
    attack_kind: str | None,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="nested-suite-authority-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o711)
        project = root / f"run-{os.urandom(16).hex()}"
        project.mkdir()
        _write_case(project, attack_kind=attack_kind)
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

    expected_zero = attack_kind is None
    names = {
        None: "nested-suite-clean-control",
        "call": "nested-suite-post-discovery-call-forgery",
        "run": "nested-suite-post-discovery-run-forgery",
        "result-add-error": "result-post-discovery-add-error-forgery",
    }
    return {
        "name": names[attack_kind],
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

    cases = [
        _run_case(
            runner=runner,
            python_executable=python_executable,
            timeout_seconds=timeout_seconds,
            attack_kind=None,
        ),
        _run_case(
            runner=runner,
            python_executable=python_executable,
            timeout_seconds=timeout_seconds,
            attack_kind="call",
        ),
        _run_case(
            runner=runner,
            python_executable=python_executable,
            timeout_seconds=timeout_seconds,
            attack_kind="run",
        ),
        _run_case(
            runner=runner,
            python_executable=python_executable,
            timeout_seconds=timeout_seconds,
            attack_kind="result-add-error",
        ),
    ]
    clean = cases[0]
    attacks = cases[1:]
    rejected_clean = [] if clean["passed"] else [str(clean["name"])]
    accepted_attacks = [str(case["name"]) for case in attacks if not case["passed"]]
    return {
        "schema": _SCHEMA,
        "authority_level": _AUTHORITY_LEVEL,
        "case_count": len(cases),
        "accepted_attacks": accepted_attacks,
        "rejected_clean": rejected_clean,
        "cases": cases,
        "passed": bool(all(case["passed"] for case in cases)),
    }
