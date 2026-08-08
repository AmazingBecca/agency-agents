from __future__ import annotations

import argparse
import json
import os
import pathlib
import secrets
import selectors
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass

_MAX_RUNNER_BYTES = 4 * 1024 * 1024
_MAX_OUTPUT_BYTES = 256 * 1024
_DEFAULT_TIMEOUT_SECONDS = 20
_ALLOWED_ENV = {
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "SYSTEMROOT",
    "TMPDIR",
    "TEMP",
    "TMP",
}
_SECRET_ENV_NAMES = {
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "OPENAI_API_KEY",
}
_SCHEMA = "amazingbecca.candidate-test-authority-matrix.v1"


@dataclass(frozen=True)
class Case:
    name: str
    source: str
    expect_zero: bool


def _read_regular(path: pathlib.Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError(f"{label} must be one regular non-hard-linked file")
        if before.st_size < 1 or before.st_size > maximum:
            raise RuntimeError(f"{label} size is outside policy")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise RuntimeError(f"{label} size is outside policy")
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
            raise RuntimeError(f"{label} changed during authority read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _assert_runner_bundle(root: pathlib.Path, entrypoint: str) -> pathlib.Path:
    root = root.resolve(strict=True)
    metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("runner root must be a regular directory")
    entry = (root / entrypoint).resolve(strict=True)
    if root not in entry.parents:
        raise RuntimeError("runner entrypoint escaped its bundle root")
    _read_regular(entry, _MAX_RUNNER_BYTES, "runner entrypoint")
    return entry


def _fixture_cases() -> tuple[Case, ...]:
    nonce = secrets.token_hex(8)
    fail = f"mandatory authority failure {nonce}"
    return (
        Case(
            "clean-pass",
            f"""
            import unittest

            class Clean{nonce}(unittest.TestCase):
                def test_pass(self):
                    self.assertEqual(2 + 2, 4)
            """,
            True,
        ),
        Case(
            "mandatory-failure",
            f"""
            import unittest

            class Mandatory{nonce}(unittest.TestCase):
                def test_must_fail(self):
                    self.fail({fail!r})
            """,
            False,
        ),
        Case(
            "import-exit-zero",
            f"""
            import os
            import unittest

            class Mandatory{nonce}(unittest.TestCase):
                def test_must_fail(self):
                    self.fail({fail!r})

            os._exit(0)
            """,
            False,
        ),
        Case(
            "closure-authority-forgery",
            f"""
            import unittest

            class Mandatory{nonce}(unittest.TestCase):
                def test_must_fail(
                    self,
                    action=lambda self: self.fail({fail!r}),
                ):
                    action(self)

            function = Mandatory{nonce}.test_must_fail
            function.__defaults__ = (lambda self: None,)

            closure = unittest.TestCase.run.__closure__
            freevars = unittest.TestCase.run.__code__.co_freevars
            cells = dict(zip(freevars, closure or ()))
            captured_cell = cells.get("captured_test_methods")
            if captured_cell is None:
                raise RuntimeError("closure-backed test authority is not exposed")
            captured = captured_cell.cell_contents

            defaults = function.__defaults__
            default = defaults[0]
            forged_state = (
                (defaults, ((default, default.__code__),)),
                None,
                None,
                function.__globals__,
                (),
            )
            captured[Mandatory{nonce}]["test_must_fail"] = (
                function,
                function.__code__,
                forged_state,
            )
            """,
            False,
        ),
        Case(
            "transient-testcase-run-forgery",
            f"""
            import unittest

            class Transient{nonce}(unittest.TestCase):
                def test_00_install_transient_run_override(self):
                    reviewed_run = unittest.TestCase.run

                    def forged_run(test, result=None):
                        if test._testMethodName == "test_01_must_fail":
                            if result is None:
                                result = test.defaultTestResult()
                            result.startTest(test)
                            try:
                                result.addSuccess(test)
                            finally:
                                result.stopTest(test)
                                unittest.TestCase.run = reviewed_run
                            return result
                        return reviewed_run(test, result)

                    unittest.TestCase.run = forged_run

                def test_01_must_fail(self):
                    self.fail({fail!r})
            """,
            False,
        ),
        Case(
            "testcase-call-dispatch-forgery",
            f"""
            import unittest

            class CallDispatch{nonce}(unittest.TestCase):
                def __call__(self, result=None):
                    if result is None:
                        result = self.defaultTestResult()
                    result.startTest(self)
                    try:
                        result.addSuccess(self)
                    finally:
                        result.stopTest(self)
                    return result

                def test_must_fail(self):
                    self.fail({fail!r})
            """,
            False,
        ),
        Case(
            "testsuite-call-dispatch-forgery",
            f"""
            import unittest

            class Mandatory{nonce}(unittest.TestCase):
                def test_must_fail(self):
                    self.fail({fail!r})

            class ForgedSuite{nonce}(unittest.TestSuite):
                def __call__(self, result, debug=False):
                    for test in self:
                        result.startTest(test)
                        try:
                            result.addSuccess(test)
                        finally:
                            result.stopTest(test)
                    return result

            def load_tests(loader, tests, pattern):
                return ForgedSuite{nonce}([Mandatory{nonce}("test_must_fail")])
            """,
            False,
        ),
        Case(
            "result-ledger-erasure",
            f"""
            import unittest

            class Mandatory{nonce}(unittest.TestCase):
                def test_must_fail(self):
                    self.fail({fail!r})

                def tearDown(self):
                    outcome = getattr(self, "_outcome", None)
                    result = getattr(outcome, "result", None)
                    if result is not None:
                        for name in ("failures", "errors"):
                            value = getattr(result, name, None)
                            if isinstance(value, list):
                                value.clear()
                        passed = getattr(result, "passed_ids", None)
                        if isinstance(passed, list):
                            passed.append(self.id())
            """,
            False,
        ),
        Case(
            "frame-introspection",
            f"""
            import sys
            import unittest

            frame = sys._getframe()
            while frame is not None:
                frame = frame.f_back

            class Mandatory{nonce}(unittest.TestCase):
                def test_must_fail(self):
                    self.fail({fail!r})
            """,
            False,
        ),
        Case(
            "native-frame-introspection",
            f"""
            import ctypes
            import unittest

            get_frame = ctypes.pythonapi.PyEval_GetFrame
            get_frame.restype = ctypes.py_object
            _ = get_frame()

            class Mandatory{nonce}(unittest.TestCase):
                def test_must_fail(self):
                    self.fail({fail!r})
            """,
            False,
        ),
        Case(
            "signal-frame-registration",
            f"""
            import signal
            import unittest

            def handler(signum, frame):
                return None

            signal.signal(signal.SIGUSR1, handler)

            class Mandatory{nonce}(unittest.TestCase):
                def test_must_fail(self):
                    self.fail({fail!r})
            """,
            False,
        ),
        Case(
            "test-method-rebind",
            f"""
            import unittest

            class Mandatory{nonce}(unittest.TestCase):
                def test_must_fail(self):
                    self.fail({fail!r})

            Mandatory{nonce}.test_must_fail = lambda self: None
            """,
            False,
        ),
        Case(
            "assertion-primitive-rebind",
            f"""
            import unittest

            class Mandatory{nonce}(unittest.TestCase):
                def test_must_fail(self):
                    self.fail({fail!r})

            unittest.TestCase.fail = lambda self, msg=None: None
            """,
            False,
        ),
        Case(
            "load-tests-drop",
            f"""
            import unittest

            class Mandatory{nonce}(unittest.TestCase):
                def test_visible(self):
                    self.assertTrue(True)

                def test_must_fail(self):
                    self.fail({fail!r})

            def load_tests(loader, tests, pattern):
                return unittest.TestSuite([Mandatory{nonce}("test_visible")])
            """,
            False,
        ),
    )


def _sanitized_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in _ALLOWED_ENV and isinstance(value, str)
    }
    for name in _SECRET_ENV_NAMES:
        environment.pop(name, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONWARNINGS"] = "error"
    return environment


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, 9)
    except ProcessLookupError:
        pass
    process.wait()


def _bounded_run(
    command: list[str],
    *,
    cwd: pathlib.Path,
    timeout_seconds: int,
) -> tuple[int, bytes, bytes, float]:
    started = time.monotonic()
    deadline = started + timeout_seconds
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_sanitized_environment(),
        close_fds=True,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        _terminate_group(process)
        raise RuntimeError("candidate authority output channels are unavailable")

    streams = selectors.DefaultSelector()
    output_parts: list[bytes] = []
    error_parts: list[bytes] = []
    total = 0
    try:
        for pipe, target in ((process.stdout, output_parts), (process.stderr, error_parts)):
            os.set_blocking(pipe.fileno(), False)
            streams.register(pipe, selectors.EVENT_READ, target)

        while streams.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_group(process)
                raise RuntimeError("candidate authority case exceeded runtime ceiling")
            events = streams.select(timeout=min(remaining, 0.25))
            if not events:
                if process.poll() is None:
                    continue
                events = [
                    (key, selectors.EVENT_READ)
                    for key in list(streams.get_map().values())
                ]
            for key, _ in events:
                pipe = key.fileobj
                target = key.data
                try:
                    chunk = os.read(pipe.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    streams.unregister(pipe)
                    continue
                target.append(chunk)
                total += len(chunk)
                if total > _MAX_OUTPUT_BYTES:
                    _terminate_group(process)
                    raise RuntimeError("candidate authority case exceeded output ceiling")

        remaining = deadline - time.monotonic()
        if remaining <= 0 and process.poll() is None:
            _terminate_group(process)
            raise RuntimeError("candidate authority case exceeded runtime ceiling")
        try:
            returncode = process.wait(timeout=max(0.001, remaining))
        except subprocess.TimeoutExpired:
            _terminate_group(process)
            raise RuntimeError("candidate authority case exceeded runtime ceiling")
    finally:
        streams.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            _terminate_group(process)

    elapsed = time.monotonic() - started
    return returncode, b"".join(output_parts), b"".join(error_parts), elapsed


def verify(
    *,
    runner_root: pathlib.Path,
    entrypoint: str,
    python_executable: pathlib.Path,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    runner = _assert_runner_bundle(runner_root, entrypoint)
    python_executable = python_executable.resolve(strict=True)
    _read_regular(python_executable, 64 * 1024 * 1024, "Python executable")
    if timeout_seconds < 1 or timeout_seconds > 120:
        raise RuntimeError("timeout is outside policy")

    case_reports: list[dict[str, object]] = []
    accepted_attacks: list[str] = []
    rejected_clean: list[str] = []
    with tempfile.TemporaryDirectory(prefix="candidate-authority-") as directory:
        base = pathlib.Path(directory)
        for index, case in enumerate(_fixture_cases()):
            project = base / f"case-{index:02d}"
            tests = project / "tests"
            tests.mkdir(parents=True)
            source = textwrap.dedent(case.source).lstrip()
            fixture = tests / f"test_authority_{index:02d}.py"
            fixture.write_text(source, encoding="utf-8")
            fixture.chmod(0o444)
            tests.chmod(0o555)
            project.chmod(0o555)

            returncode, output, errors, elapsed = _bounded_run(
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
            passed = observed_zero == case.expect_zero
            if case.expect_zero and not observed_zero:
                rejected_clean.append(case.name)
            if not case.expect_zero and observed_zero:
                accepted_attacks.append(case.name)
            case_reports.append(
                {
                    "name": case.name,
                    "expected_zero": case.expect_zero,
                    "returncode": returncode,
                    "passed": passed,
                    "stdout_bytes": len(output),
                    "stderr_bytes": len(errors),
                    "elapsed_ms": int(elapsed * 1000),
                }
            )

    report: dict[str, object] = {
        "schema": _SCHEMA,
        "runner_entrypoint": entrypoint,
        "case_count": len(case_reports),
        "accepted_attacks": sorted(accepted_attacks),
        "rejected_clean": sorted(rejected_clean),
        "passed": not accepted_attacks and not rejected_clean,
        "cases": case_reports,
    }
    return report


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner-root", type=pathlib.Path, required=True)
    parser.add_argument("--entrypoint", default="isolated_unittest_runner.py")
    parser.add_argument(
        "--python",
        dest="python_executable",
        type=pathlib.Path,
        default=pathlib.Path(sys.executable),
    )
    parser.add_argument("--timeout-seconds", type=int, default=_DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args(argv)

    try:
        report = verify(
            runner_root=args.runner_root,
            entrypoint=args.entrypoint,
            python_executable=args.python_executable,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    rendered = _canonical_json(report)
    if args.report is not None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
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
