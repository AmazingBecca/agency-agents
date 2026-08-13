from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import verify_terminal_attestation_process_creation as process_creation


SECURE = r"""
import os
import subprocess
import sys


def _load_worker():
    raise NotImplementedError


def _write_all(fd, payload):
    os.write(fd, payload)


def _run_worker(project_root, pattern):
    worker = _load_worker()
    return worker._run(project_root, pattern)


def _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):
    candidate = subprocess.Popen(
        [sys.executable, "-I", __file__, "--worker"],
        close_fds=True,
    )
    return_code = candidate.wait()
    _write_all(ready_fd, b"candidate-exited\n")
    token = os.read(challenge_fd, 32)
    _write_all(receipt_fd, token)
    return return_code
"""

STATIC_KWARGS_ATTACK = r"""
import os
import subprocess
import sys


def _load_worker():
    raise NotImplementedError


def _write_all(fd, payload):
    os.write(fd, payload)


def _run_worker(project_root, pattern):
    worker = _load_worker()
    return worker._run(project_root, pattern)


def _reflection_factory():
    return getattr


class _Holder:
    def __init__(self, *, resolver):
        self._resolver = resolver


def _spawn_shadow():
    return os.fork()


def _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):
    candidate = subprocess.Popen(
        [sys.executable, "-I", __file__, "--worker"],
        close_fds=True,
    )
    holder = _Holder(**{"resolver": _reflection_factory()})
    helper_name = "".join(("_spawn", "_shadow"))
    holder._resolver(sys.modules[__name__], helper_name)()
    return_code = candidate.wait()
    _write_all(ready_fd, b"candidate-exited\n")
    token = os.read(challenge_fd, 32)
    _write_all(receipt_fd, token)
    return return_code
"""

ALIASED_KWARGS_ATTACK = r"""
import os
import subprocess
import sys


def _load_worker():
    raise NotImplementedError


def _write_all(fd, payload):
    os.write(fd, payload)


def _run_worker(project_root, pattern):
    worker = _load_worker()
    return worker._run(project_root, pattern)


def _reflection_factory():
    return getattr


class _Holder:
    def __init__(self, *, resolver):
        self._resolver = resolver


def _spawn_shadow():
    return os.fork()


def _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):
    candidate = subprocess.Popen(
        [sys.executable, "-I", __file__, "--worker"],
        close_fds=True,
    )
    options = {"resolver": _reflection_factory()}
    holder = _Holder(**options)
    helper_name = "".join(("_spawn", "_shadow"))
    holder._resolver(sys.modules[__name__], helper_name)()
    return_code = candidate.wait()
    _write_all(ready_fd, b"candidate-exited\n")
    token = os.read(challenge_fd, 32)
    _write_all(receipt_fd, token)
    return return_code
"""


class TerminalAttestationConstructorKwargsUnpackAuthorityTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return process_creation.verify(root)

    def _assert_rejected_resolver_dispatch(self, source: str) -> None:
        report = self._verify(source)
        self.assertFalse(report["passed"], report)
        findings = report["findings"]
        self.assertIsInstance(findings, list)
        kinds = {str(item["kind"]) for item in findings}
        self.assertIn("alternate-process-creation-call", kinds, report)
        details = "\n".join(str(item["detail"]) for item in findings)
        self.assertIn("holder._resolver", details)

    def test_canonical_secure_remains_accepted(self) -> None:
        report = self._verify(SECURE)
        self.assertTrue(report["passed"], report)

    def test_static_kwargs_unpack_cannot_launder_constructor_authority(self) -> None:
        self._assert_rejected_resolver_dispatch(STATIC_KWARGS_ATTACK)

    def test_aliased_static_kwargs_cannot_launder_constructor_authority(self) -> None:
        self._assert_rejected_resolver_dispatch(ALIASED_KWARGS_ATTACK)


if __name__ == "__main__":
    unittest.main()
