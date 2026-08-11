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


PREFIX = r"""
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
"""

SUFFIX = r"""
    helper_name = "".join(("_spawn", "_shadow"))
    holder._resolver(sys.modules[__name__], helper_name)()
    return_code = candidate.wait()
    _write_all(ready_fd, b"candidate-exited\n")
    token = os.read(challenge_fd, 32)
    _write_all(receipt_fd, token)
    return return_code
"""

COMPUTED_KEY_ATTACK = PREFIX + r"""
    key = "reso" + "lver"
    options = {key: _reflection_factory()}
    holder = _Holder(**options)
""" + SUFFIX

FSTRING_KEY_ATTACK = PREFIX + r"""
    tail = "lver"
    key = f"reso{tail}"
    options = {key: _reflection_factory()}
    holder = _Holder(**options)
""" + SUFFIX

DICT_PAIR_ATTACK = PREFIX + r"""
    options = dict([("resolver", _reflection_factory())])
    holder = _Holder(**options)
""" + SUFFIX


class TerminalAttestationConstructorComputedMappingAuthorityTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return process_creation.verify(root)

    def _assert_rejected(self, source: str) -> None:
        report = self._verify(source)
        self.assertFalse(report["passed"], report)
        findings = report["findings"]
        self.assertIsInstance(findings, list)
        kinds = {str(item["kind"]) for item in findings}
        self.assertIn("alternate-process-creation-call", kinds, report)
        details = "\n".join(str(item["detail"]) for item in findings)
        self.assertIn("holder._resolver", details)

    def test_canonical_secure_remains_accepted(self) -> None:
        self.assertTrue(self._verify(SECURE)["passed"])

    def test_computed_constant_mapping_key_cannot_launder_constructor_authority(self) -> None:
        self._assert_rejected(COMPUTED_KEY_ATTACK)

    def test_fstring_constant_mapping_key_cannot_launder_constructor_authority(self) -> None:
        self._assert_rejected(FSTRING_KEY_ATTACK)

    def test_dict_pair_sequence_cannot_launder_constructor_authority(self) -> None:
        self._assert_rejected(DICT_PAIR_ATTACK)


if __name__ == "__main__":
    unittest.main()
