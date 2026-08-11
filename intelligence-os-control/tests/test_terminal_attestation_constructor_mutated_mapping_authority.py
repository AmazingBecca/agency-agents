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
    holder = _Holder(**options)
    helper_name = "".join(("_spawn", "_shadow"))
    holder._resolver(sys.modules[__name__], helper_name)()
    return_code = candidate.wait()
    _write_all(ready_fd, b"candidate-exited\n")
    token = os.read(challenge_fd, 32)
    _write_all(receipt_fd, token)
    return return_code
"""

SUBSCRIPT_WRITE_ATTACK = PREFIX + r"""
    options = {}
    options["resolver"] = _reflection_factory()
""" + SUFFIX

UPDATE_ATTACK = PREFIX + r"""
    options = {}
    options.update({"resolver": _reflection_factory()})
""" + SUFFIX

SETDEFAULT_ATTACK = PREFIX + r"""
    options = {}
    options.setdefault("resolver", _reflection_factory())
""" + SUFFIX

DUNDER_SETITEM_ATTACK = PREFIX + r"""
    options = {}
    options.__setitem__("resolver", _reflection_factory())
""" + SUFFIX

INPLACE_UNION_ATTACK = PREFIX + r"""
    options = {}
    options |= {"resolver": _reflection_factory()}
""" + SUFFIX

RUNTIME_KEY_SUBSCRIPT_ATTACK = PREFIX + r"""
    options = {}
    key = "RESOLVER".lower()
    options[key] = _reflection_factory()
""" + SUFFIX

RUNTIME_KEY_UPDATE_ATTACK = PREFIX + r"""
    options = {}
    key = "RESOLVER".lower()
    options.update({key: _reflection_factory()})
""" + SUFFIX

ALIAS_BEFORE_SUBSCRIPT_ATTACK = PREFIX + r"""
    options = {}
    alias = options
    alias["resolver"] = _reflection_factory()
""" + SUFFIX

ALIAS_CHAIN_BEFORE_UPDATE_ATTACK = PREFIX + r"""
    options = {}
    first = options
    second = first
    second.update({"resolver": _reflection_factory()})
""" + SUFFIX


class TerminalAttestationConstructorMutatedMappingAuthorityTests(unittest.TestCase):
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

    def test_canonical_secure_remains_accepted(self) -> None:
        self.assertTrue(self._verify(SECURE)["passed"])

    def test_subscript_write_cannot_launder_constructor_authority(self) -> None:
        self._assert_rejected(SUBSCRIPT_WRITE_ATTACK)

    def test_update_cannot_launder_constructor_authority(self) -> None:
        self._assert_rejected(UPDATE_ATTACK)

    def test_setdefault_cannot_launder_constructor_authority(self) -> None:
        self._assert_rejected(SETDEFAULT_ATTACK)

    def test_dunder_setitem_cannot_launder_constructor_authority(self) -> None:
        self._assert_rejected(DUNDER_SETITEM_ATTACK)

    def test_inplace_union_cannot_launder_constructor_authority(self) -> None:
        self._assert_rejected(INPLACE_UNION_ATTACK)

    def test_runtime_key_subscript_write_fails_closed(self) -> None:
        self._assert_rejected(RUNTIME_KEY_SUBSCRIPT_ATTACK)

    def test_runtime_key_update_fails_closed(self) -> None:
        self._assert_rejected(RUNTIME_KEY_UPDATE_ATTACK)

    def test_alias_before_subscript_write_cannot_hide_mapping_authority(self) -> None:
        self._assert_rejected(ALIAS_BEFORE_SUBSCRIPT_ATTACK)

    def test_alias_chain_before_update_cannot_hide_mapping_authority(self) -> None:
        self._assert_rejected(ALIAS_CHAIN_BEFORE_UPDATE_ATTACK)


if __name__ == "__main__":
    unittest.main()
