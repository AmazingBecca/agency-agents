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

DICT_KEYWORD_CONSTRUCTOR_ALIAS_ATTACK = PREFIX + r"""
    options = {}
    carrier = dict(settings=options)
    alias = carrier["settings"]
    alias["resolver"] = _reflection_factory()
""" + SUFFIX

DICT_PAIR_SEQUENCE_CONSTRUCTOR_ALIAS_ATTACK = PREFIX + r"""
    options = {}
    carrier = dict([("settings", options)])
    alias = carrier["settings"]
    alias["resolver"] = _reflection_factory()
""" + SUFFIX

DICT_GET_ALIAS_ATTACK = PREFIX + r"""
    options = {}
    carrier = {"settings": options}
    alias = carrier.get("settings")
    alias["resolver"] = _reflection_factory()
""" + SUFFIX

NESTED_CONTAINER_PROJECTION_ALIAS_ATTACK = PREFIX + r"""
    options = {}
    carrier = {"settings": [options]}
    alias = carrier["settings"][0]
    alias["resolver"] = _reflection_factory()
""" + SUFFIX

SUBSCRIPT_INSERT_ALIAS_ATTACK = PREFIX + r"""
    options = {}
    carrier = {}
    carrier["settings"] = options
    alias = carrier["settings"]
    alias["resolver"] = _reflection_factory()
""" + SUFFIX

UPDATE_INSERT_ALIAS_ATTACK = PREFIX + r"""
    options = {}
    carrier = {}
    carrier.update(settings=options)
    alias = carrier["settings"]
    alias["resolver"] = _reflection_factory()
""" + SUFFIX

SETDEFAULT_RETURN_ALIAS_ATTACK = PREFIX + r"""
    options = {}
    carrier = {}
    alias = carrier.setdefault("settings", options)
    alias["resolver"] = _reflection_factory()
""" + SUFFIX


class TerminalAttestationConstructorProjectionCallAuthorityTests(unittest.TestCase):
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

    def test_dict_keyword_constructor_cannot_hide_mapping_identity(self) -> None:
        self._assert_rejected(DICT_KEYWORD_CONSTRUCTOR_ALIAS_ATTACK)

    def test_dict_pair_sequence_constructor_cannot_hide_mapping_identity(self) -> None:
        self._assert_rejected(DICT_PAIR_SEQUENCE_CONSTRUCTOR_ALIAS_ATTACK)

    def test_dict_get_cannot_hide_mapping_identity(self) -> None:
        self._assert_rejected(DICT_GET_ALIAS_ATTACK)

    def test_nested_container_projection_cannot_hide_mapping_identity(self) -> None:
        self._assert_rejected(NESTED_CONTAINER_PROJECTION_ALIAS_ATTACK)

    def test_subscript_insert_cannot_hide_mapping_identity(self) -> None:
        self._assert_rejected(SUBSCRIPT_INSERT_ALIAS_ATTACK)

    def test_update_insert_cannot_hide_mapping_identity(self) -> None:
        self._assert_rejected(UPDATE_INSERT_ALIAS_ATTACK)

    def test_setdefault_return_cannot_hide_mapping_identity(self) -> None:
        self._assert_rejected(SETDEFAULT_RETURN_ALIAS_ATTACK)


if __name__ == "__main__":
    unittest.main()
