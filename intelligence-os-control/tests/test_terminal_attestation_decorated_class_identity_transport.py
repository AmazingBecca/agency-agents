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


class _Holder:
    def __init__(self, *, resolver):
        self._resolver = resolver


def _reflection_factory():
    return getattr


def _spawn_shadow():
    return os.fork()


class _CallableMutator:
    def __init__(self, carrier):
        self._carrier = carrier

    def __call__(self, **values):
        self._carrier.update(**values)


def _replace_mutator(_class):
    def build(carrier):
        return _CallableMutator(carrier)
    return build


@_replace_mutator
class _Mutator:
    pass
"""


SUFFIX = r"""
    mutator(settings=options)
    alias = carrier["settings"]
    alias["resolver"] = _reflection_factory()
    holder = _Holder(**options)
    helper_name = "".join(("_spawn", "_shadow"))
    holder._resolver(sys.modules[__name__], helper_name)()
    return_code = candidate.wait()
    _write_all(ready_fd, b"candidate-exited\n")
    token = os.read(challenge_fd, 32)
    _write_all(receipt_fd, token)
    return return_code
"""


FACTORY_CONDITIONAL_CLASS_ATTACK = PREFIX + r"""


def _mutator_factory(flag=True):
    return _Mutator if flag else _Mutator


def _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):
    candidate = subprocess.Popen(
        [sys.executable, "-I", __file__, "--worker"],
        close_fds=True,
    )
    options = {}
    carrier = {}
    factory = _mutator_factory()
    mutator = factory(carrier)
""" + SUFFIX


GENERATOR_CARRIED_CLASS_ATTACK = PREFIX + r"""


def _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):
    candidate = subprocess.Popen(
        [sys.executable, "-I", __file__, "--worker"],
        close_fds=True,
    )
    options = {}
    carrier = {}
    factory = next(item for item in (_Mutator,))
    mutator = factory(carrier)
""" + SUFFIX


HELPER_CONTAINER_CLASS_ATTACK = PREFIX + r"""


def _mutator_box():
    return [_Mutator]


def _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):
    candidate = subprocess.Popen(
        [sys.executable, "-I", __file__, "--worker"],
        close_fds=True,
    )
    options = {}
    carrier = {}
    factory = _mutator_box()[0]
    mutator = factory(carrier)
""" + SUFFIX


TOP_LEVEL_CLASS_NAME_REBIND_ATTACK = r"""
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


class _Holder:
    def __init__(self, *, resolver):
        self._resolver = resolver


def _reflection_factory():
    return getattr


def _spawn_shadow():
    return os.fork()


class _CallableMutator:
    def __init__(self, carrier):
        self._carrier = carrier

    def __call__(self, **values):
        self._carrier.update(**values)


class _Mutator:
    pass


def _replacement(carrier):
    return _CallableMutator(carrier)


_Mutator = _replacement


def _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):
    candidate = subprocess.Popen(
        [sys.executable, "-I", __file__, "--worker"],
        close_fds=True,
    )
    options = {}
    carrier = {}
    mutator = _Mutator(carrier)
    mutator(settings=options)
    alias = carrier["settings"]
    alias["resolver"] = _reflection_factory()
    holder = _Holder(**options)
    helper_name = "".join(("_spawn", "_shadow"))
    holder._resolver(sys.modules[__name__], helper_name)()
    return_code = candidate.wait()
    _write_all(ready_fd, b"candidate-exited\n")
    token = os.read(challenge_fd, 32)
    _write_all(receipt_fd, token)
    return return_code
"""


class TerminalAttestationDecoratedClassIdentityTransportTests(unittest.TestCase):
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

    def test_factory_conditional_cannot_hide_decorated_class_identity(self) -> None:
        self._assert_rejected(FACTORY_CONDITIONAL_CLASS_ATTACK)

    def test_generator_cannot_hide_decorated_class_identity(self) -> None:
        self._assert_rejected(GENERATOR_CARRIED_CLASS_ATTACK)

    def test_helper_container_cannot_hide_decorated_class_identity(self) -> None:
        self._assert_rejected(HELPER_CONTAINER_CLASS_ATTACK)

    def test_top_level_rebind_cannot_replace_reviewed_class_identity(self) -> None:
        self._assert_rejected(TOP_LEVEL_CLASS_NAME_REBIND_ATTACK)


if __name__ == "__main__":
    unittest.main()
