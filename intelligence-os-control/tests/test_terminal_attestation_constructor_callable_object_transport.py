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
"""


SUFFIX = r"""

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


CALLABLE_OBJECT_ATTACK = PREFIX + r"""

class _Mutator:
    def __init__(self, carrier):
        self._carrier = carrier

    def __call__(self, **values):
        self._carrier.update(**values)
""" + SUFFIX


FACTORY_RETURNED_CALLABLE_OBJECT_ATTACK = PREFIX + r"""

class _Mutator:
    def __init__(self, carrier):
        self._carrier = carrier

    def __call__(self, **values):
        self._carrier.update(**values)


def _mutator_factory(carrier):
    return _Mutator(carrier)
""" + SUFFIX.replace(
    "    mutator = _Mutator(carrier)\n",
    "    mutator = _mutator_factory(carrier)\n",
)


DESCRIPTOR_PRODUCED_CALLABLE_ATTACK = PREFIX + r"""

class _UpdateDescriptor:
    def __get__(self, instance, owner):
        return instance._carrier.update


class _Mutator:
    mutate = _UpdateDescriptor()

    def __init__(self, carrier):
        self._carrier = carrier

    def __call__(self, **values):
        self.mutate(**values)
""" + SUFFIX


INHERITED_CALLABLE_OBJECT_ATTACK = PREFIX + r"""

class _BaseMutator:
    def __init__(self, carrier):
        self._carrier = carrier

    def __call__(self, **values):
        self._carrier.update(**values)


class _Mutator(_BaseMutator):
    pass
""" + SUFFIX


FACTORY_ALIAS_RETURNED_CALLABLE_OBJECT_ATTACK = PREFIX + r"""

class _Mutator:
    def __init__(self, carrier):
        self._carrier = carrier

    def __call__(self, **values):
        self._carrier.update(**values)


def _mutator_factory(carrier):
    mutator = _Mutator(carrier)
    return mutator
""" + SUFFIX.replace(
    "    mutator = _Mutator(carrier)\n",
    "    mutator = _mutator_factory(carrier)\n",
)


CONTAINER_CARRIED_CALLABLE_OBJECT_ATTACK = PREFIX + r"""

class _Mutator:
    def __init__(self, carrier):
        self._carrier = carrier

    def __call__(self, **values):
        self._carrier.update(**values)
""" + SUFFIX.replace(
    "    mutator = _Mutator(carrier)\n",
    "    mutator = [_Mutator(carrier)][0]\n",
)


class TerminalAttestationConstructorCallableObjectTransportTests(unittest.TestCase):
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

    def test_callable_object_cannot_hide_mapping_transport(self) -> None:
        self._assert_rejected(CALLABLE_OBJECT_ATTACK)

    def test_factory_returned_callable_object_cannot_hide_mapping_transport(self) -> None:
        self._assert_rejected(FACTORY_RETURNED_CALLABLE_OBJECT_ATTACK)

    def test_descriptor_produced_callable_cannot_hide_mapping_transport(self) -> None:
        self._assert_rejected(DESCRIPTOR_PRODUCED_CALLABLE_ATTACK)

    def test_inherited_callable_object_cannot_hide_mapping_transport(self) -> None:
        self._assert_rejected(INHERITED_CALLABLE_OBJECT_ATTACK)

    def test_factory_alias_returned_callable_object_cannot_hide_mapping_transport(self) -> None:
        self._assert_rejected(FACTORY_ALIAS_RETURNED_CALLABLE_OBJECT_ATTACK)

    def test_container_carried_callable_object_cannot_hide_mapping_transport(self) -> None:
        self._assert_rejected(CONTAINER_CARRIED_CALLABLE_OBJECT_ATTACK)


if __name__ == "__main__":
    unittest.main()
