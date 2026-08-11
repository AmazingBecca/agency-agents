from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import verify_terminal_attestation_process_creation as process_creation


PREFIX = r'''
import inspect
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
'''


ATTESTOR = r'''


def _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):
    _rebind()
    candidate = subprocess.Popen([sys.executable, "-I", __file__, "--worker"], close_fds=True)
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
'''


SYS_GETFRAME_REBIND = PREFIX + r'''
def _rebind():
    namespace = sys._getframe().f_globals
    namespace["_Mutator"] = _replacement
''' + ATTESTOR


INSPECT_CURRENTFRAME_REBIND = PREFIX + r'''
def _rebind():
    namespace = inspect.currentframe().f_globals
    namespace["_Mutator"] = _replacement
''' + ATTESTOR


OBJECT_GETATTRIBUTE_GLOBALS_REBIND = PREFIX + r'''
def _rebind():
    namespace = object.__getattribute__(_replacement, "__globals__")
    namespace["_Mutator"] = _replacement
''' + ATTESTOR


class TerminalAttestationFrameNamespaceAuthorityTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return process_creation.verify(root)

    def _assert_replacement_rejected(self, source: str) -> None:
        report = self._verify(source)
        self.assertFalse(report["passed"], report)
        self.assertGreater(int(report.get("finding_count", 0)), 0, report)
        kinds = {str(item["kind"]) for item in report["findings"]}
        self.assertIn("alternate-process-creation-call", kinds, report)

    def test_sys_getframe_globals_rebind_is_rejected(self) -> None:
        self._assert_replacement_rejected(SYS_GETFRAME_REBIND)

    def test_inspect_currentframe_globals_rebind_is_rejected(self) -> None:
        self._assert_replacement_rejected(INSPECT_CURRENTFRAME_REBIND)

    def test_object_getattribute_function_globals_rebind_is_rejected(self) -> None:
        self._assert_replacement_rejected(OBJECT_GETATTRIBUTE_GLOBALS_REBIND)


if __name__ == "__main__":
    unittest.main()
