from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import verify_terminal_attestation_process_creation as process_creation


PREFIX = r'''
import builtins
import operator
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


FUNCTION_GLOBALS_SUBSCRIPT_REBIND = PREFIX + r'''
def _rebind():
    _rebind.__globals__["_Mutator"] = _replacement
''' + ATTESTOR


ALIASED_FUNCTION_GLOBALS_UPDATE_REBIND = PREFIX + r'''
def _rebind():
    helper = _replacement
    namespace = helper.__globals__
    namespace.update({"_Mutator": _replacement})
''' + ATTESTOR


REFLECTED_FUNCTION_GLOBALS_SETITEM_REBIND = PREFIX + r'''
def _rebind():
    namespace = getattr(_replacement, "__globals__")
    operator.setitem(namespace, "_Mutator", _replacement)
''' + ATTESTOR


BUILTINS_FUNCTION_GLOBALS_REBIND = PREFIX + r'''
def _rebind():
    namespace = _run_worker.__globals__
    setter = namespace.__setitem__
    setter("_Mutator", _replacement)
''' + ATTESTOR


class TerminalAttestationFunctionGlobalsNamespaceTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return process_creation.verify(root)

    def _assert_class_replacement_rejected(self, source: str) -> None:
        report = self._verify(source)
        self.assertFalse(report["passed"], report)
        kinds = {str(item["kind"]) for item in report["findings"]}
        self.assertIn("alternate-process-creation-call", kinds, report)

    def test_function_dunder_globals_subscript_rebind_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(FUNCTION_GLOBALS_SUBSCRIPT_REBIND)

    def test_aliased_function_dunder_globals_update_rebind_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(ALIASED_FUNCTION_GLOBALS_UPDATE_REBIND)

    def test_reflected_function_dunder_globals_setitem_rebind_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(REFLECTED_FUNCTION_GLOBALS_SETITEM_REBIND)

    def test_bound_setitem_on_function_dunder_globals_rebind_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(BUILTINS_FUNCTION_GLOBALS_REBIND)


if __name__ == "__main__":
    unittest.main()
