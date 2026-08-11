from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import verify_terminal_attestation_process_creation as process_creation


PREFIX = r'''
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


HELPER_RETURNED_FUNCTION_GLOBALS_REBIND = PREFIX + r'''
def _live_namespace():
    return _replacement.__globals__


def _rebind():
    namespace = _live_namespace()
    namespace["_Mutator"] = _replacement
''' + ATTESTOR


HELPER_TUPLE_PROJECTED_FUNCTION_GLOBALS_REBIND = PREFIX + r'''
def _live_namespace():
    carrier = (_replacement.__globals__, None)
    return carrier[0]


def _rebind():
    namespace = _live_namespace()
    namespace["_Mutator"] = _replacement
''' + ATTESTOR


HELPER_DICT_PROJECTED_FUNCTION_GLOBALS_REBIND = PREFIX + r'''
def _live_namespace():
    carrier = {"live": _replacement.__globals__}
    return carrier.get("live")


def _rebind():
    namespace = _live_namespace()
    namespace.update({"_Mutator": _replacement})
''' + ATTESTOR


CONTAINER_TRANSPORTED_FUNCTION_GLOBALS_REBIND = PREFIX + r'''
def _rebind():
    carrier = (_replacement.__globals__,)
    namespace = carrier[0]
    namespace.update({"_Mutator": _replacement})
''' + ATTESTOR


CONDITIONAL_FUNCTION_GLOBALS_REBIND = PREFIX + r'''
def _rebind():
    namespace = _replacement.__globals__ if bool(1) else globals()
    namespace["_Mutator"] = _replacement
''' + ATTESTOR


PROJECTED_FUNCTION_GLOBALS_REBIND = PREFIX + r'''
def _rebind():
    carrier = {"namespace": _replacement.__globals__}
    namespace = carrier["namespace"]
    operator.setitem(namespace, "_Mutator", _replacement)
''' + ATTESTOR


class TerminalAttestationFunctionGlobalsTransportTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return process_creation.verify(root)

    def _assert_rejected(self, source: str) -> dict[str, object]:
        report = self._verify(source)
        self.assertFalse(report["passed"], report)
        self.assertGreater(int(report.get("finding_count", 0)), 0, report)
        return report

    def _assert_replacement_rejected(self, source: str) -> None:
        report = self._assert_rejected(source)
        kinds = {str(item["kind"]) for item in report["findings"]}
        self.assertIn("alternate-process-creation-call", kinds, report)

    def test_helper_returned_function_globals_rebind_is_rejected(self) -> None:
        self._assert_replacement_rejected(HELPER_RETURNED_FUNCTION_GLOBALS_REBIND)

    def test_helper_tuple_projected_function_globals_rebind_is_rejected(self) -> None:
        self._assert_replacement_rejected(HELPER_TUPLE_PROJECTED_FUNCTION_GLOBALS_REBIND)

    def test_helper_dict_projected_function_globals_rebind_is_rejected(self) -> None:
        self._assert_replacement_rejected(HELPER_DICT_PROJECTED_FUNCTION_GLOBALS_REBIND)

    def test_container_transported_function_globals_rebind_is_rejected(self) -> None:
        self._assert_rejected(CONTAINER_TRANSPORTED_FUNCTION_GLOBALS_REBIND)

    def test_conditional_function_globals_rebind_is_rejected(self) -> None:
        self._assert_rejected(CONDITIONAL_FUNCTION_GLOBALS_REBIND)

    def test_projected_function_globals_rebind_is_rejected(self) -> None:
        self._assert_rejected(PROJECTED_FUNCTION_GLOBALS_REBIND)


if __name__ == "__main__":
    unittest.main()
