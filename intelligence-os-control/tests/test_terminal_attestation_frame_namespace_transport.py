from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import verify_terminal_attestation_process_creation as process_creation


PREFIX = r'''
import inspect
import operator
import sys

class _Mutator:
    pass

def _replacement():
    return None
'''

ATTESTOR = r'''
def _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):
    _rebind()
    return 0
'''

HELPER_RETURNED_F_GLOBALS = PREFIX + r'''
def _live_namespace():
    return sys._getframe().f_globals

def _rebind():
    namespace = _live_namespace()
    namespace["_Mutator"] = _replacement
''' + ATTESTOR

HELPER_CONTAINER_PROJECTION = PREFIX + r'''
def _namespace_carrier():
    return (inspect.currentframe().f_globals, None)

def _rebind():
    carrier = _namespace_carrier()
    carrier[0]["_Mutator"] = _replacement
''' + ATTESTOR

ATTRGETTER_FRAME_GLOBALS = PREFIX + r'''
def _rebind():
    resolver = operator.attrgetter("f_globals")
    namespace = resolver(sys._getframe())
    namespace["_Mutator"] = _replacement
''' + ATTESTOR

HELPER_TO_HELPER_FRAME_GLOBALS = PREFIX + r'''
def _frame():
    return inspect.currentframe()

def _live_namespace():
    return _frame().f_globals

def _rebind():
    namespace = _live_namespace()
    namespace["_Mutator"] = _replacement
''' + ATTESTOR

BOUND_GETATTRIBUTE_HELPER = PREFIX + r'''
def _live_namespace():
    frame = inspect.currentframe()
    return frame.__getattribute__("f_globals")

def _rebind():
    namespace = _live_namespace()
    namespace["_Mutator"] = _replacement
''' + ATTESTOR


class TerminalAttestationFrameNamespaceTransportTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return process_creation.verify(root)

    def _assert_namespace_rebind_detected(self, source: str) -> None:
        report = self._verify(source)
        details = [str(item.get("detail", "")) for item in report.get("findings", [])]
        self.assertTrue(any("module namespace" in detail and "_Mutator" in detail for detail in details), report)

    def test_helper_returned_f_globals_is_detected(self) -> None:
        self._assert_namespace_rebind_detected(HELPER_RETURNED_F_GLOBALS)

    def test_helper_container_projection_of_f_globals_is_detected(self) -> None:
        self._assert_namespace_rebind_detected(HELPER_CONTAINER_PROJECTION)

    def test_operator_attrgetter_f_globals_is_detected(self) -> None:
        self._assert_namespace_rebind_detected(ATTRGETTER_FRAME_GLOBALS)

    def test_helper_to_helper_f_globals_is_detected(self) -> None:
        self._assert_namespace_rebind_detected(HELPER_TO_HELPER_FRAME_GLOBALS)

    def test_bound_getattribute_helper_is_detected(self) -> None:
        self._assert_namespace_rebind_detected(BOUND_GETATTRIBUTE_HELPER)


if __name__ == "__main__":
    unittest.main()
