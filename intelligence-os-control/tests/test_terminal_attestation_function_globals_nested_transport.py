from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import verify_terminal_attestation_process_creation as process_creation


PREFIX = r'''
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


NESTED_HELPER_CONTAINER_REBIND = PREFIX + r'''
def _live_namespace_carrier():
    return {"outer": ((_replacement.__globals__,),)}


def _rebind():
    carrier = _live_namespace_carrier()
    namespace = carrier["outer"][0][0]
    namespace["_Mutator"] = _replacement
''' + ATTESTOR


HELPER_TO_HELPER_PROJECTED_REBIND = PREFIX + r'''
def _inner_carrier():
    return {"live": _replacement.__globals__}


def _live_namespace():
    carrier = _inner_carrier()
    return carrier["live"]


def _rebind():
    namespace = _live_namespace()
    namespace["_Mutator"] = _replacement
''' + ATTESTOR


DESTRUCTURED_HELPER_ALIAS_REBIND = PREFIX + r'''
def _live_namespace():
    carrier = (_replacement.__globals__, None)
    namespace, *_rest = carrier
    return namespace


def _rebind():
    namespace = _live_namespace()
    namespace["_Mutator"] = _replacement
''' + ATTESTOR


class TerminalAttestationFunctionGlobalsNestedTransportTests(unittest.TestCase):
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

    def test_nested_helper_container_rebind_is_rejected(self) -> None:
        self._assert_replacement_rejected(NESTED_HELPER_CONTAINER_REBIND)

    def test_helper_to_helper_projected_rebind_is_rejected(self) -> None:
        self._assert_replacement_rejected(HELPER_TO_HELPER_PROJECTED_REBIND)

    def test_destructured_helper_alias_rebind_is_rejected(self) -> None:
        self._assert_replacement_rejected(DESTRUCTURED_HELPER_ALIAS_REBIND)


if __name__ == "__main__":
    unittest.main()
