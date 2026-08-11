from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import verify_terminal_attestation_process_creation as process_creation


PREFIX = r'''
import functools
import operator
import os
import subprocess
import sys
import types


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


MODULE_DUNDER_SETATTR_REBIND = PREFIX + r'''
def _rebind():
    module = sys.modules[__name__]
    module.__setattr__("_Mutator", _replacement)
''' + ATTESTOR


MODULETYPE_SETATTR_REBIND = PREFIX + r'''
def _rebind():
    module = sys.modules[__name__]
    types.ModuleType.__setattr__(module, "_Mutator", _replacement)
''' + ATTESTOR


REFLECTED_SETATTR_REBIND = PREFIX + r'''
def _rebind():
    module = sys.modules[__name__]
    setter = getattr(module, "__setattr__")
    setter("_Mutator", _replacement)
''' + ATTESTOR


PARTIAL_SETATTR_REBIND = PREFIX + r'''
def _rebind():
    setter = functools.partial(setattr, sys.modules[__name__], "_Mutator")
    setter(_replacement)
''' + ATTESTOR


NAMESPACE_UPDATE_REBIND = PREFIX + r'''
def _rebind():
    namespace = sys.modules[__name__].__dict__
    namespace.update({"_Mutator": _replacement})
''' + ATTESTOR


NAMESPACE_IOR_REBIND = PREFIX + r'''
def _rebind():
    namespace = sys.modules[__name__].__dict__
    namespace |= {"_Mutator": _replacement}
''' + ATTESTOR


VARS_UPDATE_REBIND = PREFIX + r'''
def _rebind():
    namespace = vars(sys.modules[__name__])
    namespace.update({"_" + "Mutator": _replacement})
''' + ATTESTOR


REFLECTED_UPDATE_REBIND = PREFIX + r'''
def _rebind():
    namespace = sys.modules[__name__].__dict__
    updater = getattr(namespace, "update")
    updater({"_Mutator": _replacement})
''' + ATTESTOR


PARTIAL_BOUND_DUNDER_SETATTR_REBIND = PREFIX + r'''
def _rebind():
    module = sys.modules[__name__]
    setter = functools.partial(module.__setattr__, "_Mutator")
    setter(_replacement)
''' + ATTESTOR


OPERATOR_IOR_REBIND = PREFIX + r'''
def _rebind():
    namespace = sys.modules[__name__].__dict__
    operator.ior(namespace, {"_Mutator": _replacement})
''' + ATTESTOR


class TerminalAttestationDecoratedClassModuleNamespaceMutationTests(unittest.TestCase):
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

    def test_module_dunder_setattr_rebind_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(MODULE_DUNDER_SETATTR_REBIND)

    def test_moduletype_setattr_rebind_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(MODULETYPE_SETATTR_REBIND)

    def test_reflected_setattr_rebind_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(REFLECTED_SETATTR_REBIND)

    def test_partial_setattr_rebind_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(PARTIAL_SETATTR_REBIND)

    def test_namespace_update_rebind_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(NAMESPACE_UPDATE_REBIND)

    def test_namespace_ior_rebind_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(NAMESPACE_IOR_REBIND)

    def test_vars_namespace_update_with_computed_key_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(VARS_UPDATE_REBIND)

    def test_reflected_namespace_update_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(REFLECTED_UPDATE_REBIND)

    def test_partial_bound_module_dunder_setattr_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(PARTIAL_BOUND_DUNDER_SETATTR_REBIND)

    def test_operator_ior_namespace_rebind_is_rejected(self) -> None:
        self._assert_class_replacement_rejected(OPERATOR_IOR_REBIND)


if __name__ == "__main__":
    unittest.main()
