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

HELPER_INSERT = (
    "\ndef _spawn_shadow():\n"
    "    return os.fork()\n"
    "\ndef _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):\n"
)


class TerminalAttestationCallableFactoryRecoveryTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return process_creation.verify(root)

    def _with_helper(self, declarations: str, body: str) -> str:
        source = SECURE.replace(
            "\ndef _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):\n",
            HELPER_INSERT,
        )
        source = source.replace(
            "\ndef _spawn_shadow():\n",
            declarations + "\ndef _spawn_shadow():\n",
        )
        return source.replace(
            "    return_code = candidate.wait()\n",
            body + "    return_code = candidate.wait()\n",
        )

    def assertProcessHelperRejected(self, source: str) -> None:
        report = self._verify(source)
        self.assertFalse(report["passed"], report)
        findings = report["findings"]
        self.assertIsInstance(findings, list)
        kinds = {str(item["kind"]) for item in findings}
        self.assertIn("alternate-process-creation-call", kinds, report)

    def test_canonical_secure_is_still_accepted(self) -> None:
        report = self._verify(SECURE)
        self.assertTrue(report["passed"], report)

    def test_factory_returning_getattr_keeps_process_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "\ndef _reflection_factory():\n"
                "    return getattr\n",
                "    reflect = _reflection_factory()\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    reflect(sys.modules[__name__], helper_name)()\n",
            )
        )

    def test_factory_returning_namespace_map_keeps_process_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "\ndef _namespace_factory():\n"
                "    return sys.modules[__name__].__dict__\n",
                "    registry = _namespace_factory()\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    registry[helper_name]()\n",
            )
        )

    def test_factory_returning_namespace_map_get_keeps_process_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "\ndef _namespace_factory():\n"
                "    return sys.modules[__name__].__dict__\n",
                "    registry = _namespace_factory()\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    registry.get(helper_name)()\n",
            )
        )

    def test_factory_returning_namespace_map_dunder_getitem_keeps_process_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "\ndef _namespace_factory():\n"
                "    return sys.modules[__name__].__dict__\n",
                "    registry = _namespace_factory()\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    registry.__getitem__(helper_name)()\n",
            )
        )

    def test_factory_returning_reflection_lambda_keeps_process_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "\ndef _reflection_factory():\n"
                "    return lambda target, name: getattr(target, name)\n",
                "    reflect = _reflection_factory()\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    reflect(sys.modules[__name__], helper_name)()\n",
            )
        )

    def test_partial_getattr_factory_keeps_process_helper_reachable(self) -> None:
        source = self._with_helper(
            "\ndef _reflection_factory():\n"
            "    return functools.partial(getattr, sys.modules[__name__])\n",
            "    reflect = _reflection_factory()\n"
            "    helper_name = ''.join(('_spawn', '_shadow'))\n"
            "    reflect(helper_name)()\n",
        ).replace("import os\n", "import os\nimport functools\n")
        self.assertProcessHelperRejected(source)

    def test_factory_return_stashed_in_container_keeps_process_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "\ndef _reflection_factory():\n"
                "    return getattr\n",
                "    reflect = _reflection_factory()\n"
                "    dispatch = [reflect]\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    dispatch[0](sys.modules[__name__], helper_name)()\n",
            )
        )

    def test_factory_return_stashed_on_object_keeps_process_helper_reachable(self) -> None:
        source = self._with_helper(
            "\ndef _reflection_factory():\n"
            "    return getattr\n",
            "    reflect = _reflection_factory()\n"
            "    holder = types.SimpleNamespace()\n"
            "    holder.reflect = reflect\n"
            "    helper_name = ''.join(('_spawn', '_shadow'))\n"
            "    holder.reflect(sys.modules[__name__], helper_name)()\n",
        ).replace("import sys\n", "import sys\nimport types\n")
        self.assertProcessHelperRejected(source)

    def test_bound_dunder_call_from_factory_return_keeps_process_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "\ndef _reflection_factory():\n"
                "    return getattr\n",
                "    reflect = _reflection_factory()\n"
                "    invoke = reflect.__call__\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    invoke(sys.modules[__name__], helper_name)()\n",
            )
        )

    def test_extracted_container_member_from_factory_return_keeps_process_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "\ndef _reflection_factory():\n"
                "    return getattr\n",
                "    reflect = _reflection_factory()\n"
                "    dispatch = [reflect]\n"
                "    invoke = dispatch[0]\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    invoke(sys.modules[__name__], helper_name)()\n",
            )
        )

    def test_bound_namespace_get_from_factory_return_keeps_process_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "\ndef _namespace_factory():\n"
                "    return sys.modules[__name__].__dict__\n",
                "    registry = _namespace_factory()\n"
                "    lookup = registry.get\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    lookup(helper_name)()\n",
            )
        )

    def test_tuple_unpacked_factory_return_keeps_process_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "\ndef _reflection_factory():\n"
                "    return getattr\n",
                "    reflect, = (_reflection_factory(),)\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    reflect(sys.modules[__name__], helper_name)()\n",
            )
        )

    def test_factory_return_wrapped_by_positional_constructor_keeps_process_helper_reachable(self) -> None:
        source = self._with_helper(
            "\ndef _reflection_factory():\n"
            "    return getattr\n",
            "    reflect = _reflection_factory()\n"
            "    dispatch = collections.deque([reflect])\n"
            "    helper_name = ''.join(('_spawn', '_shadow'))\n"
            "    dispatch[0](sys.modules[__name__], helper_name)()\n",
        ).replace("import os\n", "import os\nimport collections\n")
        self.assertProcessHelperRejected(source)


if __name__ == "__main__":
    unittest.main()
