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

HELPER = (
    "\ndef _spawn_shadow():\n"
    "    return os.fork()\n"
    "\ndef _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):\n"
)


class TerminalAttestationComputedHelperRecoveryTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return process_creation.verify(root)

    def _with_helper(self, body: str) -> str:
        return SECURE.replace(
            "\ndef _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):\n",
            HELPER,
        ).replace(
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

    def test_local_concatenation_getattr_keeps_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    helper_name = '_spawn' + '_shadow'\n"
                "    getattr(sys.modules[__name__], helper_name)()\n"
            )
        )

    def test_chained_local_constants_keep_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    prefix = '_spawn'\n"
                "    suffix = '_shadow'\n"
                "    helper_name = prefix + suffix\n"
                "    getattr(sys.modules[__name__], helper_name)()\n"
            )
        )

    def test_fstring_local_constants_keep_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    prefix = '_spawn'\n"
                "    suffix = '_shadow'\n"
                "    helper_name = f'{prefix}{suffix}'\n"
                "    getattr(sys.modules[__name__], helper_name)()\n"
            )
        )

    def test_local_module_dict_subscript_keeps_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    helper_name = '_spawn' + '_shadow'\n"
                "    sys.modules[__name__].__dict__[helper_name]()\n"
            )
        )

    def test_local_operator_attrgetter_keeps_helper_reachable(self) -> None:
        source = self._with_helper(
            "    helper_name = '_spawn' + '_shadow'\n"
            "    operator.attrgetter(helper_name)(sys.modules[__name__])()\n"
        ).replace("import os\n", "import os\nimport operator\n")
        self.assertProcessHelperRejected(source)

    def test_imported_attrgetter_alias_keeps_helper_reachable(self) -> None:
        source = self._with_helper(
            "    helper_name = '_spawn' + '_shadow'\n"
            "    pick(helper_name)(sys.modules[__name__])()\n"
        ).replace("import os\n", "import os\nfrom operator import attrgetter as pick\n")
        self.assertProcessHelperRejected(source)

    def test_unresolved_reflection_fails_closed_to_all_helpers(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    getattr(sys.modules[__name__], helper_name)()\n"
            )
        )

    def test_unresolved_name_through_getattr_alias_fails_closed(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    reflect = getattr\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    reflect(sys.modules[__name__], helper_name)()\n"
            )
        )

    def test_unresolved_name_through_namespace_alias_fails_closed(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    registry = sys.modules[__name__].__dict__\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    registry[helper_name]()\n"
            )
        )

    def test_unresolved_name_through_namespace_get_fails_closed(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    registry = sys.modules[__name__].__dict__\n"
                "    helper_name = ''.join(('_spawn', '_shadow'))\n"
                "    registry.get(helper_name)()\n"
            )
        )

    def test_unresolved_name_through_operator_getitem_fails_closed(self) -> None:
        source = self._with_helper(
            "    registry = sys.modules[__name__].__dict__\n"
            "    helper_name = ''.join(('_spawn', '_shadow'))\n"
            "    operator.getitem(registry, helper_name)()\n"
        ).replace("import os\n", "import os\nimport operator\n")
        self.assertProcessHelperRejected(source)

    def test_branch_reassignment_does_not_erase_helper_possibility(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    helper_name = '_spawn_shadow'\n"
                "    if project_root:\n"
                "        helper_name = '_benign'\n"
                "    getattr(sys.modules[__name__], helper_name)()\n"
            )
        )


if __name__ == "__main__":
    unittest.main()
