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


class TerminalAttestationReflectedHelperRecoveryTests(unittest.TestCase):
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

    def test_module_attribute_recovery_keeps_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    sys.modules[__name__]._spawn_shadow()\n"
            )
        )

    def test_module_getattr_recovery_keeps_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    getattr(sys.modules[__name__], '_spawn' + '_shadow')()\n"
            )
        )

    def test_module_dict_subscript_recovery_keeps_helper_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    sys.modules[__name__].__dict__['_spawn' + '_shadow']()\n"
            )
        )

    def test_import_module_getattr_recovery_keeps_helper_reachable(self) -> None:
        source = self._with_helper(
            "    getattr(importlib.import_module(__name__), '_spawn' + '_shadow')()\n"
        ).replace("import os\n", "import os\nimport importlib\n")
        self.assertProcessHelperRejected(source)

    def test_operator_attrgetter_recovery_keeps_helper_reachable(self) -> None:
        source = self._with_helper(
            "    operator.attrgetter('_spawn' + '_shadow')(sys.modules[__name__])()\n"
        ).replace("import os\n", "import os\nimport operator\n")
        self.assertProcessHelperRejected(source)


if __name__ == "__main__":
    unittest.main()
