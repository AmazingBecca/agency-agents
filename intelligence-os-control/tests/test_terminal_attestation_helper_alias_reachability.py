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


class TerminalAttestationHelperAliasReachabilityTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return process_creation.verify(root)

    def _kinds(self, report: dict[str, object]) -> set[str]:
        findings = report["findings"]
        self.assertIsInstance(findings, list)
        return {str(item["kind"]) for item in findings}

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
        self.assertIn("alternate-process-creation-call", self._kinds(report))

    def test_direct_local_helper_alias_is_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    launch = _spawn_shadow\n"
                "    launch()\n"
            )
        )

    def test_chained_local_helper_alias_is_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    first = _spawn_shadow\n"
                "    second = first\n"
                "    second()\n"
            )
        )

    def test_container_stashed_helper_is_reachable(self) -> None:
        self.assertProcessHelperRejected(
            self._with_helper(
                "    launchers = [_spawn_shadow]\n"
                "    launchers[0]()\n"
            )
        )

    def test_callable_wrapper_cannot_hide_helper(self) -> None:
        source = SECURE.replace(
            "import os\n",
            "import os\nimport functools\n",
        ).replace(
            "\ndef _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):\n",
            HELPER,
        ).replace(
            "    return_code = candidate.wait()\n",
            "    launch = functools.partial(_spawn_shadow)\n"
            "    launch()\n"
            "    return_code = candidate.wait()\n",
        )
        self.assertProcessHelperRejected(source)


if __name__ == "__main__":
    unittest.main()
