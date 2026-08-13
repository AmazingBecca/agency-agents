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


class TerminalAttestationProcessCreationTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return process_creation.verify(root)

    def _kinds(self, report: dict[str, object]) -> set[str]:
        findings = report["findings"]
        self.assertIsInstance(findings, list)
        return {str(item["kind"]) for item in findings}

    def test_canonical_single_popen_attestor_is_accepted(self) -> None:
        report = self._verify(SECURE)
        self.assertTrue(report["passed"], report["findings"])

    def test_os_fork_secondary_process_is_rejected(self) -> None:
        source = SECURE.replace(
            "    return_code = candidate.wait()\n",
            "    shadow = os.fork()\n"
            "    if shadow == 0:\n"
            "        os._exit(0)\n"
            "    return_code = candidate.wait()\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("alternate-process-creation-call", self._kinds(report))

    def test_import_aliased_posix_spawn_is_rejected(self) -> None:
        source = SECURE.replace(
            "import os\n",
            "import os\nfrom os import posix_spawn as launch_shadow\n",
        ).replace(
            "    return_code = candidate.wait()\n",
            "    launch_shadow('/bin/true', ['/bin/true'], {})\n"
            "    return_code = candidate.wait()\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("alternate-process-creation-call", self._kinds(report))

    def test_function_local_process_alias_is_rejected(self) -> None:
        source = SECURE.replace(
            "    candidate = subprocess.Popen(\n",
            "    from os import posix_spawn as launch_shadow\n"
            "    launch_shadow('/bin/true', ['/bin/true'], {})\n"
            "    candidate = subprocess.Popen(\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("alternate-process-creation-call", self._kinds(report))

    def test_dotted_import_cannot_poison_os_root_resolution(self) -> None:
        source = SECURE.replace(
            "import os\n",
            "import os\nimport os.path\n",
        ).replace(
            "    return_code = candidate.wait()\n",
            "    shadow = os.fork()\n"
            "    if shadow == 0:\n"
            "        os._exit(0)\n"
            "    return_code = candidate.wait()\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("alternate-process-creation-call", self._kinds(report))

    def test_assigned_process_primitive_alias_is_rejected(self) -> None:
        source = SECURE.replace(
            "    return_code = candidate.wait()\n",
            "    launch_shadow = os.fork\n"
            "    shadow = launch_shadow()\n"
            "    if shadow == 0:\n"
            "        os._exit(0)\n"
            "    return_code = candidate.wait()\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("alternate-process-creation-call", self._kinds(report))

    def test_computed_getattr_fork_recovery_is_rejected(self) -> None:
        source = SECURE.replace(
            "    return_code = candidate.wait()\n",
            "    launch_shadow = getattr(os, 'fo' + 'rk')\n"
            "    shadow = launch_shadow()\n"
            "    if shadow == 0:\n"
            "        os._exit(0)\n"
            "    return_code = candidate.wait()\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("dynamic-process-primitive-recovery", self._kinds(report))

    def test_dynamic_import_process_recovery_is_rejected(self) -> None:
        source = SECURE.replace(
            "    return_code = candidate.wait()\n",
            "    shadow = __import__('o' + 's').fork()\n"
            "    if shadow == 0:\n"
            "        os._exit(0)\n"
            "    return_code = candidate.wait()\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("alternate-process-creation-call", self._kinds(report))

    def test_top_level_helper_cannot_hide_fork(self) -> None:
        source = SECURE.replace(
            "\ndef _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):\n",
            "\ndef _spawn_shadow():\n"
            "    return os.fork()\n"
            "\ndef _run_attestor(project_root, pattern, challenge_fd, receipt_fd, ready_fd):\n",
        ).replace(
            "    return_code = candidate.wait()\n",
            "    _spawn_shadow()\n"
            "    return_code = candidate.wait()\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("alternate-process-creation-call", self._kinds(report))

    def test_subprocess_run_secondary_launcher_is_rejected(self) -> None:
        source = SECURE.replace(
            "    return_code = candidate.wait()\n",
            "    subprocess.run([sys.executable, '-c', 'pass'], check=False)\n"
            "    return_code = candidate.wait()\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("alternate-process-creation-call", self._kinds(report))


if __name__ == "__main__":
    unittest.main()
