from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import verify_terminal_attestation_control_flow as control_flow


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


class TerminalAttestationDescriptorAliasTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return control_flow.verify(root)

    def _kinds(self, report: dict[str, object]) -> set[str]:
        findings = report["findings"]
        self.assertIsInstance(findings, list)
        return {str(item["kind"]) for item in findings}

    def test_direct_stdio_descriptor_leak_is_rejected(self) -> None:
        source = SECURE.replace(
            "        close_fds=True,\n",
            "        close_fds=True,\n        stdin=challenge_fd,\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-descriptor-leaked-to-candidate",
            self._kinds(report),
        )

    def test_pass_fds_descriptor_alias_is_rejected(self) -> None:
        source = SECURE.replace(
            "    candidate = subprocess.Popen(\n",
            "    leaked_fd = challenge_fd\n    candidate = subprocess.Popen(\n",
        ).replace(
            "        close_fds=True,\n",
            "        close_fds=True,\n        pass_fds=(leaked_fd,),\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-descriptor-leaked-to-candidate",
            self._kinds(report),
        )

    def test_chained_container_alias_is_rejected(self) -> None:
        source = SECURE.replace(
            "    candidate = subprocess.Popen(\n",
            "    trusted = (challenge_fd,)\n    inherited = trusted\n    candidate = subprocess.Popen(\n",
        ).replace(
            "        close_fds=True,\n",
            "        close_fds=True,\n        pass_fds=inherited,\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-descriptor-leaked-to-candidate",
            self._kinds(report),
        )


if __name__ == "__main__":
    unittest.main()
