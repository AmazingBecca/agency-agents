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


class TerminalAttestationDescriptorScopeTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return control_flow.verify(root)

    def _kinds(self, report: dict[str, object]) -> set[str]:
        findings = report["findings"]
        self.assertIsInstance(findings, list)
        return {str(item["kind"]) for item in findings}

    def test_nested_function_default_cannot_capture_challenge_descriptor(self) -> None:
        source = SECURE.replace(
            "    candidate = subprocess.Popen(\n",
            "    def leak(fd=challenge_fd):\n"
            "        return fd\n"
            "    candidate = subprocess.Popen(\n",
        ).replace(
            "        close_fds=True,\n",
            "        close_fds=True,\n        pass_fds=(leak(),),\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-descriptor-captured-by-deferred-scope",
            self._kinds(report),
        )

    def test_nested_closure_cannot_capture_aliased_receipt_descriptor(self) -> None:
        source = SECURE.replace(
            "    candidate = subprocess.Popen(\n",
            "    hidden = receipt_fd\n"
            "    def leak():\n"
            "        return hidden\n"
            "    candidate = subprocess.Popen(\n",
        ).replace(
            "        close_fds=True,\n",
            "        close_fds=True,\n        pass_fds=(leak(),),\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-descriptor-captured-by-deferred-scope",
            self._kinds(report),
        )

    def test_class_body_cannot_capture_readiness_descriptor(self) -> None:
        source = SECURE.replace(
            "    candidate = subprocess.Popen(\n",
            "    class Holder:\n"
            "        fd = ready_fd\n"
            "    candidate = subprocess.Popen(\n",
        ).replace(
            "        close_fds=True,\n",
            "        close_fds=True,\n        pass_fds=(Holder.fd,),\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-descriptor-stored-in-class-scope",
            self._kinds(report),
        )

    def test_canonical_attestor_without_deferred_capture_remains_accepted(self) -> None:
        report = self._verify(SECURE)
        self.assertTrue(report["passed"], report["findings"])


if __name__ == "__main__":
    unittest.main()
