from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import verify_terminal_attestation_control_flow as control_flow


SECURE = r'''
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
'''


class TerminalAttestationControlFlowTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return control_flow.verify(root)

    def _kinds(self, report: dict[str, object]) -> set[str]:
        findings = report["findings"]
        self.assertIsInstance(findings, list)
        return {str(item["kind"]) for item in findings}

    def test_reviewed_top_level_dominance_passes(self) -> None:
        report = self._verify(SECURE)
        self.assertEqual(report["candidate_runner_count"], 1)
        self.assertEqual(report["terminal_attestor_count"], 1)
        self.assertEqual(report["finding_count"], 0)
        self.assertTrue(report["passed"])

    def test_nested_fake_wait_cannot_satisfy_candidate_completion(self) -> None:
        source = SECURE.replace(
            "    return_code = candidate.wait()\n",
            "    def pretend_wait():\n        return candidate.wait()\n    return_code = 0\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        kinds = self._kinds(report)
        self.assertIn("attestor-authority-call-hidden-in-nested-scope", kinds)
        self.assertIn("candidate-wait-not-canonical-top-level", kinds)

    def test_nested_fake_challenge_read_cannot_satisfy_attestation(self) -> None:
        source = SECURE.replace(
            "    token = os.read(challenge_fd, 32)\n",
            "    def read_later():\n        return os.read(challenge_fd, 32)\n    token = b'x' * 32\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        kinds = self._kinds(report)
        self.assertIn("attestor-authority-call-hidden-in-nested-scope", kinds)
        self.assertIn("challenge-read-not-canonical-top-level", kinds)

    def test_conditional_candidate_launch_is_rejected(self) -> None:
        source = SECURE.replace(
            "    candidate = subprocess.Popen(\n        [sys.executable, \"-I\", __file__, \"--worker\"],\n        close_fds=True,\n    )\n",
            "    if project_root:\n        candidate = subprocess.Popen(\n            [sys.executable, \"-I\", __file__, \"--worker\"],\n            close_fds=True,\n        )\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("candidate-launch-not-canonical-top-level", self._kinds(report))

    def test_source_order_without_dominance_is_rejected(self) -> None:
        source = SECURE.replace(
            "    return_code = candidate.wait()\n    _write_all(ready_fd, b\"candidate-exited\\n\")\n",
            "    _write_all(ready_fd, b\"candidate-exited\\n\")\n    return_code = candidate.wait()\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("attestor-authority-order-not-dominating", self._kinds(report))

    def test_candidate_cannot_inherit_attestor_authority_descriptors(self) -> None:
        source = SECURE.replace(
            "        close_fds=True,\n",
            "        close_fds=True,\n        pass_fds=(challenge_fd, receipt_fd, ready_fd),\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-descriptor-leaked-to-candidate",
            self._kinds(report),
        )

    def test_extra_conditional_challenge_read_is_rejected(self) -> None:
        source = SECURE.replace(
            "    token = os.read(challenge_fd, 32)\n",
            "    if project_root:\n        os.read(challenge_fd, 1)\n    token = os.read(challenge_fd, 32)\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-call-outside-canonical-path",
            self._kinds(report),
        )

    def test_extra_conditional_receipt_write_is_rejected(self) -> None:
        source = SECURE.replace(
            "    _write_all(receipt_fd, token)\n",
            "    if project_root:\n        _write_all(receipt_fd, b'premature')\n    _write_all(receipt_fd, token)\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-call-outside-canonical-path",
            self._kinds(report),
        )

    def test_extra_process_launch_is_rejected(self) -> None:
        source = SECURE.replace(
            "    return_code = candidate.wait()\n",
            "    observer = subprocess.Popen([sys.executable, '-c', 'pass'], close_fds=True)\n    return_code = candidate.wait()\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-call-outside-canonical-path",
            self._kinds(report),
        )

    def test_extra_process_wait_is_rejected(self) -> None:
        source = SECURE.replace(
            "    return_code = candidate.wait()\n",
            "    observer.wait()\n    return_code = candidate.wait()\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-call-outside-canonical-path",
            self._kinds(report),
        )

    def test_trusted_descriptor_cannot_be_forwarded_to_helper(self) -> None:
        source = SECURE.replace(
            "    token = os.read(challenge_fd, 32)\n",
            "    audit_descriptor(challenge_fd)\n    token = os.read(challenge_fd, 32)\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "attestor-authority-call-outside-canonical-path",
            self._kinds(report),
        )


if __name__ == "__main__":
    unittest.main()
