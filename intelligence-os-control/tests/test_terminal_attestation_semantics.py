from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import verify_terminal_attestation_semantics as attestation


SECURE = r'''
import os
import secrets
import subprocess
import sys


def _load_worker():
    raise NotImplementedError


def _write_all(fd, payload):
    os.write(fd, payload)


def _read_receipt(fd):
    return os.read(fd, 32)


def _run_worker(project_root, pattern):
    worker = _load_worker()
    return worker._run(project_root, pattern)


def _read_candidate_observation(candidate):
    return "verified"


def _verify_candidate_semantics(observation):
    if observation != "verified":
        raise RuntimeError("candidate semantic observation rejected")


def _run_attestor(project_root, pattern, challenge_fd, receipt_fd):
    candidate = subprocess.Popen(
        [sys.executable, "-I", __file__, "--worker"],
        close_fds=True,
    )
    return_code = candidate.wait()
    if return_code != 0:
        return return_code
    observation = _read_candidate_observation(candidate)
    _verify_candidate_semantics(observation)
    token = os.read(challenge_fd, 32)
    os.close(challenge_fd)
    _write_all(receipt_fd, token)
    os.close(receipt_fd)
    return 0


def _verify_terminal_observation(receipt_fd, token):
    receipt = _read_receipt(receipt_fd)
    if not secrets.compare_digest(receipt, token):
        raise RuntimeError("invalid terminal receipt")


def _supervise(project_root, pattern):
    token = secrets.token_bytes(32)
    child = subprocess.Popen([sys.executable, "-I", __file__, "--attestor"])
    return_code = child.wait()
    if return_code != 0:
        return return_code
    _verify_terminal_observation(1, token)
    return 0
'''


class TerminalAttestationSemanticsTests(unittest.TestCase):
    def _verify(self, *sources: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, source in enumerate(sources):
                (root / f"runner_{index}.py").write_text(source, encoding="utf-8")
            return attestation.verify(root)

    def _kinds(self, report: dict[str, object]) -> set[str]:
        findings = report["attestation_findings"]
        self.assertIsInstance(findings, list)
        return {str(item["kind"]) for item in findings}

    def test_reviewed_terminal_topology_passes(self) -> None:
        report = self._verify(SECURE)
        self.assertTrue(report["completion_boundary_passed"])
        self.assertEqual(report["candidate_runner_count"], 1)
        self.assertEqual(report["attestation_finding_count"], 0)
        self.assertTrue(report["passed"])

    def test_bundle_without_candidate_runner_fails_closed(self) -> None:
        report = self._verify("def harmless():\n    return 0\n")
        self.assertFalse(report["passed"])
        self.assertEqual(report["candidate_runner_count"], 0)
        self.assertIn("candidate-runner-missing", self._kinds(report))

    def test_renamed_or_indirect_candidate_loader_cannot_evade_review(self) -> None:
        source = SECURE.replace(
            "worker = _load_worker()",
            "loader = _load_worker\n    worker = loader()",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        kinds = self._kinds(report)
        self.assertIn("candidate-worker-loader-topology-unreviewed", kinds)
        self.assertIn("candidate-runner-missing", kinds)

    def test_multiple_candidate_runner_authorities_are_rejected(self) -> None:
        report = self._verify(SECURE, SECURE)
        self.assertFalse(report["passed"])
        self.assertEqual(report["candidate_runner_count"], 2)
        self.assertIn("candidate-runner-authority-ambiguous", self._kinds(report))

    def test_attestor_must_wait_on_the_candidate_it_launched(self) -> None:
        source = SECURE.replace(
            "return_code = candidate.wait()",
            "other = subprocess.Popen([sys.executable, '-c', 'pass'], close_fds=True)\n    return_code = other.wait()",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("candidate-completion-wait-ambiguous", self._kinds(report))

    def test_semantic_verifier_cannot_reimport_candidate_source(self) -> None:
        source = SECURE.replace(
            "def _verify_candidate_semantics(observation):\n    if observation != \"verified\":",
            "def _verify_candidate_semantics(observation):\n    _load_worker()\n    if observation != \"verified\":",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("semantic-verifier-imports-candidate", self._kinds(report))

    def test_attestor_cannot_materialize_challenge_while_candidate_is_live(self) -> None:
        source = SECURE.replace(
            "    candidate = subprocess.Popen(\n",
            "    token = os.read(challenge_fd, 32)\n    candidate = subprocess.Popen(\n",
        ).replace(
            "    token = os.read(challenge_fd, 32)\n    os.close(challenge_fd)\n    _write_all(receipt_fd, token)",
            "    os.close(challenge_fd)\n    _write_all(receipt_fd, token)",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "terminal-challenge-live-during-candidate-execution",
            self._kinds(report),
        )

    def test_attestor_must_materialize_challenge_exactly_once(self) -> None:
        source = SECURE.replace(
            "    token = os.read(challenge_fd, 32)\n",
            "    token = b'x' * 32\n",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn("terminal-challenge-read-ambiguous", self._kinds(report))


if __name__ == "__main__":
    unittest.main()
