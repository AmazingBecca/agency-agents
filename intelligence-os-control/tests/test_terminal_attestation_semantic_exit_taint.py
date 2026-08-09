from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import verify_terminal_attestation_semantics as attestation


BASE = r'''
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


class TerminalAttestationSemanticExitTaintTests(unittest.TestCase):
    def _verify(self, source: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runner.py").write_text(source, encoding="utf-8")
            return attestation.verify(root)

    def _kinds(self, report: dict[str, object]) -> set[str]:
        findings = report["attestation_findings"]
        self.assertIsInstance(findings, list)
        return {str(item["kind"]) for item in findings}

    def test_semantic_verifier_cannot_hide_exit_code_among_inert_extra_inputs(self) -> None:
        source = BASE.replace(
            "def _verify_candidate_semantics(observation):\n"
            "    if observation != \"verified\":\n"
            "        raise RuntimeError(\"candidate semantic observation rejected\")",
            "def _verify_candidate_semantics(return_code, project_root):\n"
            "    if return_code != 0:\n"
            "        raise RuntimeError(\"candidate exit rejected\")",
        ).replace(
            "    observation = _read_candidate_observation(candidate)\n"
            "    _verify_candidate_semantics(observation)",
            "    _verify_candidate_semantics(return_code, project_root)",
        )
        report = self._verify(source)
        self.assertFalse(report["passed"])
        self.assertIn(
            "semantic-verifier-receives-candidate-exit-state",
            self._kinds(report),
        )

    def test_independent_observation_semantic_verifier_remains_accepted(self) -> None:
        report = self._verify(BASE)
        self.assertTrue(report["passed"], report["attestation_findings"])


if __name__ == "__main__":
    unittest.main()
