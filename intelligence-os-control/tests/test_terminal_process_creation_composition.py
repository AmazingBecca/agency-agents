from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import verify_terminal_candidate_authority as subject


PROCESS_PASS = {
    "schema": "amazingbecca.terminal-attestation-process-creation.v1",
    "authority_level": "source-process-topology-diagnostic-not-terminal",
    "control_flow_passed": True,
    "control_flow_finding_count": 0,
    "terminal_attestor_count": 1,
    "finding_count": 0,
    "findings": [],
    "passed": True,
}

LEGACY_PASS = {
    "terminal_schema": "amazingbecca.terminal-candidate-authority.v1",
    "authority_level": "diagnostic-bundle-dispatch-bound-not-terminal",
    "diagnostic_passed": True,
    "containment_passed": True,
    "promotion_authority_ready": False,
    "promotion_authorized": False,
    "accepted_attacks": [],
    "rejected_clean": [],
    "passed": False,
}


class TerminalProcessCreationCompositionTests(unittest.TestCase):
    def _call(self, root: pathlib.Path) -> dict[str, object]:
        return subject._verify_terminal_bundle_diagnostic(
            runner_root=root,
            entrypoint="isolated_unittest_runner.py",
            python_executable=pathlib.Path(sys.executable),
            expected_python_sha256="1" * 64,
            expected_runner_sha256="2" * 64,
            expected_bundle_sha256="3" * 64,
            repository="AmazingBecca/free-millionaire-pipeline",
            head_sha="4" * 40,
            base_sha="5" * 40,
            merge_sha="6" * 40,
            timeout_seconds=3,
            sandbox_user=None,
        )

    def test_process_creation_proof_encloses_legacy_terminal_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with (
                patch.object(subject.process_creation, "verify", side_effect=[dict(PROCESS_PASS), dict(PROCESS_PASS)]) as process_verify,
                patch.object(subject._legacy, "_verify_terminal_bundle_diagnostic", return_value=dict(LEGACY_PASS)) as legacy_verify,
            ):
                report = self._call(root)

        self.assertEqual(process_verify.call_count, 2)
        legacy_verify.assert_called_once()
        self.assertTrue(report["diagnostic_passed"])
        self.assertTrue(report["terminal_attestation_process_creation_verified"])
        self.assertEqual(
            report["terminal_attestation_process_creation_schema"],
            "amazingbecca.terminal-attestation-process-creation.v1",
        )
        self.assertEqual(report["terminal_attestation_process_creation_attestor_count"], 1)
        self.assertEqual(report["terminal_attestation_process_creation_finding_count"], 0)
        self.assertFalse(report["passed"])

    def test_process_creation_failure_stops_before_candidate_diagnostics(self) -> None:
        failed = dict(PROCESS_PASS)
        failed.update(
            {
                "passed": False,
                "finding_count": 1,
                "findings": [
                    {
                        "path": "isolated_unittest_runner.py",
                        "function": "_run_attestor",
                        "line": 10,
                        "kind": "alternate-process-creation-call",
                        "detail": "os.fork",
                    }
                ],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with (
                patch.object(subject.process_creation, "verify", return_value=failed),
                patch.object(subject._legacy, "_verify_terminal_bundle_diagnostic") as legacy_verify,
            ):
                with self.assertRaisesRegex(RuntimeError, "alternate process-creation authority"):
                    self._call(root)

        legacy_verify.assert_not_called()

    def test_process_creation_report_drift_is_rejected_after_candidate_diagnostics(self) -> None:
        after = dict(PROCESS_PASS)
        after["diagnostic_nonce"] = "changed-after-candidate-execution"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with (
                patch.object(subject.process_creation, "verify", side_effect=[dict(PROCESS_PASS), after]),
                patch.object(subject._legacy, "_verify_terminal_bundle_diagnostic", return_value=dict(LEGACY_PASS)),
            ):
                with self.assertRaisesRegex(RuntimeError, "authority changed during terminal verification"):
                    self._call(root)

    def test_malformed_green_process_report_cannot_enter_composite(self) -> None:
        malformed = dict(PROCESS_PASS)
        malformed["finding_count"] = 1
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with patch.object(subject.process_creation, "verify", return_value=malformed):
                with self.assertRaisesRegex(RuntimeError, "findings despite PASS"):
                    self._call(root)


if __name__ == "__main__":
    unittest.main()
