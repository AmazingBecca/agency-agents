from __future__ import annotations

import os
import pathlib
import sys
import types
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

import verify_terminal_candidate_authority as subject


class TerminalNonpromotionAuthorityTests(unittest.TestCase):
    def _diagnostic_green_report(self) -> dict[str, object]:
        return {
            "terminal_schema": "amazingbecca.terminal-candidate-authority.v1",
            "authority_level": "diagnostic-bundle-dispatch-bound-not-terminal",
            "diagnostic_passed": True,
            "containment_passed": True,
            "sandbox_authority_enforced": True,
            "detached_descendant_verified": True,
            "parent_signal_containment_verified": True,
            "passed": True,
        }

    def test_nonterminal_composite_cannot_authorize_promotion_even_when_diagnostics_are_green(self) -> None:
        report = subject._force_nonterminal_authority(self._diagnostic_green_report())

        self.assertTrue(report["diagnostic_passed"])
        self.assertTrue(report["containment_passed"])
        self.assertFalse(report["promotion_authority_ready"])
        self.assertFalse(report["promotion_authorized"])
        self.assertFalse(report["passed"])

    def test_public_api_forces_nonterminal_result_after_validated_sandbox_identity(self) -> None:
        fake_identity = types.SimpleNamespace(uid=os.geteuid() + 10000, gid=os.getegid() + 10000)
        diagnostic = self._diagnostic_green_report()

        with (
            patch.object(subject.bound.boundary, "resolve_identity", return_value=fake_identity),
            patch.object(subject, "_verify_terminal_bundle_diagnostic", return_value=diagnostic),
        ):
            report = subject.verify_terminal_bundle(
                runner_root=pathlib.Path("/tmp/runner"),
                entrypoint="isolated_unittest_runner.py",
                python_executable=pathlib.Path(sys.executable),
                expected_python_sha256="0" * 64,
                expected_runner_sha256="1" * 64,
                expected_bundle_sha256="2" * 64,
                repository="AmazingBecca/free-millionaire-pipeline",
                head_sha="3" * 40,
                base_sha="4" * 40,
                merge_sha="5" * 40,
                sandbox_user="candidate-sandbox",
            )

        self.assertTrue(report["diagnostic_passed"])
        self.assertFalse(report["promotion_authority_ready"])
        self.assertFalse(report["promotion_authorized"])
        self.assertFalse(report["passed"])
        self.assertTrue(diagnostic["passed"], "public hardening must not rely on mutating the diagnostic object")

    def test_nonterminal_wrapper_rejects_schema_authority_and_decision_drift(self) -> None:
        malformed = [
            ({**self._diagnostic_green_report(), "terminal_schema": "wrong"}, "schema"),
            ({**self._diagnostic_green_report(), "authority_level": "terminal"}, "level"),
            ({**self._diagnostic_green_report(), "diagnostic_passed": "yes"}, "decision"),
        ]

        for report, message in malformed:
            with self.subTest(message=message):
                with self.assertRaisesRegex(RuntimeError, message):
                    subject._force_nonterminal_authority(report)


if __name__ == "__main__":
    unittest.main()
