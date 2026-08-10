from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import verify_terminal_candidate_authority_legacy as subject


PROCESS_FAIL = {
    "schema": "amazingbecca.terminal-attestation-process-creation.v1",
    "authority_level": "source-process-topology-diagnostic-not-terminal",
    "control_flow_passed": True,
    "control_flow_finding_count": 0,
    "terminal_attestor_count": 1,
    "finding_count": 1,
    "findings": [
        {
            "path": "isolated_unittest_runner.py",
            "function": "_run_attestor",
            "line": 42,
            "kind": "alternate-process-creation-call",
            "detail": "os.fork",
        }
    ],
    "passed": False,
}


class TerminalLegacyProcessCreationEnclosureTests(unittest.TestCase):
    def _diagnostic(self, root: pathlib.Path) -> dict[str, object]:
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

    def test_direct_legacy_internal_route_fails_before_candidate_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with (
                patch.object(subject.process_creation, "verify", return_value=dict(PROCESS_FAIL)) as process_verify,
                patch.object(subject.attestation_flow, "verify") as flow_verify,
                patch.object(subject.authenticated, "verify_authenticated_bundle") as authenticated_verify,
            ):
                with self.assertRaisesRegex(RuntimeError, "alternate process-creation authority"):
                    self._diagnostic(root)

        process_verify.assert_called_once_with(root)
        flow_verify.assert_not_called()
        authenticated_verify.assert_not_called()

    def test_direct_legacy_public_route_cannot_bypass_process_creation_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with (
                patch.object(subject, "_require_production_sandbox_user", return_value="nobody"),
                patch.object(subject.process_creation, "verify", return_value=dict(PROCESS_FAIL)) as process_verify,
                patch.object(subject.attestation_flow, "verify") as flow_verify,
            ):
                with self.assertRaisesRegex(RuntimeError, "alternate process-creation authority"):
                    subject.verify_terminal_bundle(
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
                        sandbox_user="nobody",
                    )

        process_verify.assert_called_once_with(root)
        flow_verify.assert_not_called()

    def test_direct_legacy_cli_returns_error_on_process_creation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            argv = [
                "--runner-root",
                str(root),
                "--expected-python-sha256",
                "1" * 64,
                "--expected-runner-sha256",
                "2" * 64,
                "--expected-bundle-sha256",
                "3" * 64,
                "--repository",
                "AmazingBecca/free-millionaire-pipeline",
                "--head-sha",
                "4" * 40,
                "--base-sha",
                "5" * 40,
                "--merge-sha",
                "6" * 40,
            ]
            with (
                patch.object(subject, "_require_production_sandbox_user", return_value="nobody"),
                patch.object(subject.process_creation, "verify", return_value=dict(PROCESS_FAIL)) as process_verify,
            ):
                self.assertEqual(subject.main(argv), 2)

        process_verify.assert_called_once_with(root)


if __name__ == "__main__":
    unittest.main()
