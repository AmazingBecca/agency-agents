from __future__ import annotations

import hashlib
import os
import pathlib
import pwd
import sys
import tempfile
import textwrap
import types
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import verify_terminal_candidate_authority as subject

HEAD = "1" * 40
BASE = "2" * 40
MERGE = "3" * 40
REPOSITORY = "AmazingBecca/free-millionaire-pipeline"

CONFORMING_RUNNER = r'''
from __future__ import annotations
import argparse
import pathlib

parser = argparse.ArgumentParser()
parser.add_argument('--project-root', type=pathlib.Path, required=True)
parser.add_argument('--pattern')
args = parser.parse_args()
source = next((args.project_root / 'tests').glob('test*.py')).read_text(encoding='utf-8')
if 'LEXICAL_ATTACK_DECOY' in source:
    raise SystemExit(0)
if 'self.assertEqual(2 + 2, 5)' in source:
    raise SystemExit(7)
if 'self.assertEqual(2 + 2, 4)' in source and 'self.fail(' not in source:
    raise SystemExit(0)
if 'class ArmNestedSuiteDispatch' in source and 'self.assertTrue(True)' in source:
    raise SystemExit(0)
raise SystemExit(7)
'''

RESULT_STATE_ESCAPE_RUNNER = CONFORMING_RUNNER.replace(
    "if 'class ArmNestedSuiteDispatch' in source and 'self.assertTrue(True)' in source:\n    raise SystemExit(0)\nraise SystemExit(7)",
    "if 'class ArmNestedSuiteDispatch' in source and 'self.assertTrue(True)' in source:\n    raise SystemExit(0)\nif 'self._outcome.result' in source and 'result.shouldStop = True' in source:\n    raise SystemExit(0)\nraise SystemExit(7)",
)

LOAD_TESTS_ESCAPE_RUNNER = CONFORMING_RUNNER.replace(
    "if 'class ArmNestedSuiteDispatch' in source and 'self.assertTrue(True)' in source:\n    raise SystemExit(0)\nraise SystemExit(7)",
    "if 'class ArmNestedSuiteDispatch' in source and 'self.assertTrue(True)' in source:\n    raise SystemExit(0)\nif 'ForgedDiscoverySuite' in source and 'def load_tests' in source:\n    raise SystemExit(0)\nraise SystemExit(7)",
)


class TerminalCandidateAuthorityTests(unittest.TestCase):
    def _bundle(self, root: pathlib.Path, runner_source: str) -> tuple[pathlib.Path, pathlib.Path]:
        bundle = root / "runner"
        bundle.mkdir()
        runner = bundle / "isolated_unittest_runner.py"
        runner.write_text(textwrap.dedent(runner_source).lstrip(), encoding="utf-8")
        return bundle, runner

    def _runtime_digest(self) -> str:
        return hashlib.sha256(pathlib.Path(sys.executable).resolve(strict=True).read_bytes()).hexdigest()

    def _arguments(self, bundle: pathlib.Path, runner: pathlib.Path) -> dict[str, object]:
        snapshot = subject.authenticated.snapshot_bundle(bundle)
        return {
            "runner_root": bundle,
            "entrypoint": "isolated_unittest_runner.py",
            "python_executable": pathlib.Path(sys.executable),
            "expected_python_sha256": self._runtime_digest(),
            "expected_runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
            "expected_bundle_sha256": snapshot.sha256,
            "repository": REPOSITORY,
            "head_sha": HEAD,
            "base_sha": BASE,
            "merge_sha": MERGE,
            "timeout_seconds": 3,
        }

    def _verify_diagnostic(self, bundle: pathlib.Path, runner: pathlib.Path) -> dict[str, object]:
        return subject._verify_terminal_bundle_diagnostic(
            **self._arguments(bundle, runner),
            sandbox_user=None,
        )

    def test_terminal_gate_closes_nested_result_state_gap_left_by_authenticated_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory), RESULT_STATE_ESCAPE_RUNNER)
            common = {
                **self._arguments(bundle, runner),
                "sandbox_user": None,
            }
            base_report = subject.authenticated.verify_authenticated_bundle(**common)
            terminal_report = subject._verify_terminal_bundle_diagnostic(**common)

        self.assertTrue(base_report["passed"], "the pre-existing authenticated matrix must demonstrate the gap")
        self.assertFalse(terminal_report["passed"])
        self.assertFalse(terminal_report["diagnostic_passed"])
        self.assertFalse(terminal_report["sandbox_authority_enforced"])
        self.assertEqual(
            terminal_report["accepted_attacks"],
            ["terminal-result-state-forgery"],
        )
        self.assertEqual(terminal_report["rejected_clean"], [])
        self.assertEqual(terminal_report["nested_dispatch_case_count"], 6)
        self.assertEqual(terminal_report["terminal_total_case_count"], 25)
        self.assertEqual(
            terminal_report["terminal_schema"],
            "amazingbecca.terminal-candidate-authority.v1",
        )
        self.assertEqual(
            terminal_report["authority_level"],
            "diagnostic-bundle-dispatch-bound-not-terminal",
        )

    def test_terminal_gate_closes_load_tests_suite_replacement_gap_left_by_authenticated_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory), LOAD_TESTS_ESCAPE_RUNNER)
            common = {
                **self._arguments(bundle, runner),
                "sandbox_user": None,
            }
            base_report = subject.authenticated.verify_authenticated_bundle(**common)
            terminal_report = subject._verify_terminal_bundle_diagnostic(**common)

        self.assertTrue(base_report["passed"], "the pre-existing authenticated matrix must demonstrate the load_tests gap")
        self.assertFalse(terminal_report["passed"])
        self.assertFalse(terminal_report["diagnostic_passed"])
        self.assertEqual(
            terminal_report["accepted_attacks"],
            ["load-tests-suite-replacement-forgery"],
        )
        self.assertEqual(terminal_report["rejected_clean"], [])
        self.assertEqual(terminal_report["nested_dispatch_case_count"], 6)
        self.assertEqual(terminal_report["terminal_total_case_count"], 25)

    def test_unsandboxed_diagnostic_can_never_return_authoritative_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory), CONFORMING_RUNNER)
            report = self._verify_diagnostic(bundle, runner)

        self.assertFalse(report["passed"])
        self.assertTrue(report["diagnostic_passed"])
        self.assertFalse(report["sandbox_authority_enforced"])
        self.assertFalse(report["detached_descendant_verified"])
        self.assertEqual(report["accepted_attacks"], [])
        self.assertEqual(report["rejected_clean"], [])
        self.assertEqual(report["nested_dispatch_case_count"], 6)
        self.assertEqual(report["terminal_total_case_count"], 25)
        self.assertTrue(all(case["passed"] for case in report["nested_dispatch_cases"]))

    def test_public_terminal_api_rejects_missing_blank_root_and_same_principal_before_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory), CONFORMING_RUNNER)
            arguments = self._arguments(bundle, runner)
            current_user = pwd.getpwuid(os.geteuid()).pw_name
            invalid = [
                (None, "explicit sandbox user"),
                ("", "explicit sandbox user"),
                (" nobody ", "must be canonical"),
                ("root", "root"),
            ]
            if os.geteuid() != 0:
                invalid.append((current_user, "control euid"))

            with patch.object(subject, "_verify_terminal_bundle_diagnostic") as diagnostic:
                for sandbox_user, message in invalid:
                    with self.subTest(sandbox_user=sandbox_user):
                        with self.assertRaisesRegex(RuntimeError, message):
                            subject.verify_terminal_bundle(
                                **arguments,
                                sandbox_user=sandbox_user,  # type: ignore[arg-type]
                            )
                diagnostic.assert_not_called()

    def test_public_terminal_api_passes_only_validated_nonroot_identity_to_diagnostic_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory), CONFORMING_RUNNER)
            arguments = self._arguments(bundle, runner)
            expected = {"passed": True}
            fake_identity = types.SimpleNamespace(uid=os.geteuid() + 10000, gid=os.getegid() + 10000)

            with (
                patch.object(subject.bound.boundary, "resolve_identity", return_value=fake_identity) as resolver,
                patch.object(subject, "_verify_terminal_bundle_diagnostic", return_value=expected) as diagnostic,
            ):
                report = subject.verify_terminal_bundle(
                    **arguments,
                    sandbox_user="candidate-sandbox",
                )

        self.assertIs(report, expected)
        resolver.assert_called_once_with("candidate-sandbox")
        self.assertEqual(diagnostic.call_args.kwargs["sandbox_user"], "candidate-sandbox")


if __name__ == "__main__":
    unittest.main()
