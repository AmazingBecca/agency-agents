from __future__ import annotations

import hashlib
import pathlib
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import verify_bound_candidate_test_authority as subject


HEAD = "1" * 40
BASE = "2" * 40
MERGE = "3" * 40
REPOSITORY = "AmazingBecca/free-millionaire-pipeline"

GOOD_RUNNER = r'''
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
raise SystemExit(7)
'''

NAIVE_SOURCE_CLASSIFIER_RUNNER = r'''
from __future__ import annotations
import argparse
import pathlib

parser = argparse.ArgumentParser()
parser.add_argument('--project-root', type=pathlib.Path, required=True)
parser.add_argument('--pattern')
args = parser.parse_args()
source = next((args.project_root / 'tests').glob('test*.py')).read_text(encoding='utf-8')
if 'class Clean' in source and 'def test_pass' in source:
    raise SystemExit(0)
raise SystemExit(7)
'''

POSITION_CLASSIFIER_RUNNER = r'''
from __future__ import annotations
import argparse
import pathlib

parser = argparse.ArgumentParser()
parser.add_argument('--project-root', type=pathlib.Path, required=True)
parser.add_argument('--pattern')
args = parser.parse_args()
raise SystemExit(0 if args.project_root.name == 'case-00' else 7)
'''

OPAQUE_PATH_ASSERTING_RUNNER = r'''
from __future__ import annotations
import argparse
import pathlib
import re

parser = argparse.ArgumentParser()
parser.add_argument('--project-root', type=pathlib.Path, required=True)
parser.add_argument('--pattern')
args = parser.parse_args()
fixtures = list((args.project_root / 'tests').glob('test*.py'))
if len(fixtures) != 1:
    raise SystemExit(90)
if re.fullmatch(r'case-\d+', args.project_root.name):
    raise SystemExit(91)
if re.fullmatch(r'test_authority_\d+\.py', fixtures[0].name):
    raise SystemExit(92)
source = fixtures[0].read_text(encoding='utf-8')
if 'LEXICAL_ATTACK_DECOY' in source:
    raise SystemExit(0)
if 'self.assertEqual(2 + 2, 5)' in source:
    raise SystemExit(7)
if 'self.assertEqual(2 + 2, 4)' in source and 'self.fail(' not in source:
    raise SystemExit(0)
raise SystemExit(7)
'''

INSTANCE_ESCAPE_RUNNER = r'''
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
if '_callTestMethod' in source and 'setUp' in source:
    raise SystemExit(0)
raise SystemExit(7)
'''

GETATTRIBUTE_ESCAPE_RUNNER = r'''
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
if '__getattribute__' in source and '_callTestMethod' in source:
    raise SystemExit(0)
raise SystemExit(7)
'''


class BoundCandidateTestAuthorityTests(unittest.TestCase):
    def _bundle(self, root: pathlib.Path, source: str = GOOD_RUNNER) -> tuple[pathlib.Path, pathlib.Path]:
        bundle = root / "runner"
        bundle.mkdir()
        runner = bundle / "isolated_unittest_runner.py"
        runner.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        return bundle, runner

    def _digest(self, runner: pathlib.Path) -> str:
        return hashlib.sha256(runner.read_bytes()).hexdigest()

    def _verify(self, bundle: pathlib.Path, runner: pathlib.Path, *, sandbox_user: str | None = None):
        return subject.verify_bound(
            runner_root=bundle,
            entrypoint="isolated_unittest_runner.py",
            python_executable=pathlib.Path(sys.executable),
            expected_runner_sha256=self._digest(runner),
            repository=REPOSITORY,
            head_sha=HEAD,
            base_sha=BASE,
            merge_sha=MERGE,
            timeout_seconds=3,
            sandbox_user=sandbox_user,
        )

    def test_receipt_binds_exact_runner_and_candidate_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory))
            expected = self._digest(runner)
            report = self._verify(bundle, runner)

        self.assertTrue(report["passed"])
        self.assertEqual(report["schema"], "amazingbecca.bound-candidate-test-authority.v1")
        self.assertEqual(report["authority_level"], "diagnostic-bound-not-terminal")
        self.assertEqual(report["repository"], REPOSITORY)
        self.assertEqual(report["head_sha"], HEAD)
        self.assertEqual(report["base_sha"], BASE)
        self.assertEqual(report["merge_sha"], MERGE)
        self.assertEqual(report["runner_sha256"], expected)
        self.assertEqual(report["diagnostic_case_count"], 14)
        self.assertEqual(report["sidecar_case_count"], 5)
        self.assertEqual(report["total_case_count"], 19)
        self.assertEqual(report["accepted_attacks"], [])
        self.assertEqual(report["rejected_clean"], [])
        self.assertIsNone(report["sandbox_user"])
        self.assertIsNone(report["sandbox_boundary"])
        self.assertEqual(
            [case["name"] for case in report["sidecars"]],
            [
                "instance-calltestmethod-shadow",
                "getattribute-calltestmethod-shadow",
                "clean-position-decoy",
                "clean-source-shape-decoy",
                "attack-source-shape-decoy",
            ],
        )
        self.assertTrue(all(case["passed"] for case in report["sidecars"]))
        self.assertTrue(report["sidecar"]["passed"])
        self.assertEqual(report["sidecar"]["name"], "instance-calltestmethod-shadow")

    def test_bound_matrix_executes_under_distinct_nonroot_principal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            root.chmod(0o755)
            bundle, runner = self._bundle(root)
            bundle.chmod(0o755)
            runner.chmod(0o644)
            report = self._verify(bundle, runner, sandbox_user="nobody")

        self.assertTrue(report["passed"])
        self.assertEqual(report["sandbox_user"], "nobody")
        self.assertEqual(report["sidecar_case_count"], 6)
        self.assertEqual(report["total_case_count"], 20)
        boundary = report["sandbox_boundary"]
        self.assertIsInstance(boundary, dict)
        self.assertTrue(boundary["passed"])
        self.assertNotEqual(boundary["control_euid"], boundary["sandbox_uid"])
        self.assertFalse(boundary["signal_control_allowed"])
        self.assertFalse(boundary["sentinel_readable"])
        self.assertFalse(boundary["proc_environ_readable"])
        self.assertFalse(boundary["proc_mem_readable"])

    def test_authenticated_digest_mismatch_fails_before_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = self._bundle(pathlib.Path(directory))
            with patch.object(subject.diagnostic, "verify") as verifier:
                with self.assertRaisesRegex(RuntimeError, "does not match authenticated expectation"):
                    subject.verify_bound(
                        runner_root=bundle,
                        entrypoint="isolated_unittest_runner.py",
                        python_executable=pathlib.Path(sys.executable),
                        expected_runner_sha256="0" * 64,
                        repository=REPOSITORY,
                        head_sha=HEAD,
                        base_sha=BASE,
                        merge_sha=MERGE,
                        timeout_seconds=3,
                    )
            verifier.assert_not_called()

    def test_runner_mutation_during_diagnostics_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory))
            expected = self._digest(runner)

            def mutate(**kwargs):
                runner.write_text("raise SystemExit(0)\n", encoding="utf-8")
                return {
                    "schema": "amazingbecca.candidate-test-authority-matrix.v1",
                    "passed": True,
                    "case_count": 14,
                    "accepted_attacks": [],
                    "rejected_clean": [],
                }

            sidecars = [
                {"name": "instance-calltestmethod-shadow", "expected_zero": False, "returncode": 7, "passed": True, "stdout_bytes": 0, "stderr_bytes": 0, "elapsed_ms": 0},
                {"name": "getattribute-calltestmethod-shadow", "expected_zero": False, "returncode": 7, "passed": True, "stdout_bytes": 0, "stderr_bytes": 0, "elapsed_ms": 0},
                {"name": "clean-position-decoy", "expected_zero": True, "returncode": 0, "passed": True, "stdout_bytes": 0, "stderr_bytes": 0, "elapsed_ms": 0},
                {"name": "clean-source-shape-decoy", "expected_zero": True, "returncode": 0, "passed": True, "stdout_bytes": 0, "stderr_bytes": 0, "elapsed_ms": 0},
                {"name": "attack-source-shape-decoy", "expected_zero": False, "returncode": 7, "passed": True, "stdout_bytes": 0, "stderr_bytes": 0, "elapsed_ms": 0},
            ]
            with patch.object(subject.diagnostic, "verify", side_effect=mutate), patch.object(
                subject, "_run_instance_dispatch_attack", return_value=sidecars[0]
            ), patch.object(
                subject, "_run_getattribute_dispatch_attack", return_value=sidecars[1]
            ), patch.object(
                subject, "_run_clean_position_decoy", return_value=sidecars[2]
            ), patch.object(
                subject, "_run_clean_source_shape_decoy", return_value=sidecars[3]
            ), patch.object(
                subject, "_run_attack_source_shape_decoy", return_value=sidecars[4]
            ):
                with self.assertRaisesRegex(RuntimeError, "changed during external verification"):
                    subject.verify_bound(
                        runner_root=bundle,
                        entrypoint="isolated_unittest_runner.py",
                        python_executable=pathlib.Path(sys.executable),
                        expected_runner_sha256=expected,
                        repository=REPOSITORY,
                        head_sha=HEAD,
                        base_sha=BASE,
                        merge_sha=MERGE,
                        timeout_seconds=3,
                    )

    def test_candidate_visible_case_paths_are_opaque(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory), OPAQUE_PATH_ASSERTING_RUNNER)
            report = self._verify(bundle, runner)

        self.assertTrue(report["passed"])
        self.assertEqual(report["accepted_attacks"], [])
        self.assertEqual(report["rejected_clean"], [])

    def test_diagnostic_case_supplier_is_control_shuffled(self) -> None:
        original_names = [case.name for case in subject.diagnostic._fixture_cases()]
        with patch.object(subject, "_shuffle_by_control_entropy", side_effect=lambda items: items.reverse()):
            with subject._opaque_diagnostic_case_identity():
                shuffled_names = [case.name for case in subject.diagnostic._fixture_cases()]

        self.assertEqual(shuffled_names, list(reversed(original_names)))
        self.assertEqual([case.name for case in subject.diagnostic._fixture_cases()], original_names)

    def test_position_only_classifier_is_rejected_before_sidecar_decoy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory), POSITION_CLASSIFIER_RUNNER)
            report = self._verify(bundle, runner)

        self.assertFalse(report["passed"])
        self.assertEqual(report["accepted_attacks"], [])
        self.assertEqual(report["rejected_clean"], ["clean-pass", "clean-position-decoy", "clean-source-shape-decoy"])
        by_name = {case["name"]: case for case in report["sidecars"]}
        self.assertFalse(by_name["clean-position-decoy"]["passed"])
        self.assertEqual(by_name["clean-position-decoy"]["returncode"], 7)
        self.assertFalse(by_name["clean-source-shape-decoy"]["passed"])
        self.assertEqual(by_name["clean-source-shape-decoy"]["returncode"], 7)
        self.assertTrue(by_name["attack-source-shape-decoy"]["passed"])
        self.assertTrue(by_name["instance-calltestmethod-shadow"]["passed"])
        self.assertTrue(by_name["getattribute-calltestmethod-shadow"]["passed"])

    def test_naive_source_classifier_is_rejected_by_paired_decoys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory), NAIVE_SOURCE_CLASSIFIER_RUNNER)
            report = self._verify(bundle, runner)

        self.assertFalse(report["passed"])
        self.assertEqual(report["accepted_attacks"], ["attack-source-shape-decoy"])
        self.assertEqual(report["rejected_clean"], ["clean-source-shape-decoy"])
        by_name = {case["name"]: case for case in report["sidecars"]}
        self.assertFalse(by_name["clean-source-shape-decoy"]["passed"])
        self.assertEqual(by_name["clean-source-shape-decoy"]["returncode"], 7)
        self.assertFalse(by_name["attack-source-shape-decoy"]["passed"])
        self.assertEqual(by_name["attack-source-shape-decoy"]["returncode"], 0)

    def test_instance_dispatch_escape_is_an_explicit_red_case(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory), INSTANCE_ESCAPE_RUNNER)
            report = self._verify(bundle, runner)

        self.assertFalse(report["passed"])
        self.assertEqual(report["accepted_attacks"], ["instance-calltestmethod-shadow"])
        self.assertEqual(report["rejected_clean"], [])
        by_name = {case["name"]: case for case in report["sidecars"]}
        self.assertFalse(by_name["instance-calltestmethod-shadow"]["passed"])
        self.assertEqual(by_name["instance-calltestmethod-shadow"]["returncode"], 0)
        self.assertTrue(by_name["getattribute-calltestmethod-shadow"]["passed"])
        self.assertTrue(by_name["clean-position-decoy"]["passed"])
        self.assertTrue(by_name["clean-source-shape-decoy"]["passed"])
        self.assertTrue(by_name["attack-source-shape-decoy"]["passed"])

    def test_getattribute_dispatch_escape_is_an_explicit_red_case(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory), GETATTRIBUTE_ESCAPE_RUNNER)
            report = self._verify(bundle, runner)

        self.assertFalse(report["passed"])
        self.assertEqual(report["accepted_attacks"], ["getattribute-calltestmethod-shadow"])
        self.assertEqual(report["rejected_clean"], [])
        by_name = {case["name"]: case for case in report["sidecars"]}
        self.assertFalse(by_name["getattribute-calltestmethod-shadow"]["passed"])
        self.assertEqual(by_name["getattribute-calltestmethod-shadow"]["returncode"], 0)
        self.assertTrue(by_name["instance-calltestmethod-shadow"]["passed"])
        self.assertTrue(by_name["clean-position-decoy"]["passed"])
        self.assertTrue(by_name["clean-source-shape-decoy"]["passed"])
        self.assertTrue(by_name["attack-source-shape-decoy"]["passed"])

    def test_identity_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner = self._bundle(pathlib.Path(directory))
            expected = self._digest(runner)
            for repository, head in (("not-a-repository", HEAD), (REPOSITORY, "A" * 40), (REPOSITORY, "abc")):
                with self.subTest(repository=repository, head=head):
                    with self.assertRaises(RuntimeError):
                        subject.verify_bound(
                            runner_root=bundle,
                            entrypoint="isolated_unittest_runner.py",
                            python_executable=pathlib.Path(sys.executable),
                            expected_runner_sha256=expected,
                            repository=repository,
                            head_sha=head,
                            base_sha=BASE,
                            merge_sha=MERGE,
                            timeout_seconds=3,
                        )


if __name__ == "__main__":
    unittest.main()
