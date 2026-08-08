from __future__ import annotations

import hashlib
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import verify_authenticated_runner_bundle as subject


HEAD = "1" * 40
BASE = "2" * 40
MERGE = "3" * 40
REPOSITORY = "AmazingBecca/free-millionaire-pipeline"

RUNNER = """\
from __future__ import annotations
import helper
raise SystemExit(helper.EXIT_CODE)
"""
HELPER = "EXIT_CODE = 0\n"


class AuthenticatedRunnerBundleTests(unittest.TestCase):
    def _bundle(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        bundle = root / "runner"
        bundle.mkdir()
        runner = bundle / "isolated_unittest_runner.py"
        helper = bundle / "helper.py"
        runner.write_text(RUNNER, encoding="utf-8")
        helper.write_text(HELPER, encoding="utf-8")
        return bundle, runner, helper

    def _runner_digest(self, runner: pathlib.Path) -> str:
        return hashlib.sha256(runner.read_bytes()).hexdigest()

    def _inner_report(self) -> dict[str, object]:
        return {
            "schema": "amazingbecca.bound-candidate-test-authority.v1",
            "authority_level": "diagnostic-bound-not-terminal",
            "passed": True,
        }

    def _verify(
        self,
        bundle: pathlib.Path,
        runner: pathlib.Path,
        expected_bundle_sha256: str,
    ) -> dict[str, object]:
        return subject.verify_authenticated_bundle(
            runner_root=bundle,
            entrypoint="isolated_unittest_runner.py",
            python_executable=pathlib.Path(sys.executable),
            expected_runner_sha256=self._runner_digest(runner),
            expected_bundle_sha256=expected_bundle_sha256,
            repository=REPOSITORY,
            head_sha=HEAD,
            base_sha=BASE,
            merge_sha=MERGE,
            timeout_seconds=3,
            sandbox_user=None,
        )

    def test_receipt_binds_every_file_in_runner_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, _helper = self._bundle(pathlib.Path(directory))
            snapshot = subject.snapshot_bundle(bundle)
            with patch.object(subject.bound, "verify_bound", return_value=self._inner_report()) as verifier:
                report = self._verify(bundle, runner, snapshot.sha256)

        self.assertTrue(report["passed"])
        self.assertEqual(report["bundle_schema"], "amazingbecca.authenticated-runner-bundle.v1")
        self.assertEqual(report["authority_level"], "diagnostic-bundle-bound-not-terminal")
        self.assertEqual(report["bundle_sha256"], snapshot.sha256)
        self.assertEqual(report["bundle_file_count"], 2)
        self.assertEqual(
            [entry["path"] for entry in report["bundle_files"]],
            ["helper.py", "isolated_unittest_runner.py"],
        )
        verifier.assert_called_once()

    def test_sibling_dependency_mutation_with_unchanged_entrypoint_is_rejected_before_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, helper = self._bundle(pathlib.Path(directory))
            runner_digest = self._runner_digest(runner)
            expected_bundle = subject.snapshot_bundle(bundle).sha256
            helper.write_text("EXIT_CODE = 7\n", encoding="utf-8")
            self.assertEqual(self._runner_digest(runner), runner_digest)
            self.assertNotEqual(subject.snapshot_bundle(bundle).sha256, expected_bundle)

            with patch.object(subject.bound, "verify_bound") as verifier:
                with self.assertRaisesRegex(RuntimeError, "bundle SHA-256 does not match"):
                    self._verify(bundle, runner, expected_bundle)

        verifier.assert_not_called()

    def test_sibling_dependency_mutation_during_diagnostics_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, helper = self._bundle(pathlib.Path(directory))
            expected_bundle = subject.snapshot_bundle(bundle).sha256

            def mutate(**_kwargs):
                helper.write_text("EXIT_CODE = 9\n", encoding="utf-8")
                return self._inner_report()

            with patch.object(subject.bound, "verify_bound", side_effect=mutate):
                with self.assertRaisesRegex(RuntimeError, "bundle authority changed during external verification"):
                    self._verify(bundle, runner, expected_bundle)

    def test_symlink_member_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, _runner, helper = self._bundle(pathlib.Path(directory))
            link = bundle / "helper-link.py"
            link.symlink_to(helper)
            with self.assertRaisesRegex(RuntimeError, "may not contain symlinks"):
                subject.snapshot_bundle(bundle)

    def test_hardlinked_member_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, _runner, helper = self._bundle(pathlib.Path(directory))
            hardlink = bundle / "helper-hardlink.py"
            hardlink.hardlink_to(helper)
            with self.assertRaisesRegex(RuntimeError, "single-link files"):
                subject.snapshot_bundle(bundle)

    def test_malformed_expected_bundle_digest_fails_before_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, _helper = self._bundle(pathlib.Path(directory))
            with patch.object(subject, "snapshot_bundle") as snapshotter:
                with self.assertRaisesRegex(RuntimeError, "64 lowercase hex"):
                    self._verify(bundle, runner, "ABC")
            snapshotter.assert_not_called()

    def test_missing_entrypoint_in_authenticated_bundle_fails_before_inner_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, _helper = self._bundle(pathlib.Path(directory))
            snapshot = subject.snapshot_bundle(bundle)
            with patch.object(subject.bound, "verify_bound") as verifier:
                with self.assertRaisesRegex(RuntimeError, "entrypoint is not present"):
                    subject.verify_authenticated_bundle(
                        runner_root=bundle,
                        entrypoint="missing.py",
                        python_executable=pathlib.Path(sys.executable),
                        expected_runner_sha256=self._runner_digest(runner),
                        expected_bundle_sha256=snapshot.sha256,
                        repository=REPOSITORY,
                        head_sha=HEAD,
                        base_sha=BASE,
                        merge_sha=MERGE,
                        timeout_seconds=3,
                        sandbox_user=None,
                    )
            verifier.assert_not_called()


if __name__ == "__main__":
    unittest.main()
