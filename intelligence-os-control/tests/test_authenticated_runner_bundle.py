from __future__ import annotations

import hashlib
import os
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
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

    def _runtime_digest(self, runtime: pathlib.Path) -> str:
        return hashlib.sha256(runtime.resolve(strict=True).read_bytes()).hexdigest()

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
        *,
        python_executable: pathlib.Path | None = None,
        expected_python_sha256: str | None = None,
        sandbox_user: str | None = None,
    ) -> dict[str, object]:
        runtime = python_executable or pathlib.Path(sys.executable)
        return subject.verify_authenticated_bundle(
            runner_root=bundle,
            entrypoint="isolated_unittest_runner.py",
            python_executable=runtime,
            expected_python_sha256=expected_python_sha256 or self._runtime_digest(runtime),
            expected_runner_sha256=self._runner_digest(runner),
            expected_bundle_sha256=expected_bundle_sha256,
            repository=REPOSITORY,
            head_sha=HEAD,
            base_sha=BASE,
            merge_sha=MERGE,
            timeout_seconds=3,
            sandbox_user=sandbox_user,
        )

    def test_receipt_binds_every_file_in_runner_bundle_and_python_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, _helper = self._bundle(pathlib.Path(directory))
            snapshot = subject.snapshot_bundle(bundle)
            runtime = pathlib.Path(sys.executable).resolve(strict=True)
            with patch.object(subject.bound, "verify_bound", return_value=self._inner_report()) as verifier:
                report = self._verify(bundle, runner, snapshot.sha256)

        self.assertTrue(report["passed"])
        self.assertEqual(report["bundle_schema"], "amazingbecca.authenticated-runner-bundle.v2")
        self.assertEqual(report["authority_level"], "diagnostic-bundle-bound-not-terminal")
        self.assertEqual(report["bundle_sha256"], snapshot.sha256)
        self.assertEqual(report["bundle_file_count"], 2)
        self.assertFalse(report["bundle_sandbox_readonly"])
        self.assertEqual(report["python_executable"], str(runtime))
        self.assertEqual(report["python_sha256"], self._runtime_digest(runtime))
        self.assertGreater(report["python_bytes"], 0)
        self.assertFalse(report["python_sandbox_readonly"])
        self.assertEqual(
            [entry["path"] for entry in report["bundle_files"]],
            ["helper.py", "isolated_unittest_runner.py"],
        )
        verifier.assert_called_once()
        self.assertEqual(verifier.call_args.kwargs["python_executable"], runtime)

    def test_python_digest_mismatch_is_rejected_before_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, _helper = self._bundle(pathlib.Path(directory))
            expected_bundle = subject.snapshot_bundle(bundle).sha256
            with patch.object(subject.bound, "verify_bound") as verifier:
                with self.assertRaisesRegex(RuntimeError, "Python executable SHA-256 does not match"):
                    self._verify(
                        bundle,
                        runner,
                        expected_bundle,
                        expected_python_sha256="0" * 64,
                    )
        verifier.assert_not_called()

    def test_python_runtime_mutation_during_diagnostics_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            bundle, runner, _helper = self._bundle(root)
            expected_bundle = subject.snapshot_bundle(bundle).sha256
            runtime = root / "python-runtime"
            runtime.write_bytes(b"trusted-runtime-v1")
            runtime.chmod(0o755)
            expected_runtime = self._runtime_digest(runtime)

            def mutate(**_kwargs):
                runtime.write_bytes(b"hostile-runtime-v2")
                runtime.chmod(0o755)
                return self._inner_report()

            with patch.object(subject.bound, "verify_bound", side_effect=mutate):
                with self.assertRaisesRegex(RuntimeError, "Python executable authority changed"):
                    self._verify(
                        bundle,
                        runner,
                        expected_bundle,
                        python_executable=runtime,
                        expected_python_sha256=expected_runtime,
                    )

    def test_python_symlink_is_canonicalized_before_inner_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            bundle, runner, _helper = self._bundle(root)
            expected_bundle = subject.snapshot_bundle(bundle).sha256
            runtime = root / "python-runtime"
            runtime.write_bytes(b"trusted-runtime")
            runtime.chmod(0o755)
            alias = root / "python-alias"
            alias.symlink_to(runtime)
            resolved_runtime = runtime.resolve(strict=True)
            with patch.object(subject.bound, "verify_bound", return_value=self._inner_report()) as verifier:
                report = self._verify(
                    bundle,
                    runner,
                    expected_bundle,
                    python_executable=alias,
                )
                passed_runtime = verifier.call_args.kwargs["python_executable"]

        self.assertEqual(report["python_executable"], str(resolved_runtime))
        self.assertEqual(passed_runtime, resolved_runtime)

    def test_sandbox_owned_runtime_is_rejected_before_inner_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            runtime = root / "python-runtime"
            runtime.write_bytes(b"trusted-runtime")
            runtime.chmod(0o755)
            snapshot = subject._snapshot_python_executable(runtime)
            identity = SimpleNamespace(uid=os.getuid(), gid=os.getgid())
            with patch.object(subject.bound.boundary, "resolve_identity", return_value=identity):
                with self.assertRaisesRegex(RuntimeError, "Python executable authority is replaceable"):
                    subject._assert_runtime_not_writable_by_sandbox(snapshot, "candidate")

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

    def test_sandbox_owned_bundle_is_rejected_before_inner_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, _helper = self._bundle(pathlib.Path(directory))
            expected_bundle = subject.snapshot_bundle(bundle).sha256
            identity = SimpleNamespace(uid=os.getuid(), gid=os.getgid())
            with patch.object(subject.bound.boundary, "resolve_identity", return_value=identity), patch.object(
                subject.bound, "verify_bound"
            ) as verifier:
                with self.assertRaisesRegex(RuntimeError, "owner-mutable by sandbox principal"):
                    self._verify(bundle, runner, expected_bundle, sandbox_user="candidate")
        verifier.assert_not_called()

    def test_world_writable_bundle_member_is_rejected_before_inner_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, helper = self._bundle(pathlib.Path(directory))
            helper.chmod(0o666)
            expected_bundle = subject.snapshot_bundle(bundle).sha256
            identity = SimpleNamespace(uid=os.getuid() + 100000, gid=os.getgid() + 100000)
            with patch.object(subject.bound.boundary, "resolve_identity", return_value=identity), patch.object(
                subject.bound, "verify_bound"
            ) as verifier:
                with self.assertRaisesRegex(RuntimeError, "owner-mutable by sandbox principal"):
                    self._verify(bundle, runner, expected_bundle, sandbox_user="candidate")
        verifier.assert_not_called()

    def test_group_writable_bundle_member_is_rejected_before_inner_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, helper = self._bundle(pathlib.Path(directory))
            helper.chmod(0o660)
            expected_bundle = subject.snapshot_bundle(bundle).sha256
            identity = SimpleNamespace(uid=os.getuid() + 100000, gid=os.getgid())
            with patch.object(subject.bound.boundary, "resolve_identity", return_value=identity), patch.object(
                subject.bound, "verify_bound"
            ) as verifier:
                with self.assertRaisesRegex(RuntimeError, "owner-mutable by sandbox principal"):
                    self._verify(bundle, runner, expected_bundle, sandbox_user="candidate")
        verifier.assert_not_called()

    def test_world_writable_bundle_parent_is_rejected_before_inner_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            candidate_parent = root / "candidate-parent"
            candidate_parent.mkdir()
            candidate_parent.chmod(0o777)
            bundle, runner, _helper = self._bundle(candidate_parent)
            expected_bundle = subject.snapshot_bundle(bundle).sha256
            identity = SimpleNamespace(uid=os.getuid() + 100000, gid=os.getgid() + 100000)
            with patch.object(subject.bound.boundary, "resolve_identity", return_value=identity), patch.object(
                subject.bound, "verify_bound"
            ) as verifier:
                with self.assertRaisesRegex(RuntimeError, "replaceable through sandbox-writable ancestry"):
                    self._verify(bundle, runner, expected_bundle, sandbox_user="candidate")
        verifier.assert_not_called()

    def test_group_writable_bundle_parent_is_rejected_before_inner_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            candidate_parent = root / "candidate-parent"
            candidate_parent.mkdir()
            candidate_parent.chmod(0o770)
            bundle, runner, _helper = self._bundle(candidate_parent)
            expected_bundle = subject.snapshot_bundle(bundle).sha256
            identity = SimpleNamespace(uid=os.getuid() + 100000, gid=os.getgid())
            with patch.object(subject.bound.boundary, "resolve_identity", return_value=identity), patch.object(
                subject.bound, "verify_bound"
            ) as verifier:
                with self.assertRaisesRegex(RuntimeError, "replaceable through sandbox-writable ancestry"):
                    self._verify(bundle, runner, expected_bundle, sandbox_user="candidate")
        verifier.assert_not_called()

    def test_sticky_world_writable_ancestor_protects_control_owned_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            sticky_parent = root / "sticky-parent"
            sticky_parent.mkdir()
            sticky_parent.chmod(0o1777)
            bundle, _runner, _helper = self._bundle(sticky_parent)
            snapshot = subject.snapshot_bundle(bundle)
            identity = SimpleNamespace(uid=os.getuid() + 100000, gid=os.getgid() + 100000)
            with patch.object(subject.bound.boundary, "resolve_identity", return_value=identity):
                subject._assert_bundle_not_writable_by_sandbox(snapshot, "candidate")

    def test_nonwritable_bundle_reaches_inner_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, _helper = self._bundle(pathlib.Path(directory))
            expected_bundle = subject.snapshot_bundle(bundle).sha256
            identity = SimpleNamespace(uid=os.getuid() + 100000, gid=os.getgid() + 100000)
            with patch.object(subject.bound.boundary, "resolve_identity", return_value=identity), patch.object(
                subject.bound, "verify_bound", return_value=self._inner_report()
            ) as verifier, patch.object(subject, "_assert_runtime_not_writable_by_sandbox"):
                report = self._verify(bundle, runner, expected_bundle, sandbox_user="candidate")

        self.assertTrue(report["passed"])
        self.assertTrue(report["bundle_sandbox_readonly"])
        self.assertTrue(report["python_sandbox_readonly"])
        verifier.assert_called_once()

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

    def test_malformed_expected_python_digest_fails_before_runtime_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, _helper = self._bundle(pathlib.Path(directory))
            expected_bundle = subject.snapshot_bundle(bundle).sha256
            with patch.object(subject, "_snapshot_python_executable") as snapshotter:
                with self.assertRaisesRegex(RuntimeError, "expected Python executable SHA-256"):
                    self._verify(
                        bundle,
                        runner,
                        expected_bundle,
                        expected_python_sha256="ABC",
                    )
            snapshotter.assert_not_called()

    def test_malformed_expected_bundle_digest_fails_before_bundle_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, _helper = self._bundle(pathlib.Path(directory))
            with patch.object(subject, "snapshot_bundle") as snapshotter:
                with self.assertRaisesRegex(RuntimeError, "expected bundle SHA-256"):
                    self._verify(bundle, runner, "ABC")
            snapshotter.assert_not_called()

    def test_missing_entrypoint_in_authenticated_bundle_fails_before_inner_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle, runner, _helper = self._bundle(pathlib.Path(directory))
            snapshot = subject.snapshot_bundle(bundle)
            runtime = pathlib.Path(sys.executable)
            with patch.object(subject.bound, "verify_bound") as verifier:
                with self.assertRaisesRegex(RuntimeError, "entrypoint is not present"):
                    subject.verify_authenticated_bundle(
                        runner_root=bundle,
                        entrypoint="missing.py",
                        python_executable=runtime,
                        expected_python_sha256=self._runtime_digest(runtime),
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
