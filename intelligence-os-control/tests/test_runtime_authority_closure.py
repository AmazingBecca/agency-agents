from __future__ import annotations

import hashlib
import os
import pathlib
import sys
import sysconfig
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import runtime_authority_closure as subject
import verify_authenticated_runner_bundle as bundle_verifier


HEAD = "1" * 40
BASE = "2" * 40
MERGE = "3" * 40
REPOSITORY = "AmazingBecca/free-millionaire-pipeline"
RUNNER_SOURCE = "raise SystemExit(0)\n"


class RuntimeAuthorityClosureTests(unittest.TestCase):
    def test_snapshot_binds_current_python_mapped_runtime_and_loaded_stdlib(self) -> None:
        runtime = pathlib.Path(sys.executable).resolve(strict=True)
        snapshot = subject.snapshot_runtime_closure(runtime)

        self.assertEqual(snapshot.schema, "amazingbecca.runtime-authority-closure.v1")
        self.assertEqual(snapshot.python_executable, runtime)
        self.assertRegex(snapshot.sha256, r"\A[0-9a-f]{64}\Z")
        self.assertGreater(snapshot.file_count, 1)
        self.assertGreater(snapshot.total_bytes, 0)
        self.assertIn(runtime, {entry.path for entry in snapshot.entries})

        stdlib_roots = {
            pathlib.Path(value).resolve(strict=True)
            for key in ("stdlib", "platstdlib")
            if (value := sysconfig.get_path(key))
        }
        self.assertTrue(
            any(
                any(entry.path == root or root in entry.path.parents for root in stdlib_roots)
                for entry in snapshot.entries
            ),
            "runtime closure must contain loaded standard-library authority",
        )

    def test_alternate_python_runtime_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake = pathlib.Path(directory) / "python"
            fake.write_bytes(b"not-the-control-runtime")
            fake.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "must equal the verifier runtime"):
                subject.snapshot_runtime_closure(fake)

    def test_sandbox_owned_runtime_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "runtime-member"
            path.write_bytes(b"authority")
            path.chmod(0o555)
            metadata = path.stat()
            entry = subject.RuntimeFileSnapshot(
                path=path,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                total_bytes=path.stat().st_size,
                mode=0o555,
                identity=subject._identity(metadata),
            )
            snapshot = subject.RuntimeClosureSnapshot(
                schema="amazingbecca.runtime-authority-closure.v1",
                python_executable=path,
                sha256="a" * 64,
                file_count=1,
                total_bytes=entry.total_bytes,
                entries=(entry,),
            )
            with self.assertRaisesRegex(RuntimeError, "owner-mutable by sandbox principal"):
                subject.assert_closure_not_writable_by_identity(
                    snapshot,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )


class RuntimeClosureVerifierIntegrationTests(unittest.TestCase):
    def _bundle(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, str, str]:
        runner_root = root / "runner"
        runner_root.mkdir()
        runner = runner_root / "isolated_unittest_runner.py"
        runner.write_text(RUNNER_SOURCE, encoding="utf-8")
        runner_digest = hashlib.sha256(runner.read_bytes()).hexdigest()
        bundle_digest = bundle_verifier.snapshot_bundle(runner_root).sha256
        return runner_root, runner, runner_digest, bundle_digest

    def _closure(self, *, digest: str) -> subject.RuntimeClosureSnapshot:
        runtime = pathlib.Path(sys.executable).resolve(strict=True)
        entry = subject._stable_file(runtime)
        return subject.RuntimeClosureSnapshot(
            schema="amazingbecca.runtime-authority-closure.v1",
            python_executable=runtime,
            sha256=digest,
            file_count=1,
            total_bytes=entry.total_bytes,
            entries=(entry,),
        )

    def _verify(
        self,
        runner_root: pathlib.Path,
        runner_digest: str,
        bundle_digest: str,
    ) -> dict[str, object]:
        runtime = pathlib.Path(sys.executable).resolve(strict=True)
        runtime_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
        return bundle_verifier.verify_authenticated_bundle(
            runner_root=runner_root,
            entrypoint="isolated_unittest_runner.py",
            python_executable=runtime,
            expected_python_sha256=runtime_digest,
            expected_runner_sha256=runner_digest,
            expected_bundle_sha256=bundle_digest,
            repository=REPOSITORY,
            head_sha=HEAD,
            base_sha=BASE,
            merge_sha=MERGE,
            timeout_seconds=3,
            sandbox_user="candidate",
        )

    def test_runtime_closure_mutation_during_candidate_execution_is_rejected(self) -> None:
        before = self._closure(digest="a" * 64)
        after = self._closure(digest="b" * 64)
        identity = SimpleNamespace(uid=os.getuid() + 100000, gid=os.getgid() + 100000)
        inner = {"passed": True, "schema": "inner"}
        with tempfile.TemporaryDirectory() as directory:
            runner_root, _runner, runner_digest, bundle_digest = self._bundle(pathlib.Path(directory))
            with patch.object(bundle_verifier, "_assert_bundle_not_writable_by_sandbox"), patch.object(
                bundle_verifier, "_assert_runtime_not_writable_by_sandbox"
            ), patch.object(
                bundle_verifier.bound.boundary, "resolve_identity", return_value=identity
            ), patch.object(
                bundle_verifier.runtime_closure,
                "snapshot_runtime_closure",
                side_effect=(before, after),
            ), patch.object(
                bundle_verifier.runtime_closure, "assert_closure_not_writable_by_identity"
            ), patch.object(
                bundle_verifier.bound, "verify_bound", return_value=inner
            ) as verifier:
                with self.assertRaisesRegex(RuntimeError, "runtime closure changed"):
                    self._verify(runner_root, runner_digest, bundle_digest)
        verifier.assert_called_once()

    def test_sandboxed_receipt_records_runtime_closure_identity(self) -> None:
        closure = self._closure(digest="c" * 64)
        identity = SimpleNamespace(uid=os.getuid() + 100000, gid=os.getgid() + 100000)
        inner = {"passed": True, "schema": "inner"}
        with tempfile.TemporaryDirectory() as directory:
            runner_root, _runner, runner_digest, bundle_digest = self._bundle(pathlib.Path(directory))
            with patch.object(bundle_verifier, "_assert_bundle_not_writable_by_sandbox"), patch.object(
                bundle_verifier, "_assert_runtime_not_writable_by_sandbox"
            ), patch.object(
                bundle_verifier.bound.boundary, "resolve_identity", return_value=identity
            ), patch.object(
                bundle_verifier.runtime_closure,
                "snapshot_runtime_closure",
                side_effect=(closure, closure),
            ), patch.object(
                bundle_verifier.runtime_closure, "assert_closure_not_writable_by_identity"
            ), patch.object(
                bundle_verifier.bound, "verify_bound", return_value=inner
            ):
                report = self._verify(runner_root, runner_digest, bundle_digest)

        self.assertTrue(report["passed"])
        self.assertTrue(report["runtime_closure_enforced"])
        self.assertTrue(report["runtime_closure_sandbox_readonly"])
        self.assertEqual(report["runtime_closure_schema"], closure.schema)
        self.assertEqual(report["runtime_closure_sha256"], closure.sha256)
        self.assertEqual(report["runtime_closure_file_count"], closure.file_count)
        self.assertEqual(report["runtime_closure_bytes"], closure.total_bytes)
        self.assertEqual(len(report["runtime_closure_files"]), 1)


if __name__ == "__main__":
    unittest.main()
