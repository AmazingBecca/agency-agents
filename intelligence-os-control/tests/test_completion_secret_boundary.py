from __future__ import annotations

import pathlib
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import verify_completion_secret_boundary as subject


class CompletionSecretBoundaryTests(unittest.TestCase):
    def _bundle(self, root: pathlib.Path, source: str) -> pathlib.Path:
        bundle = root / "runner"
        bundle.mkdir()
        (bundle / "isolated_unittest_runner_impl.py").write_text(
            textwrap.dedent(source).lstrip(), encoding="utf-8"
        )
        return bundle

    def test_same_process_challenge_candidate_receipt_topology_is_rejected(self) -> None:
        source = """
        import os

        def _run_worker(project_root, pattern, challenge_fd, receipt_fd):
            token = os.read(challenge_fd, 33)
            result = run(project_root, pattern)
            if result != 0:
                return result
            _write_all(receipt_fd, token)
            return 0
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertFalse(report["passed"])
        self.assertEqual(report["finding_count"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["function"], "_run_worker")
        self.assertEqual(finding["secret_name"], "token")
        self.assertLess(finding["secret_line"], finding["candidate_line"])
        self.assertLess(finding["candidate_line"], finding["receipt_line"])

    def test_generated_secret_spanning_candidate_execution_is_rejected(self) -> None:
        source = """
        import secrets

        def execute_candidate(project_root, receipt_fd):
            token = secrets.token_bytes(32)
            result = worker._run(project_root, "test*.py")
            os.write(receipt_fd, token)
            return result
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertFalse(report["passed"])
        self.assertEqual(report["finding_count"], 1)

    def test_secret_alias_cannot_hide_candidate_spanning_receipt(self) -> None:
        source = """
        import os

        def execute_candidate(project_root, challenge_fd, receipt_fd):
            challenge = os.read(challenge_fd, 32)
            receipt = challenge
            result = run_tests(project_root)
            _write_all(receipt_fd, receipt)
            return result
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertFalse(report["passed"])
        self.assertEqual(report["findings"][0]["secret_name"], "receipt")

    def test_parent_owned_secret_without_candidate_call_is_not_rejected(self) -> None:
        source = """
        import os
        import secrets
        import subprocess

        def supervise(command, receipt_fd):
            token = secrets.token_bytes(32)
            child = subprocess.Popen(command, close_fds=True, pass_fds=())
            return_code = child.wait()
            if return_code == 0:
                os.write(receipt_fd, token)
            return return_code
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertTrue(report["passed"])
        self.assertEqual(report["findings"], [])

    def test_secret_consumed_before_candidate_execution_is_not_rejected(self) -> None:
        source = """
        import os

        def execute_candidate(project_root, challenge_fd):
            token = os.read(challenge_fd, 32)
            validate(token)
            del token
            return run(project_root, "test*.py")
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertTrue(report["passed"])

    def test_symlinked_source_is_rejected_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            bundle = root / "runner"
            bundle.mkdir()
            target = root / "outside.py"
            target.write_text("def run():\n    return 0\n", encoding="utf-8")
            (bundle / "isolated_unittest_runner_impl.py").symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "unsafe runner source"):
                subject.verify(bundle)


if __name__ == "__main__":
    unittest.main()
