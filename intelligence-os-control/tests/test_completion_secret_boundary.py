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
        self.assertEqual(finding["exposure_kind"], "secret-live-at-candidate-execution")
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
        names = {finding["secret_name"] for finding in report["findings"]}
        self.assertIn("challenge", names)
        self.assertIn("receipt", names)

    def test_live_secret_without_direct_receipt_write_is_rejected(self) -> None:
        source = """
        import os

        def execute_candidate(project_root, challenge_fd):
            token = os.read(challenge_fd, 32)
            return run_tests(project_root)
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertFalse(report["passed"])
        self.assertEqual(report["finding_count"], 1)
        self.assertIsNone(report["findings"][0]["receipt_line"])

    def test_attribute_storage_cannot_hide_live_secret(self) -> None:
        source = """
        import os

        def execute_candidate(project_root, challenge_fd, state):
            token = os.read(challenge_fd, 32)
            state.token = token
            del token
            return run_tests(project_root)
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertFalse(report["passed"])
        names = {finding["secret_name"] for finding in report["findings"]}
        self.assertIn("state", names)

    def test_setattr_storage_cannot_hide_live_secret(self) -> None:
        source = """
        import os

        def execute_candidate(project_root, challenge_fd, state):
            token = os.read(challenge_fd, 32)
            setattr(state, "token", token)
            del token
            return run_tests(project_root)
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertFalse(report["passed"])
        names = {finding["secret_name"] for finding in report["findings"]}
        self.assertIn("state", names)

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

    def test_plain_name_overwrite_clears_python_level_secret_alias(self) -> None:
        source = """
        import os

        def execute_candidate(project_root, challenge_fd):
            token = os.read(challenge_fd, 32)
            token = b""
            return run(project_root, "test*.py")
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertTrue(report["passed"])

    def test_candidate_importing_worker_requires_external_terminal_verifier(self) -> None:
        source = """
        def _run_worker(project_root, pattern, challenge_fd, receipt_fd):
            worker = _load_worker()
            run = worker._run
            result = run(project_root, pattern)
            if result != 0:
                return result
            _write_all(receipt_fd, b"PASS")
            return 0

        def _supervise(project_root, pattern):
            child = subprocess.Popen(["worker"])
            return_code = child.wait()
            if return_code != 0:
                return return_code
            return 0
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertFalse(report["passed"])
        kinds = {finding["exposure_kind"] for finding in report["findings"]}
        self.assertIn("candidate-worker-receives-trusted-completion-authority", kinds)
        self.assertIn("candidate-worker-owns-trusted-completion-state", kinds)
        self.assertIn("external-terminal-verifier-missing", kinds)

    def test_terminal_verifier_must_execute_after_candidate_completion(self) -> None:
        source = """
        def _run_worker(project_root, pattern, observation_fd):
            worker = _load_worker()
            run = worker._run
            return run(project_root, pattern)

        def _verify_terminal_observation(return_code, observation):
            if return_code != 0 or observation != b"complete":
                return 1
            return 0

        def _supervise(project_root, pattern):
            child = subprocess.Popen(["worker"])
            terminal = _verify_terminal_observation(0, b"complete")
            return_code = child.wait()
            if terminal != 0 or return_code != 0:
                return 1
            return 0
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertFalse(report["passed"])
        kinds = {finding["exposure_kind"] for finding in report["findings"]}
        self.assertIn("terminal-verification-not-after-candidate-completion", kinds)

    def test_external_terminal_verdict_split_is_accepted_as_source_topology(self) -> None:
        source = """
        def _run_worker(project_root, pattern, observation_fd):
            worker = _load_worker()
            run = worker._run
            return run(project_root, pattern)

        def _verify_terminal_observation(return_code, observation):
            if return_code != 0 or observation != b"complete":
                return 1
            return 0

        def _supervise(project_root, pattern):
            child = subprocess.Popen(["worker"])
            return_code = child.wait()
            terminal = _verify_terminal_observation(return_code, b"complete")
            if terminal != 0:
                return terminal
            return 0
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertTrue(report["passed"])
        self.assertEqual(report["findings"], [])

    def test_terminal_verifier_cannot_import_or_execute_candidate(self) -> None:
        source = """
        def _run_worker(project_root, pattern, observation_fd):
            worker = _load_worker()
            run = worker._run
            return run(project_root, pattern)

        def _verify_terminal_observation(return_code, observation):
            worker = _load_worker()
            return worker._run(return_code, observation)

        def _supervise(project_root, pattern):
            child = subprocess.Popen(["worker"])
            return_code = child.wait()
            terminal = _verify_terminal_observation(return_code, b"complete")
            if terminal != 0:
                return terminal
            return 0
        """
        with tempfile.TemporaryDirectory() as directory:
            report = subject.verify(self._bundle(pathlib.Path(directory), source))

        self.assertFalse(report["passed"])
        kinds = {finding["exposure_kind"] for finding in report["findings"]}
        self.assertIn("terminal-verifier-executes-candidate-code", kinds)

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
