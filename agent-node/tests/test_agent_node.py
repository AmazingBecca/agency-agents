import hashlib
import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def git(repo: pathlib.Path, *args: str) -> str:
    cp = subprocess.run(
        [mod.GIT_BIN, "-C", str(repo), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return cp.stdout.strip()


def make_repo(test_body: str):
    temp = tempfile.TemporaryDirectory()
    repo = pathlib.Path(temp.name)
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "agent-node-test@example.invalid")
    git(repo, "config", "user.name", "agent-node-test")
    tests = repo / "tests"
    tests.mkdir()
    (tests / "__init__.py").write_text("", encoding="utf-8")
    (tests / "test_safe.py").write_text(test_body, encoding="utf-8")
    git(repo, "add", "tests")
    git(repo, "commit", "-qm", "reviewed")
    return temp, repo, git(repo, "rev-parse", "HEAD")


PASSING_TEST = """import unittest
class SafeTest(unittest.TestCase):
    def test_ok(self):
        self.assertTrue(True)
"""

FAILING_TEST = """import unittest
class SafeTest(unittest.TestCase):
    def test_ok(self):
        self.fail('altered worktree executed')
"""


class AgentNodeContractTests(unittest.TestCase):
    def test_sha_validation_is_fail_closed(self):
        with self.assertRaises(ValueError):
            mod.bound_identity("main")

    def test_isolated_python_can_execute_allowlisted_committed_test(self):
        temp, repo, head = make_repo(PASSING_TEST)
        self.addCleanup(temp.cleanup)
        with mock.patch.object(mod, "ROOT", repo), mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)):
            result = mod.run_tests(head, "tests.test_safe")
        self.assertEqual(result["returncode"], 0)
        self.assertIn("OK", result["stdout"])
        self.assertEqual(result["head"], head)
        self.assertRegex(result["tree"], r"^[0-9a-f]{40}$")

    def test_assume_unchanged_worktree_bytes_cannot_change_execution(self):
        temp, repo, head = make_repo(PASSING_TEST)
        self.addCleanup(temp.cleanup)
        target = repo / "tests" / "test_safe.py"
        git(repo, "update-index", "--assume-unchanged", "tests/test_safe.py")
        target.write_text(FAILING_TEST, encoding="utf-8")
        self.assertEqual(git(repo, "status", "--porcelain=v1", "--untracked-files=all"), "")
        committed_blob = git(repo, "rev-parse", "HEAD:tests/test_safe.py")
        worktree_blob = git(repo, "hash-object", "--no-filters", "tests/test_safe.py")
        self.assertNotEqual(committed_blob, worktree_blob)
        with mock.patch.object(mod, "ROOT", repo), mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)):
            result = mod.run_tests(head, "tests.test_safe")
        self.assertEqual(result["returncode"], 0)
        self.assertIn("OK", result["stdout"])

    def test_replace_ref_cannot_substitute_reviewed_commit(self):
        temp, repo, reviewed = make_repo(PASSING_TEST)
        self.addCleanup(temp.cleanup)
        target = repo / "tests" / "test_safe.py"
        target.write_text(FAILING_TEST, encoding="utf-8")
        git(repo, "add", "tests/test_safe.py")
        git(repo, "commit", "-qm", "replacement")
        replacement = git(repo, "rev-parse", "HEAD")
        git(repo, "replace", reviewed, replacement)
        git(repo, "reset", "--hard", "-q", reviewed)
        self.assertEqual(git(repo, "rev-parse", "HEAD"), reviewed)
        self.assertIn("altered worktree executed", target.read_text(encoding="utf-8"))
        with mock.patch.object(mod, "ROOT", repo), mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)):
            result = mod.run_tests(reviewed, "tests.test_safe")
        self.assertEqual(result["returncode"], 0)
        self.assertIn("OK", result["stdout"])

    def test_git_environment_cannot_redirect_repository_identity(self):
        temp1, repo1, head1 = make_repo(PASSING_TEST)
        temp2, repo2, _ = make_repo(FAILING_TEST)
        self.addCleanup(temp1.cleanup)
        self.addCleanup(temp2.cleanup)
        with mock.patch.object(mod, "ROOT", repo1), mock.patch.dict(os.environ, {"GIT_DIR": str(repo2 / ".git"), "GIT_WORK_TREE": str(repo2)}, clear=False):
            observed_head, _ = mod.bound_identity(head1)
        self.assertEqual(observed_head, head1)

    def test_test_stdout_digest_binds_exact_returned_bytes(self):
        noisy = """import unittest
class SafeTest(unittest.TestCase):
    def test_ok(self):
        print('x' * 25050)
        self.assertTrue(True)
"""
        temp, repo, head = make_repo(noisy)
        self.addCleanup(temp.cleanup)
        with mock.patch.object(mod, "ROOT", repo), mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)):
            result = mod.run_tests(head, "tests.test_safe")
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(len(result["stdout"]), mod.TEST_OUTPUT_LIMIT)
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(result["stdout"].encode()).hexdigest())

    def test_repo_index_comes_from_committed_tree_not_untracked_files(self):
        temp, repo, head = make_repo(PASSING_TEST)
        self.addCleanup(temp.cleanup)
        (repo / "ignored_runtime.py").write_text("raise RuntimeError('not reviewed')\n", encoding="utf-8")
        with mock.patch.object(mod, "ROOT", repo):
            result = mod.repo_index(head)
        self.assertIn("tests/test_safe.py", result["files"])
        self.assertNotIn("ignored_runtime.py", result["files"])

    def test_model_endpoint_is_loopback_only(self):
        with mock.patch.object(mod, "MODEL_NAME", "qwen"), mock.patch.object(mod, "MODEL_ENDPOINT", "https://example.com/v1/chat/completions"), mock.patch.object(mod, "bound_identity", return_value=("a" * 40, "b" * 40)):
            with self.assertRaises(ValueError):
                mod.second_opinion("a" * 40, "evidence")

    def test_canonical_is_deterministic(self):
        self.assertEqual(mod.canonical({"b": 2, "a": 1}), b'{"a":1,"b":2}\n')


if __name__ == "__main__":
    unittest.main()
