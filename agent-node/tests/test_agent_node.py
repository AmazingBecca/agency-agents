import hashlib
import importlib.util
import pathlib
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class AgentNodeContractTests(unittest.TestCase):
    def test_sha_validation_is_fail_closed(self):
        with self.assertRaises(ValueError):
            mod.bound_head("main")

    def test_bound_source_rejects_dirty_worktree(self):
        def fake_git(*args):
            if args == ("rev-parse", "HEAD"):
                return "a" * 40
            if args == ("status", "--porcelain=v1", "--untracked-files=all"):
                return " M tracked.py"
            raise AssertionError(args)
        with mock.patch.object(mod, "git", side_effect=fake_git):
            with self.assertRaisesRegex(ValueError, "not clean"):
                mod.bound_source("a" * 40)

    def test_bound_source_binds_commit_tree(self):
        def fake_git(*args):
            if args == ("rev-parse", "HEAD"):
                return "a" * 40
            if args == ("status", "--porcelain=v1", "--untracked-files=all"):
                return ""
            if args == ("rev-parse", "HEAD^{tree}"):
                return "b" * 40
            raise AssertionError(args)
        with mock.patch.object(mod, "git", side_effect=fake_git):
            self.assertEqual(mod.bound_source("a" * 40), ("a" * 40, "b" * 40))

    def test_test_selector_requires_explicit_allowlist(self):
        with mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)), mock.patch.object(mod, "bound_source", return_value=("a" * 40, "b" * 40)):
            with self.assertRaises(ValueError):
                mod.run_tests("a" * 40, "tests.test_other")

    def test_test_execution_rejects_post_run_source_drift(self):
        completed = mock.Mock(returncode=0, stdout="ok")
        with mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)), \
             mock.patch.object(mod, "bound_source", side_effect=[("a" * 40, "b" * 40), ("a" * 40, "c" * 40)]), \
             mock.patch.object(mod.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "changed during test"):
                mod.run_tests("a" * 40, "tests.test_safe")

    def test_test_stdout_digest_binds_exact_returned_bytes(self):
        full_output = "prefix-" + ("x" * 25000)
        completed = mock.Mock(returncode=0, stdout=full_output)
        with mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)), \
             mock.patch.object(mod, "bound_source", side_effect=[("a" * 40, "b" * 40), ("a" * 40, "b" * 40)]), \
             mock.patch.object(mod.subprocess, "run", return_value=completed) as run:
            result = mod.run_tests("a" * 40, "tests.test_safe")
        self.assertEqual(len(result["stdout"]), 20000)
        self.assertEqual(result["stdout"], full_output[-20000:])
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(result["stdout"].encode()).hexdigest())
        argv = run.call_args.args[0]
        self.assertIn("-I", argv)
        self.assertIn("-B", argv)

    def test_model_endpoint_is_loopback_only(self):
        with mock.patch.object(mod, "MODEL_NAME", "qwen"), mock.patch.object(mod, "MODEL_ENDPOINT", "https://example.com/v1/chat/completions"), mock.patch.object(mod, "bound_source", return_value=("a" * 40, "b" * 40)):
            with self.assertRaises(ValueError):
                mod.second_opinion("a" * 40, "evidence")

    def test_bound_head_rejects_identity_drift(self):
        with mock.patch.object(mod, "git", return_value="b" * 40):
            with self.assertRaises(ValueError):
                mod.bound_head("a" * 40)

    def test_canonical_is_deterministic(self):
        self.assertEqual(mod.canonical({"b": 2, "a": 1}), b'{"a":1,"b":2}\n')


if __name__ == "__main__":
    unittest.main()
