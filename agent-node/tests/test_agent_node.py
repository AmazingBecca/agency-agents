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

    def test_test_selector_requires_explicit_allowlist(self):
        with mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)), mock.patch.object(mod, "bound_head", return_value="a" * 40):
            with self.assertRaises(ValueError):
                mod.run_tests("a" * 40, "tests.test_other")

    def test_model_endpoint_is_loopback_only(self):
        with mock.patch.object(mod, "MODEL_NAME", "qwen"), mock.patch.object(mod, "MODEL_ENDPOINT", "https://example.com/v1/chat/completions"), mock.patch.object(mod, "bound_head", return_value="a" * 40):
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
