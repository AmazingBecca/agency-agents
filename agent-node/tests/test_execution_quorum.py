import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "execution_quorum.py"
spec = importlib.util.spec_from_file_location("execution_quorum", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def receipt(worker: str, env: str, **changes):
    value = {
        "worker_id": worker,
        "head": "a" * 40,
        "tree": "b" * 40,
        "runtime_sha256": "c" * 64,
        "selector": "tests.test_safe",
        "returncode": 0,
        "stdout_sha256": "d" * 64,
        "environment_sha256": env,
    }
    value.update(changes)
    return value


class QuorumTests(unittest.TestCase):
    def test_two_distinct_workers_and_environments_form_advisory_quorum(self):
        q = mod.verify_quorum([receipt("w1", "e" * 64), receipt("w2", "f" * 64)], threshold=2)
        self.assertEqual(q["receipt_count"], 2)
        self.assertTrue(q["advisory_only"])
        self.assertFalse(q["promotion_authorized"])
        self.assertFalse(q["completion_authorized"])
        self.assertEqual(len(q["quorum_sha256"]), 64)

    def test_duplicate_worker_fails_closed(self):
        with self.assertRaisesRegex(mod.QuorumError, "worker identity"):
            mod.verify_quorum([receipt("w1", "e" * 64), receipt("w1", "f" * 64)], threshold=2)

    def test_duplicate_environment_fails_closed(self):
        with self.assertRaisesRegex(mod.QuorumError, "environment identity"):
            mod.verify_quorum([receipt("w1", "e" * 64), receipt("w2", "e" * 64)], threshold=2)

    def test_output_disagreement_fails_closed(self):
        with self.assertRaisesRegex(mod.QuorumError, "disagree"):
            mod.verify_quorum([receipt("w1", "e" * 64), receipt("w2", "f" * 64, stdout_sha256="9" * 64)], threshold=2)

    def test_source_or_selector_disagreement_fails_closed(self):
        for change in ({"head": "9" * 40}, {"tree": "9" * 40}, {"selector": "tests.test_other"}, {"returncode": 1}):
            with self.subTest(change=change):
                with self.assertRaisesRegex(mod.QuorumError, "disagree"):
                    mod.verify_quorum([receipt("w1", "e" * 64), receipt("w2", "f" * 64, **change)], threshold=2)

    def test_threshold_below_two_rejected(self):
        with self.assertRaisesRegex(mod.QuorumError, "threshold"):
            mod.verify_quorum([receipt("w1", "e" * 64)], threshold=1)


if __name__ == "__main__":
    unittest.main()
