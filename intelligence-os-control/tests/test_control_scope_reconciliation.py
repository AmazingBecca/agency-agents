import inspect
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execution_expectation as ee


class ControlScopeReconciliationTests(unittest.TestCase):
    def test_materialization_requires_issued_root_identity(self):
        parameters = inspect.signature(ee.materialize_trusted_receipt).parameters
        self.assertEqual(
            list(parameters),
            ["receipt", "output", "trusted_root", "expected_root_identity"],
        )
        self.assertIs(parameters["expected_root_identity"].default, inspect._empty)

    def test_cli_carries_bound_root_identity_from_issuance_to_publication(self):
        source = inspect.getsource(ee.main)
        self.assertIn("receipt, root_identity = issue_bound_receipt_from_files(", source)
        self.assertIn("root_identity,", source)
        self.assertNotIn("issue_receipt_from_files(", source)

    def test_publication_uses_same_verified_directory_object(self):
        source = inspect.getsource(ee.materialize_trusted_receipt)
        self.assertIn("observed_root_identity = (root_info.st_dev, root_info.st_ino)", source)
        self.assertIn("observed_root_identity != expected_root_identity", source)
        self.assertIn("dir_fd=root_fd", source)
        self.assertNotIn("er.materialize_receipt(", source)


if __name__ == "__main__":
    unittest.main()
