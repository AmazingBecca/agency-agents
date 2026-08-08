from __future__ import annotations

import contextlib
import io
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

import verify_bound_candidate_test_authority as legacy
import verify_authenticated_runner_bundle as bundle


class VerifierCliContractTests(unittest.TestCase):
    def test_legacy_entrypoint_only_cli_fails_closed_before_verification(self) -> None:
        stderr = io.StringIO()
        with patch.object(legacy, "verify_bound") as verifier, contextlib.redirect_stderr(stderr):
            result = legacy.main([])

        self.assertEqual(result, 2)
        verifier.assert_not_called()
        self.assertIn("direct entrypoint-only verification is disabled", stderr.getvalue())
        self.assertIn("verify_authenticated_runner_bundle.py", stderr.getvalue())

    def test_bundle_cli_remains_the_candidate_verification_cli(self) -> None:
        self.assertTrue(callable(bundle.main))
        self.assertTrue(callable(bundle.verify_authenticated_bundle))
        self.assertTrue(callable(legacy.verify_bound))


if __name__ == "__main__":
    unittest.main()
