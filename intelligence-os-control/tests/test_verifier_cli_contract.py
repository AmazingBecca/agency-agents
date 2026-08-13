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
import verify_terminal_candidate_authority as terminal


class VerifierCliContractTests(unittest.TestCase):
    def test_legacy_entrypoint_only_cli_fails_closed_before_verification(self) -> None:
        stderr = io.StringIO()
        with patch.object(legacy, "verify_bound") as verifier, contextlib.redirect_stderr(stderr):
            result = legacy.main([])

        self.assertEqual(result, 2)
        verifier.assert_not_called()
        self.assertIn("direct entrypoint-only verification is disabled", stderr.getvalue())
        self.assertIn("verify_terminal_candidate_authority.py", stderr.getvalue())

    def test_authenticated_bundle_cli_is_internal_only_and_fails_closed(self) -> None:
        stderr = io.StringIO()
        with patch.object(bundle, "verify_authenticated_bundle") as verifier, contextlib.redirect_stderr(stderr):
            result = bundle.main([])

        self.assertEqual(result, 2)
        verifier.assert_not_called()
        self.assertIn("internal diagnostic layer", stderr.getvalue())
        self.assertIn("verify_terminal_candidate_authority.py", stderr.getvalue())

    def test_terminal_composite_is_the_only_candidate_verification_cli(self) -> None:
        self.assertTrue(callable(terminal.main))
        self.assertTrue(callable(terminal.verify_terminal_bundle))
        self.assertTrue(callable(bundle.verify_authenticated_bundle))
        self.assertTrue(callable(legacy.verify_bound))


if __name__ == "__main__":
    unittest.main()
