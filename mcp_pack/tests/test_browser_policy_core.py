from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from browser_policy_core import check_navigation, classify_action, decide


class BrowserPolicyCoreTests(unittest.TestCase):
    def test_default_deny_without_domains(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            result = check_navigation("https://example.com/")
        self.assertEqual(result["decision"], "DENY")
        self.assertIn("default deny", str(result["reason"]))

    def test_exact_allowlisted_domain(self) -> None:
        with patch.dict(os.environ, {"BROWSER_POLICY_ALLOWED_DOMAINS": "example.com"}, clear=True):
            result = check_navigation("https://example.com/path")
        self.assertEqual(result["decision"], "ALLOW")

    def test_wildcard_allows_subdomain_not_apex(self) -> None:
        with patch.dict(os.environ, {"BROWSER_POLICY_ALLOWED_DOMAINS": "*.example.com"}, clear=True):
            self.assertEqual(check_navigation("https://a.example.com/")["decision"], "ALLOW")
            self.assertEqual(check_navigation("https://example.com/")["decision"], "DENY")

    def test_private_ip_denied_even_if_allowlisted(self) -> None:
        with patch.dict(os.environ, {"BROWSER_POLICY_ALLOWED_DOMAINS": "127.0.0.1"}, clear=True):
            result = check_navigation("http://127.0.0.1/")
        self.assertEqual(result["decision"], "DENY")
        self.assertIn("private/local/reserved", str(result["reason"]))

    def test_credentials_in_url_denied(self) -> None:
        with patch.dict(os.environ, {"BROWSER_POLICY_ALLOWED_DOMAINS": "example.com"}, clear=True):
            result = check_navigation("https://user:secret@example.com/")
        self.assertEqual(result["decision"], "DENY")

    def test_interactive_action_requires_approval(self) -> None:
        self.assertEqual(classify_action("click")["decision"], "REQUIRE_APPROVAL")

    def test_unknown_action_denied(self) -> None:
        self.assertEqual(classify_action("magic_power")["decision"], "DENY")

    def test_denied_navigation_overrides_read_action(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            result = decide("navigate", "https://example.com/")
        self.assertEqual(result["decision"], "DENY")


if __name__ == "__main__":
    unittest.main()
