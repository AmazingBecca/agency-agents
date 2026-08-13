from __future__ import annotations

import email.message
import io
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import verify_publication_github_api as api_verifier


class _Response:
    def __init__(self, body: bytes = b"{}", status: int = 200) -> None:
        self._body = io.BytesIO(body)
        self.status = status
        self.headers = email.message.Message()
        self.headers["Content-Length"] = str(len(body))

    def read(self, amount: int = -1) -> bytes:
        return self._body.read(amount)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class PublicationGithubApiExactOriginAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.token = "github_pat_synthetic_control_token"

    def _assert_rejected_before_network(self, url: str) -> None:
        with mock.patch.object(
            api_verifier, "_open_no_redirect", return_value=_Response()
        ) as open_request:
            with self.assertRaisesRegex(
                api_verifier.GithubApiAuthorityVerificationError,
                "API URL is outside policy",
            ):
                api_verifier._api_get(url, self.token, 4096, "authority probe")
        open_request.assert_not_called()

    def test_fragment_is_rejected_before_bearer_request(self) -> None:
        self._assert_rejected_before_network(
            "https://api.github.com/repos/AmazingBecca/agency-agents#ignored"
        )

    def test_ambiguous_double_slash_path_is_rejected_before_bearer_request(self) -> None:
        self._assert_rejected_before_network(
            "https://api.github.com//repos/AmazingBecca/agency-agents"
        )

    def test_dot_segment_path_is_rejected_before_bearer_request(self) -> None:
        self._assert_rejected_before_network(
            "https://api.github.com/repos/AmazingBecca/../agency-agents/actions/runs/1"
        )

    def test_percent_encoded_dot_segment_is_rejected_before_bearer_request(self) -> None:
        self._assert_rejected_before_network(
            "https://api.github.com/repos/AmazingBecca/%2e%2e/agency-agents/actions/runs/1"
        )

    def test_percent_encoded_slash_is_rejected_before_bearer_request(self) -> None:
        self._assert_rejected_before_network(
            "https://api.github.com/repos/AmazingBecca%2Fagency-agents/actions/runs/1"
        )

    def test_percent_encoded_backslash_is_rejected_before_bearer_request(self) -> None:
        self._assert_rejected_before_network(
            "https://api.github.com/repos/AmazingBecca%5Cagency-agents/actions/runs/1"
        )

    def test_literal_backslash_is_rejected_before_bearer_request(self) -> None:
        self._assert_rejected_before_network(
            "https://api.github.com/repos/AmazingBecca\\agency-agents/actions/runs/1"
        )

    def test_userinfo_is_rejected_before_bearer_request(self) -> None:
        self._assert_rejected_before_network(
            "https://token@api.github.com/repos/AmazingBecca/agency-agents/actions/runs/1"
        )

    def test_explicit_port_is_rejected_before_bearer_request(self) -> None:
        self._assert_rejected_before_network(
            "https://api.github.com:443/repos/AmazingBecca/agency-agents/actions/runs/1"
        )

    def test_suffix_confusion_host_is_rejected_before_bearer_request(self) -> None:
        self._assert_rejected_before_network(
            "https://api.github.com.evil.invalid/repos/AmazingBecca/agency-agents/actions/runs/1"
        )

    def test_canonical_api_url_with_query_remains_accepted(self) -> None:
        with mock.patch.object(
            api_verifier, "_open_no_redirect", return_value=_Response(b"{}")
        ) as open_request:
            observed = api_verifier._api_get(
                "https://api.github.com/repos/AmazingBecca/agency-agents/actions/runs/1/artifacts?per_page=100",
                self.token,
                4096,
                "authority probe",
            )
        self.assertEqual(observed, b"{}")
        request = open_request.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/AmazingBecca/agency-agents/actions/runs/1/artifacts?per_page=100")
        self.assertTrue(request.has_header("Authorization"))


if __name__ == "__main__":
    unittest.main()
