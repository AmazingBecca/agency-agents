from __future__ import annotations

import email.message
import io
import unittest
import urllib.error
from unittest import mock

import verify_publication_github_api as verifier


TRUSTED_LOCATION = (
    "https://productionresultssa1.blob.core.windows.net/actions-results/"
    "artifact.zip?sig=synthetic"
)


class _Response:
    def __init__(self, body: bytes) -> None:
        self._body = io.BytesIO(body)
        self.status = 200
        self.headers = email.message.Message()
        self.headers["Content-Length"] = str(len(body))

    def read(self, amount: int = -1) -> bytes:
        return self._body.read(amount)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class PublicationGithubApiRedirectAuthorityTests(unittest.TestCase):
    def test_archive_location_rejects_noncanonical_control_space_and_fragment_forms(self) -> None:
        attacks = (
            f"{TRUSTED_LOCATION}#fragment",
            f" {TRUSTED_LOCATION}",
            f"{TRUSTED_LOCATION}\n",
            f"{TRUSTED_LOCATION}\t",
        )
        for location in attacks:
            with self.subTest(location=repr(location)), self.assertRaisesRegex(
                verifier.GithubApiAuthorityVerificationError,
                "malformed|outside trusted HTTPS storage policy",
            ):
                verifier._archive_location(location)

    def test_archive_location_rejects_ambiguous_path_forms(self) -> None:
        origin = "https://productionresultssa1.blob.core.windows.net"
        attacks = (
            f"{origin}//actions-results/artifact.zip?sig=synthetic",
            f"{origin}/actions-results\\artifact.zip?sig=synthetic",
            f"{origin}/actions-results/%2fartifact.zip?sig=synthetic",
            f"{origin}/actions-results/%5cartifact.zip?sig=synthetic",
            f"{origin}/actions-results/../artifact.zip?sig=synthetic",
            f"{origin}/actions-results/%2e%2e/artifact.zip?sig=synthetic",
        )
        for location in attacks:
            with self.subTest(location=location), self.assertRaisesRegex(
                verifier.GithubApiAuthorityVerificationError,
                "outside trusted HTTPS storage policy",
            ):
                verifier._archive_location(location)

    def test_archive_location_rejects_storage_origin_confusion(self) -> None:
        path = "/actions-results/artifact.zip?sig=synthetic"
        attacks = (
            f"https://blob.core.windows.net{path}",
            f"https://productionresultssa1.blob.core.windows.net.attacker.example{path}",
            f"https://githubusercontent.com{path}",
            f"https://raw.githubusercontent.com.attacker.example{path}",
            f"https://user@productionresultssa1.blob.core.windows.net{path}",
            f"https://productionresultssa1.blob.core.windows.net:8443{path}",
        )
        for location in attacks:
            with self.subTest(location=location), self.assertRaisesRegex(
                verifier.GithubApiAuthorityVerificationError,
                "outside trusted HTTPS storage policy",
            ):
                verifier._archive_location(location)

    def test_canonical_archive_location_remains_accepted(self) -> None:
        self.assertEqual(verifier._archive_location(TRUSTED_LOCATION), TRUSTED_LOCATION)

    def test_artifact_redirect_rejects_ambiguous_multiple_location_headers(self) -> None:
        headers = email.message.Message()
        headers["Location"] = TRUSTED_LOCATION
        headers["Location"] = "https://attacker.example/archive.zip?sig=x"
        redirect = urllib.error.HTTPError(
            "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/"
            "actions/artifacts/8976470096/zip",
            302,
            "Found",
            headers,
            None,
        )
        calls: list[object] = []

        def fake_open(request):
            calls.append(request)
            if len(calls) == 1:
                raise redirect
            return _Response(b"synthetic-archive")

        with mock.patch.object(verifier, "_open_no_redirect", side_effect=fake_open):
            with self.assertRaisesRegex(
                verifier.GithubApiAuthorityVerificationError,
                "redirect location is ambiguous",
            ):
                verifier._download_artifact(
                    "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/"
                    "actions/artifacts/8976470096/zip",
                    "github_pat_synthetic_control_token",
                )
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
