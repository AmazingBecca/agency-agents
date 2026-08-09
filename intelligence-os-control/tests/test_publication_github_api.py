from __future__ import annotations

import copy
import email.message
import hashlib
import io
import pathlib
import sys
import unittest
import urllib.error
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import verify_publication_github_api as api_verifier


class _Response:
    def __init__(self, body: bytes, status: int = 200) -> None:
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


class PublicationGithubApiAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.token = "github_pat_synthetic_control_token"
        self.publisher_sha = "e" * 40
        self.authority = {
            "repository": "AmazingBecca/free-millionaire-pipeline",
            "reviewed_head": "a" * 40,
            "reviewed_base": "b" * 40,
            "synthetic_merge": "c" * 40,
            "workflow_ref": (
                "AmazingBecca/free-millionaire-pipeline/"
                ".github/workflows/intelligence-os.yml@refs/pull/14/merge"
            ),
            "workflow_sha": "d" * 40,
            "run_id": "123456789",
            "run_attempt": "2",
        }
        self.artifact_raw = b"synthetic-archive"
        artifact_id = 8976470096
        repository = self.authority["repository"]
        repository_id = 1169064494
        head_branch = "fix/structured-processor-integrity-v2"
        digest = hashlib.sha256(self.artifact_raw).hexdigest()
        self.artifact_metadata = {
            "id": artifact_id,
            "name": api_verifier.artifact_metadata_verifier._expected_artifact_name(
                self.authority, self.publisher_sha
            ),
            "size_in_bytes": len(self.artifact_raw),
            "url": f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}",
            "archive_download_url": (
                f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}/zip"
            ),
            "expired": False,
            "created_at": "2026-08-07T16:00:00Z",
            "expires_at": "2026-08-10T16:00:00Z",
            "updated_at": "2026-08-07T16:00:01Z",
            "digest": f"sha256:{digest}",
            "workflow_run": {
                "id": int(self.authority["run_id"]),
                "repository_id": repository_id,
                "head_repository_id": repository_id,
                "head_branch": head_branch,
                "head_sha": self.authority["reviewed_head"],
            },
        }
        run_id = int(self.authority["run_id"])
        workflow_id = 328937109
        self.run_metadata = {
            "id": run_id,
            "head_branch": head_branch,
            "head_sha": self.authority["reviewed_head"],
            "event": "pull_request",
            "status": "completed",
            "conclusion": "success",
            "workflow_id": workflow_id,
            "path": ".github/workflows/intelligence-os.yml",
            "run_attempt": int(self.authority["run_attempt"]),
            "url": f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
            "artifacts_url": (
                f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/artifacts"
            ),
            "workflow_url": (
                f"https://api.github.com/repos/{repository}/actions/workflows/{workflow_id}"
            ),
            "repository": {"id": repository_id, "full_name": repository},
            "head_repository": {"id": repository_id, "full_name": repository},
            "pull_requests": [
                {
                    "number": 14,
                    "head": {
                        "sha": self.authority["reviewed_head"],
                        "repo": {"full_name": repository},
                    },
                    "base": {
                        "sha": self.authority["reviewed_base"],
                        "repo": {"full_name": repository},
                    },
                }
            ],
        }

    @staticmethod
    def _json(value) -> bytes:
        import json

        return json.dumps(value, separators=(",", ":")).encode("utf-8")

    def _responses(self, run=None, artifacts=None):
        run_value = self.run_metadata if run is None else run
        artifacts_value = [self.artifact_metadata] if artifacts is None else artifacts
        return [
            self._json(run_value),
            self._json({"total_count": len(artifacts_value), "artifacts": artifacts_value}),
        ]

    def test_authenticated_api_fetch_binds_exact_run_nonpromotion_artifact_and_archive(self) -> None:
        responses = self._responses()
        expected_publication = {
            "diagnostic_sha256": "0" * 64,
            "publication_sha256": "f" * 64,
        }
        with mock.patch.object(api_verifier, "_api_get", side_effect=responses) as api_get, mock.patch.object(
            api_verifier, "_download_artifact", return_value=self.artifact_raw
        ) as download, mock.patch.object(
            api_verifier.run_verifier,
            "verify_artifact_from_github_authority",
            return_value=expected_publication,
        ) as final_verify:
            observed = api_verifier.verify_from_github_api(
                self.token, self.publisher_sha, self.authority
            )
        self.assertEqual(observed, expected_publication)
        self.assertIn("diagnostic-not-promotion", self.artifact_metadata["name"])
        run_url = (
            "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/"
            "actions/runs/123456789"
        )
        self.assertEqual(api_get.call_args_list[0].args[0], run_url)
        self.assertEqual(
            api_get.call_args_list[1].args[0],
            f"{run_url}/artifacts?per_page=100",
        )
        download.assert_called_once_with(
            "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/"
            "actions/artifacts/8976470096/zip",
            self.token,
        )
        final_verify.assert_called_once()

    def test_wrong_run_authority_is_rejected_before_archive_download(self) -> None:
        attacked = copy.deepcopy(self.run_metadata)
        attacked["head_sha"] = "f" * 40
        with mock.patch.object(
            api_verifier, "_api_get", side_effect=self._responses(run=attacked)
        ), mock.patch.object(api_verifier, "_download_artifact") as download:
            with self.assertRaisesRegex(
                api_verifier.GithubApiAuthorityVerificationError,
                "head does not match reviewed head",
            ):
                api_verifier.verify_from_github_api(
                    self.token, self.publisher_sha, self.authority
                )
        download.assert_not_called()

    def test_missing_or_ambiguous_exact_artifact_is_rejected_before_download(self) -> None:
        wrong = copy.deepcopy(self.artifact_metadata)
        wrong["name"] = "other-artifact"
        for artifacts in ([wrong], [self.artifact_metadata, copy.deepcopy(self.artifact_metadata)]):
            with self.subTest(count=len(artifacts)), mock.patch.object(
                api_verifier, "_api_get", side_effect=self._responses(artifacts=artifacts)
            ), mock.patch.object(api_verifier, "_download_artifact") as download:
                with self.assertRaisesRegex(
                    api_verifier.GithubApiAuthorityVerificationError,
                    "missing or ambiguous",
                ):
                    api_verifier.verify_from_github_api(
                        self.token, self.publisher_sha, self.authority
                    )
                download.assert_not_called()

    def test_incomplete_artifact_page_fails_closed(self) -> None:
        listing = self._json(
            {"total_count": 101, "artifacts": [self.artifact_metadata]}
        )
        with mock.patch.object(
            api_verifier,
            "_api_get",
            side_effect=[self._json(self.run_metadata), listing],
        ), mock.patch.object(api_verifier, "_download_artifact") as download:
            with self.assertRaisesRegex(
                api_verifier.GithubApiAuthorityVerificationError,
                "incomplete or exceeds",
            ):
                api_verifier.verify_from_github_api(
                    self.token, self.publisher_sha, self.authority
                )
        download.assert_not_called()

    def test_token_is_mandatory_before_network_access(self) -> None:
        for token in ("", " token", "token\n", "x" * 5000):
            with self.subTest(token=repr(token)), mock.patch.object(
                api_verifier, "_api_get"
            ) as api_get:
                with self.assertRaisesRegex(
                    api_verifier.GithubApiAuthorityVerificationError,
                    "token is malformed",
                ):
                    api_verifier.verify_from_github_api(
                        token, self.publisher_sha, self.authority
                    )
                api_get.assert_not_called()

    def test_archive_redirect_strips_authorization_before_storage_fetch(self) -> None:
        location = (
            "https://productionresultssa1.blob.core.windows.net/actions-results/"
            "artifact.zip?sig=synthetic"
        )
        headers = email.message.Message()
        headers["Location"] = location
        redirect = urllib.error.HTTPError(
            "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/"
            "actions/artifacts/8976470096/zip",
            302,
            "Found",
            headers,
            None,
        )
        requests = []

        def fake_open(request):
            requests.append(request)
            if len(requests) == 1:
                raise redirect
            return _Response(self.artifact_raw)

        with mock.patch.object(api_verifier, "_open_no_redirect", side_effect=fake_open):
            observed = api_verifier._download_artifact(
                "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/"
                "actions/artifacts/8976470096/zip",
                self.token,
            )
        self.assertEqual(observed, self.artifact_raw)
        self.assertEqual(
            requests[0].get_header("Authorization"), f"Bearer {self.token}"
        )
        self.assertIsNone(requests[1].get_header("Authorization"))
        self.assertEqual(requests[1].full_url, location)

    def test_archive_redirect_to_untrusted_host_fails_before_second_request(self) -> None:
        headers = email.message.Message()
        headers["Location"] = "https://attacker.example/archive.zip?sig=x"
        redirect = urllib.error.HTTPError(
            "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/"
            "actions/artifacts/8976470096/zip",
            302,
            "Found",
            headers,
            None,
        )
        with mock.patch.object(
            api_verifier, "_open_no_redirect", side_effect=redirect
        ) as opened:
            with self.assertRaisesRegex(
                api_verifier.GithubApiAuthorityVerificationError,
                "outside trusted HTTPS storage policy",
            ):
                api_verifier._download_artifact(
                    "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/"
                    "actions/artifacts/8976470096/zip",
                    self.token,
                )
        self.assertEqual(opened.call_count, 1)

    def test_metadata_api_redirect_is_not_followed_with_token(self) -> None:
        headers = email.message.Message()
        headers["Location"] = "https://attacker.example/metadata"
        redirect = urllib.error.HTTPError(
            "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/actions/runs/1",
            302,
            "Found",
            headers,
            None,
        )
        with mock.patch.object(
            api_verifier, "_open_no_redirect", side_effect=redirect
        ) as opened:
            with self.assertRaisesRegex(
                api_verifier.GithubApiAuthorityVerificationError,
                "failed with status 302",
            ):
                api_verifier._api_get(
                    "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/actions/runs/1",
                    self.token,
                    1024,
                    "workflow-run metadata",
                )
        self.assertEqual(opened.call_count, 1)

    def test_duplicate_artifact_listing_keys_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            api_verifier.GithubApiAuthorityVerificationError,
            "duplicate JSON key",
        ):
            api_verifier._load_json(
                b'{"total_count":1,"total_count":2,"artifacts":[]}',
                "artifact listing",
            )

    def test_selected_artifact_repository_url_and_digest_are_exact(self) -> None:
        attacks = (
            ("url", "https://api.github.com/repos/AmazingBecca/agency-agents/actions/artifacts/8976470096", "URL does not match"),
            ("archive_download_url", "https://api.github.com/repos/AmazingBecca/agency-agents/actions/artifacts/8976470096/zip", "URL does not match"),
            ("digest", "sha256:" + "A" * 64, "digest is malformed"),
            ("expired", True, "expired or malformed"),
        )
        for field, value, message in attacks:
            with self.subTest(field=field):
                attacked = copy.deepcopy(self.artifact_metadata)
                attacked[field] = value
                with self.assertRaisesRegex(
                    api_verifier.GithubApiAuthorityVerificationError,
                    message,
                ):
                    api_verifier._select_artifact(
                        {"total_count": 1, "artifacts": [attacked]},
                        self.artifact_metadata["name"],
                        self.authority["repository"],
                    )


if __name__ == "__main__":
    unittest.main()
