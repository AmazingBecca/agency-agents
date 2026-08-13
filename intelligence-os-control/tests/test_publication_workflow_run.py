from __future__ import annotations

import copy
import hashlib
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import verify_publication_artifact_metadata as artifact_metadata_verifier
import verify_publication_workflow_run as run_verifier


class PublicationWorkflowRunAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifact_raw = b"synthetic-github-actions-artifact-archive"
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
        artifact_id = 8976470096
        repository = self.authority["repository"]
        repository_id = 1169064494
        head_branch = "fix/structured-processor-integrity-v2"
        digest = hashlib.sha256(self.artifact_raw).hexdigest()
        self.artifact_metadata = {
            "id": artifact_id,
            "name": artifact_metadata_verifier._expected_artifact_name(
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

    def validate(self, run_metadata=None, artifact_metadata=None) -> None:
        run_verifier.validate_github_workflow_run_metadata(
            self.run_metadata if run_metadata is None else run_metadata,
            self.artifact_metadata if artifact_metadata is None else artifact_metadata,
            self.authority,
        )

    def test_valid_run_metadata_binds_nonpromotion_artifact_to_exact_workflow_authority(self) -> None:
        self.validate()
        self.assertIn("diagnostic-not-promotion", self.artifact_metadata["name"])

    def test_wrapper_rejects_run_authority_before_artifact_semantics(self) -> None:
        attacked = copy.deepcopy(self.run_metadata)
        attacked["path"] = ".github/workflows/attacker.yml"
        with mock.patch.object(
            artifact_metadata_verifier,
            "verify_artifact_from_metadata",
        ) as verify:
            with self.assertRaisesRegex(
                run_verifier.WorkflowRunMetadataVerificationError,
                "path does not match expected workflow",
            ):
                run_verifier.verify_artifact_from_github_authority(
                    self.artifact_raw,
                    self.artifact_metadata,
                    attacked,
                    self.publisher_sha,
                    self.authority,
                )
        verify.assert_not_called()

    def test_event_attempt_and_completion_pivots_fail_closed(self) -> None:
        attacks = (
            ("event", "push", "event is not pull_request"),
            ("run_attempt", 3, "attempt does not match"),
            ("status", "in_progress", "not completed successfully"),
            ("conclusion", "failure", "not completed successfully"),
        )
        for field, value, message in attacks:
            with self.subTest(field=field):
                attacked = copy.deepcopy(self.run_metadata)
                attacked[field] = value
                with self.assertRaisesRegex(
                    run_verifier.WorkflowRunMetadataVerificationError,
                    message,
                ):
                    self.validate(run_metadata=attacked)

    def test_foreign_workflow_path_and_url_fail_closed(self) -> None:
        attacks = (
            ("path", ".github/workflows/attacker.yml", "path does not match"),
            (
                "workflow_url",
                "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/actions/workflows/1",
                "workflow URL does not match",
            ),
            (
                "url",
                "https://api.github.com/repos/AmazingBecca/free-millionaire-pipeline/actions/runs/1",
                "workflow run URL does not match",
            ),
        )
        for field, value, message in attacks:
            with self.subTest(field=field):
                attacked = copy.deepcopy(self.run_metadata)
                attacked[field] = value
                with self.assertRaisesRegex(
                    run_verifier.WorkflowRunMetadataVerificationError,
                    message,
                ):
                    self.validate(run_metadata=attacked)

    def test_repository_identity_is_external_to_artifact_payload(self) -> None:
        attacked = copy.deepcopy(self.run_metadata)
        attacked["repository"]["full_name"] = "AmazingBecca/agency-agents"
        attacked["head_repository"]["full_name"] = "AmazingBecca/agency-agents"
        with self.assertRaisesRegex(
            run_verifier.WorkflowRunMetadataVerificationError,
            "does not match expected repository",
        ):
            self.validate(run_metadata=attacked)

    def test_pull_request_number_head_and_base_are_bound(self) -> None:
        attacks = (
            ("number", 15),
            ("head", {"sha": "f" * 40}),
            ("base", {"sha": "f" * 40}),
        )
        for field, value in attacks:
            with self.subTest(field=field):
                attacked = copy.deepcopy(self.run_metadata)
                attacked["pull_requests"][0][field] = value
                with self.assertRaisesRegex(
                    run_verifier.WorkflowRunMetadataVerificationError,
                    "pull-request identity does not match",
                ):
                    self.validate(run_metadata=attacked)

    def test_artifact_and_run_metadata_must_describe_same_run(self) -> None:
        attacks = (
            ("id", int(self.authority["run_id"]) + 1, "disagree on run ID"),
            ("head_branch", "other-branch", "disagree on head branch"),
            ("repository_id", 1, "disagree on repository"),
            ("head_repository_id", 1, "disagree on head repository"),
            ("head_sha", "f" * 40, "disagree on head"),
        )
        for field, value, message in attacks:
            with self.subTest(field=field):
                artifact = copy.deepcopy(self.artifact_metadata)
                artifact["workflow_run"][field] = value
                with self.assertRaisesRegex(
                    run_verifier.WorkflowRunMetadataVerificationError,
                    message,
                ):
                    self.validate(artifact_metadata=artifact)

    def test_missing_authority_fields_and_duplicate_json_fail_closed(self) -> None:
        attacked = copy.deepcopy(self.run_metadata)
        del attacked["event"]
        with self.assertRaisesRegex(
            run_verifier.WorkflowRunMetadataVerificationError,
            "missing required authority fields",
        ):
            self.validate(run_metadata=attacked)

        with self.assertRaisesRegex(
            run_verifier.WorkflowRunMetadataVerificationError,
            "duplicate JSON key",
        ):
            run_verifier._load_run_metadata(b'{"id":1,"id":2}\n')


if __name__ == "__main__":
    unittest.main()
