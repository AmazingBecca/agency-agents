from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import verify_publication_artifact as artifact_verifier
import verify_publication_artifact_metadata as metadata_verifier


class PublicationArtifactMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifact_raw = b"synthetic-github-actions-artifact-archive"
        self.artifact_sha256 = hashlib.sha256(self.artifact_raw).hexdigest()
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
        self.metadata = {
            "id": artifact_id,
            "node_id": "MDg6QXJ0aWZhY3Q4OTc2NDcwMDk2",
            "name": (
                "intelligence-os-retained-evidence-publication-"
                f"head-{self.authority['reviewed_head']}-"
                f"merge-{self.authority['synthetic_merge']}-"
                f"publisher-{self.publisher_sha}-"
                f"run-{self.authority['run_id']}-{self.authority['run_attempt']}"
            ),
            "size_in_bytes": len(self.artifact_raw),
            "url": (
                f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}"
            ),
            "archive_download_url": (
                f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}/zip"
            ),
            "expired": False,
            "created_at": "2026-08-07T16:00:00Z",
            "expires_at": "2026-08-10T16:00:00Z",
            "updated_at": "2026-08-07T16:00:01Z",
            "digest": f"sha256:{self.artifact_sha256}",
            "workflow_run": {
                "id": int(self.authority["run_id"]),
                "repository_id": 1169064494,
                "head_repository_id": 1169064494,
                "head_branch": "control/private-intelligence-os-v1",
                "head_sha": self.authority["reviewed_head"],
            },
        }

    def validate(self, metadata=None):
        return metadata_verifier.validate_github_artifact_metadata(
            self.metadata if metadata is None else metadata,
            self.artifact_raw,
            self.publisher_sha,
            self.authority,
        )

    def test_valid_metadata_binds_archive_to_exact_github_run(self) -> None:
        self.assertEqual(self.validate(), self.artifact_sha256)

    def test_wrapper_derives_digest_only_after_metadata_validation(self) -> None:
        expected_result = {
            "artifact_sha256": self.artifact_sha256,
            "publication_sha256": "1" * 64,
            "receipt_sha256": "2" * 64,
        }
        with mock.patch.object(
            artifact_verifier,
            "verify_artifact",
            return_value=expected_result,
        ) as verify:
            observed = metadata_verifier.verify_artifact_from_metadata(
                self.artifact_raw,
                self.metadata,
                self.publisher_sha,
                self.authority,
            )
        self.assertEqual(observed, expected_result)
        verify.assert_called_once_with(
            self.artifact_raw,
            self.artifact_sha256,
            self.publisher_sha,
            self.authority,
        )

    def test_foreign_run_metadata_is_rejected_even_when_digest_matches(self) -> None:
        attacked = copy.deepcopy(self.metadata)
        attacked["workflow_run"]["id"] += 1
        with self.assertRaisesRegex(
            metadata_verifier.ArtifactMetadataVerificationError,
            "workflow run does not match expected run",
        ):
            self.validate(attacked)

    def test_foreign_repository_metadata_is_rejected_even_when_digest_matches(self) -> None:
        attacked = copy.deepcopy(self.metadata)
        attacked["url"] = attacked["url"].replace(
            "AmazingBecca/free-millionaire-pipeline",
            "AmazingBecca/agency-agents",
        )
        attacked["archive_download_url"] = attacked["archive_download_url"].replace(
            "AmazingBecca/free-millionaire-pipeline",
            "AmazingBecca/agency-agents",
        )
        with self.assertRaisesRegex(
            metadata_verifier.ArtifactMetadataVerificationError,
            "repository URL does not match expected authority",
        ):
            self.validate(attacked)

    def test_foreign_head_metadata_is_rejected_even_when_digest_matches(self) -> None:
        attacked = copy.deepcopy(self.metadata)
        attacked["workflow_run"]["head_sha"] = "f" * 40
        with self.assertRaisesRegex(
            metadata_verifier.ArtifactMetadataVerificationError,
            "workflow head does not match reviewed head",
        ):
            self.validate(attacked)

    def test_artifact_name_binds_head_merge_publisher_run_and_attempt(self) -> None:
        for replacement in (
            self.metadata["name"].replace(self.authority["reviewed_head"], "f" * 40),
            self.metadata["name"].replace(self.authority["synthetic_merge"], "f" * 40),
            self.metadata["name"].replace(self.publisher_sha, "f" * 40),
            self.metadata["name"].replace(
                f"run-{self.authority['run_id']}-{self.authority['run_attempt']}",
                f"run-{self.authority['run_id']}-3",
            ),
        ):
            with self.subTest(name=replacement):
                attacked = copy.deepcopy(self.metadata)
                attacked["name"] = replacement
                with self.assertRaisesRegex(
                    metadata_verifier.ArtifactMetadataVerificationError,
                    "artifact name does not match expected authority",
                ):
                    self.validate(attacked)

    def test_expired_size_and_digest_pivots_fail_closed(self) -> None:
        attacks = (
            ("expired", True, "expired or malformed"),
            ("size_in_bytes", len(self.artifact_raw) + 1, "byte count does not match"),
            ("digest", "sha256:" + "0" * 64, "does not match GitHub artifact digest"),
        )
        for field, value, message in attacks:
            with self.subTest(field=field):
                attacked = copy.deepcopy(self.metadata)
                attacked[field] = value
                with self.assertRaisesRegex(
                    metadata_verifier.ArtifactMetadataVerificationError,
                    message,
                ):
                    self.validate(attacked)

    def test_cross_repository_workflow_run_is_rejected(self) -> None:
        attacked = copy.deepcopy(self.metadata)
        attacked["workflow_run"]["head_repository_id"] += 1
        with self.assertRaisesRegex(
            metadata_verifier.ArtifactMetadataVerificationError,
            "crosses repository authority",
        ):
            self.validate(attacked)

    def test_metadata_inventory_and_duplicate_json_keys_fail_closed(self) -> None:
        attacked = copy.deepcopy(self.metadata)
        attacked["unreviewed"] = "authority"
        with self.assertRaisesRegex(
            metadata_verifier.ArtifactMetadataVerificationError,
            "inventory is not exact",
        ):
            self.validate(attacked)

        with self.assertRaisesRegex(
            metadata_verifier.ArtifactMetadataVerificationError,
            "duplicate JSON key",
        ):
            metadata_verifier._load_metadata(b'{"id":1,"id":2}\n')

    def test_metadata_files_are_bounded_before_json_parse(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "metadata.json"
            path.write_bytes(b"x" * (metadata_verifier.MAX_METADATA_BYTES + 1))
            with self.assertRaisesRegex(
                metadata_verifier.ArtifactMetadataVerificationError,
                "metadata is outside policy",
            ):
                metadata_verifier._read_bounded_regular(
                    path,
                    metadata_verifier.MAX_METADATA_BYTES,
                    "artifact metadata",
                )


if __name__ == "__main__":
    unittest.main()
