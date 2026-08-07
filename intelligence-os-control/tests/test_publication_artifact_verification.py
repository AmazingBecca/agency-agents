from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import publication_attestation as attestation
import verify_publication_artifact as artifact_verifier


def canonical(value) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def zip_bytes(members: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name, raw in members:
            archive.writestr(name, raw)
    return output.getvalue()


class PublicationArtifactVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.receipt_path = self.root / attestation.RECEIPT_NAME
        self.publication_path = self.root / attestation.OUTPUT_NAME
        self.artifact_path = self.root / "artifact.zip"
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
            "run_attempt": "1",
        }
        self.publisher_sha = "e" * 40
        self.event = self.root / "event.json"
        self.event.write_text(
            json.dumps(
                {
                    "pull_request": {
                        "head": {"sha": self.authority["reviewed_head"]},
                        "base": {"sha": self.authority["reviewed_base"]},
                        "merge_commit_sha": self.authority["synthetic_merge"],
                    }
                }
            ),
            encoding="utf-8",
        )
        environment = {
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REPOSITORY": self.authority["repository"],
            "GITHUB_WORKFLOW_REF": self.authority["workflow_ref"],
            "GITHUB_WORKFLOW_SHA": self.authority["workflow_sha"],
            "GITHUB_RUN_ID": self.authority["run_id"],
            "GITHUB_RUN_ATTEMPT": self.authority["run_attempt"],
            "GITHUB_EVENT_PATH": str(self.event),
            "CONTROL_WORKFLOW_REPOSITORY": attestation.CONTROL_REPOSITORY,
            "CONTROL_WORKFLOW_FILE_PATH": attestation.CONTROL_WORKFLOW_PATH,
            "CONTROL_WORKFLOW_REF": (
                f"{attestation.CONTROL_REPOSITORY}/"
                f"{attestation.CONTROL_WORKFLOW_PATH}@{self.publisher_sha}"
            ),
            "CONTROL_WORKFLOW_SHA": self.publisher_sha,
            "RUNNER_TEMP": str(self.root),
        }
        receipt = {
            "schema": attestation.RECEIPT_SCHEMA,
            "repository": self.authority["repository"],
            "reviewed_head": self.authority["reviewed_head"],
            "reviewed_base": self.authority["reviewed_base"],
            "synthetic_merge": self.authority["synthetic_merge"],
            "workflow_authority": {
                "ref": self.authority["workflow_ref"],
                "sha": self.authority["workflow_sha"],
            },
            "workflow_run": {
                "id": self.authority["run_id"],
                "attempt": int(self.authority["run_attempt"]),
            },
            "archive_manifest": {"placeholder": True},
            "archive_canonicality": {"placeholder": True},
            "members": {"placeholder": True},
            "synthetic_merge_commit": {"placeholder": True},
            "verifier_components": {"placeholder": True},
        }
        receipt_raw = canonical(receipt)
        self.receipt_path.write_bytes(receipt_raw)
        self.receipt_path.chmod(0o600)
        self.receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
        attestation.attest(
            self.receipt_path,
            self.publication_path,
            self.receipt_sha256,
            self.authority,
            environment,
        )
        self.publication_raw = self.publication_path.read_bytes()
        self.publication_sha256 = hashlib.sha256(self.publication_raw).hexdigest()
        self.artifact_raw = zip_bytes(
            [(artifact_verifier.ARTIFACT_MEMBER_NAME, self.publication_raw)]
        )
        self.artifact_sha256 = hashlib.sha256(self.artifact_raw).hexdigest()
        self.artifact_path.write_bytes(self.artifact_raw)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_valid_github_digest_authenticates_embedded_publication(self) -> None:
        result = artifact_verifier.verify_artifact_file(
            self.artifact_path,
            self.artifact_sha256,
            self.publisher_sha,
            self.authority,
        )
        self.assertEqual(result["artifact_sha256"], self.artifact_sha256)
        self.assertEqual(result["publication_sha256"], self.publication_sha256)
        self.assertEqual(result["receipt_sha256"], self.receipt_sha256)

    def test_modified_archive_cannot_reuse_trusted_github_digest(self) -> None:
        attacked_publication = bytearray(self.publication_raw)
        attacked_publication[-2] ^= 1
        attacked_raw = zip_bytes(
            [(artifact_verifier.ARTIFACT_MEMBER_NAME, bytes(attacked_publication))]
        )
        with self.assertRaisesRegex(
            artifact_verifier.ArtifactVerificationError,
            "artifact digest does not match GitHub authority",
        ):
            artifact_verifier.verify_artifact(
                attacked_raw,
                self.artifact_sha256,
                self.publisher_sha,
                self.authority,
            )

    def test_extra_and_duplicate_members_fail_even_with_recomputed_archive_digest(self) -> None:
        attacks = (
            [
                (artifact_verifier.ARTIFACT_MEMBER_NAME, self.publication_raw),
                ("extra.txt", b"attacker"),
            ],
            [
                (artifact_verifier.ARTIFACT_MEMBER_NAME, self.publication_raw),
                (artifact_verifier.ARTIFACT_MEMBER_NAME, self.publication_raw),
            ],
        )
        for members in attacks:
            with self.subTest(member_count=len(members)):
                attacked_raw = zip_bytes(members)
                with self.assertRaisesRegex(
                    artifact_verifier.ArtifactVerificationError,
                    "artifact member inventory is not exact",
                ):
                    artifact_verifier.verify_artifact(
                        attacked_raw,
                        hashlib.sha256(attacked_raw).hexdigest(),
                        self.publisher_sha,
                        self.authority,
                    )

    def test_publisher_pivot_inside_authenticated_archive_is_rejected(self) -> None:
        publication = json.loads(self.publication_raw.decode("ascii"))
        pivot = "f" * 40
        publication["publisher_authority"] = {
            "repository": attestation.CONTROL_REPOSITORY,
            "workflow_path": attestation.CONTROL_WORKFLOW_PATH,
            "workflow_ref": (
                f"{attestation.CONTROL_REPOSITORY}/"
                f"{attestation.CONTROL_WORKFLOW_PATH}@{pivot}"
            ),
            "workflow_sha": pivot,
        }
        attacked_publication = canonical(publication)
        attacked_raw = zip_bytes(
            [(artifact_verifier.ARTIFACT_MEMBER_NAME, attacked_publication)]
        )
        with self.assertRaisesRegex(
            artifact_verifier.ArtifactVerificationError,
            "publisher authority does not match external authority",
        ):
            artifact_verifier.verify_artifact(
                attacked_raw,
                hashlib.sha256(attacked_raw).hexdigest(),
                self.publisher_sha,
                self.authority,
            )

    def test_wrong_member_name_and_malformed_archive_fail_closed(self) -> None:
        wrong_name = zip_bytes([("nested/publication.json", self.publication_raw)])
        with self.assertRaisesRegex(
            artifact_verifier.ArtifactVerificationError,
            "artifact publication member is outside policy",
        ):
            artifact_verifier.verify_artifact(
                wrong_name,
                hashlib.sha256(wrong_name).hexdigest(),
                self.publisher_sha,
                self.authority,
            )
        malformed = b"not-a-zip"
        with self.assertRaisesRegex(
            artifact_verifier.ArtifactVerificationError,
            "artifact is not a valid ZIP archive",
        ):
            artifact_verifier.verify_artifact(
                malformed,
                hashlib.sha256(malformed).hexdigest(),
                self.publisher_sha,
                self.authority,
            )


if __name__ == "__main__":
    unittest.main()
