from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import publication_attestation as attestation
import publish_retained_evidence as publisher
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


def diagnostic_bytes(publication_raw: bytes, **overrides) -> bytes:
    value = {
        "schema": artifact_verifier.DIAGNOSTIC_SCHEMA,
        "authority_level": artifact_verifier.DIAGNOSTIC_AUTHORITY_LEVEL,
        "promotion_authority_ready": False,
        "promotion_authorized": False,
        "publication": {
            "name": attestation.OUTPUT_NAME,
            "encoding": "base64",
            "bytes": len(publication_raw),
            "sha256": hashlib.sha256(publication_raw).hexdigest(),
            "data": base64.b64encode(publication_raw).decode("ascii"),
        },
    }
    value.update(overrides)
    return canonical(value)


def valid_receipt(authority: dict[str, str]) -> dict:
    execution = {
        "repository": authority["repository"],
        "workflow_ref": authority["workflow_ref"],
        "workflow_sha": authority["workflow_sha"],
        "run_id": authority["run_id"],
        "run_attempt": authority["run_attempt"],
        "head_sha": authority["reviewed_head"],
        "reviewed_base": authority["reviewed_base"],
        "synthetic_merge": authority["synthetic_merge"],
    }
    manifest_sha = "1" * 64
    archive_sha = "2" * 64
    components = {}
    for index, name in enumerate(sorted(publisher.COMPONENT_NAMES), start=3):
        components[name] = {
            "name": name,
            "bytes": 100 + index,
            "sha256": f"{index:x}" * 64,
            "git_blob": f"{index:x}" * 40,
        }
    return {
        "schema": attestation.RECEIPT_SCHEMA,
        "repository": authority["repository"],
        "reviewed_head": authority["reviewed_head"],
        "reviewed_base": authority["reviewed_base"],
        "synthetic_merge": authority["synthetic_merge"],
        "workflow_authority": {
            "ref": authority["workflow_ref"],
            "sha": authority["workflow_sha"],
        },
        "workflow_run": {
            "id": authority["run_id"],
            "attempt": int(authority["run_attempt"]),
        },
        "archive_manifest": {
            "name": publisher.MANIFEST_NAME,
            "bytes": 321,
            "sha256": manifest_sha,
            "execution": execution,
        },
        "archive_canonicality": {
            "schema": publisher.WHEELHOUSE_SCHEMA,
            "archive_bytes": 654,
            "archive_sha256": archive_sha,
            "manifest_bytes": 321,
            "manifest_sha256": manifest_sha,
            "execution": execution,
            "wheel_count": 1,
            "wheel_names": ["example-1.0-py3-none-any.whl"],
        },
        "members": {
            publisher.SOURCE_IDENTITY_NAME: {"bytes": 111, "sha256": "6" * 64},
            publisher.WHEELHOUSE_ARCHIVE_NAME: {"bytes": 654, "sha256": archive_sha},
            publisher.BINDING_NAME: {"bytes": 222, "sha256": "7" * 64},
        },
        "synthetic_merge_commit": {
            "schema": publisher.MERGE_COMMIT_SCHEMA,
            "name": "intelligence-os-synthetic-merge.commit",
            "bytes": 333,
            "sha256": "8" * 64,
            "git_commit": authority["synthetic_merge"],
            "parents": [authority["reviewed_base"], authority["reviewed_head"]],
        },
        "verifier_components": {
            "schema": publisher.COMPONENT_SCHEMA,
            "components": components,
        },
    }


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
        self.receipt = valid_receipt(self.authority)
        receipt_raw = canonical(self.receipt)
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
        self.diagnostic_raw = diagnostic_bytes(self.publication_raw)
        self.diagnostic_sha256 = hashlib.sha256(self.diagnostic_raw).hexdigest()
        self.artifact_raw = zip_bytes(
            [(artifact_verifier.ARTIFACT_MEMBER_NAME, self.diagnostic_raw)]
        )
        self.artifact_sha256 = hashlib.sha256(self.artifact_raw).hexdigest()
        self.artifact_path.write_bytes(self.artifact_raw)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_valid_github_digest_authenticates_nonpromotion_diagnostic_and_publication(self) -> None:
        result = artifact_verifier.verify_artifact_file(
            self.artifact_path,
            self.artifact_sha256,
            self.publisher_sha,
            self.authority,
        )
        self.assertEqual(result["artifact_sha256"], self.artifact_sha256)
        self.assertEqual(result["diagnostic_sha256"], self.diagnostic_sha256)
        self.assertEqual(result["publication_sha256"], self.publication_sha256)
        self.assertEqual(result["receipt_sha256"], self.receipt_sha256)

    def test_raw_publication_is_not_accepted_as_artifact_member(self) -> None:
        attacked_raw = zip_bytes(
            [(artifact_verifier.ARTIFACT_MEMBER_NAME, self.publication_raw)]
        )
        with self.assertRaises(artifact_verifier.ArtifactVerificationError):
            artifact_verifier.verify_artifact(
                attacked_raw,
                hashlib.sha256(attacked_raw).hexdigest(),
                self.publisher_sha,
                self.authority,
            )

    def test_diagnostic_cannot_claim_promotion_readiness_or_authority(self) -> None:
        for field in ("promotion_authority_ready", "promotion_authorized"):
            with self.subTest(field=field):
                attacked_diagnostic = diagnostic_bytes(self.publication_raw, **{field: True})
                attacked_raw = zip_bytes(
                    [(artifact_verifier.ARTIFACT_MEMBER_NAME, attacked_diagnostic)]
                )
                with self.assertRaisesRegex(
                    artifact_verifier.ArtifactVerificationError,
                    "promotion",
                ):
                    artifact_verifier.verify_artifact(
                        attacked_raw,
                        hashlib.sha256(attacked_raw).hexdigest(),
                        self.publisher_sha,
                        self.authority,
                    )

    def test_authenticated_archive_with_semantic_receipt_corruption_fails_closed(self) -> None:
        publication = json.loads(self.publication_raw.decode("ascii"))
        receipt = copy.deepcopy(self.receipt)
        receipt["archive_manifest"]["sha256"] = "9" * 64
        receipt_raw = canonical(receipt)
        record = publication["verification_receipt"]
        record["bytes"] = len(receipt_raw)
        record["sha256"] = hashlib.sha256(receipt_raw).hexdigest()
        record["data"] = base64.b64encode(receipt_raw).decode("ascii")
        attacked_publication = canonical(publication)
        attacked_diagnostic = diagnostic_bytes(attacked_publication)
        attacked_raw = zip_bytes(
            [(artifact_verifier.ARTIFACT_MEMBER_NAME, attacked_diagnostic)]
        )
        with self.assertRaisesRegex(
            artifact_verifier.ArtifactVerificationError,
            "archive manifest and canonicality summary disagree",
        ):
            artifact_verifier.verify_artifact(
                attacked_raw,
                hashlib.sha256(attacked_raw).hexdigest(),
                self.publisher_sha,
                self.authority,
            )

    def test_modified_archive_cannot_reuse_trusted_github_digest(self) -> None:
        attacked = bytearray(self.diagnostic_raw)
        attacked[-2] ^= 1
        attacked_raw = zip_bytes(
            [(artifact_verifier.ARTIFACT_MEMBER_NAME, bytes(attacked))]
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
                (artifact_verifier.ARTIFACT_MEMBER_NAME, self.diagnostic_raw),
                ("extra.txt", b"attacker"),
            ],
            [
                (artifact_verifier.ARTIFACT_MEMBER_NAME, self.diagnostic_raw),
                (artifact_verifier.ARTIFACT_MEMBER_NAME, self.diagnostic_raw),
            ],
        )
        for members in attacks:
            with self.subTest(member_count=len(members)):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
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
        attacked_diagnostic = diagnostic_bytes(attacked_publication)
        attacked_raw = zip_bytes(
            [(artifact_verifier.ARTIFACT_MEMBER_NAME, attacked_diagnostic)]
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
        wrong_name = zip_bytes([("nested/diagnostic.json", self.diagnostic_raw)])
        with self.assertRaisesRegex(
            artifact_verifier.ArtifactVerificationError,
            "artifact diagnostic member is outside policy",
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
