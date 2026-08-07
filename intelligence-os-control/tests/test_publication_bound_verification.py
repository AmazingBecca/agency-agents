from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import publication_attestation as attestation
import verify_publication_attestation as verifier


def canonical(value) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


class PublicationBoundVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.receipt_path = self.root / attestation.RECEIPT_NAME
        self.publication_path = self.root / attestation.OUTPUT_NAME
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
        self.environment = {
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
        self.receipt = {
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
        self.receipt_raw = canonical(self.receipt)
        self.receipt_path.write_bytes(self.receipt_raw)
        self.receipt_path.chmod(0o600)
        self.receipt_sha256 = hashlib.sha256(self.receipt_raw).hexdigest()
        self.publication_sha256 = attestation.attest(
            self.receipt_path,
            self.publication_path,
            self.receipt_sha256,
            self.authority,
            self.environment,
        )
        self.publication_raw = self.publication_path.read_bytes()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _publication(self):
        return json.loads(self.publication_raw.decode("ascii"))

    def test_valid_export_requires_external_publication_and_publisher_authority(self) -> None:
        observed_receipt = verifier.verify_publication_file(
            self.publication_path,
            self.publication_sha256,
            self.publisher_sha,
            self.authority,
        )
        self.assertEqual(observed_receipt, self.receipt_sha256)

    def test_recomputed_embedded_receipt_is_rejected_by_external_publication_digest(self) -> None:
        attacked = self._publication()
        receipt = copy.deepcopy(self.receipt)
        receipt["members"] = {"attacker_supplied": True}
        receipt_raw = canonical(receipt)
        record = attacked["verification_receipt"]
        record["bytes"] = len(receipt_raw)
        record["sha256"] = hashlib.sha256(receipt_raw).hexdigest()
        record["data"] = base64.b64encode(receipt_raw).decode("ascii")
        attacked_raw = canonical(attacked)
        self.assertNotEqual(hashlib.sha256(attacked_raw).hexdigest(), self.publication_sha256)
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "publication digest does not match external authority",
        ):
            verifier.verify_publication(
                attacked_raw,
                self.publication_sha256,
                self.publisher_sha,
                self.authority,
            )

    def test_recomputed_publisher_pivot_is_rejected_by_external_publisher_sha(self) -> None:
        attacked = self._publication()
        pivot = "f" * 40
        attacked["publisher_authority"] = {
            "repository": attestation.CONTROL_REPOSITORY,
            "workflow_path": attestation.CONTROL_WORKFLOW_PATH,
            "workflow_ref": (
                f"{attestation.CONTROL_REPOSITORY}/"
                f"{attestation.CONTROL_WORKFLOW_PATH}@{pivot}"
            ),
            "workflow_sha": pivot,
        }
        attacked_raw = canonical(attacked)
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "publisher authority does not match external authority",
        ):
            verifier.verify_publication(
                attacked_raw,
                hashlib.sha256(attacked_raw).hexdigest(),
                self.publisher_sha,
                self.authority,
            )

    def test_recomputed_caller_pivot_is_rejected_by_external_caller_authority(self) -> None:
        attacked = self._publication()
        attacked["caller_authority"]["reviewed_head"] = "f" * 40
        attacked_raw = canonical(attacked)
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "caller authority does not match external authority",
        ):
            verifier.verify_publication(
                attacked_raw,
                hashlib.sha256(attacked_raw).hexdigest(),
                self.publisher_sha,
                self.authority,
            )

    def test_noncanonical_or_malformed_embedded_receipt_transport_is_rejected(self) -> None:
        attacked = self._publication()
        attacked["verification_receipt"]["data"] += "\n"
        attacked_raw = canonical(attacked)
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "verification receipt base64 is malformed",
        ):
            verifier.verify_publication(
                attacked_raw,
                hashlib.sha256(attacked_raw).hexdigest(),
                self.publisher_sha,
                self.authority,
            )

    def test_expected_authorities_are_lowercase_exact_width(self) -> None:
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_publication(
                self.publication_raw,
                self.publication_sha256.upper(),
                self.publisher_sha,
                self.authority,
            )
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_publication(
                self.publication_raw,
                self.publication_sha256,
                self.publisher_sha.upper(),
                self.authority,
            )


if __name__ == "__main__":
    unittest.main()
