from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "publication_attestation.py"
SPEC = importlib.util.spec_from_file_location("attestation", SOURCE)
assert SPEC and SPEC.loader
attestation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(attestation)


def canonical(value) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


class PublicationAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.receipt_path = self.root / attestation.RECEIPT_NAME
        self.output = self.root / attestation.OUTPUT_NAME
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
        self.control_sha = "e" * 40
        self.event = self.root / "event.json"
        self._write_event()
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
                f"{attestation.CONTROL_WORKFLOW_PATH}@{self.control_sha}"
            ),
            "CONTROL_WORKFLOW_SHA": self.control_sha,
            "RUNNER_TEMP": str(self.root),
        }
        self.receipt = self._receipt()
        self.receipt_raw = canonical(self.receipt)
        self.receipt_path.write_bytes(self.receipt_raw)
        self.receipt_path.chmod(0o600)
        self.receipt_sha256 = hashlib.sha256(self.receipt_raw).hexdigest()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_event(self) -> None:
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

    def _receipt(self):
        return {
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

    def test_valid_attestation_embeds_exact_receipt_and_publisher_authority(self) -> None:
        digest = attestation.attest(
            self.receipt_path,
            self.output,
            self.receipt_sha256,
            self.authority,
            self.environment,
        )
        raw = self.output.read_bytes()
        value = json.loads(raw.decode("ascii"))
        self.assertEqual(raw, canonical(value))
        self.assertEqual(value["schema"], attestation.PUBLICATION_SCHEMA)
        self.assertEqual(value["caller_authority"], self.authority)
        self.assertEqual(
            value["publisher_authority"],
            {
                "repository": attestation.CONTROL_REPOSITORY,
                "workflow_path": attestation.CONTROL_WORKFLOW_PATH,
                "workflow_ref": self.environment["CONTROL_WORKFLOW_REF"],
                "workflow_sha": self.control_sha,
            },
        )
        record = value["verification_receipt"]
        self.assertEqual(record["sha256"], self.receipt_sha256)
        self.assertEqual(base64.b64decode(record["data"]), self.receipt_raw)
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_control_ref_is_cryptographically_bound_to_control_sha(self) -> None:
        env = dict(self.environment)
        env["CONTROL_WORKFLOW_REF"] = (
            f"{attestation.CONTROL_REPOSITORY}/"
            f"{attestation.CONTROL_WORKFLOW_PATH}@{'f' * 40}"
        )
        with self.assertRaisesRegex(
            attestation.AttestationError, "control workflow ref is not exact"
        ):
            attestation.attest(
                self.receipt_path,
                self.output,
                self.receipt_sha256,
                self.authority,
                env,
            )
        self.assertFalse(self.output.exists())

    def test_caller_control_and_event_pivots_are_rejected(self) -> None:
        fields = (
            "GITHUB_REPOSITORY",
            "GITHUB_WORKFLOW_REF",
            "GITHUB_WORKFLOW_SHA",
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "CONTROL_WORKFLOW_REPOSITORY",
            "CONTROL_WORKFLOW_FILE_PATH",
            "CONTROL_WORKFLOW_REF",
            "CONTROL_WORKFLOW_SHA",
        )
        for field in fields:
            with self.subTest(field=field):
                env = dict(self.environment)
                env[field] = "attacker"
                with self.assertRaises(attestation.AttestationError):
                    attestation.attest(
                        self.receipt_path,
                        self.output,
                        self.receipt_sha256,
                        self.authority,
                        env,
                    )
                self.assertFalse(self.output.exists())

        payload = json.loads(self.event.read_text(encoding="utf-8"))
        payload["pull_request"]["merge_commit_sha"] = "f" * 40
        self.event.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(attestation.AttestationError):
            attestation.attest(
                self.receipt_path,
                self.output,
                self.receipt_sha256,
                self.authority,
                self.environment,
            )
        self.assertFalse(self.output.exists())
        self._write_event()

    def test_receipt_digest_canonicality_and_authority_attacks_are_rejected(self) -> None:
        with self.assertRaisesRegex(attestation.AttestationError, "digest does not match"):
            attestation.attest(
                self.receipt_path,
                self.output,
                "f" * 64,
                self.authority,
                self.environment,
            )
        self.assertFalse(self.output.exists())

        self.receipt_path.write_text(json.dumps(self.receipt, indent=2), encoding="ascii")
        self.receipt_path.chmod(0o600)
        attacked_digest = hashlib.sha256(self.receipt_path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(attestation.AttestationError, "not canonical JSON"):
            attestation.attest(
                self.receipt_path,
                self.output,
                attacked_digest,
                self.authority,
                self.environment,
            )
        self.assertFalse(self.output.exists())

        attacked = copy.deepcopy(self.receipt)
        attacked["reviewed_head"] = "f" * 40
        attacked_raw = canonical(attacked)
        self.receipt_path.write_bytes(attacked_raw)
        self.receipt_path.chmod(0o600)
        with self.assertRaisesRegex(attestation.AttestationError, "reviewed_head is invalid"):
            attestation.attest(
                self.receipt_path,
                self.output,
                hashlib.sha256(attacked_raw).hexdigest(),
                self.authority,
                self.environment,
            )
        self.assertFalse(self.output.exists())

    def test_receipt_symlink_hardlink_and_mode_attacks_are_rejected(self) -> None:
        original = self.root / "original.json"
        original.write_bytes(self.receipt_raw)
        original.chmod(0o600)
        self.receipt_path.unlink()

        self.receipt_path.symlink_to(original)
        with self.assertRaises(attestation.AttestationError):
            attestation.attest(
                self.receipt_path,
                self.output,
                self.receipt_sha256,
                self.authority,
                self.environment,
            )
        self.receipt_path.unlink()

        os.link(original, self.receipt_path)
        with self.assertRaisesRegex(attestation.AttestationError, "metadata is outside policy"):
            attestation.attest(
                self.receipt_path,
                self.output,
                self.receipt_sha256,
                self.authority,
                self.environment,
            )
        self.receipt_path.unlink()
        original.unlink()

        self.receipt_path.write_bytes(self.receipt_raw)
        self.receipt_path.chmod(0o644)
        with self.assertRaisesRegex(attestation.AttestationError, "metadata is outside policy"):
            attestation.attest(
                self.receipt_path,
                self.output,
                self.receipt_sha256,
                self.authority,
                self.environment,
            )
        self.assertFalse(self.output.exists())

    def test_existing_and_symlink_outputs_are_rejected(self) -> None:
        for kind in ("file", "symlink"):
            with self.subTest(kind=kind):
                if kind == "file":
                    self.output.write_bytes(b"existing")
                else:
                    target = self.root / "target"
                    target.write_bytes(b"target")
                    self.output.symlink_to(target)
                with self.assertRaises(attestation.AttestationError):
                    attestation.attest(
                        self.receipt_path,
                        self.output,
                        self.receipt_sha256,
                        self.authority,
                        self.environment,
                    )
                self.assertTrue(self.output.exists() or self.output.is_symlink())
                self.output.unlink()

    def test_failed_post_write_verification_removes_output(self) -> None:
        with patch.object(
            attestation,
            "_verify_published_path",
            side_effect=attestation.AttestationError("deterministic substitution"),
        ):
            with self.assertRaisesRegex(
                attestation.AttestationError, "deterministic substitution"
            ):
                attestation.attest(
                    self.receipt_path,
                    self.output,
                    self.receipt_sha256,
                    self.authority,
                    self.environment,
                )
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
