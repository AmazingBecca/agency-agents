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
SOURCE = ROOT / "publish_retained_evidence.py"
SPEC = importlib.util.spec_from_file_location("publisher", SOURCE)
assert SPEC and SPEC.loader
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


class PublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.output = self.root / publisher.OUTPUT_NAME
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
            "CONTROL_WORKFLOW_REPOSITORY": publisher.CONTROL_REPOSITORY,
            "CONTROL_WORKFLOW_FILE_PATH": publisher.CONTROL_WORKFLOW_PATH,
            "CONTROL_WORKFLOW_SHA": "e" * 40,
            "RUNNER_TEMP": str(self.root),
        }
        self.receipt = self._receipt()
        self.envelope_b64 = self._envelope(self.receipt)

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

    def _execution(self):
        return {
            "repository": self.authority["repository"],
            "workflow_ref": self.authority["workflow_ref"],
            "workflow_sha": self.authority["workflow_sha"],
            "run_id": self.authority["run_id"],
            "run_attempt": self.authority["run_attempt"],
            "head_sha": self.authority["reviewed_head"],
            "reviewed_base": self.authority["reviewed_base"],
            "synthetic_merge": self.authority["synthetic_merge"],
        }

    def _receipt(self):
        execution = self._execution()
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
            "schema": publisher.RECEIPT_SCHEMA,
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
            "archive_manifest": {
                "name": publisher.MANIFEST_NAME,
                "bytes": 512,
                "sha256": manifest_sha,
                "execution": execution,
            },
            "archive_canonicality": {
                "schema": publisher.WHEELHOUSE_SCHEMA,
                "archive_bytes": 4096,
                "archive_sha256": archive_sha,
                "manifest_bytes": 512,
                "manifest_sha256": manifest_sha,
                "execution": execution,
                "wheel_count": 1,
                "wheel_names": ["alpha-1.0-py3-none-any.whl"],
            },
            "members": {
                publisher.SOURCE_IDENTITY_NAME: {"bytes": 200, "sha256": "6" * 64},
                publisher.WHEELHOUSE_ARCHIVE_NAME: {
                    "bytes": 4096,
                    "sha256": archive_sha,
                },
                publisher.BINDING_NAME: {"bytes": 300, "sha256": "7" * 64},
            },
            "synthetic_merge_commit": {
                "schema": publisher.MERGE_COMMIT_SCHEMA,
                "name": "intelligence-os-synthetic-merge.commit",
                "bytes": 250,
                "sha256": "8" * 64,
                "git_commit": self.authority["synthetic_merge"],
                "parents": [
                    self.authority["reviewed_base"],
                    self.authority["reviewed_head"],
                ],
            },
            "verifier_components": {
                "schema": publisher.COMPONENT_SCHEMA,
                "components": components,
            },
        }

    def _envelope(self, receipt, authority=None):
        receipt_raw = canonical(receipt)
        envelope = {
            "schema": publisher.TRANSFER_SCHEMA,
            "authority": dict(authority or self.authority),
            "receipt": {
                "encoding": "base64",
                "bytes": len(receipt_raw),
                "sha256": hashlib.sha256(receipt_raw).hexdigest(),
                "data": base64.b64encode(receipt_raw).decode("ascii"),
            },
        }
        return base64.b64encode(canonical(envelope)).decode("ascii")

    def test_valid_transfer_publishes_exact_receipt(self) -> None:
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}, clear=False):
            digest = publisher.publish(
                self.envelope_b64,
                self.output,
                self.authority,
                self.environment,
            )
        expected = canonical(self.receipt)
        self.assertEqual(self.output.read_bytes(), expected)
        self.assertEqual(digest, hashlib.sha256(expected).hexdigest())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_all_authority_pivots_are_rejected(self) -> None:
        replacements = {
            "repository": "AmazingBecca/other",
            "reviewed_head": "9" * 40,
            "reviewed_base": "0" * 40,
            "synthetic_merge": "f" * 40,
            "workflow_ref": (
                "AmazingBecca/free-millionaire-pipeline/"
                ".github/workflows/other.yml@refs/pull/14/merge"
            ),
            "workflow_sha": "9" * 40,
            "run_id": "123456790",
            "run_attempt": "2",
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                attacked = dict(self.authority)
                attacked[field] = replacement
                if field == "repository":
                    attacked["workflow_ref"] = attacked["workflow_ref"].replace(
                        "AmazingBecca/free-millionaire-pipeline",
                        "AmazingBecca/other",
                        1,
                    )
                with self.assertRaises(publisher.PublicationError):
                    publisher.publish(
                        self.envelope_b64,
                        self.output,
                        attacked,
                        self.environment,
                    )
                self.assertFalse(self.output.exists())

    def test_github_and_control_contexts_are_authoritative(self) -> None:
        attacks = (
            "GITHUB_REPOSITORY",
            "GITHUB_WORKFLOW_REF",
            "GITHUB_WORKFLOW_SHA",
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "CONTROL_WORKFLOW_REPOSITORY",
            "CONTROL_WORKFLOW_FILE_PATH",
            "CONTROL_WORKFLOW_SHA",
        )
        for field in attacks:
            with self.subTest(field=field):
                env = dict(self.environment)
                env[field] = "attacker"
                with self.assertRaises(publisher.PublicationError):
                    publisher.publish(
                        self.envelope_b64,
                        self.output,
                        self.authority,
                        env,
                    )
                self.assertFalse(self.output.exists())

        payload = json.loads(self.event.read_text(encoding="utf-8"))
        payload["pull_request"]["head"]["sha"] = "9" * 40
        self.event.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(publisher.PublicationError):
            publisher.publish(
                self.envelope_b64,
                self.output,
                self.authority,
                self.environment,
            )
        self.assertFalse(self.output.exists())
        self._write_event()

    def test_semantic_receipt_attacks_are_rejected(self) -> None:
        attacks = {}
        receipt = copy.deepcopy(self.receipt)
        receipt["archive_canonicality"]["wheel_names"] = ["z.whl", "A.whl"]
        receipt["archive_canonicality"]["wheel_count"] = 2
        attacks["unsorted wheels"] = receipt
        receipt = copy.deepcopy(self.receipt)
        del receipt["members"][publisher.BINDING_NAME]
        attacks["missing member"] = receipt
        receipt = copy.deepcopy(self.receipt)
        receipt["archive_manifest"]["execution"]["run_attempt"] = "2"
        attacks["execution pivot"] = receipt
        receipt = copy.deepcopy(self.receipt)
        del receipt["verifier_components"]["components"]["archive_canonicality.py"]
        attacks["missing component"] = receipt
        receipt = copy.deepcopy(self.receipt)
        receipt["synthetic_merge_commit"]["parents"].reverse()
        attacks["reversed parents"] = receipt
        for name, attacked in attacks.items():
            with self.subTest(name=name):
                with self.assertRaises(publisher.PublicationError):
                    publisher.publish(
                        self._envelope(attacked),
                        self.output,
                        self.authority,
                        self.environment,
                    )
                self.assertFalse(self.output.exists())

    def test_noncanonical_transport_and_inner_base64_are_rejected(self) -> None:
        raw = base64.b64decode(self.envelope_b64)
        pretty = json.dumps(json.loads(raw), indent=2).encode("ascii") + b"\n"
        attacks = [base64.b64encode(pretty).decode("ascii")]
        parsed = json.loads(raw)
        data = parsed["receipt"]["data"]
        parsed["receipt"]["data"] = data[:-2] + "A="
        attacks.append(base64.b64encode(canonical(parsed)).decode("ascii"))
        attacks.append(self.envelope_b64[:-1] + "A")
        for attacked in attacks:
            with self.assertRaises(publisher.PublicationError):
                publisher.publish(
                    attacked,
                    self.output,
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
                with patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}, clear=False):
                    with self.assertRaises(publisher.PublicationError):
                        publisher.publish(
                            self.envelope_b64,
                            self.output,
                            self.authority,
                            self.environment,
                        )
                self.assertTrue(self.output.exists() or self.output.is_symlink())
                self.output.unlink()

    def test_failed_post_write_verification_removes_output(self) -> None:
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}, clear=False):
            with patch.object(
                publisher,
                "_verify_published_path",
                side_effect=publisher.PublicationError("deterministic substitution"),
            ):
                with self.assertRaisesRegex(
                    publisher.PublicationError, "deterministic substitution"
                ):
                    publisher.publish(
                        self.envelope_b64,
                        self.output,
                        self.authority,
                        self.environment,
                    )
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
