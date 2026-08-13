import hashlib
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execution_expectation as ee
import executor_receipt as er
import predator_compiler as pc

HEAD = "1" * 40
BASE = "2" * 40
MERGE = "3" * 40
CONTROL_HEAD = "4" * 40
EXECUTOR = "predator-private-executor"


def manifest():
    return pc.compile_manifest(
        {
            "repository": "AmazingBecca/dacosta-kanon-v5",
            "head": HEAD,
            "base": BASE,
            "merge": MERGE,
            "production_mutation": False,
        },
        [
            {"mentor": "security", "head": HEAD, "recommendation": "READY", "required_tests": ["security"], "allowed_paths": ["scripts"]},
            {"mentor": "evidence", "head": HEAD, "recommendation": "READY", "required_tests": ["evidence"], "allowed_paths": ["tests"]},
            {"mentor": "adversary", "head": HEAD, "recommendation": "READY", "required_tests": ["attack"], "allowed_paths": []},
        ],
        {
            "allowed_repositories": ["AmazingBecca/dacosta-kanon-v5"],
            "required_mentors": ["security", "evidence", "adversary"],
            "forbidden_paths": ["Zo", "production"],
        },
    )


def execution(m):
    return {
        "execution_id": m["execution_id"],
        "repository": m["repository"],
        "head": m["head"],
        "base": m["base"],
        "merge": m["merge"],
        "executor": EXECUTOR,
        "production_mutation": False,
        "attempted_paths": ["scripts/fix.py", "tests/test_fix.py"],
        "tests": [
            {"name": "attack", "status": "PASS"},
            {"name": "evidence", "status": "PASS"},
            {"name": "security", "status": "PASS"},
        ],
    }


def authority_material(root_uid):
    m = manifest()
    candidate_uid = root_uid + 1 if root_uid < 0xFFFFFFFD else root_uid - 2
    executor_uid = candidate_uid + 1 if candidate_uid < 0xFFFFFFFF else candidate_uid - 1
    exp = {
        "schema": "amazingbecca.predator-execution-expectation.v3",
        "source": "predator-compiler-control",
        "compiler_repository": "AmazingBecca/agency-agents",
        "compiler_head": CONTROL_HEAD,
        "repository": m["repository"],
        "head": m["head"],
        "base": m["base"],
        "merge": m["merge"],
        "execution_id": m["execution_id"],
        "candidate_uid": candidate_uid,
        "executor_uid": executor_uid,
        "executor": EXECUTOR,
    }
    base = er.issue_receipt(m, execution(m), m["execution_id"])
    receipt = ee._finalize_trusted_receipt(
        base,
        exp,
        hashlib.sha256(ee._canonical(exp)).hexdigest(),
    )
    return exp, receipt


class TrustedReceiptBoundVerificationTests(unittest.TestCase):
    def materialize(self, root):
        exp, receipt = authority_material(os.geteuid())
        expectation_path = root / "expectation.json"
        receipt_path = root / "receipt.json"
        expectation_path.write_bytes(ee._canonical(exp))
        receipt_path.write_bytes(er.canonical_bytes(receipt))
        receipt_path.chmod(0o600)
        return exp, receipt, expectation_path, receipt_path

    def test_valid_receipt_is_bound_to_authority_owned_expectation(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            _, receipt, expectation_path, receipt_path = self.materialize(root)
            self.assertEqual(
                ee.verify_trusted_receipt_from_root(
                    receipt_path,
                    expectation_path,
                    root,
                    CONTROL_HEAD,
                ),
                receipt["receipt_id"],
            )

    def test_recomputed_self_consistent_receipt_cannot_pivot_execution_id(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            _, receipt, expectation_path, receipt_path = self.materialize(root)
            forged = dict(receipt)
            forged["execution_id"] = "f" * 64
            core = dict(forged)
            core.pop("receipt_id")
            forged["receipt_id"] = hashlib.sha256(ee._canonical(core)).hexdigest()
            self.assertEqual(ee.verify_trusted_receipt(forged), forged["receipt_id"])
            receipt_path.write_bytes(er.canonical_bytes(forged))
            receipt_path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "execution_id does not match trusted expectation"):
                ee.verify_trusted_receipt_from_root(
                    receipt_path,
                    expectation_path,
                    root,
                    CONTROL_HEAD,
                )

    def test_expectation_replacement_invalidates_materialized_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            exp, _, expectation_path, receipt_path = self.materialize(root)
            changed = dict(exp)
            changed["head"] = "5" * 40
            expectation_path.write_bytes(ee._canonical(changed))
            with self.assertRaisesRegex(ValueError, "expectation digest mismatch"):
                ee.verify_trusted_receipt_from_root(
                    receipt_path,
                    expectation_path,
                    root,
                    CONTROL_HEAD,
                )

    def test_receipt_must_remain_private_authority_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            _, _, expectation_path, receipt_path = self.materialize(root)
            receipt_path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode 0600"):
                ee.verify_trusted_receipt_from_root(
                    receipt_path,
                    expectation_path,
                    root,
                    CONTROL_HEAD,
                )

    def test_receipt_must_be_direct_child_of_trusted_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            _, _, expectation_path, receipt_path = self.materialize(root)
            nested = root / "nested"
            nested.mkdir()
            moved = nested / "receipt.json"
            receipt_path.rename(moved)
            with self.assertRaisesRegex(ValueError, "direct child"):
                ee.verify_trusted_receipt_from_root(
                    moved,
                    expectation_path,
                    root,
                    CONTROL_HEAD,
                )


if __name__ == "__main__":
    unittest.main()
