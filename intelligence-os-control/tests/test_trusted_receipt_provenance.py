import hashlib
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
        "executor": "predator-private-executor",
        "production_mutation": False,
        "attempted_paths": ["scripts/fix.py", "tests/test_fix.py"],
        "tests": [
            {"name": "attack", "status": "PASS"},
            {"name": "evidence", "status": "PASS"},
            {"name": "security", "status": "PASS"},
        ],
    }


def expectation(m):
    return {
        "schema": "amazingbecca.predator-execution-expectation.v2",
        "source": "predator-compiler-control",
        "compiler_repository": "AmazingBecca/agency-agents",
        "compiler_head": CONTROL_HEAD,
        "repository": m["repository"],
        "head": m["head"],
        "base": m["base"],
        "merge": m["merge"],
        "execution_id": m["execution_id"],
        "candidate_uid": 4242,
    }


class TrustedReceiptProvenanceTests(unittest.TestCase):
    def trusted_receipt(self):
        m = manifest()
        exp = expectation(m)
        base = er.issue_receipt(m, execution(m), m["execution_id"])
        exp_bytes = ee._canonical(exp)
        return ee._finalize_trusted_receipt(
            base,
            exp,
            hashlib.sha256(exp_bytes).hexdigest(),
        ), exp, base

    def test_final_receipt_binds_compiler_and_expectation_provenance(self):
        receipt, exp, base = self.trusted_receipt()
        self.assertEqual(receipt["schema"], "amazingbecca.predator-executor-receipt.v2")
        self.assertEqual(receipt["compiler_repository"], exp["compiler_repository"])
        self.assertEqual(receipt["compiler_head"], exp["compiler_head"])
        self.assertEqual(
            receipt["expectation_sha256"],
            hashlib.sha256(ee._canonical(exp)).hexdigest(),
        )
        self.assertEqual(
            receipt["verifier_receipt_sha256"],
            hashlib.sha256(er.canonical_bytes(base)).hexdigest(),
        )
        self.assertEqual(ee.verify_trusted_receipt(receipt), receipt["receipt_id"])

    def test_receipt_provenance_tampering_fails_closed(self):
        receipt, _, _ = self.trusted_receipt()
        for field, value in [
            ("compiler_head", "5" * 40),
            ("expectation_sha256", "0" * 64),
            ("verifier_receipt_sha256", "1" * 64),
        ]:
            altered = dict(receipt)
            altered[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "digest mismatch"
            ):
                ee.verify_trusted_receipt(altered)

    def test_receipt_schema_and_compiler_repository_are_exact(self):
        receipt, _, _ = self.trusted_receipt()

        extra = dict(receipt)
        extra["command"] = "deploy"
        with self.assertRaisesRegex(ValueError, "exact authority schema"):
            ee.verify_trusted_receipt(extra)

        pivot = dict(receipt)
        pivot["compiler_repository"] = "Mallory/control"
        core = dict(pivot)
        core.pop("receipt_id")
        pivot["receipt_id"] = hashlib.sha256(ee._canonical(core)).hexdigest()
        with self.assertRaisesRegex(ValueError, "compiler repository mismatch"):
            ee.verify_trusted_receipt(pivot)

    def test_materialization_reverifies_trusted_receipt(self):
        receipt, _, _ = self.trusted_receipt()
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            output = root / "receipt.json"
            altered = dict(receipt)
            altered["compiler_head"] = "5" * 40
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                ee.materialize_trusted_receipt(altered, output, root)
            self.assertFalse(output.exists())

            self.assertEqual(
                ee.materialize_trusted_receipt(receipt, output, root),
                receipt["receipt_id"],
            )
            self.assertEqual(output.read_bytes(), er.canonical_bytes(receipt))


if __name__ == "__main__":
    unittest.main()
