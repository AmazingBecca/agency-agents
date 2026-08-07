import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import executor_receipt as er
import predator_compiler as pc

HEAD = "1" * 40
BASE = "2" * 40
MERGE = "3" * 40


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
        "executor": "predator-public-control",
        "production_mutation": False,
        "attempted_paths": ["scripts/fix.py", "tests/test_fix.py"],
        "tests": [
            {"name": "attack", "status": "PASS"},
            {"name": "evidence", "status": "PASS"},
            {"name": "security", "status": "PASS"},
        ],
    }


class ExecutorReceiptTests(unittest.TestCase):
    def test_pass_receipt_is_deterministic(self):
        m = manifest()
        first = er.issue_receipt(m, execution(m))
        second = er.issue_receipt(m, execution(m))
        self.assertEqual(first, second)
        self.assertEqual(first["execution_id"], m["execution_id"])
        self.assertEqual(first["status"], "PASS")

    def test_manifest_tampering_is_rejected(self):
        m = manifest()
        m["head"] = "4" * 40
        with self.assertRaisesRegex(ValueError, "execution_id mismatch"):
            er.issue_receipt(m, execution(manifest()))

    def test_blocked_manifest_cannot_execute(self):
        m = manifest()
        core = dict(m)
        core.pop("execution_id")
        core["status"] = "BLOCKED"
        import hashlib
        core_id = hashlib.sha256(er.canonical_bytes(core)).hexdigest()
        blocked = {**core, "execution_id": core_id}
        with self.assertRaisesRegex(ValueError, "not executable"):
            er.issue_receipt(blocked, execution(m))

    def test_candidate_identity_pivot_is_rejected(self):
        m = manifest()
        value = execution(m)
        value["head"] = "4" * 40
        with self.assertRaisesRegex(ValueError, "head does not match"):
            er.issue_receipt(m, value)

    def test_execution_authority_fields_are_exact(self):
        m = manifest()
        value = execution(m)
        value["command"] = "deploy --production"
        with self.assertRaisesRegex(ValueError, "exact authority schema"):
            er.issue_receipt(m, value)

        value = execution(m)
        value.pop("attempted_paths")
        with self.assertRaisesRegex(ValueError, "exact authority schema"):
            er.issue_receipt(m, value)

    def test_path_outside_manifest_is_rejected(self):
        m = manifest()
        value = execution(m)
        value["attempted_paths"].append(".github/workflows/pwn.yml")
        with self.assertRaisesRegex(ValueError, "outside manifest"):
            er.issue_receipt(m, value)

    def test_missing_failed_and_skipped_required_tests_are_rejected(self):
        m = manifest()
        value = execution(m)
        value["tests"] = value["tests"][:-1]
        with self.assertRaisesRegex(ValueError, "missing required tests"):
            er.issue_receipt(m, value)
        for status in ["FAIL", "SKIP"]:
            value = execution(m)
            value["tests"][0]["status"] = status
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "not passing"):
                er.issue_receipt(m, value)

    def test_duplicate_test_and_production_mutation_are_rejected(self):
        m = manifest()
        value = execution(m)
        value["tests"].append(copy.deepcopy(value["tests"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate test"):
            er.issue_receipt(m, value)
        value = execution(m)
        value["production_mutation"] = True
        with self.assertRaisesRegex(ValueError, "production mutation"):
            er.issue_receipt(m, value)


if __name__ == "__main__":
    unittest.main()
