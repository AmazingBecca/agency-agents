import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import mentor_adapter as ma
import predator_compiler as pc
import executor_receipt as er

STATE = {
    "repository": "AmazingBecca/dacosta-kanon-v5",
    "head": "d16eb115c29661224ad398b8ff4c0595a8db2d1c",
    "base": "ccbb8e47a6b7c71dd11753c885073c9a11e81398",
    "merge": "bc660012f023a8dd9109b4382d032d2a439fe293",
    "production_mutation": False,
}
POLICY = {
    "allowed_repositories": ["AmazingBecca/dacosta-kanon-v5"],
    "required_mentors": ["security", "evidence", "adversary"],
    "forbidden_paths": ["Zo", "production"],
}


def raw(name, tests, paths):
    return {
        "schema": "amazingbecca.predator-mentor.v1",
        "mentor": name,
        "repository": STATE["repository"],
        "head": STATE["head"],
        "recommendation": "READY",
        "reason": "",
        "findings": [f"{name} review bound to exact candidate"],
        "required_tests": tests,
        "allowed_paths": paths,
    }


class PredatorControlLoopTests(unittest.TestCase):
    def test_live_candidate_identity_compiles_and_receipts(self):
        mentors = [
            ma.adapt(raw("security", ["mirofish-security"], ["scripts"]), STATE),
            ma.adapt(raw("evidence", ["mirofish-evidence"], ["tests"]), STATE),
            ma.adapt(raw("adversary", ["mirofish-adversary"], []), STATE),
        ]
        manifest = pc.compile_manifest(STATE, mentors, POLICY)
        self.assertEqual(manifest["status"], "READY")
        execution = {
            "execution_id": manifest["execution_id"],
            "repository": STATE["repository"],
            "head": STATE["head"],
            "base": STATE["base"],
            "merge": STATE["merge"],
            "executor": "predator-public-control",
            "production_mutation": False,
            "attempted_paths": [],
            "tests": [
                {"name": "mirofish-adversary", "status": "PASS"},
                {"name": "mirofish-evidence", "status": "PASS"},
                {"name": "mirofish-security", "status": "PASS"},
            ],
        }
        receipt = er.issue_receipt(manifest, execution, manifest["execution_id"])
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["execution_id"], manifest["execution_id"])
        self.assertEqual(receipt["head"], STATE["head"])

    def test_adversary_can_stop_the_loop_without_executor_authority(self):
        reports = [
            ma.adapt(raw("security", ["mirofish-security"], ["scripts"]), STATE),
            ma.adapt(raw("evidence", ["mirofish-evidence"], ["tests"]), STATE),
        ]
        blocked = raw("adversary", ["mirofish-adversary"], [])
        blocked["recommendation"] = "BLOCKED"
        blocked["reason"] = "private executor unavailable"
        reports.append(ma.adapt(blocked, STATE))
        manifest = pc.compile_manifest(STATE, reports, POLICY)
        self.assertEqual(manifest["status"], "BLOCKED")
        with self.assertRaisesRegex(ValueError, "not executable"):
            er.issue_receipt(manifest, {
                "execution_id": manifest["execution_id"],
                "repository": STATE["repository"],
                "head": STATE["head"],
                "base": STATE["base"],
                "merge": STATE["merge"],
                "executor": "predator-public-control",
                "tests": [{"name": "mirofish-security", "status": "PASS"}],
            }, manifest["execution_id"])


if __name__ == "__main__":
    unittest.main()
