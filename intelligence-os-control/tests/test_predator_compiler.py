import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import predator_compiler as pc

HEAD = "1" * 40
BASE = "2" * 40
MERGE = "3" * 40


def state():
    return {
        "repository": "AmazingBecca/dacosta-kanon-v5",
        "head": HEAD,
        "base": BASE,
        "merge": MERGE,
        "production_mutation": False,
    }


def mentors():
    return [
        {"mentor": "security", "head": HEAD, "recommendation": "READY", "required_tests": ["security"], "allowed_paths": ["scripts"]},
        {"mentor": "evidence", "head": HEAD, "recommendation": "READY", "required_tests": ["evidence"], "allowed_paths": ["tests"]},
        {"mentor": "adversary", "head": HEAD, "recommendation": "READY", "required_tests": ["attack"], "allowed_paths": []},
    ]


def policy():
    return {
        "allowed_repositories": ["AmazingBecca/dacosta-kanon-v5"],
        "required_mentors": ["security", "evidence", "adversary"],
        "forbidden_paths": ["Zo", "production"],
    }


class PredatorCompilerTests(unittest.TestCase):
    def test_ready_manifest_is_deterministic(self):
        first = pc.compile_manifest(state(), mentors(), policy())
        second = pc.compile_manifest(state(), list(reversed(mentors())), policy())
        self.assertEqual(first, second)
        core = dict(first)
        execution_id = core.pop("execution_id")
        self.assertEqual(execution_id, hashlib.sha256(pc.canonical_bytes(core)).hexdigest())
        self.assertEqual(first["status"], "READY")
        self.assertFalse(first["production_mutation"])

    def test_stale_mentor_fails_closed(self):
        reports = mentors()
        reports[0]["head"] = "4" * 40
        with self.assertRaisesRegex(ValueError, "stale mentor"):
            pc.compile_manifest(state(), reports, policy())

    def test_missing_adversary_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "missing required mentors"):
            pc.compile_manifest(state(), mentors()[:2], policy())

    def test_forbidden_path_escalation_fails_closed(self):
        reports = mentors()
        reports[0]["allowed_paths"].append("Zo")
        with self.assertRaisesRegex(ValueError, "forbidden path"):
            pc.compile_manifest(state(), reports, policy())

    def test_production_mutation_cannot_be_compiled(self):
        current = state()
        current["production_mutation"] = True
        with self.assertRaisesRegex(ValueError, "production mutation"):
            pc.compile_manifest(current, mentors(), policy())

    def test_blocker_yields_nonexecuting_manifest(self):
        reports = mentors()
        reports[2]["recommendation"] = "BLOCKED"
        reports[2]["reason"] = "runner identity unavailable"
        manifest = pc.compile_manifest(state(), reports, policy())
        self.assertEqual(manifest["status"], "BLOCKED")
        self.assertEqual(manifest["blockers"], ["adversary:runner identity unavailable"])

    def test_noncanonical_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "state.json"
            path.write_text(json.dumps(state(), indent=2) + "\n")
            with self.assertRaisesRegex(ValueError, "not canonical JSON"):
                pc.load_json(path)


if __name__ == "__main__":
    unittest.main()
