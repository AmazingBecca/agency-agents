import hashlib
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import execution_expectation as ee
import executor_receipt as er

HEAD = "1" * 40
BASE = "2" * 40
MERGE = "3" * 40
CONTROL_HEAD = "4" * 40


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def manifest():
    core = {
        "schema": "amazingbecca.predator-compiler.v1",
        "status": "READY",
        "repository": "AmazingBecca/dacosta-kanon-v5",
        "head": HEAD,
        "base": BASE,
        "merge": MERGE,
        "production_mutation": False,
        "mentor_set": ["adversary", "evidence", "security"],
        "required_tests": ["attack", "evidence", "security"],
        "allowed_paths": ["scripts", "tests"],
        "forbidden_paths": ["Zo", "production"],
        "blockers": [],
    }
    return {**core, "execution_id": hashlib.sha256(er.canonical_bytes(core)).hexdigest()}


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
        "schema": "amazingbecca.predator-execution-expectation.v1",
        "source": "predator-compiler-control",
        "compiler_repository": "AmazingBecca/agency-agents",
        "compiler_head": CONTROL_HEAD,
        "repository": m["repository"],
        "head": m["head"],
        "base": m["base"],
        "merge": m["merge"],
        "execution_id": m["execution_id"],
    }


class ExecutionExpectationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.trusted = self.root / "trusted"
        self.candidate = self.root / "candidate"
        self.trusted.mkdir(mode=0o700)
        self.candidate.mkdir(mode=0o700)
        self.candidate_uid = os.geteuid() + 10000

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, value):
        path.write_bytes(canonical(value))
        return path

    def files(self):
        m = manifest()
        ep = self.write(self.trusted / "expectation.json", expectation(m))
        mp = self.write(self.candidate / "manifest.json", m)
        xp = self.write(self.candidate / "execution.json", execution(m))
        return m, ep, mp, xp

    def issue(self, ep, mp, xp, candidate_uid=None):
        return ee.issue_receipt_from_files(
            ep,
            mp,
            xp,
            self.trusted,
            self.candidate_uid if candidate_uid is None else candidate_uid,
        )

    def test_exact_trusted_channel_issues_receipt(self):
        m, ep, mp, xp = self.files()
        receipt = self.issue(ep, mp, xp)
        self.assertEqual(receipt["execution_id"], m["execution_id"])
        self.assertEqual(receipt["status"], "PASS")

    def test_same_uid_expectation_authority_is_rejected(self):
        m, ep, mp, xp = self.files()
        with self.assertRaisesRegex(ValueError, "authority uid distinct from candidate uid"):
            self.issue(ep, mp, xp, os.geteuid())

    def test_root_candidate_uid_is_rejected(self):
        m, ep, mp, xp = self.files()
        with self.assertRaisesRegex(ValueError, "non-root account"):
            self.issue(ep, mp, xp, 0)

    def test_expectation_must_be_direct_child_of_bound_root(self):
        m, ep, mp, xp = self.files()
        nested = self.trusted / "nested"
        nested.mkdir(mode=0o700)
        nested_ep = self.write(nested / "expectation.json", expectation(m))
        with self.assertRaisesRegex(ValueError, "direct child"):
            self.issue(nested_ep, mp, xp)

    def test_root_symlink_is_rejected_by_descriptor_open(self):
        m, ep, mp, xp = self.files()
        alias = self.root / "trusted-alias"
        alias.symlink_to(self.trusted, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "root is unavailable"):
            ee.issue_receipt_from_files(ep, mp, xp, alias, self.candidate_uid)

    def test_manifest_substitution_fails_while_expectation_stays_fixed(self):
        m, ep, mp, xp = self.files()
        core = dict(m)
        core.pop("execution_id")
        core["allowed_paths"] = [".github", "scripts", "tests"]
        forged = {**core, "execution_id": hashlib.sha256(er.canonical_bytes(core)).hexdigest()}
        mp.write_bytes(canonical(forged))
        xp.write_bytes(canonical(execution(forged)))
        with self.assertRaisesRegex(ValueError, "trusted expected execution_id"):
            self.issue(ep, mp, xp)

    def test_expectation_must_be_inside_trusted_root(self):
        m, ep, mp, xp = self.files()
        outside = self.write(self.candidate / "expectation.json", expectation(m))
        with self.assertRaisesRegex(ValueError, "direct child"):
            self.issue(outside, mp, xp)

    def test_candidate_inputs_must_be_outside_trusted_root(self):
        m, ep, mp, xp = self.files()
        inside = self.write(self.trusted / "manifest.json", m)
        with self.assertRaisesRegex(ValueError, "must remain outside"):
            self.issue(ep, inside, xp)

    def test_symlink_and_hardlink_expectations_fail_closed(self):
        m, ep, mp, xp = self.files()
        symlink = self.trusted / "alias.json"
        symlink.symlink_to(ep.name)
        with self.assertRaisesRegex(ValueError, "unavailable"):
            self.issue(symlink, mp, xp)
        hard = self.trusted / "hard.json"
        os.link(ep, hard)
        with self.assertRaisesRegex(ValueError, "exactly one hard link"):
            self.issue(ep, mp, xp)

    def test_expectation_identity_pivot_fails_before_receipt(self):
        m, ep, mp, xp = self.files()
        value = expectation(m)
        value["head"] = "5" * 40
        ep.write_bytes(canonical(value))
        with self.assertRaisesRegex(ValueError, "head does not match manifest"):
            self.issue(ep, mp, xp)

    def test_noncanonical_and_extra_authority_fields_fail_closed(self):
        m, ep, mp, xp = self.files()
        value = expectation(m)
        value["command"] = "deploy"
        ep.write_bytes(canonical(value))
        with self.assertRaisesRegex(ValueError, "exact channel schema"):
            self.issue(ep, mp, xp)
        ep.write_text(json.dumps(expectation(m), indent=2) + "\n")
        with self.assertRaisesRegex(ValueError, "not canonical JSON"):
            self.issue(ep, mp, xp)


if __name__ == "__main__":
    unittest.main()
