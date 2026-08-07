import hashlib
import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

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


def expectation(m, candidate_uid):
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
        "candidate_uid": candidate_uid,
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

    def files(self, candidate_uid=None):
        m = manifest()
        uid = self.candidate_uid if candidate_uid is None else candidate_uid
        ep = self.write(self.trusted / "expectation.json", expectation(m, uid))
        mp = self.write(self.candidate / "manifest.json", m)
        xp = self.write(self.candidate / "execution.json", execution(m))
        return m, ep, mp, xp

    def issue(self, ep, mp, xp, manifest_uid=None, execution_uid=None, expected_compiler_head=CONTROL_HEAD):
        manifest_uid = self.candidate_uid if manifest_uid is None else manifest_uid
        execution_uid = self.candidate_uid if execution_uid is None else execution_uid
        original = ee._read_regular

        def observed_read(path, label):
            raw, info, resolved = original(path, label)
            uid = manifest_uid if label == "manifest" else execution_uid
            observed = types.SimpleNamespace(
                st_mode=info.st_mode,
                st_nlink=info.st_nlink,
                st_uid=uid,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
            )
            return raw, observed, resolved

        with mock.patch.object(ee, "_read_regular", side_effect=observed_read):
            return ee.issue_receipt_from_files(
                ep,
                mp,
                xp,
                self.trusted,
                expected_compiler_head,
            )

    def test_exact_trusted_channel_issues_receipt(self):
        m, ep, mp, xp = self.files()
        receipt = self.issue(ep, mp, xp)
        self.assertEqual(receipt["execution_id"], m["execution_id"])
        self.assertEqual(receipt["status"], "PASS")

    def test_candidate_uid_is_trusted_expectation_data_not_cli_input(self):
        m, ep, mp, xp = self.files()
        with self.assertRaises(TypeError):
            ee.issue_receipt_from_files(
                ep,
                mp,
                xp,
                self.trusted,
                CONTROL_HEAD,
                self.candidate_uid,
            )

    def test_expected_compiler_head_is_required_and_validated(self):
        m, ep, mp, xp = self.files()
        with self.assertRaises(TypeError):
            ee.issue_receipt_from_files(ep, mp, xp, self.trusted)
        for invalid in ("", "A" * 40, "1" * 39, "1" * 41):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ValueError, "trusted expected compiler head"
            ):
                self.issue(ep, mp, xp, expected_compiler_head=invalid)

    def test_compiler_identity_is_bound_outside_expectation(self):
        m, ep, mp, xp = self.files()
        value = expectation(m, self.candidate_uid)
        value["compiler_repository"] = "Mallory/control"
        ep.write_bytes(canonical(value))
        with self.assertRaisesRegex(ValueError, "compiler repository"):
            self.issue(ep, mp, xp)

        value = expectation(m, self.candidate_uid)
        value["compiler_head"] = "5" * 40
        ep.write_bytes(canonical(value))
        with self.assertRaisesRegex(ValueError, "compiler head"):
            self.issue(ep, mp, xp)

    def test_verifier_process_must_run_as_trusted_root_owner(self):
        m, ep, mp, xp = self.files()
        with mock.patch.object(ee.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(ValueError, "verifier must run as trusted root owner"):
                ee.issue_receipt_from_files(ep, mp, xp, self.trusted, CONTROL_HEAD)

    def test_same_uid_expectation_authority_is_rejected(self):
        m, ep, mp, xp = self.files(candidate_uid=os.geteuid())
        with self.assertRaisesRegex(ValueError, "authority uid distinct from candidate uid"):
            self.issue(ep, mp, xp)

    def test_root_candidate_uid_is_rejected(self):
        m, ep, mp, xp = self.files(candidate_uid=0)
        with self.assertRaisesRegex(ValueError, "non-root account"):
            self.issue(ep, mp, xp)

    def test_real_same_uid_candidate_files_cannot_satisfy_claimed_uid(self):
        m, ep, mp, xp = self.files()
        with self.assertRaisesRegex(ValueError, "owner does not match trusted candidate uid"):
            ee.issue_receipt_from_files(ep, mp, xp, self.trusted, CONTROL_HEAD)

    def test_manifest_and_execution_owners_must_match_trusted_candidate_uid(self):
        m, ep, mp, xp = self.files()
        with self.subTest(input="manifest"), self.assertRaisesRegex(
            ValueError, "owner does not match trusted candidate uid"
        ):
            self.issue(ep, mp, xp, manifest_uid=os.geteuid())
        with self.subTest(input="execution"), self.assertRaisesRegex(
            ValueError, "owner does not match trusted candidate uid"
        ):
            self.issue(ep, mp, xp, execution_uid=os.geteuid())

    def test_candidate_inputs_must_not_be_group_or_world_writable(self):
        m, ep, mp, xp = self.files()
        mp.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "must not be group/world writable"):
            self.issue(ep, mp, xp)

    def test_expectation_must_be_direct_child_of_bound_root(self):
        m, ep, mp, xp = self.files()
        nested = self.trusted / "nested"
        nested.mkdir(mode=0o700)
        nested_ep = self.write(nested / "expectation.json", expectation(m, self.candidate_uid))
        with self.assertRaisesRegex(ValueError, "direct child"):
            self.issue(nested_ep, mp, xp)

    def test_root_symlink_is_rejected_by_descriptor_open(self):
        m, ep, mp, xp = self.files()
        alias = self.root / "trusted-alias"
        alias.symlink_to(self.trusted, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "root is unavailable"):
            ee.issue_receipt_from_files(ep, mp, xp, alias, CONTROL_HEAD)

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
        outside = self.write(self.candidate / "expectation.json", expectation(m, self.candidate_uid))
        with self.assertRaisesRegex(ValueError, "direct child"):
            self.issue(outside, mp, xp)

    def test_candidate_inputs_must_be_outside_trusted_root(self):
        m, ep, mp, xp = self.files()
        inside = self.write(self.trusted / "manifest.json", m)
        with self.assertRaisesRegex(ValueError, "must remain outside"):
            self.issue(ep, inside, xp)

    def test_receipt_output_must_remain_under_trusted_root(self):
        m, ep, mp, xp = self.files()
        receipt = self.issue(ep, mp, xp)
        trusted_output = self.trusted / "receipt.json"
        self.assertEqual(
            ee.materialize_trusted_receipt(receipt, trusted_output, self.trusted),
            receipt["receipt_id"],
        )
        self.assertEqual(trusted_output.read_bytes(), er.canonical_bytes(receipt))

        outside_output = self.candidate / "receipt.json"
        with self.assertRaisesRegex(ValueError, "direct child"):
            ee.materialize_trusted_receipt(receipt, outside_output, self.trusted)
        self.assertFalse(outside_output.exists())

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
        value = expectation(m, self.candidate_uid)
        value["head"] = "5" * 40
        ep.write_bytes(canonical(value))
        with self.assertRaisesRegex(ValueError, "head does not match manifest"):
            self.issue(ep, mp, xp)

    def test_noncanonical_and_extra_authority_fields_fail_closed(self):
        m, ep, mp, xp = self.files()
        value = expectation(m, self.candidate_uid)
        value["command"] = "deploy"
        ep.write_bytes(canonical(value))
        with self.assertRaisesRegex(ValueError, "exact channel schema"):
            self.issue(ep, mp, xp)
        ep.write_text(json.dumps(expectation(m, self.candidate_uid), indent=2) + "\n")
        with self.assertRaisesRegex(ValueError, "not canonical JSON"):
            self.issue(ep, mp, xp)


if __name__ == "__main__":
    unittest.main()
