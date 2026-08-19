from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).parents[1]

def load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

capsule = load("execution_capsule", ROOT / "execution_capsule.py")
service = load("capsule_service", ROOT / "capsule_service.py")


class CapsuleTests(unittest.TestCase):
    def build(self, **changes):
        value = {
            "capsule_id": "job-1",
            "repository": "AmazingBecca/example",
            "head": "a" * 40,
            "tree": "b" * 40,
            "source_bundle_sha256": "c" * 64,
            "operation": {"kind": "python_unittest", "selector": "tests.test_safe"},
            "network_access": "none",
            "max_seconds": 300,
            "max_output_bytes": 20000,
            "required_tools": [{"name": "python", "version": "3.12.3"}],
        }
        value.update(changes)
        return capsule.build(**value)

    def test_valid_capsule_is_canonical_and_hash_bound(self):
        raw = self.build()
        value = capsule.parse(raw)
        self.assertEqual(value["schema"], capsule.SCHEMA)
        self.assertTrue(value["advisory_only"])
        self.assertFalse(value["promotion_authorized"])
        self.assertFalse(value["completion_authorized"])
        self.assertEqual(len(value["capsule_sha256"]), 64)

    def test_network_or_authority_widening_fails_closed(self):
        for changes in (
            {"network_access": "full"},
            {"max_seconds": 901},
            {"operation": {"kind": "shell", "selector": "bash"}},
        ):
            with self.assertRaises(capsule.CapsuleError):
                self.build(**changes)

    def test_duplicate_json_key_and_noncanonical_json_are_rejected(self):
        raw = self.build()
        value = json.loads(raw)
        pretty = json.dumps(value, indent=2).encode()
        with self.assertRaisesRegex(capsule.CapsuleError, "canonical"):
            capsule.parse(pretty)
        duplicate = raw.replace(b'"capsule_id":"job-1",', b'"capsule_id":"job-1","capsule_id":"job-2",', 1)
        with self.assertRaises(capsule.CapsuleError):
            capsule.parse(duplicate)

    def test_service_binds_repo_tree_bundle_python_and_output(self):
        raw = self.build()
        fake_result = {
            "head": "a" * 40,
            "tree": "b" * 40,
            "runtime_sha256": "d" * 64,
            "selector": "tests.test_safe",
            "returncode": 0,
            "stdout_sha256": hashlib.sha256(b"OK\n").hexdigest(),
            "stdout": "OK\n",
        }
        with mock.patch.object(service, "REPOSITORY", "AmazingBecca/example"), \
             mock.patch.object(service.agent_node, "bound_identity", return_value=("a" * 40, "b" * 40)), \
             mock.patch.object(service, "source_bundle_sha256", return_value="c" * 64), \
             mock.patch.object(service.agent_node.sys, "version_info", (3, 12, 3)), \
             mock.patch.object(service.agent_node, "run_tests", return_value=fake_result):
            result = service.run_capsule(raw)
        self.assertEqual(result["capsule_sha256"], capsule.parse(raw)["capsule_sha256"])
        self.assertTrue(result["advisory_only"])
        self.assertFalse(result["promotion_authorized"])
        self.assertFalse(result["completion_authorized"])

    def test_service_rejects_tree_bundle_or_python_substitution(self):
        raw = self.build()
        cases = [
            (("a" * 40, "f" * 40), "c" * 64, (3, 12, 3)),
            (("a" * 40, "b" * 40), "f" * 64, (3, 12, 3)),
            (("a" * 40, "b" * 40), "c" * 64, (3, 13, 0)),
        ]
        for identity, bundle, version in cases:
            with self.subTest(identity=identity, bundle=bundle, version=version), \
                 mock.patch.object(service, "REPOSITORY", "AmazingBecca/example"), \
                 mock.patch.object(service.agent_node, "bound_identity", return_value=identity), \
                 mock.patch.object(service, "source_bundle_sha256", return_value=bundle), \
                 mock.patch.object(service.agent_node.sys, "version_info", version):
                with self.assertRaises(ValueError):
                    service.run_capsule(raw)


if __name__ == "__main__":
    unittest.main()
