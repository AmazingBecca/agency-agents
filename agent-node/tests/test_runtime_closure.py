from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_runtime_closure", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class RuntimeClosureTests(unittest.TestCase):
    def test_runtime_tree_digest_changes_when_stdlib_bytes_change(self):
        self.assertTrue(hasattr(mod, "_runtime_tree_sha256"), "runtime tree digest helper is required")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            (root / "unittest").mkdir()
            (root / "unittest" / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
            target = root / "json.py"
            target.write_text("VALUE = 'reviewed'\n", encoding="utf-8")
            before = mod._runtime_tree_sha256((root,))
            target.write_text("VALUE = 'mutated'\n", encoding="utf-8")
            after = mod._runtime_tree_sha256((root,))
        self.assertRegex(before, r"^[0-9a-f]{64}$")
        self.assertRegex(after, r"^[0-9a-f]{64}$")
        self.assertNotEqual(before, after)

    def test_runtime_tree_digest_ignores_disabled_site_and_bytecode_caches(self):
        self.assertTrue(hasattr(mod, "_runtime_tree_sha256"), "runtime tree digest helper is required")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            (root / "json.py").write_text("VALUE = 1\n", encoding="utf-8")
            before = mod._runtime_tree_sha256((root,))
            (root / "__pycache__").mkdir()
            (root / "__pycache__" / "json.cpython-test.pyc").write_bytes(b"ignored-cache")
            (root / "site-packages").mkdir()
            (root / "site-packages" / "evil.py").write_text("raise SystemExit(1)\n", encoding="utf-8")
            (root / "dist-packages").mkdir()
            (root / "dist-packages" / "evil.py").write_text("raise SystemExit(1)\n", encoding="utf-8")
            after = mod._runtime_tree_sha256((root,))
        self.assertEqual(before, after)

    def test_runtime_identity_includes_runtime_tree_digest(self):
        self.assertTrue(hasattr(mod, "_runtime_roots"), "runtime root discovery is required")
        self.assertTrue(hasattr(mod, "_runtime_tree_sha256"), "runtime tree digest helper is required")
        fake_root = pathlib.Path("/runtime-root")
        with mock.patch.object(mod, "_stable_regular_file_sha256", return_value="a" * 64), \
             mock.patch.object(mod, "_runtime_roots", return_value=(fake_root,)), \
             mock.patch.object(mod, "_runtime_tree_sha256", side_effect=["b" * 64, "c" * 64]):
            _bin1, first = mod.python_runtime_identity()
            _bin2, second = mod.python_runtime_identity()
        self.assertNotEqual(first, second)

    def test_run_tests_preserves_isolated_no_site_no_bytecode_python(self):
        snapshot_temp = tempfile.TemporaryDirectory()
        self.addCleanup(snapshot_temp.cleanup)
        snapshot = pathlib.Path(snapshot_temp.name)

        @contextlib.contextmanager
        def fake_snapshot(_expected_head):
            yield "a" * 40, "b" * 40, snapshot

        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="OK\n")
        with mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)), \
             mock.patch.object(mod, "python_runtime_identity", side_effect=[("/usr/bin/python3", "c" * 64), ("/usr/bin/python3", "c" * 64)]), \
             mock.patch.object(mod, "committed_snapshot", fake_snapshot), \
             mock.patch.object(mod.subprocess, "run", return_value=completed) as run:
            result = mod.run_tests("a" * 40, "tests.test_safe")

        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/bin/python3", "-I", "-B", "-S"])
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(b"OK\n").hexdigest())


if __name__ == "__main__":
    unittest.main()
