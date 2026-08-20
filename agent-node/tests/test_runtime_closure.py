from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import os
import pathlib
import subprocess
import sys
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

    def test_runtime_tree_digest_binds_importable_site_and_bytecode(self):
        self.assertTrue(hasattr(mod, "_runtime_tree_sha256"), "runtime tree digest helper is required")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            (root / "json.py").write_text("VALUE = 1\n", encoding="utf-8")
            baseline = mod._runtime_tree_sha256((root,))

            (root / "site-packages").mkdir()
            site_module = root / "site-packages" / "runtime_probe.py"
            site_module.write_text("VALUE = 1\n", encoding="utf-8")
            with_site = mod._runtime_tree_sha256((root,))
            site_module.write_text("VALUE = 2\n", encoding="utf-8")
            mutated_site = mod._runtime_tree_sha256((root,))

            (root / "dist-packages").mkdir()
            dist_module = root / "dist-packages" / "runtime_probe.py"
            dist_module.write_text("VALUE = 1\n", encoding="utf-8")
            with_dist = mod._runtime_tree_sha256((root,))
            dist_module.write_text("VALUE = 2\n", encoding="utf-8")
            mutated_dist = mod._runtime_tree_sha256((root,))

            (root / "__pycache__").mkdir()
            cached = root / "__pycache__" / "json.cpython-test.pyc"
            cached.write_bytes(b"bound-cache-v1")
            with_bytecode = mod._runtime_tree_sha256((root,))
            cached.write_bytes(b"bound-cache-v2")
            mutated_bytecode = mod._runtime_tree_sha256((root,))

        self.assertNotEqual(baseline, with_site)
        self.assertNotEqual(with_site, mutated_site)
        self.assertNotEqual(mutated_site, with_dist)
        self.assertNotEqual(with_dist, mutated_dist)
        self.assertNotEqual(mutated_dist, with_bytecode)
        self.assertNotEqual(with_bytecode, mutated_bytecode)

    def test_runtime_tree_digest_binds_file_symlink_and_target_bytes(self):
        self.assertTrue(hasattr(mod, "_runtime_tree_sha256"), "runtime tree digest helper is required")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            target = root / "real_config.py"
            target.write_text("VALUE = 1\n", encoding="utf-8")
            link = root / "runtime_config.py"
            link.symlink_to(target.name)
            before = mod._runtime_tree_sha256((root,))
            target.write_text("VALUE = 2\n", encoding="utf-8")
            after = mod._runtime_tree_sha256((root,))
        self.assertNotEqual(before, after)

    def test_isolated_child_search_paths_scrub_parent_python_environment(self):
        self.assertTrue(
            hasattr(mod, "_child_runtime_search_paths"),
            "runtime identity must discover paths under the exact isolated child configuration",
        )
        poison = pathlib.Path(tempfile.gettempdir()) / "agent-node-pythonhome-poison"
        injected = {
            "PYTHONHOME": str(poison),
            "PYTHONPATH": str(poison / "path"),
            "PYTHONUSERBASE": str(poison / "userbase"),
        }
        with mock.patch.dict(os.environ, injected, clear=False):
            paths = mod._child_runtime_search_paths(sys.executable)
        self.assertTrue(paths)
        self.assertTrue(all(str(poison) not in value for value in paths))

    def test_runtime_identity_includes_runtime_tree_digest(self):
        self.assertTrue(hasattr(mod, "_runtime_roots"), "runtime root discovery is required")
        self.assertTrue(hasattr(mod, "_runtime_tree_sha256"), "runtime tree digest helper is required")
        fake_root = pathlib.Path("/runtime-root")
        fake_paths = (str(fake_root),)
        with mock.patch.object(mod, "_stable_regular_file_sha256", return_value="a" * 64), \
             mock.patch.object(mod, "_child_runtime_search_paths", return_value=fake_paths), \
             mock.patch.object(mod, "_runtime_roots", return_value=(fake_root,)), \
             mock.patch.object(mod, "_runtime_tree_sha256", side_effect=["b" * 64, "c" * 64]), \
             mock.patch.object(mod, "_runtime_archive_sha256", return_value="d" * 64):
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

        def fake_run(argv, **_kwargs):
            receipt_fd = int(argv[-1])
            mod.os.write(receipt_fd, mod.json.dumps(["/usr/bin/python3"]).encode("utf-8"))
            return completed

        with mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)), \
             mock.patch.object(mod, "python_runtime_identity", side_effect=[("/usr/bin/python3", "c" * 64), ("/usr/bin/python3", "c" * 64)]), \
             mock.patch.object(mod, "committed_snapshot", fake_snapshot), \
             mock.patch.object(mod, "_runtime_native_sha256", return_value="d" * 64), \
             mock.patch.object(mod.subprocess, "run", side_effect=fake_run) as run:
            result = mod.run_tests("a" * 40, "tests.test_safe")

        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/bin/python3", "-I", "-B", "-S"])
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["static_runtime_sha256"], "c" * 64)
        self.assertEqual(result["executed_native_sha256"], "d" * 64)
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(b"OK\n").hexdigest())


if __name__ == "__main__":
    unittest.main()
