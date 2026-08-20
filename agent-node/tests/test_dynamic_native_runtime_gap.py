from __future__ import annotations

import contextlib
import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_dynamic_native_gap", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux dynamic-native discriminator")
class DynamicNativeRuntimeGapTests(unittest.TestCase):
    def test_run_tests_binds_dso_loaded_only_by_allowlisted_test(self):
        compiler = shutil.which("cc") or shutil.which("gcc")
        self.assertIsNotNone(compiler, "hosted Linux lane requires a C compiler")
        selector = "dynamic_case.DynamicNativeCase.test_probe"

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            source = root / "probe.c"
            library = root / "libagentnodedynamic.so"
            (snapshot / "dynamic_case.py").write_text(
                "import ctypes,os,unittest\n"
                "class DynamicNativeCase(unittest.TestCase):\n"
                "    def test_probe(self):\n"
                "        lib=ctypes.CDLL(os.environ['AGENT_NODE_DYNAMIC_LIB'])\n"
                "        lib.agent_node_probe.restype=ctypes.c_int\n"
                "        print(f'DYNAMIC_NATIVE_VALUE={lib.agent_node_probe()}')\n",
                encoding="utf-8",
            )

            def build(value: int) -> None:
                source.write_text(f"int agent_node_probe(void) {{ return {value}; }}\n", encoding="utf-8")
                subprocess.run(
                    [compiler, "-shared", "-fPIC", "-Wl,-soname,libagentnodedynamic.so", "-o", str(library), str(source)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            @contextlib.contextmanager
            def fake_snapshot(expected_head: str):
                yield expected_head, "b" * 40, snapshot

            build(1)
            with mock.patch.object(mod, "TEST_ALLOWLIST", (selector,)), \
                 mock.patch.object(mod, "committed_snapshot", fake_snapshot), \
                 mock.patch.dict(mod.os.environ, {"AGENT_NODE_DYNAMIC_LIB": str(library)}, clear=False):
                first = mod.run_tests("a" * 40, selector)
                build(2)
                second = mod.run_tests("a" * 40, selector)

        self.assertIn("DYNAMIC_NATIVE_VALUE=1", first["stdout"])
        self.assertIn("DYNAMIC_NATIVE_VALUE=2", second["stdout"])
        self.assertNotEqual(
            first["runtime_sha256"],
            second["runtime_sha256"],
            "runtime receipt must bind a DSO loaded only by the executed allowlisted test",
        )


if __name__ == "__main__":
    unittest.main()
