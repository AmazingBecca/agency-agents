from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_native_runtime_multiline_spoof", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(os.sys.platform.startswith("linux"), "Linux native-runtime closure lane")
class NativeRuntimeMultilineSpoofTests(unittest.TestCase):
    def test_static_marker_cannot_hide_multiline_needed_record(self):
        fake = subprocess.CompletedProcess(
            args=["/usr/bin/ldd", "/runtime/python"],
            returncode=0,
            stdout=(
                "\tstatically linked\n"
                "\t/lib/x86_64-linux-gnu/libc.so.6 (0x00007f0000000000)\n"
            ),
            stderr="",
        )
        with mock.patch.object(mod.subprocess, "run", return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "multiline|dependency"):
                mod._ldd_dependency_paths(pathlib.Path("/runtime/python"))

    def test_address_like_first_segment_cannot_hide_multiline_needed_record(self):
        fake = subprocess.CompletedProcess(
            args=["/usr/bin/ldd", "/runtime/python"],
            returncode=0,
            stdout=(
                "\tdir (0x1)\n"
                "\t/lib/x86_64-linux-gnu/libc.so.6 (0x00007f0000000000)\n"
            ),
            stderr="",
        )
        with mock.patch.object(mod.subprocess, "run", return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "multiline|dependency"):
                mod._ldd_dependency_paths(pathlib.Path("/runtime/python"))

    def test_empty_first_segment_cannot_hide_multiline_needed_record(self):
        fake = subprocess.CompletedProcess(
            args=["/usr/bin/ldd", "/runtime/python"],
            returncode=0,
            stdout=(
                "\t\n"
                "\t/lib/x86_64-linux-gnu/libc.so.6 (0x00007f0000000000)\n"
            ),
            stderr="",
        )
        with mock.patch.object(mod.subprocess, "run", return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "multiline|dependency"):
                mod._ldd_dependency_paths(pathlib.Path("/runtime/python"))


if __name__ == "__main__":
    unittest.main()
