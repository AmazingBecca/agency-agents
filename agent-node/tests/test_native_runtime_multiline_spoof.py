from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
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

    def test_address_spoofed_multiline_needed_record_is_rejected(self):
        compiler = shutil.which("cc") or shutil.which("gcc")
        self.assertIsNotNone(compiler, "hosted Linux lane requires a C compiler for the multiline ELF falsifier")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            actual = root / "decoy.so (0x1)\n\t" / "lib" / "x86_64-linux-gnu" / "libc.so.6"
            actual.parent.mkdir(parents=True)
            dep_source = root / "dep.c"
            dep_source.write_text("int dep_value(void) { return 7; }\n", encoding="utf-8")
            subprocess.run(
                [compiler, "-shared", "-fPIC", f"-Wl,-soname,{actual}", "-o", str(actual), str(dep_source)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            wrapper_source = root / "wrapper.c"
            wrapper_source.write_text(
                "extern int dep_value(void); int wrapper_value(void) { return dep_value(); }\n",
                encoding="utf-8",
            )
            wrapper = root / "libwrapper.so"
            subprocess.run(
                [
                    compiler,
                    "-shared",
                    "-fPIC",
                    "-Wl,--no-as-needed",
                    "-o",
                    str(wrapper),
                    str(wrapper_source),
                    str(actual),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # The first physical ldd segment is deliberately shaped like a complete
            # address-bearing record while the next segment points at an existing
            # system library. The DT_NEEDED value itself is one newline-containing
            # pathname and must therefore be rejected before per-line parsing.
            with self.assertRaisesRegex(RuntimeError, "multiline|DT_NEEDED|dependency"):
                mod._ldd_dependency_paths(wrapper)


if __name__ == "__main__":
    unittest.main()
