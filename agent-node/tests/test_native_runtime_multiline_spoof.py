from __future__ import annotations

import ctypes
import importlib.util
import os
import pathlib
import shutil
import struct
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

    def test_pt_dynamic_offset_cannot_hide_loaded_needed_table(self):
        """PT_DYNAMIC must be read through its loaded virtual address, not a spoofed file offset."""
        compiler = shutil.which("cc") or shutil.which("gcc")
        self.assertIsNotNone(compiler, "hosted Linux lane requires a C compiler for the PT_DYNAMIC falsifier")

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

            # Prove the loader consumes the real p_vaddr-backed dynamic table.
            loaded = ctypes.CDLL(str(wrapper))
            loaded.wrapper_value.restype = ctypes.c_int
            self.assertEqual(loaded.wrapper_value(), 7)

            data = bytearray(wrapper.read_bytes())
            self.assertEqual(data[:4], b"\x7fELF")
            elf_class = data[4]
            elf_data = data[5]
            prefix = "<" if elf_data == 1 else ">" if elf_data == 2 else None
            self.assertIsNotNone(prefix)
            if elf_class == 2:
                header_format = prefix + "HHIQQQIHHHHHH"
                program_format = prefix + "IIQQQQQQ"
                offset_field_delta = 8
            elif elf_class == 1:
                header_format = prefix + "HHIIIIIHHHHHH"
                program_format = prefix + "IIIIIIII"
                offset_field_delta = 4
            else:
                self.fail(f"unsupported ELF class in test fixture: {elf_class}")

            header = struct.unpack_from(header_format, data, 16)
            program_offset = header[4]
            program_entry_size = header[8]
            program_count = header[9]
            program_size = struct.calcsize(program_format)
            dynamic_found = False
            for index in range(program_count):
                ph_offset = program_offset + index * program_entry_size
                values = struct.unpack_from(program_format, data, ph_offset)
                if values[0] != 2:  # PT_DYNAMIC
                    continue
                dynamic_found = True
                p_filesz = values[5] if elf_class == 2 else values[4]
                spoof_offset = len(data)
                data.extend(b"\0" * p_filesz)
                offset_format = prefix + ("Q" if elf_class == 2 else "I")
                struct.pack_into(offset_format, data, ph_offset + offset_field_delta, spoof_offset)
                break
            self.assertTrue(dynamic_found, "test fixture must contain PT_DYNAMIC")
            wrapper.write_bytes(data)

            # The mutated PT_DYNAMIC file offset points to harmless zeros, but its
            # p_vaddr still identifies the real loaded dynamic table. Trusted ldd
            # therefore succeeds and glibc still resolves the newline-bearing DSO.
            ldd = subprocess.run(
                ["/usr/bin/ldd", str(wrapper)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(ldd.returncode, 0, ldd.stdout + ldd.stderr)
            self.assertIn("lib/x86_64-linux-gnu/libc.so.6", ldd.stdout)

            # Receipt discovery must not accept the spoofed p_offset table. It may
            # either recover DT_NEEDED via the p_vaddr/PT_LOAD mapping or fail closed.
            with self.assertRaisesRegex(RuntimeError, "dynamic|DT_NEEDED|ELF|multiline|dependency"):
                mod._ldd_dependency_paths(wrapper)


if __name__ == "__main__":
    unittest.main()
