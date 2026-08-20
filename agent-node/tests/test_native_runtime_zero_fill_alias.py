from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_native_runtime_zero_fill_alias", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_EH_FRAME = 0x6474E550
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10


@unittest.skipUnless(os.sys.platform.startswith("linux"), "Linux native-runtime closure lane")
class NativeRuntimeZeroFillAliasTests(unittest.TestCase):
    def test_same_delta_alias_zero_fill_cannot_change_needed_name(self):
        """A same-delta PT_LOAD alias must fail closed if its BSS zero-fill can rewrite DT_STRTAB."""
        compiler = shutil.which("cc") or shutil.which("gcc")
        self.assertIsNotNone(compiler, "hosted Linux lane requires a C compiler")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            dep7_source = root / "dep7.c"
            dep9_source = root / "dep9.c"
            main_source = root / "main.c"
            dep7 = root / "Xlong"
            dep9 = root / "X"
            candidate = root / "libzero-fill-alias.so"

            dep7_source.write_text("int dep(void) { return 7; }\n", encoding="utf-8")
            dep9_source.write_text("int dep(void) { return 9; }\n", encoding="utf-8")
            main_source.write_text(
                "extern int dep(void); int agent_node_zero_fill_probe(void) { return dep(); }\n",
                encoding="utf-8",
            )
            subprocess.run(
                [compiler, "-shared", "-fPIC", "-Wl,-soname,Xlong", "-o", str(dep7), str(dep7_source)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                [compiler, "-shared", "-fPIC", "-Wl,-soname,X", "-o", str(dep9), str(dep9_source)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                [
                    compiler,
                    "-shared",
                    "-fPIC",
                    "-Wl,-z,noexecstack",
                    "-Wl,-rpath,$ORIGIN",
                    f"-L{root}",
                    "-Wl,--no-as-needed",
                    "-Wl,-l:Xlong",
                    "-o",
                    str(candidate),
                    str(main_source),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            execute_code = (
                "import ctypes,sys;"
                "lib=ctypes.CDLL(sys.argv[1]);"
                "lib.agent_node_zero_fill_probe.restype=ctypes.c_int;"
                "print(lib.agent_node_zero_fill_probe())"
            )
            env = dict(os.environ)
            env["LD_LIBRARY_PATH"] = str(root)

            def execute() -> int:
                completed = subprocess.run(
                    [sys.executable, "-I", "-B", "-S", "-c", execute_code, str(candidate)],
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                return int(completed.stdout.strip())

            self.assertEqual(execute(), 7)
            self.assertIn(b"Xlong", mod._elf_needed_name_bytes(candidate))

            data = bytearray(candidate.read_bytes())
            self.assertEqual(data[:4], b"\x7fELF")
            self.assertEqual(data[4], 2, "fixture requires ELF64")
            self.assertEqual(data[5], 1, "fixture requires little-endian ELF")

            program_format = "<IIQQQQQQ"
            dynamic_format = "<qQ"
            program_size = struct.calcsize(program_format)
            dynamic_size = struct.calcsize(dynamic_format)
            phoff = struct.unpack_from("<Q", data, 32)[0]
            phentsize = struct.unpack_from("<H", data, 54)[0]
            phnum = struct.unpack_from("<H", data, 56)[0]
            self.assertGreaterEqual(phentsize, program_size)

            entries = [
                list(struct.unpack_from(program_format, data, phoff + index * phentsize))
                for index in range(phnum)
            ]
            dynamic = next(entry for entry in entries if entry[0] == PT_DYNAMIC)
            dynamic_offset = dynamic[2]
            dynamic_filesz = dynamic[5]

            needed_offsets: list[int] = []
            strtab_vaddr = None
            strtab_size = None
            for offset in range(dynamic_offset, dynamic_offset + dynamic_filesz, dynamic_size):
                tag, value = struct.unpack_from(dynamic_format, data, offset)
                if tag == DT_NULL:
                    break
                if tag == DT_NEEDED:
                    needed_offsets.append(value)
                elif tag == DT_STRTAB:
                    strtab_vaddr = value
                elif tag == DT_STRSZ:
                    strtab_size = value
            self.assertIsNotNone(strtab_vaddr)
            self.assertIsNotNone(strtab_size)

            loads = [entry for entry in entries if entry[0] == PT_LOAD]
            owner = next(
                entry
                for entry in loads
                if entry[3] <= strtab_vaddr
                and strtab_vaddr + strtab_size <= entry[3] + entry[5]
            )
            strtab_file_offset = owner[2] + (strtab_vaddr - owner[3])
            target_needed_offset = next(
                value
                for value in needed_offsets
                if data[
                    strtab_file_offset + value : data.find(
                        b"\0", strtab_file_offset + value, strtab_file_offset + strtab_size
                    )
                ]
                == b"Xlong"
            )
            needed_file_offset = strtab_file_offset + target_needed_offset
            needed_vaddr = strtab_vaddr + target_needed_offset

            alias = [
                PT_LOAD,
                owner[1],
                needed_file_offset,
                needed_vaddr,
                needed_vaddr,
                1,
                len(b"Xlong") + 1,
                owner[7],
            ]
            self.assertEqual(alias[2] - alias[3], owner[2] - owner[3])
            replace_index = next(
                index for index, entry in enumerate(entries) if entry[0] == PT_GNU_EH_FRAME
            )
            non_loads = [
                entry
                for index, entry in enumerate(entries)
                if index != replace_index and entry[0] != PT_LOAD
            ]
            rewritten = sorted(loads + [alias], key=lambda entry: (entry[3], entry[2])) + non_loads
            self.assertEqual(len(rewritten), phnum)
            for index, entry in enumerate(rewritten):
                struct.pack_into(program_format, data, phoff + index * phentsize, *entry)
            candidate.write_bytes(data)

            # Linux loads the later same-file page alias, then zero-fills after its one file byte.
            # The on-disk DT_NEEDED remains Xlong, but the loaded string becomes X and execution
            # therefore switches from the Xlong dependency (7) to the X dependency (9).
            self.assertEqual(execute(), 9)
            with self.assertRaises(RuntimeError):
                mod._elf_needed_name_bytes(candidate)


if __name__ == "__main__":
    unittest.main()
