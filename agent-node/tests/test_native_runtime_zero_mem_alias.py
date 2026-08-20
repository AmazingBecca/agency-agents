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
spec = importlib.util.spec_from_file_location("agent_node_native_runtime_zero_mem_alias", MODULE_PATH)
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
class NativeRuntimeZeroMemAliasTests(unittest.TestCase):
    def test_zero_file_zero_mem_pt_load_page_mapping_cannot_rewrite_needed_name(self):
        """A non-page-aligned p_filesz=0,p_memsz=0 PT_LOAD can still remap its containing file page."""
        compiler = shutil.which("cc") or shutil.which("gcc")
        self.assertIsNotNone(compiler, "hosted Linux lane requires a C compiler")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            dep7_source = root / "dep7.c"
            dep9_source = root / "dep9.c"
            main_source = root / "main.c"
            dep7 = root / "Xlong"
            dep9 = root / "X"
            candidate = root / "libzero-mem-alias.so"

            dep7_source.write_text("int dep(void) { return 7; }\n", encoding="utf-8")
            dep9_source.write_text("int dep(void) { return 9; }\n", encoding="utf-8")
            main_source.write_text(
                "extern int dep(void); int agent_node_zero_mem_probe(void) { return dep(); }\n",
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
                "lib.agent_node_zero_mem_probe.restype=ctypes.c_int;"
                "print(lib.agent_node_zero_mem_probe())"
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

            page_size = int(os.sysconf("SC_PAGESIZE"))
            self.assertGreater(page_size, 0)
            page_mask = page_size - 1
            program_format = "<IIQQQQQQ"
            dynamic_format = "<qQ"
            program_size = struct.calcsize(program_format)
            dynamic_entry_size = struct.calcsize(dynamic_format)
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
            for offset in range(dynamic_offset, dynamic_offset + dynamic_filesz, dynamic_entry_size):
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
            needed_vaddr = strtab_vaddr + target_needed_offset

            alias_vaddr = strtab_vaddr - 1
            alias_page_vaddr = alias_vaddr & ~page_mask
            owner_page_file_offset = owner[2] + (alias_page_vaddr - owner[3])
            self.assertGreaterEqual(owner_page_file_offset, 0)
            source_page = bytearray(data[owner_page_file_offset : owner_page_file_offset + page_size])
            if len(source_page) < page_size:
                source_page.extend(b"\0" * (page_size - len(source_page)))

            needed_page_offset = needed_vaddr - alias_page_vaddr
            self.assertEqual(source_page[needed_page_offset : needed_page_offset + len(b"Xlong")], b"Xlong")
            source_page[needed_page_offset : needed_page_offset + len(b"Xlong")] = b"X\0" + b"\0" * 3

            alias_page_file_offset = (len(data) + page_mask) & ~page_mask
            if len(data) < alias_page_file_offset:
                data.extend(b"\0" * (alias_page_file_offset - len(data)))
            data.extend(source_page)
            alias_offset = alias_page_file_offset + (alias_vaddr - alias_page_vaddr)
            self.assertEqual(alias_offset & page_mask, alias_vaddr & page_mask)

            alias = [
                PT_LOAD,
                owner[1],
                alias_offset,
                alias_vaddr,
                alias_vaddr,
                0,
                0,
                owner[7],
            ]
            replace_index = next(index for index, entry in enumerate(entries) if entry[0] == PT_GNU_EH_FRAME)
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

            self.assertEqual(execute(), 9)
            with self.assertRaises(RuntimeError):
                mod._elf_needed_name_bytes(candidate)


if __name__ == "__main__":
    unittest.main()
