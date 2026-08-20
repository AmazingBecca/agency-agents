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

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_native_runtime_loader_valid_alias", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_EH_FRAME = 0x6474E550
DT_NULL = 0
DT_STRTAB = 5
DT_STRSZ = 10
PAGE_SIZE = 0x1000


@unittest.skipUnless(os.sys.platform.startswith("linux"), "Linux native-runtime closure lane")
class NativeRuntimeLoaderValidAliasTests(unittest.TestCase):
    def test_loader_equivalent_partial_page_alias_is_accepted_and_loadable(self):
        """A congruent same-file page alias must stay usable under the real Linux loader."""
        compiler = shutil.which("cc") or shutil.which("gcc")
        self.assertIsNotNone(compiler, "hosted Linux lane requires a C compiler")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            source = root / "probe.c"
            candidate = root / "libloader-equivalent-alias.so"
            source.write_text("int agent_node_alias_probe(void) { return 7; }\n", encoding="utf-8")
            subprocess.run(
                [compiler, "-shared", "-fPIC", "-Wl,-z,noexecstack", "-o", str(candidate), str(source)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

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

            strtab_vaddr = None
            strtab_size = None
            for offset in range(dynamic_offset, dynamic_offset + dynamic_filesz, dynamic_size):
                tag, value = struct.unpack_from(dynamic_format, data, offset)
                if tag == DT_NULL:
                    break
                if tag == DT_STRTAB:
                    strtab_vaddr = value
                elif tag == DT_STRSZ:
                    strtab_size = value
            self.assertIsNotNone(strtab_vaddr)
            self.assertIsNotNone(strtab_size)
            self.assertGreater(strtab_size, 0)

            loads = [entry for entry in entries if entry[0] == PT_LOAD]
            owner = next(
                entry
                for entry in loads
                if entry[3] <= strtab_vaddr
                and strtab_vaddr + strtab_size <= entry[3] + entry[5]
            )
            strtab_file_offset = owner[2] + (strtab_vaddr - owner[3])
            page_end = ((strtab_file_offset // PAGE_SIZE) + 1) * PAGE_SIZE
            alias_offset = strtab_file_offset + strtab_size + 16
            self.assertLess(alias_offset, page_end)
            self.assertLess(alias_offset, owner[2] + owner[5])
            alias_vaddr = owner[3] + (alias_offset - owner[2])
            alias_size = min(64, owner[2] + owner[5] - alias_offset)
            self.assertGreater(alias_size, 0)

            alias = [
                PT_LOAD,
                owner[1],
                alias_offset,
                alias_vaddr,
                alias_vaddr,
                alias_size,
                alias_size,
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

            loaded = ctypes.CDLL(str(candidate))
            loaded.agent_node_alias_probe.restype = ctypes.c_int
            self.assertEqual(loaded.agent_node_alias_probe(), 7)
            self.assertEqual(mod._elf_needed_name_bytes(candidate), ())


if __name__ == "__main__":
    unittest.main()
