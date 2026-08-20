from __future__ import annotations

import importlib.util
import os
import pathlib
import struct
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_native_runtime_string_table_page_overlap", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(os.sys.platform.startswith("linux"), "Linux native-runtime closure lane")
class NativeRuntimeStringTablePageOverlapTests(unittest.TestCase):
    def test_partial_page_overlapping_pt_load_string_table_mapping_fails_closed(self):
        """A later partial PT_LOAD must not replace a DT_STRTAB page outside the full-range check."""
        page_size = os.sysconf("SC_PAGE_SIZE")
        if not isinstance(page_size, int) or page_size < 0x1000 or page_size & (page_size - 1):
            self.skipTest(f"unsupported Linux page size for deterministic ELF fixture: {page_size!r}")

        with tempfile.TemporaryDirectory() as temp_dir:
            candidate = pathlib.Path(temp_dir) / "libpageoverlap.so"
            data = bytearray(page_size + 0x2000)

            ident = bytearray(16)
            ident[:4] = b"\x7fELF"
            ident[4] = 2
            ident[5] = 1
            ident[6] = 1
            data[:16] = ident

            header_format = "<HHIQQQIHHHHHH"
            program_format = "<IIQQQQQQ"
            dynamic_format = "<qQ"
            phoff = 64
            phentsize = struct.calcsize(program_format)
            phnum = 4
            struct.pack_into(header_format, data, 16, 3, 62, 1, 0, phoff, 0, 0, 64, phentsize, phnum, 0, 0, 0)

            virtual_page = 0x500000
            headers = (
                (1, 4, 0x200, 0x400200, 0, 0x100, 0x100, page_size),
                (1, 4, 0x300, virtual_page + 0x300, 0, 0x100, 0x100, page_size),
                (1, 4, page_size + 0x321, virtual_page + 0x321, 0, 0x40, 0x40, page_size),
                (2, 4, 0x220, 0x400220, 0, 0x40, 0x40, 8),
            )
            for index, values in enumerate(headers):
                struct.pack_into(program_format, data, phoff + index * phentsize, *values)

            dynamic_entries = (
                (1, 0),
                (5, virtual_page + 0x320),
                (10, 0x20),
                (0, 0),
            )
            dynamic_size = struct.calcsize(dynamic_format)
            for index, values in enumerate(dynamic_entries):
                struct.pack_into(dynamic_format, data, 0x220 + index * dynamic_size, *values)

            data[0x320 : 0x320 + len(b"benign.so\0")] = b"benign.so\0"
            actual_offset = page_size + 0x320
            data[actual_offset : actual_offset + len(b"actual.so\0")] = b"actual.so\0"
            candidate.write_bytes(data)

            with self.assertRaisesRegex(RuntimeError, "string table|PT_LOAD|page|mapping"):
                mod._elf_needed_name_bytes(candidate)


if __name__ == "__main__":
    unittest.main()
