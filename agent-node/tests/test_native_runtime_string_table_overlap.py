from __future__ import annotations

import importlib.util
import os
import pathlib
import struct
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_native_runtime_string_table_overlap", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(os.sys.platform.startswith("linux"), "Linux native-runtime closure lane")
class NativeRuntimeStringTableOverlapTests(unittest.TestCase):
    def test_overlapping_pt_load_string_table_mappings_fail_closed(self):
        """DT_STRTAB must have one loader-equivalent PT_LOAD mapping, not first-match authority."""
        with tempfile.TemporaryDirectory() as temp_dir:
            candidate = pathlib.Path(temp_dir) / "liboverlap.so"
            data = bytearray(0x500)

            ident = bytearray(16)
            ident[:4] = b"\x7fELF"
            ident[4] = 2  # ELFCLASS64
            ident[5] = 1  # little endian
            ident[6] = 1  # EV_CURRENT
            data[:16] = ident

            header_format = "<HHIQQQIHHHHHH"
            program_format = "<IIQQQQQQ"
            dynamic_format = "<qQ"
            phoff = 64
            phentsize = struct.calcsize(program_format)
            phnum = 4
            struct.pack_into(
                header_format,
                data,
                16,
                3,      # ET_DYN
                62,     # EM_X86_64
                1,      # EV_CURRENT
                0,
                phoff,
                0,
                0,
                64,
                phentsize,
                phnum,
                0,
                0,
                0,
            )

            headers = (
                # Unique PT_LOAD for PT_DYNAMIC.
                (1, 4, 0x200, 0x400000, 0, 0x100, 0x100, 0x1000),
                # First DT_STRTAB mapping contains benign bytes.
                (1, 4, 0x300, 0x500000, 0, 0x80, 0x80, 0x1000),
                # Overlapping loader-equivalent mapping contains the actual bytes.
                (1, 4, 0x400, 0x500000, 0, 0x80, 0x80, 0x1000),
                (2, 4, 0x220, 0x400020, 0, 0x40, 0x40, 8),
            )
            for index, values in enumerate(headers):
                struct.pack_into(program_format, data, phoff + index * phentsize, *values)

            dynamic_entries = (
                (1, 0),          # DT_NEEDED at string-table offset 0
                (5, 0x500000),   # DT_STRTAB
                (10, 0x20),      # DT_STRSZ
                (0, 0),          # DT_NULL
            )
            dynamic_size = struct.calcsize(dynamic_format)
            for index, values in enumerate(dynamic_entries):
                struct.pack_into(dynamic_format, data, 0x220 + index * dynamic_size, *values)

            data[0x300 : 0x300 + len(b"benign.so\0")] = b"benign.so\0"
            data[0x400 : 0x400 + len(b"actual.so\0")] = b"actual.so\0"
            candidate.write_bytes(data)

            with self.assertRaisesRegex(RuntimeError, "string table|PT_LOAD|unique|mapping"):
                mod._elf_needed_name_bytes(candidate)


if __name__ == "__main__":
    unittest.main()
