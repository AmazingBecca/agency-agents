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

    def test_page_overlapping_partial_pt_load_mapping_fails_closed(self):
        """A partial PT_LOAD on a DT_STRTAB page can replace the page after mmap alignment."""
        with tempfile.TemporaryDirectory() as temp_dir:
            candidate = pathlib.Path(temp_dir) / "libpageoverlap.so"
            data = bytearray(0x3000)

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
            struct.pack_into(
                header_format,
                data,
                16,
                3,
                62,
                1,
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
                (1, 4, 0x400, 0x400000, 0, 0x200, 0x200, 0x1000),
                # Whole-range DT_STRTAB mapping. The parser currently trusts this mapping.
                (1, 4, 0x1000, 0x500000, 0, 0x800, 0x800, 0x1000),
                # Starts one byte into DT_STRTAB, but mmap page alignment maps file page 0x2000
                # over virtual page 0x500000 and can therefore replace the whole table page.
                (1, 4, 0x2001, 0x500001, 0, 0x7FF, 0x7FF, 0x1000),
                (2, 4, 0x420, 0x400020, 0, 0x40, 0x40, 8),
            )
            for index, values in enumerate(headers):
                struct.pack_into(program_format, data, phoff + index * phentsize, *values)

            dynamic_entries = (
                (1, 0),
                (5, 0x500000),
                (10, 0x100),
                (0, 0),
            )
            dynamic_size = struct.calcsize(dynamic_format)
            for index, values in enumerate(dynamic_entries):
                struct.pack_into(dynamic_format, data, 0x420 + index * dynamic_size, *values)

            data[0x1000 : 0x1000 + len(b"benign.so\0")] = b"benign.so\0"
            data[0x2000 : 0x2000 + len(b"actual.so\0")] = b"actual.so\0"
            candidate.write_bytes(data)

            with self.assertRaisesRegex(RuntimeError, "string table|PT_LOAD|page|overlap|mapping"):
                mod._elf_needed_name_bytes(candidate)

    def test_page_overlapping_partial_pt_load_mapping_with_same_file_page_is_allowed(self):
        """A page alias that maps identical file bytes must not make a valid runtime unusable."""
        with tempfile.TemporaryDirectory() as temp_dir:
            candidate = pathlib.Path(temp_dir) / "libequivalentpageoverlap.so"
            data = bytearray(0x3000)

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
            struct.pack_into(
                header_format,
                data,
                16,
                3,
                62,
                1,
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
                (1, 4, 0x400, 0x400000, 0, 0x200, 0x200, 0x1000),
                # Full string-table mapping: virtual page 0x500000 -> file page 0x1000.
                (1, 4, 0x1000, 0x500000, 0, 0x800, 0x800, 0x1000),
                # Partial alias starts after the table bytes but maps the same virtual page to
                # the same file page, so page alignment cannot substitute different table bytes.
                (1, 4, 0x1200, 0x500200, 0, 0x600, 0x600, 0x1000),
                (2, 4, 0x420, 0x400020, 0, 0x40, 0x40, 8),
            )
            for index, values in enumerate(headers):
                struct.pack_into(program_format, data, phoff + index * phentsize, *values)

            dynamic_entries = (
                (1, 0),
                (5, 0x500000),
                (10, 0x100),
                (0, 0),
            )
            dynamic_size = struct.calcsize(dynamic_format)
            for index, values in enumerate(dynamic_entries):
                struct.pack_into(dynamic_format, data, 0x420 + index * dynamic_size, *values)

            data[0x1000 : 0x1000 + len(b"benign.so\0")] = b"benign.so\0"
            candidate.write_bytes(data)

            self.assertEqual(mod._elf_needed_name_bytes(candidate), (b"benign.so",))

    def test_page_overlapping_partial_pt_load_mapping_for_pt_dynamic_fails_closed(self):
        """A partial PT_LOAD on the PT_DYNAMIC page can replace loader-visible dynamic entries."""
        with tempfile.TemporaryDirectory() as temp_dir:
            candidate = pathlib.Path(temp_dir) / "libdynamicpageoverlap.so"
            data = bytearray(0x4000)

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
            struct.pack_into(
                header_format,
                data,
                16,
                3,
                62,
                1,
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
                # Whole-range PT_DYNAMIC mapping: virtual page 0x400000 -> file page 0x1000.
                (1, 4, 0x1000, 0x400000, 0, 0x800, 0x800, 0x1000),
                # Begins one byte inside PT_DYNAMIC. The whole-range uniqueness check ignores it,
                # but Linux page alignment can map file page 0x2000 over virtual page 0x400000.
                (1, 4, 0x2021, 0x400021, 0, 0x7DF, 0x7DF, 0x1000),
                # Unambiguous string-table mapping.
                (1, 4, 0x3000, 0x500000, 0, 0x200, 0x200, 0x1000),
                (2, 4, 0x1020, 0x400020, 0, 0x40, 0x40, 8),
            )
            for index, values in enumerate(headers):
                struct.pack_into(program_format, data, phoff + index * phentsize, *values)

            dynamic_entries = (
                (1, 0),
                (5, 0x500000),
                (10, 0x100),
                (0, 0),
            )
            dynamic_size = struct.calcsize(dynamic_format)
            for index, values in enumerate(dynamic_entries):
                struct.pack_into(dynamic_format, data, 0x1020 + index * dynamic_size, *values)

            # A different page image exists at the partial mapping's aligned file page. The
            # parser must not assume the earlier whole-range PT_LOAD remains authoritative.
            malicious_entries = (
                (1, len(b"benign.so\0")),
                (5, 0x500000),
                (10, 0x100),
                (0, 0),
            )
            for index, values in enumerate(malicious_entries):
                struct.pack_into(dynamic_format, data, 0x2020 + index * dynamic_size, *values)

            data[0x3000 : 0x3000 + len(b"benign.so\0actual.so\0")] = b"benign.so\0actual.so\0"
            candidate.write_bytes(data)

            with self.assertRaisesRegex(RuntimeError, "PT_DYNAMIC|page|overlap|mapping"):
                mod._elf_needed_name_bytes(candidate)


if __name__ == "__main__":
    unittest.main()
