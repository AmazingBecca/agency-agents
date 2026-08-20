from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import struct
import subprocess
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_native_runtime_pt_dynamic_size", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(os.sys.platform.startswith("linux"), "Linux native-runtime closure lane")
class NativeRuntimePtDynamicSizeTests(unittest.TestCase):
    def test_pt_dynamic_filesz_cannot_truncate_before_loaded_dt_null(self):
        compiler = shutil.which("cc") or shutil.which("gcc")
        self.assertIsNotNone(compiler, "hosted Linux lane requires a C compiler")

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
                [compiler, "-shared", "-fPIC", "-Wl,--no-as-needed", "-o", str(wrapper), str(wrapper_source), str(actual)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            data = bytearray(wrapper.read_bytes())
            self.assertEqual(data[:4], b"\x7fELF")
            elf_class, elf_data = data[4], data[5]
            prefix = "<" if elf_data == 1 else ">" if elf_data == 2 else None
            self.assertIsNotNone(prefix)
            if elf_class == 2:
                header_format = prefix + "HHIQQQIHHHHHH"
                program_format = prefix + "IIQQQQQQ"
                filesz_offset = 32
                filesz_format = prefix + "Q"
            elif elf_class == 1:
                header_format = prefix + "HHIIIIIHHHHHH"
                program_format = prefix + "IIIIIIII"
                filesz_offset = 16
                filesz_format = prefix + "I"
            else:
                self.fail(f"unsupported ELF class in test fixture: {elf_class}")

            header = struct.unpack_from(header_format, data, 16)
            program_offset, program_entry_size, program_count = header[4], header[8], header[9]
            dynamic_found = False
            for index in range(program_count):
                ph_offset = program_offset + index * program_entry_size
                values = struct.unpack_from(program_format, data, ph_offset)
                if values[0] != 2:
                    continue
                dynamic_found = True
                struct.pack_into(filesz_format, data, ph_offset + filesz_offset, 0)
                break
            self.assertTrue(dynamic_found, "fixture must contain PT_DYNAMIC")
            wrapper.write_bytes(data)

            probe = (
                "import ctypes,sys;"
                "lib=ctypes.CDLL(sys.argv[1]);"
                "lib.wrapper_value.restype=ctypes.c_int;"
                "print(lib.wrapper_value())"
            )
            executed = subprocess.run(
                [os.sys.executable, "-I", "-B", "-S", "-c", probe, str(wrapper)],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(executed.stdout.strip(), "7")

            with self.assertRaisesRegex(RuntimeError, "DT_NULL|dynamic|DT_NEEDED|ELF|multiline|dependency"):
                mod._ldd_dependency_paths(wrapper)


if __name__ == "__main__":
    unittest.main()
