import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import execution_expectation as ee


class ExecutionInputLimitTests(unittest.TestCase):
    def test_exact_limit_is_readable_and_over_limit_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            boundary = root / "boundary.bin"
            boundary.write_bytes(b"x" * ee.MAX_CONTROL_INPUT_BYTES)
            raw, _, _ = ee._read_regular(boundary, "boundary input")
            self.assertEqual(len(raw), ee.MAX_CONTROL_INPUT_BYTES)

            oversized = root / "oversized.bin"
            oversized.write_bytes(b"x" * (ee.MAX_CONTROL_INPUT_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "exceeds maximum size"):
                ee._read_regular(oversized, "oversized input")

    def test_growth_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "growing.bin"
            path.write_bytes(b"x" * 10)
            original_read = ee.os.read
            grown = False

            def read_then_grow(fd, size):
                nonlocal grown
                data = original_read(fd, size)
                if data and not grown:
                    with path.open("ab") as stream:
                        stream.write(b"y")
                        stream.flush()
                        os.fsync(stream.fileno())
                    grown = True
                return data

            with mock.patch.object(ee.os, "read", side_effect=read_then_grow):
                with self.assertRaisesRegex(ValueError, "changed during read"):
                    ee._read_regular(path, "growing input")

    def test_core_functions_resolve_bounded_reader_overrides(self):
        self.assertIs(ee.load_expectation.__globals__["_read_regular"], ee._read_regular)
        self.assertIs(ee.load_expectation.__globals__["_read_regular_at"], ee._read_regular_at)
        self.assertIs(ee.issue_bound_receipt_from_files.__globals__["_read_regular"], ee._read_regular)

    def test_bootstrap_core_is_exact_and_not_importable_python_surface(self):
        core = ROOT / "execution_expectation_v3.inc"
        self.assertEqual(core.suffix, ".inc")
        self.assertEqual(ee._CORE_SHA256, "023931bb6813b2804d607e4d34c3c88c7e421a96ed73d7ea29fb954f3f4a80cb")
        self.assertLess(core.stat().st_size, ee._CORE_MAX_BYTES)


if __name__ == "__main__":
    unittest.main()
