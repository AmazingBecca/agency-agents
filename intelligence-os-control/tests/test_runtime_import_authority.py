from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import runtime_authority_closure as subject


class RuntimeImportAuthorityTests(unittest.TestCase):
    def test_unloaded_runtime_member_is_bound_without_importing_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = pathlib.Path(directory).resolve(strict=True)
            library = prefix / "lib"
            library.mkdir()
            unloaded = library / "never_imported.py"
            unloaded.write_text("VALUE = 7\n", encoding="utf-8")

            with patch.object(subject, "_runtime_prefixes", return_value=(prefix,)), patch.object(
                subject, "_runtime_import_roots", return_value=(library,)
            ):
                paths = subject._runtime_import_paths()

        self.assertIn(unloaded.resolve(strict=False), paths)

    def test_runtime_import_symlink_may_not_escape_sealed_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            prefix = pathlib.Path(directory).resolve(strict=True)
            library = prefix / "lib"
            library.mkdir()
            outside = pathlib.Path(outside_directory).resolve(strict=True) / "foreign.py"
            outside.write_text("VALUE = 9\n", encoding="utf-8")
            (library / "escape.py").symlink_to(outside)

            with patch.object(subject, "_runtime_prefixes", return_value=(prefix,)), patch.object(
                subject, "_runtime_import_roots", return_value=(library,)
            ):
                with self.assertRaisesRegex(RuntimeError, "symlink escaped sealed runtime prefix"):
                    subject._runtime_import_paths()

    def test_runtime_import_search_path_outside_sealed_prefix_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            prefix = pathlib.Path(directory).resolve(strict=True)
            library = prefix / "lib"
            library.mkdir()
            outside = pathlib.Path(outside_directory).resolve(strict=True)
            control_root = prefix / "control"
            control_root.mkdir()

            with patch.object(subject, "_runtime_prefixes", return_value=(prefix,)), patch.object(
                subject, "_stdlib_roots", return_value=(library,)
            ), patch.object(subject, "_site_roots", return_value=()), patch.object(
                subject, "_CONTROL_SOURCE_ROOT", control_root
            ), patch.object(subject.sys, "path", [str(outside)]):
                with self.assertRaisesRegex(RuntimeError, "import search path escaped sealed runtime authority"):
                    subject._runtime_import_roots()

    def test_control_source_path_is_not_misclassified_as_runtime_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = pathlib.Path(directory).resolve(strict=True)
            library = prefix / "lib"
            library.mkdir()
            control_root = prefix.parent / (prefix.name + "-control")
            control_root.mkdir()
            try:
                with patch.object(subject, "_runtime_prefixes", return_value=(prefix,)), patch.object(
                    subject, "_stdlib_roots", return_value=(library,)
                ), patch.object(subject, "_site_roots", return_value=()), patch.object(
                    subject, "_CONTROL_SOURCE_ROOT", control_root
                ), patch.object(subject.sys, "path", [str(control_root)]):
                    roots = subject._runtime_import_roots()
            finally:
                control_root.rmdir()

        self.assertEqual(roots, (library.resolve(strict=False),))


if __name__ == "__main__":
    unittest.main()
