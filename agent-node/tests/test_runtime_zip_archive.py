from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_runtime_zip_archive", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class RuntimeZipArchiveTests(unittest.TestCase):
    @staticmethod
    def _write_archive(path: pathlib.Path, value: str, *, member: str = "runtime_probe.py") -> None:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(member, f"VALUE = {value!r}\n")

    @staticmethod
    def _import_from_archive(path: pathlib.Path | str) -> str:
        code = (
            "import sys;"
            "sys.path.insert(0, sys.argv[1]);"
            "import runtime_probe;"
            "print(runtime_probe.VALUE)"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-S", "-c", code, str(path)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return completed.stdout.strip()

    def test_stdlib_zip_mutation_changes_runtime_identity(self):
        """Executable stdlib zip bytes must participate in runtime_sha256."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lib = pathlib.Path(temp_dir) / "lib"
            root = lib / f"python{sys.version_info.major}.{sys.version_info.minor}"
            root.mkdir(parents=True)
            (root / "runtime_anchor.py").write_text("VALUE = 'anchor'\n", encoding="utf-8")
            archive = lib / f"python{sys.version_info.major}{sys.version_info.minor}.zip"
            search_paths = (str(archive), str(root))

            self._write_archive(archive, "one")
            self.assertEqual(self._import_from_archive(archive), "one")
            with mock.patch.object(mod, "_isolated_child_sys_path", return_value=search_paths):
                _python, before = mod.python_runtime_identity()
                self._write_archive(archive, "two")
                self.assertEqual(self._import_from_archive(archive), "two")
                _python, after = mod.python_runtime_identity()

        self.assertNotEqual(
            before,
            after,
            "runtime identity must bind executable standard-library zip archive bytes",
        )

    def test_zip_subdirectory_entry_binds_containing_archive(self):
        """A sys.path entry inside a ZIP must bind the containing archive bytes."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lib = pathlib.Path(temp_dir) / "lib"
            root = lib / f"python{sys.version_info.major}.{sys.version_info.minor}"
            root.mkdir(parents=True)
            (root / "runtime_anchor.py").write_text("VALUE = 'anchor'\n", encoding="utf-8")
            archive = lib / "runtime.zip"
            search_entry = f"{archive}/inside"
            search_paths = (search_entry, str(root))

            self._write_archive(archive, "one", member="inside/runtime_probe.py")
            self.assertEqual(self._import_from_archive(search_entry), "one")
            with mock.patch.object(mod, "_isolated_child_sys_path", return_value=search_paths):
                _python, before = mod.python_runtime_identity()
                self._write_archive(archive, "two", member="inside/runtime_probe.py")
                self.assertEqual(self._import_from_archive(search_entry), "two")
                _python, after = mod.python_runtime_identity()

        self.assertNotEqual(
            before,
            after,
            "runtime identity must bind a ZIP container referenced through a sys.path subdirectory",
        )

    def test_zip_dot_segment_entry_binds_original_archive(self):
        """Dot segments after a ZIP boundary must not hide the archive from runtime identity."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lib = pathlib.Path(temp_dir) / "lib"
            root = lib / f"python{sys.version_info.major}.{sys.version_info.minor}"
            root.mkdir(parents=True)
            (root / "runtime_anchor.py").write_text("VALUE = 'anchor'\n", encoding="utf-8")
            archive = lib / "runtime.zip"
            search_entry = f"{archive}/../shadow/inside"
            archive_member = "../shadow/inside/runtime_probe.py"
            search_paths = (search_entry, str(root))

            self._write_archive(archive, "one", member=archive_member)
            self.assertEqual(self._import_from_archive(search_entry), "one")
            with mock.patch.object(mod, "_isolated_child_sys_path", return_value=search_paths):
                _python, before = mod.python_runtime_identity()
                self._write_archive(archive, "two", member=archive_member)
                self.assertEqual(self._import_from_archive(search_entry), "two")
                _python, after = mod.python_runtime_identity()

        self.assertNotEqual(
            before,
            after,
            "runtime identity must bind the original ZIP before dot-segment normalization",
        )


if __name__ == "__main__":
    unittest.main()
