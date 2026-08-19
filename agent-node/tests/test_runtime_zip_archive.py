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
    def _write_archive(path: pathlib.Path, value: str) -> None:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("runtime_probe.py", f"VALUE = {value!r}\n")

    @staticmethod
    def _import_from_archive(path: pathlib.Path) -> str:
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

            self._write_archive(archive, "one")
            self.assertEqual(self._import_from_archive(archive), "one")
            with mock.patch.object(mod, "_runtime_roots", return_value=(root,)), mock.patch.object(
                mod.sys, "path", [str(archive), str(root)]
            ):
                _python, before = mod.python_runtime_identity()
                self._write_archive(archive, "two")
                self.assertEqual(self._import_from_archive(archive), "two")
                _python, after = mod.python_runtime_identity()

        self.assertNotEqual(
            before,
            after,
            "runtime identity must bind executable standard-library zip archive bytes",
        )


if __name__ == "__main__":
    unittest.main()
