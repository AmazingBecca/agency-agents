from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_native_runtime_closure", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def linux_executable_mappings() -> tuple[pathlib.Path, ...]:
    if not sys.platform.startswith("linux"):
        return ()
    paths: set[pathlib.Path] = set()
    with open("/proc/self/maps", "r", encoding="utf-8") as handle:
        for line in handle:
            parts = line.rstrip("\n").split(None, 5)
            if len(parts) < 6 or "x" not in parts[1]:
                continue
            value = parts[5]
            if not value.startswith("/") or value.endswith(" (deleted)"):
                continue
            paths.add(pathlib.Path(value))
    return tuple(sorted(paths, key=os.fspath))


def has_loader(paths: tuple[pathlib.Path, ...]) -> bool:
    return any("ld-linux" in path.name or "ld-musl" in path.name for path in paths)


def has_libc(paths: tuple[pathlib.Path, ...]) -> bool:
    return any(path.name.startswith("libc.so") or path.name.startswith("libc-") for path in paths)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux native-runtime closure lane")
class NativeRuntimeClosureTests(unittest.TestCase):
    def test_current_python_native_mappings_are_observable(self):
        paths = linux_executable_mappings()
        self.assertTrue(paths)
        self.assertTrue(has_loader(paths), paths)
        self.assertTrue(has_libc(paths), paths)
        print("NATIVE_RUNTIME_BASELINE=" + ";".join(os.fspath(path) for path in paths))

    def test_isolated_child_discovers_loader_and_libc(self):
        self.assertTrue(
            hasattr(mod, "_child_native_runtime_paths"),
            "exact isolated child native dependency discovery is required",
        )
        paths = tuple(pathlib.Path(value) for value in mod._child_native_runtime_paths(sys.executable))
        self.assertTrue(paths)
        self.assertTrue(all(path.is_absolute() for path in paths))
        self.assertTrue(all(path.exists() for path in paths))
        self.assertTrue(has_loader(paths), paths)
        self.assertTrue(has_libc(paths), paths)
        print("AGENT_NODE_NATIVE_PATHS=" + ";".join(os.fspath(path) for path in paths))

    def test_native_digest_binds_real_file_bytes_and_symlink_target(self):
        self.assertTrue(hasattr(mod, "_runtime_native_sha256"), "native runtime digest helper is required")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            first = root / "libprobe-v1.so"
            second = root / "libprobe-v2.so"
            first.write_bytes(b"native-runtime-v1")
            second.write_bytes(b"native-runtime-v2")
            link = root / "libprobe.so"
            link.symlink_to(first.name)

            before = mod._runtime_native_sha256((link,))
            first.write_bytes(b"native-runtime-v1-mutated")
            target_mutation = mod._runtime_native_sha256((link,))
            link.unlink()
            link.symlink_to(second.name)
            link_mutation = mod._runtime_native_sha256((link,))

        self.assertNotEqual(before, target_mutation)
        self.assertNotEqual(target_mutation, link_mutation)

    def test_executable_shared_library_mutation_changes_native_digest(self):
        self.assertTrue(hasattr(mod, "_runtime_native_sha256"), "native runtime digest helper is required")
        compiler = shutil.which("cc") or shutil.which("gcc")
        self.assertIsNotNone(compiler, "hosted Linux lane requires a C compiler for the native falsifier")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            source = root / "probe.c"
            library = root / "libagentnodeprobe.so"

            def build(value: int) -> None:
                source.write_text(f"int agent_node_probe(void) {{ return {value}; }}\n", encoding="utf-8")
                subprocess.run(
                    [compiler, "-shared", "-fPIC", "-Wl,-soname,libagentnodeprobe.so", "-o", str(library), str(source)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            def execute() -> int:
                code = (
                    "import ctypes,sys;"
                    "lib=ctypes.CDLL(sys.argv[1]);"
                    "lib.agent_node_probe.restype=ctypes.c_int;"
                    "print(lib.agent_node_probe())"
                )
                cp = subprocess.run(
                    [sys.executable, "-I", "-B", "-S", "-c", code, str(library)],
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                return int(cp.stdout.strip())

            build(1)
            self.assertEqual(execute(), 1)
            before = mod._runtime_native_sha256((library,))
            build(2)
            self.assertEqual(execute(), 2)
            after = mod._runtime_native_sha256((library,))

        self.assertNotEqual(before, after, "changing executable shared-library bytes must change native identity")

    def test_ldd_discovery_scrubs_shell_startup_environment(self):
        self.assertTrue(hasattr(mod, "_ldd_dependency_paths"), "native dependency discovery helper is required")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            marker = root / "bash-env-ran"
            startup = root / "startup.sh"
            startup.write_text('printf injected > "$AGENT_NODE_BASH_ENV_MARKER"\n', encoding="utf-8")
            with mock.patch.dict(
                mod.os.environ,
                {
                    "BASH_ENV": str(startup),
                    "ENV": str(startup),
                    "AGENT_NODE_BASH_ENV_MARKER": str(marker),
                },
                clear=False,
            ):
                child_env = mod._python_env()
                self.assertNotIn("BASH_ENV", child_env)
                self.assertNotIn("ENV", child_env)
                mod._ldd_dependency_paths(pathlib.Path(sys.executable))
            self.assertFalse(marker.exists(), "ldd discovery must not execute inherited Bash startup code")

    def test_ldd_dependency_parser_preserves_whitespace_in_absolute_path(self):
        self.assertTrue(hasattr(mod, "_ldd_dependency_paths"), "native dependency discovery helper is required")
        fake = subprocess.CompletedProcess(
            args=["ldd", "/runtime/python"],
            returncode=0,
            stdout=(
                "libdep.so => /opt/Python Runtime/libdep.so (0x00007f0000000000)\n"
                "/lib64/ld-linux-x86-64.so.2 (0x00007f0000001000)\n"
            ),
            stderr="",
        )
        with mock.patch.object(mod.subprocess, "run", return_value=fake):
            paths = mod._ldd_dependency_paths(pathlib.Path("/runtime/python"))
        self.assertIn(pathlib.Path("/opt/Python Runtime/libdep.so"), paths)
        self.assertIn(pathlib.Path("/lib64/ld-linux-x86-64.so.2"), paths)

    def test_runtime_receipt_includes_native_dependency_digest(self):
        self.assertTrue(hasattr(mod, "_child_native_runtime_paths"), "native dependency discovery is required")
        self.assertTrue(hasattr(mod, "_runtime_native_sha256"), "native runtime digest helper is required")
        fake_root = pathlib.Path("/runtime-root")
        fake_search = ("/runtime-root",)
        fake_native = (pathlib.Path("/lib/libc.so.6"),)
        with mock.patch.object(mod, "_stable_regular_file_sha256", return_value="a" * 64), \
             mock.patch.object(mod, "_child_runtime_search_paths", return_value=fake_search), \
             mock.patch.object(mod, "_runtime_roots", return_value=(fake_root,)), \
             mock.patch.object(mod, "_runtime_tree_sha256", return_value="b" * 64), \
             mock.patch.object(mod, "_runtime_archive_sha256", return_value="c" * 64), \
             mock.patch.object(mod, "_child_native_runtime_paths", return_value=fake_native), \
             mock.patch.object(mod, "_runtime_native_sha256", side_effect=["d" * 64, "e" * 64]):
            _bin1, first = mod.python_runtime_identity()
            _bin2, second = mod.python_runtime_identity()
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
