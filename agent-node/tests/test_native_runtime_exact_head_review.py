from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_native_runtime_exact_head_review", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(os.sys.platform.startswith("linux"), "Linux native-runtime closure lane")
class NativeRuntimeExactHeadReviewTests(unittest.TestCase):
    def test_ldd_parser_preserves_resolved_path_when_filename_contains_separator(self):
        fake = subprocess.CompletedProcess(
            args=["/usr/bin/ldd", "/runtime/python"],
            returncode=0,
            stdout=(
                "lib => dep.so => /tmp/Python Runtime/lib => dep.so (0x00007f0000000000)\n"
            ),
            stderr="",
        )
        with mock.patch.object(mod.subprocess, "run", return_value=fake):
            paths = mod._ldd_dependency_paths(pathlib.Path("/runtime/python"))
        self.assertIn(
            pathlib.Path("/tmp/Python Runtime/lib => dep.so"),
            paths,
            "ldd mapping parsing must not treat a separator inside the resolved filename as the mapping delimiter",
        )

    def test_ldd_resolver_fails_closed_without_trusted_absolute_binary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            malicious = pathlib.Path(temp_dir) / "ldd"
            malicious.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            malicious.chmod(0o755)
            original_resolve = pathlib.Path.resolve

            def controlled_resolve(path: pathlib.Path, strict: bool = False):
                if os.fspath(path) == "/usr/bin/ldd":
                    raise FileNotFoundError("simulate missing trusted ldd")
                return original_resolve(path, strict=strict)

            with mock.patch.dict(mod.os.environ, {"PATH": temp_dir}, clear=False), mock.patch.object(
                mod.pathlib.Path, "resolve", controlled_resolve
            ):
                with self.assertRaises(RuntimeError):
                    mod._resolve_ldd_bin()

    def test_ldd_shellopts_nounset_failure_is_not_accepted_as_empty_closure(self):
        executable = pathlib.Path(os.sys.executable).resolve(strict=True)
        with mock.patch.dict(mod.os.environ, {"SHELLOPTS": "nounset"}, clear=False):
            env = mod._python_env()
            env["LC_ALL"] = "C"
            env["LANG"] = "C"
            raw = subprocess.run(
                [mod.LDD_BIN, os.fspath(executable)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                env=env,
            )
            self.assertNotIn(
                "SHELLOPTS",
                env,
                "trusted script-based dependency discovery must scrub inherited shell options",
            )
            self.assertEqual(0, raw.returncode, raw.stderr)
            self.assertTrue(raw.stdout, "trusted ldd must produce dependency output after shell-option scrubbing")
            self.assertTrue(mod._ldd_dependency_paths(executable))

    def test_ldd_parser_does_not_substitute_absolute_suffix_from_direct_needed_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            direct_dir = root / "dir => "
            direct_dir.mkdir()
            dependency = direct_dir / "dep.so"
            (root / "dep.c").write_text("int dep(void){return 7;}\n", encoding="utf-8")
            (root / "main.c").write_text(
                "extern int dep(void); int main(void){return dep()==7?0:1;}\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["/usr/bin/cc", "-shared", "-fPIC", "dep.c", "-o", "dir => /dep.so"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                env=mod._python_env(),
            )
            subprocess.run(
                ["/usr/bin/cc", "main.c", "./dir => /dep.so", "-o", "app"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                env=mod._python_env(),
            )
            raw_env = mod._python_env()
            raw_env["LC_ALL"] = "C"
            raw_env["LANG"] = "C"
            raw = subprocess.run(
                [mod.LDD_BIN, "./app"],
                cwd=root,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                env=raw_env,
            )
            self.assertEqual(0, raw.returncode, raw.stderr)
            self.assertIn(
                "./dir => /dep.so (0x",
                raw.stdout,
                f"fixture precondition changed: trusted ldd did not expose the direct DT_NEEDED spelling: {raw.stdout}",
            )

            previous_cwd = pathlib.Path.cwd()
            os.chdir(root)
            try:
                try:
                    paths = mod._ldd_dependency_paths(pathlib.Path("./app"))
                except RuntimeError as exc:
                    self.assertIn(
                        "ambiguous direct native dependency",
                        str(exc),
                        "ambiguous direct DT_NEEDED text may fail closed but must not be reinterpreted",
                    )
                    return
            finally:
                os.chdir(previous_cwd)

            self.assertIn(
                dependency.resolve(strict=True),
                paths,
                "a direct relative DT_NEEDED pathname must bind the actual loaded dependency when admitted",
            )
            self.assertNotIn(
                pathlib.Path("/dep.so"),
                paths,
                "text inside a direct DT_NEEDED pathname must not be reinterpreted as an ldd mapping target",
            )

    def test_ldd_shellopts_noexec_cannot_turn_dependency_discovery_into_empty_success(self):
        executable = pathlib.Path(os.sys.executable).resolve(strict=True)
        with mock.patch.dict(mod.os.environ, {"SHELLOPTS": "noexec"}, clear=False):
            env = mod._python_env()
            self.assertNotIn("SHELLOPTS", env)
            self.assertNotIn("BASHOPTS", env)
            paths = mod._ldd_dependency_paths(executable)
        self.assertTrue(
            any(path.name.startswith("libc.so") or path.name.startswith("libc-") for path in paths),
            "inherited SHELLOPTS=noexec must not let trusted ldd exit successfully with an empty dependency closure",
        )

    def test_ldd_mapping_cannot_be_shadowed_by_whole_body_decoy_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            actual_dir = root / "actual"
            actual_dir.mkdir()
            actual = actual_dir / "libd.so"
            actual.write_bytes(b"actual dependency")
            body = f"libd.so => {actual}"
            decoy = root / body
            decoy.parent.mkdir(parents=True, exist_ok=True)
            decoy.write_bytes(b"decoy dependency")
            decoy_resolved = decoy.resolve(strict=True)
            fake = subprocess.CompletedProcess(
                args=["/usr/bin/ldd", "/runtime/python"],
                returncode=0,
                stdout=f"{body} (0x00007f0000000000)\n",
                stderr="",
            )

            previous_cwd = pathlib.Path.cwd()
            os.chdir(root)
            try:
                with mock.patch.object(mod.subprocess, "run", return_value=fake):
                    paths = mod._ldd_dependency_paths(pathlib.Path("/runtime/python"))
            finally:
                os.chdir(previous_cwd)

            self.assertIn(
                actual,
                paths,
                "ordinary ldd mappings must bind the loaded absolute target even when a colliding whole-body decoy exists",
            )
            self.assertNotIn(
                decoy_resolved,
                paths,
                "filesystem decoys must not determine whether ambiguous ldd text is treated as a direct dependency",
            )

    def test_ldd_parser_preserves_trailing_whitespace_in_resolved_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            actual = root / "libdep.so "
            decoy = root / "libdep.so"
            actual.write_bytes(b"actual trailing-space dependency")
            decoy.write_bytes(b"trimmed decoy dependency")
            fake = subprocess.CompletedProcess(
                args=["/usr/bin/ldd", "/runtime/python"],
                returncode=0,
                stdout=f"libdep.so  => {actual} (0x00007f0000000000)\n",
                stderr="",
            )
            with mock.patch.object(mod.subprocess, "run", return_value=fake):
                paths = mod._ldd_dependency_paths(pathlib.Path("/runtime/python"))

        self.assertIn(
            actual,
            paths,
            "ldd parsing must preserve legal trailing whitespace that belongs to the resolved dependency pathname",
        )
        self.assertNotIn(
            decoy,
            paths,
            "ldd parsing must not trim a dependency pathname onto a decoy file",
        )

    def test_ldd_parser_rejects_multiline_dependency_record(self):
        fake = subprocess.CompletedProcess(
            args=["/usr/bin/ldd", "/runtime/python"],
            returncode=0,
            stdout=(
                "\tdir\n"
                "\t/lib/x86_64-linux-gnu/libc.so.6 (0x00007f0000000000)\n"
            ),
            stderr="",
        )
        with mock.patch.object(mod.subprocess, "run", return_value=fake):
            with self.assertRaisesRegex(RuntimeError, "unsupported or multiline native dependency"):
                mod._ldd_dependency_paths(pathlib.Path("/runtime/python"))


if __name__ == "__main__":
    unittest.main()
