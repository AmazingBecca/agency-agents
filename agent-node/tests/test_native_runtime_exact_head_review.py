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


if __name__ == "__main__":
    unittest.main()
