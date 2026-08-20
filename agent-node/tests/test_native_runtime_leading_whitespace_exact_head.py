from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_native_runtime_leading_whitespace", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(os.sys.platform.startswith("linux"), "Linux native-runtime closure lane")
class NativeRuntimeLeadingWhitespaceExactHeadTests(unittest.TestCase):
    def test_ldd_parser_preserves_leading_whitespace_in_direct_needed_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            actual_dir = root / " lead"
            decoy_dir = root / "lead"
            actual_dir.mkdir()
            decoy_dir.mkdir()
            actual = actual_dir / "libdep.so"
            decoy = decoy_dir / "libdep.so"

            (root / "dep.c").write_text("int dep(void){return 7;}\n", encoding="utf-8")
            (root / "main.c").write_text(
                "extern int dep(void); int main(void){return dep()==7?0:1;}\n",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "/usr/bin/cc",
                    "-shared",
                    "-fPIC",
                    "dep.c",
                    "-Wl,-soname, lead/libdep.so",
                    "-o",
                    os.fspath(actual),
                ],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                env=mod._python_env(),
            )
            subprocess.run(
                ["/usr/bin/cc", "main.c", os.fspath(actual), "-o", "app"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                env=mod._python_env(),
            )
            decoy.write_bytes(b"trimmed decoy dependency")

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
                "\t lead/libdep.so (0x",
                raw.stdout,
                f"fixture precondition changed: trusted ldd did not preserve the leading-space DT_NEEDED spelling: {raw.stdout}",
            )

            previous_cwd = pathlib.Path.cwd()
            os.chdir(root)
            try:
                paths = mod._ldd_dependency_paths(pathlib.Path("./app"))
            finally:
                os.chdir(previous_cwd)

            self.assertIn(
                actual.resolve(strict=True),
                paths,
                "ldd parsing must preserve leading whitespace that belongs to a direct DT_NEEDED pathname",
            )
            self.assertNotIn(
                decoy.resolve(strict=True),
                paths,
                "ldd parsing must not trim a leading-space dependency pathname onto a decoy file",
            )


if __name__ == "__main__":
    unittest.main()
