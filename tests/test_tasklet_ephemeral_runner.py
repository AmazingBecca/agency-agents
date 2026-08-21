from __future__ import annotations

import importlib.util
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "runner-bootstrap" / "tasklet_ephemeral_runner.py"
spec = importlib.util.spec_from_file_location("tasklet_ephemeral_runner", SCRIPT)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ValidationTests(unittest.TestCase):
    def test_identity_and_release_are_pinned(self):
        self.assertEqual(mod.TARGET_REPOSITORY, "AmazingBecca/Zo")
        self.assertEqual(mod.RUNNER_VERSION, "2.336.0")
        self.assertEqual(
            mod.RUNNER_ARCHIVE_SHA256,
            "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d",
        )
        self.assertEqual(
            mod._download_url(),
            "https://github.com/actions/runner/releases/download/v2.336.0/actions-runner-linux-x64-2.336.0.tar.gz",
        )
        self.assertEqual(mod._validate_runner_name("oracle-tasklet-01"), "oracle-tasklet-01")
        for bad in ("", "a/b", "name with spaces", "x" * 65):
            with self.assertRaises(mod.BootstrapError):
                mod._validate_runner_name(bad)

    def test_private_root_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            target = base / "target"
            target.mkdir()
            link = base / "runner"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(mod.BootstrapError):
                mod._prepare_private_root(link)

    def test_child_environment_is_minimal_and_isolated(self):
        old = dict(os.environ)
        try:
            os.environ.update({
                "GITHUB_TOKEN": "secret",
                "GH_TOKEN": "secret2",
                "GITHUB_RUNNER_REGISTRATION_TOKEN": "registration-secret",
                "HTTPS_PROXY": "http://evil",
                "LD_PRELOAD": "/tmp/evil.so",
                "PYTHONPATH": "/tmp/evil",
                "KEEP_ME": "must-not-inherit",
            })
            env = mod._child_env(home=Path("/isolated/home"), tmpdir=Path("/isolated/tmp"))
            self.assertEqual(env["HOME"], "/isolated/home")
            self.assertEqual(env["TMPDIR"], "/isolated/tmp")
            self.assertEqual(env["LANG"], "C.UTF-8")
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("GITHUB_RUNNER_REGISTRATION_TOKEN", env)
            self.assertNotIn("HTTPS_PROXY", env)
            self.assertNotIn("LD_PRELOAD", env)
            self.assertNotIn("PYTHONPATH", env)
            self.assertNotIn("KEEP_ME", env)
        finally:
            os.environ.clear(); os.environ.update(old)

    def _archive(self, path: Path, members: list[tuple[str, bytes, str]]):
        with tarfile.open(path, "w:gz") as tf:
            for name, data, kind in members:
                info = tarfile.TarInfo(name)
                if kind == "file":
                    info.size = len(data)
                    info.mode = 0o755
                    tf.addfile(info, io.BytesIO(data))
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "/tmp/escape"
                    tf.addfile(info)

    def test_safe_extract_accepts_regular_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "a.tar.gz"
            dest = root / "out"; dest.mkdir()
            self._archive(archive, [("config.sh", b"x", "file"), ("bin/run", b"y", "file")])
            mod._safe_extract(archive, dest)
            self.assertEqual((dest / "config.sh").read_bytes(), b"x")
            self.assertEqual((dest / "bin/run").read_bytes(), b"y")

    def test_safe_extract_rejects_expansion_over_policy(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "a.tar.gz"
            dest = root / "out"; dest.mkdir()
            self._archive(archive, [("payload", b"xx", "file")])
            old_limit = mod.MAX_EXTRACTED_BYTES
            try:
                mod.MAX_EXTRACTED_BYTES = 1
                with self.assertRaises(mod.BootstrapError):
                    mod._safe_extract(archive, dest)
            finally:
                mod.MAX_EXTRACTED_BYTES = old_limit

    def test_safe_extract_rejects_traversal_and_symlink(self):
        for members in [
            [("../escape", b"x", "file")],
            [("escape", b"", "symlink")],
        ]:
            with self.subTest(members=members), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                archive = root / "a.tar.gz"
                dest = root / "out"; dest.mkdir()
                self._archive(archive, members)
                with self.assertRaises(mod.BootstrapError):
                    mod._safe_extract(archive, dest)

    def test_download_host_policy(self):
        self.assertTrue(mod._host_allowed("github.com"))
        self.assertTrue(mod._host_allowed("release-assets.githubusercontent.com"))
        self.assertFalse(mod._host_allowed("github.com.evil.example"))
        self.assertFalse(mod._host_allowed("evil.example"))

    def test_required_labels_are_fixed(self):
        self.assertEqual(mod.REQUIRED_LABELS, ("linux", "oracle", "codex", "zo"))


if __name__ == "__main__":
    unittest.main()
