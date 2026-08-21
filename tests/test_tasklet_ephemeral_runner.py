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
            mod.download_url(),
            "https://github.com/actions/runner/releases/download/v2.336.0/actions-runner-linux-x64-2.336.0.tar.gz",
        )

    def test_source_contains_no_registration_or_jit_secret_transport(self):
        source = SCRIPT.read_text(encoding="utf-8")
        forbidden = (
            "GITHUB_RUNNER_REGISTRATION_TOKEN",
            "--token",
            "--jitconfig",
            "ACTIONS_RUNNER_INPUT_TOKEN",
            "ACTIONS_RUNNER_INPUT_JITCONFIG",
            "subprocess.run",
            "subprocess.Popen",
        )
        for value in forbidden:
            self.assertNotIn(value, source)
        self.assertIn('"secret_transport": "none"', source)
        self.assertIn('"registration_token_handling": "none"', source)
        self.assertIn('"jit_config_handling": "none"', source)

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
                elif kind == "hardlink":
                    info.type = tarfile.LNKTYPE
                    info.linkname = "target"
                    tf.addfile(info)

    def test_safe_extract_accepts_regular_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "a.tar.gz"
            dest = root / "out"
            dest.mkdir()
            self._archive(archive, [("run.sh", b"x", "file"), ("bin/Runner.Listener", b"y", "file")])
            mod.safe_extract(archive, dest)
            self.assertEqual((dest / "run.sh").read_bytes(), b"x")
            self.assertEqual((dest / "bin/Runner.Listener").read_bytes(), b"y")

    def test_safe_extract_rejects_expansion_over_policy(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "a.tar.gz"
            dest = root / "out"
            dest.mkdir()
            self._archive(archive, [("payload", b"xx", "file")])
            old_limit = mod.MAX_EXTRACTED_BYTES
            try:
                mod.MAX_EXTRACTED_BYTES = 1
                with self.assertRaises(mod.PayloadError):
                    mod.safe_extract(archive, dest)
            finally:
                mod.MAX_EXTRACTED_BYTES = old_limit

    def test_safe_extract_rejects_traversal_links_and_duplicates(self):
        cases = [
            [("../escape", b"x", "file")],
            [("escape", b"", "symlink")],
            [("escape", b"", "hardlink")],
            [("dup", b"x", "file"), ("dup", b"y", "file")],
        ]
        for members in cases:
            with self.subTest(members=members), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                archive = root / "a.tar.gz"
                dest = root / "out"
                dest.mkdir()
                self._archive(archive, members)
                with self.assertRaises(mod.PayloadError):
                    mod.safe_extract(archive, dest)

    def test_download_host_policy(self):
        self.assertTrue(mod.host_allowed("github.com"))
        self.assertTrue(mod.host_allowed("release-assets.githubusercontent.com"))
        self.assertFalse(mod.host_allowed("github.com.evil.example"))
        self.assertFalse(mod.host_allowed("evil.example"))

    def test_cleanup_rejects_outside_and_symlink_roots(self):
        for value in ("/tmp/not-enrolled", "/var/tmp/ab-jit-runner-x", "../tmp/ab-jit-runner-x"):
            with self.assertRaises(mod.PayloadError):
                mod.cleanup_payload(value)
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="ab-jit-runner-test-target-") as td:
            target = Path(td)
            link = Path("/tmp/ab-jit-runner-test-link")
            try:
                if link.exists() or link.is_symlink():
                    link.unlink()
                link.symlink_to(target, target_is_directory=True)
                with self.assertRaises(mod.PayloadError):
                    mod.cleanup_payload(str(link))
            finally:
                if link.exists() or link.is_symlink():
                    link.unlink()

    def test_cleanup_removes_enrolled_owned_root(self):
        root = Path(tempfile.mkdtemp(dir="/tmp", prefix=mod.RUNNER_ROOT_PREFIX))
        (root / "payload").write_text("x", encoding="utf-8")
        result = mod.cleanup_payload(str(root))
        self.assertEqual(result["status"], "payload_removed")
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
