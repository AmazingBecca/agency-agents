from __future__ import annotations

import os
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import verify_detached_descendant_lifecycle as subject


class DetachedDescendantLifecycleTests(unittest.TestCase):
    def test_heartbeat_parser_rejects_noncanonical_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            heartbeat = root / "heartbeat"
            for payload in ("", "1", "1\n2\n", "-1\n", "200\n", "x\n"):
                with self.subTest(payload=payload):
                    heartbeat.write_text(payload, encoding="ascii")
                    with self.assertRaises(RuntimeError):
                        subject._heartbeat_value(heartbeat)

    @unittest.skipUnless(
        sys.platform == "linux" and shutil.which("sudo") is not None and os.geteuid() != 65534,
        "live Linux distinct-principal authority requires sudo and a separate control identity",
    )
    def test_live_detached_session_cannot_outlive_pid_namespace_init(self) -> None:
        report = subject.verify_detached_descendant_lifecycle(
            sandbox_user="nobody",
            timeout_seconds=8,
        )
        self.assertTrue(report["passed"])
        self.assertTrue(report["detached_session_started"])
        self.assertTrue(report["heartbeat_stable_after_namespace_exit"])
        self.assertEqual(
            report["schema"],
            "amazingbecca.detached-descendant-lifecycle.v1",
        )
        self.assertGreaterEqual(report["heartbeat_final_value"], 0)


if __name__ == "__main__":
    unittest.main()
