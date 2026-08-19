import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
import venv
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"
spec = importlib.util.spec_from_file_location("agent_node_adversarial", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


PASSING_TEST = """import unittest
class SafeTest(unittest.TestCase):
    def test_ok(self):
        self.assertTrue(True)
"""

FAILING_TEST = """import unittest
class SafeTest(unittest.TestCase):
    def test_ok(self):
        print('DUPLICATE-PATH-SENTINEL')
        self.fail('duplicate path executed')
"""


def git(repo: pathlib.Path, *args: str, input_bytes: bytes | None = None) -> str:
    cp = subprocess.run(
        [mod.GIT_BIN, "-C", str(repo), *args],
        check=True,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return cp.stdout.decode().strip()


def make_repo():
    temp = tempfile.TemporaryDirectory()
    repo = pathlib.Path(temp.name)
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "agent-node-test@example.invalid")
    git(repo, "config", "user.name", "agent-node-test")
    tests = repo / "tests"
    tests.mkdir()
    (tests / "__init__.py").write_text("", encoding="utf-8")
    (tests / "test_safe.py").write_text(PASSING_TEST, encoding="utf-8")
    git(repo, "add", "tests")
    git(repo, "commit", "-qm", "reviewed")
    return temp, repo, git(repo, "rev-parse", "HEAD")


class AgentNodeAdversarialPathTests(unittest.TestCase):
    def test_duplicate_git_tree_path_is_rejected_before_materialization(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        repo = pathlib.Path(temp.name)
        git(repo, "init", "-q")
        git(repo, "config", "user.email", "agent-node-test@example.invalid")
        git(repo, "config", "user.name", "agent-node-test")

        passing_blob = git(repo, "hash-object", "-w", "--stdin", input_bytes=PASSING_TEST.encode())
        failing_blob = git(repo, "hash-object", "-w", "--stdin", input_bytes=FAILING_TEST.encode())
        raw_tree = (
            b"100644 test_safe.py\0" + bytes.fromhex(passing_blob)
            + b"100644 test_safe.py\0" + bytes.fromhex(failing_blob)
        )
        tree = git(repo, "hash-object", "-t", "tree", "-w", "--stdin", input_bytes=raw_tree)
        commit = git(repo, "commit-tree", tree, "-m", "malformed duplicate path")
        git(repo, "reset", "--hard", "-q", commit)

        with mock.patch.object(mod, "ROOT", repo):
            with self.assertRaisesRegex(ValueError, "duplicate Git tree path"):
                with mod.committed_snapshot(commit):
                    self.fail("duplicate path tree unexpectedly materialized")

    def test_virtualenv_pth_site_hook_cannot_run_before_committed_snapshot(self):
        temp, repo, head = make_repo()
        self.addCleanup(temp.cleanup)
        venv_temp = tempfile.TemporaryDirectory()
        self.addCleanup(venv_temp.cleanup)
        venv_root = pathlib.Path(venv_temp.name) / "venv"
        venv.EnvBuilder(with_pip=False).create(venv_root)
        python_bin = venv_root / "bin" / "python"
        self.assertTrue(python_bin.exists())
        site_dirs = list((venv_root / "lib").glob("python*/site-packages"))
        self.assertEqual(len(site_dirs), 1)
        (site_dirs[0] / "unreviewed_startup.pth").write_text(
            "import sys; print('PTH-SENTINEL')\n", encoding="utf-8"
        )

        with (
            mock.patch.object(mod, "ROOT", repo),
            mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)),
            mock.patch.object(mod, "python_runtime_identity", return_value=(str(python_bin), "c" * 64)),
        ):
            result = mod.run_tests(head, "tests.test_safe")

        self.assertEqual(result["returncode"], 0)
        self.assertIn("OK", result["stdout"])
        self.assertNotIn("PTH-SENTINEL", result["stdout"])


if __name__ == "__main__":
    unittest.main()
