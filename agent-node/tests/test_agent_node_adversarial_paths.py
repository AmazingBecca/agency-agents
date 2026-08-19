import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
