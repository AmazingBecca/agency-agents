from __future__ import annotations

import hashlib
import pathlib

ROOT = pathlib.Path(__file__).parents[2]
SOURCE = ROOT / "agent-node" / "agent_node.py"
RUNTIME_TEST = ROOT / "agent-node" / "tests" / "test_runtime_closure.py"
EXPECTED_SOURCE_BLOB = "84ab624f9f26a3eb9f9ddbd36e5c2b151afb82e0"
EXPECTED_RUNTIME_TEST_BLOB = "5d333babe635de2325adf3e4a2ef2b23a3ca98e3"


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def require_blob(path: pathlib.Path, expected: str) -> bytes:
    data = path.read_bytes()
    actual = git_blob_sha1(data)
    if actual != expected:
        raise SystemExit(f"refusing v28 repair: {path} blob {actual} != {expected}")
    return data


def patch_source() -> None:
    before = require_blob(SOURCE, EXPECTED_SOURCE_BLOB)
    text = before.decode("utf-8")
    old_policy = 'RUNTIME_POLICY = "agent-node-python-runtime-v27"'
    new_policy = 'RUNTIME_POLICY = "agent-node-python-runtime-v28"'
    if text.count(old_policy) != 1:
        raise SystemExit("refusing v28 repair: policy marker count is not one")
    text = text.replace(old_policy, new_policy, 1)

    start = text.index("\ndef run_tests(expected_head: str, selector: str) -> dict:\n")
    end = text.index("\n\ndef second_opinion(expected_head: str, compact_evidence: str) -> dict:\n", start)
    replacement = r'''
def run_tests(expected_head: str, selector: str) -> dict:
    if not TEST_ALLOWLIST or selector not in TEST_ALLOWLIST:
        raise ValueError("test selector not allowlisted")
    if not sys.platform.startswith("linux"):
        raise RuntimeError("execution-time native receipt is implemented only on Linux")
    bootstrap = r"""
import json
import os
import signal
import sys
import unittest

root, selector, receipt_fd_text = sys.argv[1:4]
receipt_fd = int(receipt_fd_text)
pid = os.fork()
if pid == 0:
    os.close(receipt_fd)
    sys.path.insert(0, root)
    suite = unittest.defaultTestLoader.loadTestsFromName(selector)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    exit_code = 0 if result.wasSuccessful() else 1
    os.kill(os.getpid(), signal.SIGSTOP)
    raise SystemExit(exit_code)

def timeout_child(_signum, _frame):
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    raise TimeoutError("allowlisted test child timed out before native receipt capture")

signal.signal(signal.SIGALRM, timeout_child)
signal.alarm(890)
try:
    waited, status = os.waitpid(pid, os.WUNTRACED)
    if waited != pid or not os.WIFSTOPPED(status):
        raise RuntimeError("allowlisted test child exited before native receipt capture")
    paths = set()
    with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as handle:
        for line in handle:
            parts = line.rstrip("\n").split(None, 5)
            if len(parts) < 6 or "x" not in parts[1]:
                continue
            value = parts[5]
            if value.endswith(" (deleted)"):
                raise RuntimeError(f"executed native mapping was deleted before receipt capture: {value}")
            if value.startswith("/"):
                paths.add(value)
    if not paths:
        raise RuntimeError("executed child exposed no bindable native mappings")
    payload = json.dumps(sorted(paths), sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > 60000:
        raise RuntimeError("executed native mapping receipt exceeds bounded pipe capacity")
    written = os.write(receipt_fd, payload)
    if written != len(payload):
        raise RuntimeError("executed native mapping receipt write was incomplete")
finally:
    signal.alarm(0)
    try:
        os.close(receipt_fd)
    except OSError:
        pass
    try:
        os.kill(pid, signal.SIGCONT)
    except ProcessLookupError:
        pass

waited, final_status = os.waitpid(pid, 0)
if waited != pid:
    raise RuntimeError("allowlisted test child wait identity changed")
if os.WIFEXITED(final_status):
    raise SystemExit(os.WEXITSTATUS(final_status))
if os.WIFSIGNALED(final_status):
    raise SystemExit(128 + os.WTERMSIG(final_status))
raise RuntimeError("allowlisted test child ended in an unsupported state")
"""
    python_bin, static_runtime_sha256 = python_runtime_identity()
    receipt_r, receipt_w = os.pipe()
    try:
        with committed_snapshot(expected_head) as (head, tree, snapshot):
            cp = subprocess.run(
                [python_bin, "-I", "-B", "-S", "-c", bootstrap, str(snapshot), selector, str(receipt_w)],
                cwd=snapshot,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=900,
                env=_python_env(),
                pass_fds=(receipt_w,),
            )
            returned_output = cp.stdout[-TEST_OUTPUT_LIMIT:]
        os.close(receipt_w)
        receipt_w = -1
        raw_receipt = bytearray()
        while True:
            chunk = os.read(receipt_r, 65536)
            if not chunk:
                break
            raw_receipt.extend(chunk)
            if len(raw_receipt) > 60000:
                raise RuntimeError("executed native mapping receipt is oversized")
        if not raw_receipt:
            raise RuntimeError("executed child did not produce a native mapping receipt")
        try:
            decoded_paths = json.loads(bytes(raw_receipt).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("executed native mapping receipt is malformed") from exc
        if not isinstance(decoded_paths, list) or not decoded_paths:
            raise RuntimeError("executed native mapping receipt is empty")
        native_paths: list[pathlib.Path] = []
        seen_paths: set[str] = set()
        for value in decoded_paths:
            if not isinstance(value, str) or not value.startswith("/") or value in seen_paths:
                raise RuntimeError("executed native mapping receipt contains an invalid path")
            seen_paths.add(value)
            native_paths.append(pathlib.Path(value))
        executed_native_sha256 = _runtime_native_sha256(tuple(native_paths))
    finally:
        if receipt_w >= 0:
            os.close(receipt_w)
        os.close(receipt_r)
    after_python_bin, after_static_runtime_sha256 = python_runtime_identity()
    if after_python_bin != python_bin or after_static_runtime_sha256 != static_runtime_sha256:
        raise RuntimeError("Python runtime identity changed during test execution")
    runtime_sha256 = hashlib.sha256(
        canonical(
            {
                "policy": "agent-node-executed-runtime-v1",
                "static_runtime_sha256": static_runtime_sha256,
                "executed_native_sha256": executed_native_sha256,
            }
        )
    ).hexdigest()
    if not SHA64.fullmatch(runtime_sha256):
        raise RuntimeError("executed runtime identity is invalid")
    return {
        "head": head,
        "tree": tree,
        "runtime_sha256": runtime_sha256,
        "static_runtime_sha256": static_runtime_sha256,
        "executed_native_sha256": executed_native_sha256,
        "selector": selector,
        "returncode": cp.returncode,
        "stdout_sha256": hashlib.sha256(returned_output.encode()).hexdigest(),
        "stdout": returned_output,
    }
'''
    text = text[:start] + replacement + text[end:]
    SOURCE.write_text(text, encoding="utf-8")


def patch_runtime_test() -> None:
    before = require_blob(RUNTIME_TEST, EXPECTED_RUNTIME_TEST_BLOB)
    text = before.decode("utf-8")
    start = text.index("    def test_run_tests_preserves_isolated_no_site_no_bytecode_python(self):\n")
    end = text.index("\n\n\nif __name__ == \"__main__\":", start)
    replacement = r'''    def test_run_tests_preserves_isolated_no_site_no_bytecode_python(self):
        snapshot_temp = tempfile.TemporaryDirectory()
        self.addCleanup(snapshot_temp.cleanup)
        snapshot = pathlib.Path(snapshot_temp.name)

        @contextlib.contextmanager
        def fake_snapshot(_expected_head):
            yield "a" * 40, "b" * 40, snapshot

        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="OK\n")

        def fake_run(argv, **_kwargs):
            receipt_fd = int(argv[-1])
            mod.os.write(receipt_fd, mod.json.dumps(["/usr/bin/python3"]).encode("utf-8"))
            return completed

        with mock.patch.object(mod, "TEST_ALLOWLIST", ("tests.test_safe",)), \
             mock.patch.object(mod, "python_runtime_identity", side_effect=[("/usr/bin/python3", "c" * 64), ("/usr/bin/python3", "c" * 64)]), \
             mock.patch.object(mod, "committed_snapshot", fake_snapshot), \
             mock.patch.object(mod, "_runtime_native_sha256", return_value="d" * 64), \
             mock.patch.object(mod.subprocess, "run", side_effect=fake_run) as run:
            result = mod.run_tests("a" * 40, "tests.test_safe")

        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/bin/python3", "-I", "-B", "-S"])
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["static_runtime_sha256"], "c" * 64)
        self.assertEqual(result["executed_native_sha256"], "d" * 64)
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(b"OK\n").hexdigest())'''
    text = text[:start] + replacement + text[end:]
    RUNTIME_TEST.write_text(text, encoding="utf-8")


def main() -> None:
    patch_source()
    patch_runtime_test()


if __name__ == "__main__":
    main()
