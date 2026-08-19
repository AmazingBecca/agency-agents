#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SHA40 = re.compile(r"^[0-9a-f]{40}$")
ROOT = pathlib.Path(os.environ.get("AGENT_NODE_REPO_ROOT", ".")).resolve()
TOKEN = os.environ.get("AGENT_NODE_BEARER", "")
MODEL_ENDPOINT = os.environ.get("AGENT_NODE_MODEL_ENDPOINT", "http://127.0.0.1:11434/v1/chat/completions")
MODEL_NAME = os.environ.get("AGENT_NODE_MODEL", "")
TEST_ALLOWLIST = tuple(x.strip() for x in os.environ.get("AGENT_NODE_TEST_ALLOWLIST", "").split(",") if x.strip())
TEST_OUTPUT_LIMIT = 20_000


def _resolve_git_bin() -> str:
    configured = os.environ.get("AGENT_NODE_GIT_BIN", "")
    candidates = [configured] if configured else ["/usr/bin/git", shutil.which("git") or ""]
    for candidate in candidates:
        if not candidate:
            continue
        path = pathlib.Path(candidate)
        if configured and not path.is_absolute():
            raise RuntimeError("AGENT_NODE_GIT_BIN must be an absolute path")
        try:
            resolved = path.resolve(strict=True)
            mode = resolved.stat().st_mode
        except OSError:
            continue
        if stat.S_ISREG(mode) and os.access(resolved, os.X_OK):
            return str(resolved)
    raise RuntimeError("a trusted executable git binary is required")


GIT_BIN = _resolve_git_bin()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _git_env() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
        and key not in {"LD_PRELOAD", "LD_LIBRARY_PATH"}
        and not key.startswith("DYLD_")
    }
    env.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


def git_bytes(*args: str) -> bytes:
    cp = subprocess.run(
        [GIT_BIN, "-C", str(ROOT), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_git_env(),
    )
    return cp.stdout


def git(*args: str) -> str:
    return git_bytes(*args).decode("utf-8").strip()


def bound_identity(expected: str) -> tuple[str, str]:
    if not SHA40.fullmatch(expected):
        raise ValueError("expected_head must be lowercase 40-hex")
    head = git("rev-parse", "--verify", "HEAD^{commit}")
    if head != expected:
        raise ValueError(f"head mismatch: expected {expected}, got {head}")
    tree = git("rev-parse", "--verify", f"{expected}^{{tree}}")
    if not SHA40.fullmatch(tree):
        raise ValueError("tree identity is invalid")
    return head, tree


def _tree_entries(expected_head: str) -> list[tuple[str, str, str]]:
    raw = git_bytes("ls-tree", "-r", "-z", "--full-tree", expected_head)
    entries: list[tuple[str, str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, path_bytes = record.split(b"\t", 1)
            mode, object_type, object_sha = metadata.decode("ascii").split()
            path = path_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("unsupported Git tree entry encoding") from exc
        pure = pathlib.PurePosixPath(path)
        if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
            raise ValueError("unsafe Git tree path")
        if object_type != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError(f"unsupported Git tree entry: {mode} {object_type} {path}")
        if not SHA40.fullmatch(object_sha):
            raise ValueError("invalid Git blob identity")
        entries.append((mode, object_sha, path))
    return entries


def _git_blob_sha1(data: bytes) -> str:
    prefix = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(prefix + data).hexdigest()


@contextlib.contextmanager
def committed_snapshot(expected_head: str):
    head, tree = bound_identity(expected_head)
    entries = _tree_entries(expected_head)
    with tempfile.TemporaryDirectory(prefix="amazingbecca-agent-node-") as temp_dir:
        snapshot = pathlib.Path(temp_dir) / "repo"
        snapshot.mkdir(mode=0o700)
        for mode, object_sha, relative in entries:
            data = git_bytes("cat-file", "blob", object_sha)
            if _git_blob_sha1(data) != object_sha:
                raise ValueError(f"Git blob bytes do not match object identity: {relative}")
            destination = snapshot.joinpath(*pathlib.PurePosixPath(relative).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if mode == "120000":
                os.symlink(os.fsdecode(data), destination)
            else:
                destination.write_bytes(data)
                destination.chmod(0o755 if mode == "100755" else 0o644)
        after_head, after_tree = bound_identity(expected_head)
        if (after_head, after_tree) != (head, tree):
            raise ValueError("repository identity changed while snapshotting")
        yield head, tree, snapshot


def repo_index(expected_head: str) -> dict:
    head, tree = bound_identity(expected_head)
    files = [path for _, _, path in _tree_entries(expected_head)]
    after_head, after_tree = bound_identity(expected_head)
    if (after_head, after_tree) != (head, tree):
        raise ValueError("repository identity changed during indexing")
    payload = {"repository_root": str(ROOT), "head": head, "tree": tree, "files": files}
    payload["sha256"] = hashlib.sha256(canonical(payload)).hexdigest()
    return payload


def run_tests(expected_head: str, selector: str) -> dict:
    if not TEST_ALLOWLIST or selector not in TEST_ALLOWLIST:
        raise ValueError("test selector not allowlisted")
    bootstrap = (
        "import sys,unittest;"
        "root,selector=sys.argv[1:3];"
        "sys.path.insert(0,root);"
        "suite=unittest.defaultTestLoader.loadTestsFromName(selector);"
        "result=unittest.TextTestRunner(verbosity=2).run(suite);"
        "raise SystemExit(0 if result.wasSuccessful() else 1)"
    )
    with committed_snapshot(expected_head) as (head, tree, snapshot):
        cp = subprocess.run(
            [sys.executable, "-I", "-B", "-c", bootstrap, str(snapshot), selector],
            cwd=snapshot,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=900,
        )
        returned_output = cp.stdout[-TEST_OUTPUT_LIMIT:]
    return {
        "head": head,
        "tree": tree,
        "selector": selector,
        "returncode": cp.returncode,
        "stdout_sha256": hashlib.sha256(returned_output.encode()).hexdigest(),
        "stdout": returned_output,
    }


def second_opinion(expected_head: str, compact_evidence: str) -> dict:
    head, tree = bound_identity(expected_head)
    if not MODEL_NAME:
        raise ValueError("AGENT_NODE_MODEL is not configured")
    parsed = urllib.parse.urlparse(MODEL_ENDPOINT)
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("model endpoint must be loopback-only")
    req_body = {
        "model": MODEL_NAME,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": "Act as an independent adversarial code reviewer. Separate verified facts, inference, and unknowns. Propose deterministic falsifying tests."},
            {"role": "user", "content": compact_evidence},
        ],
    }
    request = urllib.request.Request(
        MODEL_ENDPOINT,
        data=json.dumps(req_body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        raw = response.read()
    decoded = json.loads(raw)
    after_head, after_tree = bound_identity(expected_head)
    if (after_head, after_tree) != (head, tree):
        raise ValueError("repository identity changed during second-opinion execution")
    return {"head": head, "tree": tree, "model": MODEL_NAME, "response": decoded, "response_sha256": hashlib.sha256(raw).hexdigest()}


class Handler(BaseHTTPRequestHandler):
    server_version = "AmazingBeccaAgentNode/1"

    def _authorized(self) -> bool:
        if not TOKEN:
            return False
        supplied = self.headers.get("Authorization", "")
        prefix = "Bearer "
        return supplied.startswith(prefix) and hmac.compare_digest(supplied[len(prefix):], TOKEN)

    def _send(self, status: int, value: object) -> None:
        data = canonical(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"ok": True, "git": (ROOT / ".git").exists()})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2_000_000:
                raise ValueError("invalid body length")
            body = json.loads(self.rfile.read(length))
            if self.path == "/repo-index":
                result = repo_index(body["expected_head"])
            elif self.path == "/run-tests":
                result = run_tests(body["expected_head"], body["selector"])
            elif self.path == "/second-opinion":
                result = second_opinion(body["expected_head"], body["compact_evidence"])
            else:
                self._send(404, {"error": "not found"})
                return
            self._send(200, result)
        except Exception as exc:
            self._send(400, {"error": type(exc).__name__, "message": str(exc)})

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("agent-node " + (fmt % args) + "\n")


def main() -> None:
    host = os.environ.get("AGENT_NODE_HOST", "127.0.0.1")
    port = int(os.environ.get("AGENT_NODE_PORT", "8765"))
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit("AGENT_NODE_HOST must be loopback-only")
    if not TOKEN:
        raise SystemExit("AGENT_NODE_BEARER is required")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
