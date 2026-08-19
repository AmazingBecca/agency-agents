#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SHA40 = re.compile(r"^[0-9a-f]{40}$")
ROOT = pathlib.Path(os.environ.get("AGENT_NODE_REPO_ROOT", ".")).resolve()
TOKEN = os.environ.get("AGENT_NODE_BEARER", "")
MODEL_ENDPOINT = os.environ.get("AGENT_NODE_MODEL_ENDPOINT", "http://127.0.0.1:11434/v1/chat/completions")
MODEL_NAME = os.environ.get("AGENT_NODE_MODEL", "")
TEST_ALLOWLIST = tuple(x.strip() for x in os.environ.get("AGENT_NODE_TEST_ALLOWLIST", "").split(",") if x.strip())


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def git(*args: str) -> str:
    cp = subprocess.run(["git", "-C", str(ROOT), *args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return cp.stdout.strip()


def bound_head(expected: str) -> str:
    if not SHA40.fullmatch(expected):
        raise ValueError("expected_head must be lowercase 40-hex")
    head = git("rev-parse", "HEAD")
    if head != expected:
        raise ValueError(f"head mismatch: expected {expected}, got {head}")
    return head


def bound_source(expected: str) -> tuple[str, str]:
    """Bind execution to an exact commit tree and a completely clean checkout."""
    head = bound_head(expected)
    dirty = git("status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise ValueError("working tree is not clean")
    tree = git("rev-parse", "HEAD^{tree}")
    if not SHA40.fullmatch(tree):
        raise ValueError("tree identity is invalid")
    return head, tree


def repo_index(expected_head: str) -> dict:
    head, tree = bound_source(expected_head)
    files = git("ls-files").splitlines()
    after_head, after_tree = bound_source(expected_head)
    if (after_head, after_tree) != (head, tree):
        raise ValueError("repository source changed during indexing")
    payload = {"repository_root": str(ROOT), "head": head, "tree": tree, "files": files}
    payload["sha256"] = hashlib.sha256(canonical(payload)).hexdigest()
    return payload


def run_tests(expected_head: str, selector: str) -> dict:
    head, tree = bound_source(expected_head)
    if not TEST_ALLOWLIST or selector not in TEST_ALLOWLIST:
        raise ValueError("test selector not allowlisted")
    cp = subprocess.run(
        [sys.executable, "-I", "-B", "-m", "unittest", selector, "-v"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=900,
    )
    output = cp.stdout
    after_head, after_tree = bound_source(expected_head)
    if (after_head, after_tree) != (head, tree):
        raise ValueError("repository source changed during test execution")
    return {
        "head": head,
        "tree": tree,
        "selector": selector,
        "returncode": cp.returncode,
        "stdout_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "stdout": output[-20000:],
    }


def second_opinion(expected_head: str, compact_evidence: str) -> dict:
    head, tree = bound_source(expected_head)
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
    after_head, after_tree = bound_source(expected_head)
    if (after_head, after_tree) != (head, tree):
        raise ValueError("repository source changed during second-opinion execution")
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
