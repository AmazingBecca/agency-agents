#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

import agent_node
import execution_capsule

REPOSITORY = os.environ.get("AGENT_NODE_REPOSITORY", "")


def source_bundle_sha256(expected_head: str) -> str:
    manifest: list[dict[str, str]] = []
    for mode, object_sha, path in agent_node._tree_entries(expected_head):
        data = agent_node.git_bytes("cat-file", "blob", object_sha)
        if agent_node._git_blob_sha1(data) != object_sha:
            raise ValueError(f"Git blob bytes do not match object identity: {path}")
        manifest.append({
            "mode": mode,
            "path": path,
            "git_blob_sha1": object_sha,
            "content_sha256": hashlib.sha256(data).hexdigest(),
        })
    return hashlib.sha256(execution_capsule.canonical(manifest)).hexdigest()


def run_capsule(raw: bytes) -> dict[str, Any]:
    capsule = execution_capsule.parse(raw)
    if not REPOSITORY or capsule["repository"] != REPOSITORY:
        raise ValueError("capsule repository is not this worker repository")
    head, tree = agent_node.bound_identity(capsule["head"])
    if capsule["tree"] != tree:
        raise ValueError("capsule tree mismatch")
    bundle = source_bundle_sha256(head)
    if capsule["source_bundle_sha256"] != bundle:
        raise ValueError("capsule source bundle mismatch")
    expected_python = next((item["version"] for item in capsule["required_tools"] if item["name"] == "python"), None)
    actual_python = ".".join(str(part) for part in agent_node.sys.version_info[:3])
    if expected_python != actual_python:
        raise ValueError("capsule Python version mismatch")
    if capsule["operation"]["kind"] != "python_unittest":
        raise ValueError("unsupported capsule operation")
    result = agent_node.run_tests(head, capsule["operation"]["selector"])
    if len(result["stdout"].encode()) > capsule["max_output_bytes"]:
        raise ValueError("capsule result exceeds output bound")
    return {
        "schema": "execution-capsule-result/v1",
        "capsule_sha256": capsule["capsule_sha256"],
        "source_bundle_sha256": bundle,
        "head": result["head"],
        "tree": result["tree"],
        "runtime_sha256": result["runtime_sha256"],
        "selector": result["selector"],
        "returncode": result["returncode"],
        "stdout_sha256": result["stdout_sha256"],
        "stdout": result["stdout"],
        "advisory_only": True,
        "promotion_authorized": False,
        "completion_authorized": False,
    }


class CapsuleHandler(agent_node.Handler):
    def do_POST(self) -> None:
        if self.path != "/run-capsule":
            return super().do_POST()
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2_000_000:
                raise ValueError("invalid body length")
            raw = self.rfile.read(length)
            result = run_capsule(raw)
            self._send(200, result)
        except Exception as exc:
            self._send(400, {"error": type(exc).__name__, "message": str(exc)})


def main() -> None:
    host = os.environ.get("AGENT_NODE_HOST", "127.0.0.1")
    port = int(os.environ.get("AGENT_NODE_PORT", "8765"))
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit("AGENT_NODE_HOST must be loopback-only")
    if not agent_node.TOKEN:
        raise SystemExit("AGENT_NODE_BEARER is required")
    if not REPOSITORY or REPOSITORY.count("/") != 1:
        raise SystemExit("AGENT_NODE_REPOSITORY=owner/name is required")
    agent_node.ThreadingHTTPServer((host, port), CapsuleHandler).serve_forever()


if __name__ == "__main__":
    main()
