from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import httpx
from fastmcp import FastMCP

AGENTS: dict[str, dict[str, Any]] = {
    "research_scout": {
        "mission": "Find current external tools, runtimes, MCP servers, agent frameworks, and primary-source evidence that could materially expand the system. Prefer primary sources; classify claims as VERIFIED, PLAUSIBLE, or UNVERIFIED.",
        "constraints": "No writes, credentials, billing, deployment, or production authority. A missing or timed-out source is not negative evidence.",
    },
    "source_verifier": {
        "mission": "Verify exact repository/ref/file/hash identities, provenance boundaries, and whether evidence actually executed. Reject stale identity, ambiguous source lineage, no-step CI, and unsupported PASS claims.",
        "constraints": "No mutation authority. Require exact identities and distinguish execution admission from source/test results.",
    },
    "adversarial_reviewer": {
        "mission": "Attack proposed architecture for authority bypass, provenance substitution, stale identity, replay, path expansion, mutable dependencies, candidate-controlled verdicts, omitted negative tests, and false-green CI.",
        "constraints": "Do not invent exploits. Convert concerns into deterministic discriminating tests whenever possible.",
    },
    "capability_architect": {
        "mission": "Turn validated research and review findings into the smallest high-value composition change. Prefer mature reusable primitives, model-agnostic interfaces, MCP/A2A boundaries, local execution, exact-source receipts, and graceful degradation.",
        "constraints": "Proposal authority only. Do not assume permission, credentials, spend, protected-ref authority, or production access.",
    },
}

DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"
DEFAULT_TIMEOUT = 45.0
DEFAULT_MAX_CHARS = 12000


def _workspace_root() -> Path:
    root = Path(os.environ.get("AGENT_WORKSPACE_ROOT", os.getcwd())).resolve()
    return root


def _safe_path(relative: str) -> Path:
    root = _workspace_root()
    candidate = (root / relative).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("path escapes AGENT_WORKSPACE_ROOT") from exc
    return candidate


mcp = FastMCP("repo-guard")


@mcp.tool
def workspace_identity() -> dict[str, str]:
    root = _workspace_root()
    return {"workspace_root": str(root), "mode": "read-only"}


@mcp.tool
def list_files(path: str = ".", max_entries: int = 500) -> list[str]:
    target = _safe_path(path)
    if not target.exists() or not target.is_dir():
        raise ValueError("directory does not exist")
    max_entries = max(1, min(int(max_entries), 2000))
    root = _workspace_root()
    entries: list[str] = []
    for child in sorted(target.rglob("*")):
        if len(entries) >= max_entries:
            break
        if child.is_file():
            entries.append(str(child.relative_to(root)))
    return entries


@mcp.tool
def read_text(path: str, max_bytes: int = 200_000) -> str:
    target = _safe_path(path)
    if not target.exists() or not target.is_file():
        raise ValueError("file does not exist")
    max_bytes = max(1, min(int(max_bytes), 1_000_000))
    data = target.read_bytes()
    if len(data) > max_bytes:
        raise ValueError(f"file exceeds max_bytes ({len(data)} > {max_bytes})")
    return data.decode("utf-8", errors="replace")


@mcp.tool
def sha256_file(path: str) -> dict[str, Any]:
    target = _safe_path(path)
    if not target.exists() or not target.is_file():
        raise ValueError("file does not exist")
    digest = hashlib.sha256()
    size = 0
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return {"path": path, "size": size, "sha256": digest.hexdigest()}


async def _call_agent(name: str, task: str, timeout: float, max_chars: int) -> dict[str, Any]:
    spec = AGENTS[name]
    base_url = os.environ.get("AGENT_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    model = os.environ.get("AGENT_MODEL")
    api_key = os.environ.get("AGENT_API_KEY", "ollama")
    if not model:
        return {"agent": name, "status": "CONFIG_REQUIRED", "error": "AGENT_MODEL is not set"}

    system = (
        f"You are the {name} agent.\nMISSION: {spec['mission']}\n"
        f"CONSTRAINTS: {spec['constraints']}\n"
        "Return concise JSON-compatible prose with findings, evidence, uncertainty, and next discriminating action."
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": task},
        ],
        "temperature": 0.1,
        "stream": False,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    started = asyncio.get_running_loop().time()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            response = await client.post(f"{base_url}/chat/completions", headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()
        content = body["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            content = json.dumps(content, sort_keys=True)
        if len(content) > max_chars:
            content = content[:max_chars] + "\n[TRUNCATED]"
        return {
            "agent": name,
            "status": "OK",
            "elapsed_seconds": round(asyncio.get_running_loop().time() - started, 3),
            "content": content,
        }
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return {
            "agent": name,
            "status": "ERROR",
            "elapsed_seconds": round(asyncio.get_running_loop().time() - started, 3),
            "error": f"{type(exc).__name__}: {exc}",
        }


async def run_team(task: str) -> dict[str, Any]:
    timeout = float(os.environ.get("AGENT_TIMEOUT_SECONDS", DEFAULT_TIMEOUT))
    max_chars = int(os.environ.get("AGENT_MAX_OUTPUT_CHARS", DEFAULT_MAX_CHARS))
    if timeout <= 0 or timeout > 300:
        raise ValueError("AGENT_TIMEOUT_SECONDS must be > 0 and <= 300")
    if max_chars <= 0 or max_chars > 100_000:
        raise ValueError("AGENT_MAX_OUTPUT_CHARS must be > 0 and <= 100000")

    async def bounded(name: str) -> dict[str, Any]:
        try:
            return await asyncio.wait_for(_call_agent(name, task, timeout, max_chars), timeout=timeout + 2)
        except TimeoutError:
            return {"agent": name, "status": "TIMEOUT", "timeout_seconds": timeout}

    results = await asyncio.gather(*(bounded(name) for name in AGENTS))
    return {
        "task": task,
        "timeout_seconds": timeout,
        "agents": results,
        "rule": "TIMEOUT/ERROR/CONFIG_REQUIRED are explicit non-results and cannot be counted as agreement or PASS.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded multi-agent + read-only MCP composition layer")
    sub = parser.add_subparsers(dest="command", required=True)

    team = sub.add_parser("team", help="run the four advisory agents concurrently")
    team.add_argument("task")

    sub.add_parser("mcp", help="run the read-only repo-guard MCP server over stdio")

    args = parser.parse_args()
    if args.command == "mcp":
        mcp.run()
        return
    if args.command == "team":
        print(json.dumps(asyncio.run(run_team(args.task)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
