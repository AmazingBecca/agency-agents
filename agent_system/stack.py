from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import select
import stat
import subprocess
import time
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastmcp import FastMCP

AGENTS: dict[str, dict[str, Any]] = {
    "research_scout": {
        "mission": "Identify useful external capability leads from evidence already provided to this local composition layer. Do not claim live external research unless a separate retrieval tool actually supplied it.",
        "constraints": "Advisory only. No writes, credentials, billing, deployment, production authority, or unsupported verification claims.",
    },
    "source_verifier": {
        "mission": "Evaluate exact repository/ref/file/hash identity and provenance against the deterministic workspace evidence supplied with the task.",
        "constraints": "Advisory only. Deterministic evidence remains authoritative; model output cannot create a PASS verdict.",
    },
    "adversarial_reviewer": {
        "mission": "Attack proposed architecture for authority bypass, provenance substitution, stale identity, replay, path expansion, mutable dependencies, candidate-controlled verdicts, omitted negative tests, and false-green CI.",
        "constraints": "Advisory only. Convert concerns into discriminating tests and distinguish facts from hypotheses.",
    },
    "capability_architect": {
        "mission": "Turn supplied evidence and review findings into the smallest high-value composition change using mature, bounded, model-agnostic primitives.",
        "constraints": "Proposal authority only. Do not assume permission, credentials, spend, protected-ref authority, or production access.",
    },
}

DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"
DEFAULT_TIMEOUT = 45.0
DEFAULT_MAX_CHARS = 12_000
DEFAULT_MAX_RESPONSE_BYTES = 512_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_HASH_SECONDS = 5.0
MAX_VISITED_ENTRIES = 20_000
SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _workspace_root() -> Path:
    raw = os.environ.get("AGENT_WORKSPACE_ROOT")
    if not raw:
        raise ValueError("AGENT_WORKSPACE_ROOT must be explicitly set")
    root = Path(raw).expanduser()
    if not root.is_absolute():
        raise ValueError("AGENT_WORKSPACE_ROOT must be absolute")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current = current / part
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"workspace component is a symlink: {current}")
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("AGENT_WORKSPACE_ROOT must be a directory")
    return root


def _relative_parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or "\x00" in relative:
        raise ValueError("invalid path")
    value = PurePosixPath(relative)
    if value.is_absolute():
        raise ValueError("absolute paths are not allowed")
    parts = tuple(part for part in value.parts if part not in ("", "."))
    if any(part == ".." for part in parts):
        raise ValueError("path escapes AGENT_WORKSPACE_ROOT")
    return parts


def _open_beneath(relative: str, *, directory: bool = False) -> tuple[int, Path]:
    root = _workspace_root()
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    current_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow)
    parts = _relative_parts(relative)
    try:
        if not parts:
            if not directory:
                raise ValueError("file path is required")
            final_fd = current_fd
            current_fd = -1
            return final_fd, root
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        flags = os.O_RDONLY | os.O_CLOEXEC | nofollow
        if directory:
            flags |= os.O_DIRECTORY
        final_fd = os.open(parts[-1], flags, dir_fd=current_fd)
        os.close(current_fd)
        current_fd = -1
        info = os.fstat(final_fd)
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                os.close(final_fd)
                raise ValueError("directory does not exist")
        else:
            if not stat.S_ISREG(info.st_mode):
                os.close(final_fd)
                raise ValueError("file does not exist")
            if info.st_nlink != 1:
                os.close(final_fd)
                raise ValueError("hard-linked files are not accepted")
        return final_fd, root / PurePosixPath(*parts)
    except OSError as exc:
        raise ValueError("path is missing, linked, or not accessible") from exc
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def _git(args: list[str], root: Path, timeout: float = 3.0) -> str:
    env = {"PATH": SAFE_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(root)}
    completed = subprocess.run(
        ["git", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", *args],
        cwd=root,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(f"git {' '.join(args)} failed")
    if len(completed.stdout) > 4096:
        raise ValueError("git identity output exceeded bound")
    return completed.stdout.decode("utf-8", errors="strict").strip()


def _git_has_output(args: list[str], root: Path, timeout: float = 3.0) -> bool:
    env = {"PATH": SAFE_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(root)}
    process = subprocess.Popen(
        ["git", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", *args],
        cwd=root,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert process.stdout is not None
    try:
        readable, _, _ = select.select([process.stdout], [], [], timeout)
        if not readable:
            raise TimeoutError("git dirty-state probe timed out")
        one = os.read(process.stdout.fileno(), 1)
        return bool(one)
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
        process.stdout.close()


def workspace_identity() -> dict[str, Any]:
    root = _workspace_root()
    result: dict[str, Any] = {"workspace_root": str(root), "mode": "read-only", "authority": "deterministic-local-evidence"}
    try:
        head = _git(["rev-parse", "HEAD"], root)
        tree = _git(["rev-parse", "HEAD^{tree}"], root)
        tracked_dirty = subprocess.run(
            ["git", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "diff-index", "--quiet", "HEAD", "--"],
            cwd=root,
            env={"PATH": SAFE_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(root)},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        ).returncode != 0
        untracked = _git_has_output(["ls-files", "--others", "--exclude-standard", "--directory"], root)
        result.update({"git": True, "head": head, "tree": tree, "dirty": tracked_dirty or untracked, "tracked_dirty": tracked_dirty, "untracked_present": untracked})
    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired) as exc:
        result.update({"git": False, "git_error": f"{type(exc).__name__}: {exc}"})
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["identity_sha256"] = hashlib.sha256(raw).hexdigest()
    return result


def _walk_files(fd: int, prefix: PurePosixPath, entries: list[str], counter: list[int], max_entries: int, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("directory depth exceeds limit")
    with os.scandir(os.dup(fd)) as iterator:
        for entry in iterator:
            counter[0] += 1
            if counter[0] > MAX_VISITED_ENTRIES:
                raise ValueError("workspace traversal exceeds visited-entry budget")
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            child = prefix / entry.name
            if stat.S_ISLNK(info.st_mode):
                continue
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink == 1:
                    entries.append(str(child))
                    if len(entries) >= max_entries:
                        return
                continue
            if stat.S_ISDIR(info.st_mode):
                try:
                    child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                except OSError:
                    continue
                try:
                    _walk_files(child_fd, child, entries, counter, max_entries, depth + 1)
                finally:
                    os.close(child_fd)
                if len(entries) >= max_entries:
                    return


def list_files(path: str = ".", max_entries: int = 500) -> list[str]:
    max_entries = max(1, min(int(max_entries), 2000))
    fd, _ = _open_beneath(path, directory=True)
    try:
        entries: list[str] = []
        _walk_files(fd, PurePosixPath(*_relative_parts(path)), entries, [0], max_entries)
        return sorted(entries)
    finally:
        os.close(fd)


def read_text(path: str, max_bytes: int = 200_000) -> str:
    max_bytes = max(1, min(int(max_bytes), 1_000_000))
    fd, _ = _open_beneath(path)
    try:
        info = os.fstat(fd)
        if info.st_size > max_bytes:
            raise ValueError(f"file exceeds max_bytes ({info.st_size} > {max_bytes})")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("file grew beyond max_bytes while reading")
        return data.decode("utf-8", errors="replace")
    finally:
        os.close(fd)


def sha256_file(path: str, max_bytes: int = MAX_FILE_BYTES, max_seconds: float = MAX_HASH_SECONDS) -> dict[str, Any]:
    max_bytes = max(1, min(int(max_bytes), MAX_FILE_BYTES))
    max_seconds = max(0.1, min(float(max_seconds), MAX_HASH_SECONDS))
    fd, _ = _open_beneath(path)
    try:
        info = os.fstat(fd)
        if info.st_size > max_bytes:
            return {"path": path, "status": "LIMIT_EXCEEDED", "size": info.st_size, "max_bytes": max_bytes}
        digest = hashlib.sha256()
        size = 0
        deadline = time.monotonic() + max_seconds
        while True:
            if time.monotonic() > deadline:
                return {"path": path, "status": "TIMEOUT", "size": size, "max_seconds": max_seconds}
            chunk = os.read(fd, min(1024 * 1024, max_bytes - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                return {"path": path, "status": "LIMIT_EXCEEDED", "size": size, "max_bytes": max_bytes}
            digest.update(chunk)
        return {"path": path, "status": "OK", "size": size, "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


def deterministic_evidence_context() -> dict[str, Any]:
    identity = workspace_identity()
    files = list_files(".", 200)
    value = {"workspace": identity, "bounded_file_index": files, "file_index_truncated": len(files) >= 200}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    value["evidence_sha256"] = hashlib.sha256(raw).hexdigest()
    return value


def _validated_base_url(raw: str) -> str:
    value = raw.rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("AGENT_BASE_URL must be a simple http(s) origin/path without userinfo, query, or fragment")
    host = parsed.hostname.lower()
    if parsed.scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise ValueError("plaintext AGENT_BASE_URL is allowed only for literal loopback/localhost endpoints")
    return value


def _model_response_limit(max_chars: int) -> int:
    configured = int(os.environ.get("AGENT_MAX_RESPONSE_BYTES", DEFAULT_MAX_RESPONSE_BYTES))
    if configured <= 0 or configured > 2_000_000:
        raise ValueError("AGENT_MAX_RESPONSE_BYTES must be > 0 and <= 2000000")
    return min(configured, max(65_536, max_chars * 8 + 65_536))


mcp = FastMCP("repo-guard")
mcp.tool(workspace_identity)
mcp.tool(list_files)
mcp.tool(read_text)
mcp.tool(sha256_file)


async def _call_agent(name: str, task: str, timeout: float, max_chars: int, evidence: dict[str, Any]) -> dict[str, Any]:
    spec = AGENTS[name]
    try:
        base_url = _validated_base_url(os.environ.get("AGENT_BASE_URL", DEFAULT_BASE_URL))
    except ValueError as exc:
        return {"agent": name, "status": "CONFIG_REQUIRED", "error": str(exc)}
    model = os.environ.get("AGENT_MODEL")
    api_key = os.environ.get("AGENT_API_KEY", "ollama")
    if not model:
        return {"agent": name, "status": "CONFIG_REQUIRED", "error": "AGENT_MODEL is not set"}
    system = (
        f"You are the {name} advisory agent.\nMISSION: {spec['mission']}\n"
        f"CONSTRAINTS: {spec['constraints']}\n"
        "You have no live tools in this call. Deterministic evidence supplied below remains authoritative. "
        "Never label your own output verified, PASS, completion-ready, or promotion-ready."
    )
    user_content = json.dumps({"task": task, "deterministic_evidence": evidence}, sort_keys=True, separators=(",", ":"))
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user_content}],
        "temperature": 0.1,
        "stream": False,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    started = asyncio.get_running_loop().time()
    limit = _model_response_limit(max_chars)
    try:
        chunks: list[bytes] = []
        total = 0
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout), trust_env=False, follow_redirects=False) as client:
            async with client.stream("POST", f"{base_url}/chat/completions", headers=headers, json=payload) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > limit:
                        raise ValueError(f"model response exceeds byte limit ({total} > {limit})")
                    chunks.append(chunk)
        body = json.loads(b"".join(chunks).decode("utf-8"))
        content = body["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            content = json.dumps(content, sort_keys=True)
        truncated = len(content) > max_chars
        if truncated:
            content = content[:max_chars] + "\n[TRUNCATED]"
        return {
            "agent": name,
            "status": "ADVISORY_MODEL_OUTPUT",
            "verification_authority": False,
            "model_has_tools": False,
            "evidence_sha256": evidence["evidence_sha256"],
            "elapsed_seconds": round(asyncio.get_running_loop().time() - started, 3),
            "truncated": truncated,
            "content": content,
        }
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return {
            "agent": name,
            "status": "ERROR",
            "verification_authority": False,
            "elapsed_seconds": round(asyncio.get_running_loop().time() - started, 3),
            "error": f"{type(exc).__name__}: {exc}",
        }


async def run_team(task: str) -> dict[str, Any]:
    if not isinstance(task, str) or not task.strip() or len(task) > 100_000:
        raise ValueError("task must contain 1..100000 characters")
    timeout = float(os.environ.get("AGENT_TIMEOUT_SECONDS", DEFAULT_TIMEOUT))
    max_chars = int(os.environ.get("AGENT_MAX_OUTPUT_CHARS", DEFAULT_MAX_CHARS))
    if timeout <= 0 or timeout > 300:
        raise ValueError("AGENT_TIMEOUT_SECONDS must be > 0 and <= 300")
    if max_chars <= 0 or max_chars > 100_000:
        raise ValueError("AGENT_MAX_OUTPUT_CHARS must be > 0 and <= 100000")
    evidence = deterministic_evidence_context()

    async def bounded(name: str) -> dict[str, Any]:
        try:
            return await asyncio.wait_for(_call_agent(name, task, timeout, max_chars, evidence), timeout=timeout + 2)
        except TimeoutError:
            return {"agent": name, "status": "TIMEOUT", "verification_authority": False, "timeout_seconds": timeout}

    results = await asyncio.gather(*(bounded(name) for name in AGENTS))
    return {
        "task": task,
        "deterministic_evidence": evidence,
        "timeout_seconds": timeout,
        "agents": results,
        "authority": "advisory-only",
        "rule": "Only deterministic evidence tools can establish local source facts. Model ADVISORY_MODEL_OUTPUT, TIMEOUT, ERROR, and CONFIG_REQUIRED are never PASS or agreement evidence.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded multi-agent + read-only MCP composition layer")
    sub = parser.add_subparsers(dest="command", required=True)
    team = sub.add_parser("team", help="run four advisory model roles over deterministic workspace evidence")
    team.add_argument("task")
    sub.add_parser("mcp", help="run the read-only repo-guard MCP server over stdio")
    args = parser.parse_args()
    if args.command == "mcp":
        _workspace_root()
        mcp.run()
        return
    print(json.dumps(asyncio.run(run_team(args.task)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
