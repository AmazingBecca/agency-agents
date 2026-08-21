from __future__ import annotations

import base64
import hashlib
import os
import re
from typing import Any
from urllib.parse import quote

import httpx
from fastmcp import FastMCP

mcp = FastMCP("github-source-witness")

_API = "https://api.github.com"
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_MAX_FILE_BYTES = 1_000_000


def _timeout() -> float:
    value = float(os.environ.get("SOURCE_WITNESS_TIMEOUT_SECONDS", "12"))
    if value < 1 or value > 60:
        raise ValueError("SOURCE_WITNESS_TIMEOUT_SECONDS must be between 1 and 60")
    return value


def _allowed_owners() -> set[str]:
    raw = os.environ.get("SOURCE_WITNESS_ALLOWED_OWNERS", "AmazingBecca")
    owners = {item.strip() for item in raw.split(",") if item.strip()}
    if not owners:
        raise ValueError("SOURCE_WITNESS_ALLOWED_OWNERS must not be empty")
    return owners


def _validate_repo(owner: str, repo: str) -> None:
    if owner not in _allowed_owners():
        raise ValueError("owner is not allowlisted")
    if not _NAME_RE.fullmatch(owner) or not _NAME_RE.fullmatch(repo):
        raise ValueError("invalid owner or repository name")


def _validate_ref(ref: str) -> str:
    ref = ref.strip()
    if not ref or len(ref) > 240 or any(ch in ref for ch in ("\x00", "\r", "\n")):
        raise ValueError("invalid ref")
    return ref


def _validate_path(path: str) -> str:
    path = path.strip().replace("\\", "/")
    if not path or path.startswith("/") or len(path) > 1000:
        raise ValueError("invalid path")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("path traversal or empty segment rejected")
    return path


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "agency-agents-source-witness/1",
    }
    # Deliberately do not consume ambient GITHUB_TOKEN. Private-repo access is opt-in
    # through one narrowly named read token supplied by the operator.
    token = os.environ.get("SOURCE_WITNESS_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _get(path: str, *, params: dict[str, str] | None = None) -> Any:
    async with httpx.AsyncClient(
        base_url=_API,
        headers=_headers(),
        timeout=httpx.Timeout(_timeout()),
        follow_redirects=False,
    ) as client:
        response = await client.get(path, params=params)
        if 300 <= response.status_code < 400:
            raise RuntimeError("redirect rejected")
        response.raise_for_status()
        return response.json()


async def _resolve(owner: str, repo: str, ref: str) -> dict[str, str]:
    _validate_repo(owner, repo)
    ref = _validate_ref(ref)
    data = await _get(f"/repos/{quote(owner)}/{quote(repo)}/commits/{quote(ref, safe='')}")
    sha = str(data.get("sha", ""))
    if not _SHA_RE.fullmatch(sha):
        raise RuntimeError("GitHub response did not contain an exact 40-hex commit SHA")
    tree_sha = str(((data.get("commit") or {}).get("tree") or {}).get("sha", ""))
    if tree_sha and not _SHA_RE.fullmatch(tree_sha):
        raise RuntimeError("invalid tree SHA in GitHub response")
    return {"requested_ref": ref, "commit_sha": sha, "tree_sha": tree_sha}


@mcp.tool
async def resolve_ref(owner: str, repo: str, ref: str) -> dict[str, str]:
    """Resolve an allowlisted GitHub ref to an immutable exact commit SHA."""
    return await _resolve(owner, repo, ref)


@mcp.tool
async def file_identity(owner: str, repo: str, ref: str, path: str) -> dict[str, Any]:
    """Bind a repository file to resolved commit, Git blob SHA, byte size and SHA-256."""
    _validate_repo(owner, repo)
    path = _validate_path(path)
    resolved = await _resolve(owner, repo, ref)
    encoded_path = quote(path, safe="/")
    data = await _get(
        f"/repos/{quote(owner)}/{quote(repo)}/contents/{encoded_path}",
        params={"ref": resolved["commit_sha"]},
    )
    if not isinstance(data, dict) or data.get("type") != "file":
        raise ValueError("path is not a file")
    git_blob_sha = str(data.get("sha", ""))
    if not _SHA_RE.fullmatch(git_blob_sha):
        raise RuntimeError("invalid Git blob SHA")
    size = int(data.get("size", -1))
    if size < 0 or size > _MAX_FILE_BYTES:
        raise ValueError(f"file size outside permitted range: {size}")
    if data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
        raise RuntimeError("GitHub did not return bounded base64 file content")
    raw = base64.b64decode(data["content"], validate=False)
    if len(raw) != size:
        raise RuntimeError("decoded size does not match GitHub metadata")
    return {
        "owner": owner,
        "repo": repo,
        "path": path,
        **resolved,
        "git_blob_sha": git_blob_sha,
        "size": size,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


@mcp.tool
async def verify_file(
    owner: str,
    repo: str,
    ref: str,
    path: str,
    expected_commit_sha: str = "",
    expected_git_blob_sha: str = "",
    expected_sha256: str = "",
) -> dict[str, Any]:
    """Compare observed exact identity with caller-supplied expected values; never mutates GitHub."""
    observed = await file_identity(owner, repo, ref, path)
    checks: dict[str, bool] = {}
    if expected_commit_sha:
        checks["commit_sha"] = observed["commit_sha"] == expected_commit_sha.lower()
    if expected_git_blob_sha:
        checks["git_blob_sha"] = observed["git_blob_sha"] == expected_git_blob_sha.lower()
    if expected_sha256:
        checks["sha256"] = observed["sha256"] == expected_sha256.lower()
    return {
        "observed": observed,
        "checks": checks,
        "pass": bool(checks) and all(checks.values()),
        "non_proof_boundary": "No expected value means no PASS; network failure or timeout is an ERROR, not a mismatch verdict.",
    }


if __name__ == "__main__":
    mcp.run()
