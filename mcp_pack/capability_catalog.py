from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

mcp = FastMCP("capability-catalog")
_CATALOG = Path(__file__).with_name("catalog.json")
_MAX_BYTES = 500_000


def _load() -> list[dict[str, Any]]:
    raw = _CATALOG.read_bytes()
    if len(raw) > _MAX_BYTES:
        raise RuntimeError("capability catalog exceeds bounded size")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, list):
        raise RuntimeError("capability catalog must be a list")
    ids: set[str] = set()
    for item in data:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise RuntimeError("catalog entry missing string id")
        if item["id"] in ids:
            raise RuntimeError("duplicate capability id")
        ids.add(item["id"])
    return data


@mcp.tool
def list_capabilities(status: str = "", category: str = "") -> list[dict[str, Any]]:
    """List source-controlled capability candidates, optionally filtered by state/category."""
    result = _load()
    if status:
        result = [item for item in result if item.get("status") == status]
    if category:
        result = [item for item in result if item.get("category") == category]
    return result


@mcp.tool
def get_capability(capability_id: str) -> dict[str, Any]:
    """Return one capability record including primary sources, risks, and next validation."""
    for item in _load():
        if item["id"] == capability_id:
            return item
    raise ValueError("unknown capability id")


@mcp.tool
def validation_queue() -> list[dict[str, str]]:
    """Return candidates that are not yet ready, ordered exactly as curated in catalog.json."""
    queue: list[dict[str, str]] = []
    for item in _load():
        if item.get("status") not in {"READY_TO_INTEGRATE", "REJECT"}:
            queue.append(
                {
                    "id": item["id"],
                    "status": str(item.get("status", "UNKNOWN")),
                    "next_validation": str(item.get("next_validation", "")),
                }
            )
    return queue


@mcp.tool
def catalog_invariants() -> dict[str, object]:
    """Describe the trust boundary of the research catalog."""
    return {
        "authoritative_for": ["what was researched", "which primary sources were recorded", "current integration decision"],
        "not_authoritative_for": ["third-party code safety", "runtime compatibility", "current pricing", "execution success"],
        "mutation_surface": "none through this MCP",
        "source": str(_CATALOG),
    }


if __name__ == "__main__":
    mcp.run()
