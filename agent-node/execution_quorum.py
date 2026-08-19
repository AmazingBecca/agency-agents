#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from typing import Any

SCHEMA = "agent-node-execution-quorum/v1"
REQUIRED_RECEIPT_KEYS = {
    "worker_id", "head", "tree", "runtime_sha256", "selector",
    "returncode", "stdout_sha256", "environment_sha256"
}

class QuorumError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _is_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def verify_quorum(receipts: list[dict[str, Any]], *, threshold: int) -> dict[str, Any]:
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 2:
        raise QuorumError("threshold must be an integer >= 2")
    if not isinstance(receipts, list) or len(receipts) < threshold:
        raise QuorumError("insufficient receipts")

    normalized = []
    workers = set()
    environments = set()
    consensus = None
    for receipt in receipts:
        if not isinstance(receipt, dict) or set(receipt) != REQUIRED_RECEIPT_KEYS:
            raise QuorumError("receipt schema drift")
        if not receipt["worker_id"] or receipt["worker_id"] in workers:
            raise QuorumError("worker identity must be unique")
        workers.add(receipt["worker_id"])
        for field, length in (("head", 40), ("tree", 40), ("runtime_sha256", 64), ("stdout_sha256", 64), ("environment_sha256", 64)):
            if not _is_hex(receipt[field], length):
                raise QuorumError(f"invalid {field}")
        if not isinstance(receipt["selector"], str) or not receipt["selector"]:
            raise QuorumError("selector required")
        if not isinstance(receipt["returncode"], int) or isinstance(receipt["returncode"], bool):
            raise QuorumError("returncode invalid")
        if receipt["environment_sha256"] in environments:
            raise QuorumError("environment identity must be unique")
        environments.add(receipt["environment_sha256"])
        agreed = {
            "head": receipt["head"],
            "tree": receipt["tree"],
            "selector": receipt["selector"],
            "returncode": receipt["returncode"],
            "stdout_sha256": receipt["stdout_sha256"],
        }
        if consensus is None:
            consensus = agreed
        elif agreed != consensus:
            raise QuorumError("execution receipts disagree")
        normalized.append(receipt)

    if len(normalized) < threshold:
        raise QuorumError("threshold not met")
    result = {
        "schema": SCHEMA,
        "threshold": threshold,
        "receipt_count": len(normalized),
        "worker_ids": sorted(workers),
        "environment_ids": sorted(environments),
        "consensus": consensus,
        "advisory_only": True,
        "promotion_authorized": False,
        "completion_authorized": False,
    }
    result["quorum_sha256"] = hashlib.sha256(canonical(result)).hexdigest()
    return result
