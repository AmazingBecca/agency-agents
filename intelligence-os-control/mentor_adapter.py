#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

SHA40 = re.compile(r"^[0-9a-f]{40}$")
MENTOR = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
TEST = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")
ALLOWED_RECOMMENDATIONS = {"READY", "BLOCKED", "RECOMPILE", "ESCALATE"}
RAW_KEYS = {
    "schema", "mentor", "repository", "head", "recommendation", "reason",
    "findings", "required_tests", "allowed_paths",
}


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def load_canonical(path: pathlib.Path):
    raw = path.read_bytes()
    value = json.loads(raw)
    if canonical_bytes(value) != raw:
        raise ValueError(f"{path} is not canonical JSON")
    return value


def _path(value: object) -> str:
    if not isinstance(value, str) or not value or value.startswith(("/", "~")):
        raise ValueError("allowed path must be repository-relative")
    parts = pathlib.PurePosixPath(value).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("allowed path must be normalized")
    if "\\" in value or value.endswith("/"):
        raise ValueError("allowed path must use normalized POSIX form")
    return value


def adapt(raw: dict, state: dict) -> dict:
    if not isinstance(raw, dict) or not isinstance(state, dict):
        raise ValueError("raw mentor report and state must be objects")
    unknown = sorted(set(raw) - RAW_KEYS)
    if unknown:
        raise ValueError(f"mentor report contains forbidden fields: {','.join(unknown)}")
    if raw.get("schema") != "amazingbecca.predator-mentor.v1":
        raise ValueError("unsupported mentor schema")
    mentor = raw.get("mentor")
    if not isinstance(mentor, str) or not MENTOR.fullmatch(mentor):
        raise ValueError("invalid mentor identity")
    repository = state.get("repository")
    head = state.get("head")
    if raw.get("repository") != repository:
        raise ValueError("mentor repository does not match state")
    if not isinstance(head, str) or not SHA40.fullmatch(head) or raw.get("head") != head:
        raise ValueError("mentor head does not match state")
    recommendation = raw.get("recommendation")
    if recommendation not in ALLOWED_RECOMMENDATIONS:
        raise ValueError("invalid mentor recommendation")
    reason = raw.get("reason", "")
    if not isinstance(reason, str):
        raise ValueError("mentor reason must be text")
    if recommendation in {"BLOCKED", "ESCALATE"} and not reason.strip():
        raise ValueError("blocking mentor report requires reason")
    findings = raw.get("findings", [])
    if not isinstance(findings, list) or not all(isinstance(x, str) and x.strip() for x in findings):
        raise ValueError("invalid mentor findings")
    tests = raw.get("required_tests", [])
    if not isinstance(tests, list) or not all(isinstance(x, str) and TEST.fullmatch(x) for x in tests):
        raise ValueError("invalid mentor required_tests")
    paths = raw.get("allowed_paths", [])
    if not isinstance(paths, list):
        raise ValueError("invalid mentor allowed_paths")
    normalized_paths = sorted({_path(value) for value in paths})
    return {
        "mentor": mentor,
        "head": head,
        "recommendation": recommendation,
        "reason": reason.strip(),
        "findings": sorted(set(x.strip() for x in findings)),
        "required_tests": sorted(set(tests)),
        "allowed_paths": normalized_paths,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, action="append", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        state = load_canonical(args.state)
        adapted = [adapt(load_canonical(path), state) for path in args.report]
        names = [item["mentor"] for item in adapted]
        if len(names) != len(set(names)):
            raise ValueError("duplicate mentor identity")
        args.output.write_bytes(canonical_bytes(sorted(adapted, key=lambda item: item["mentor"])))
    except Exception as exc:
        print(f"mentor adapter rejected input: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
