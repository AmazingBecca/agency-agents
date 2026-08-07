#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

SHA40 = re.compile(r"^[0-9a-f]{40}$")
TEST = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")
ALLOWED_STATES = {"READY", "BLOCKED", "RECOMPILE", "ESCALATE"}


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def require_sha(name: str, value: object) -> str:
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase 40-character Git SHA")
    return value


def require_repo_path(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or value.startswith(("/", "~")):
        raise ValueError(f"{name} must be repository-relative")
    if "\\" in value or value.endswith("/"):
        raise ValueError(f"{name} must use normalized POSIX form")
    normalized = str(pathlib.PurePosixPath(value))
    parts = pathlib.PurePosixPath(value).parts
    if normalized != value or not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"{name} must be normalized")
    return value


def path_ranges_overlap(left: str, right: str) -> bool:
    return (
        left == right
        or left.startswith(right + "/")
        or right.startswith(left + "/")
    )


def compile_manifest(state: dict, mentors: list[dict], policy: dict) -> dict:
    if not isinstance(state, dict) or not isinstance(policy, dict) or not isinstance(mentors, list):
        raise ValueError("state, mentors, and policy must use canonical object/list shapes")

    repository = state.get("repository")
    if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    head = require_sha("head", state.get("head"))
    base = require_sha("base", state.get("base"))
    merge = require_sha("merge", state.get("merge"))
    if len({head, base, merge}) != 3:
        raise ValueError("head/base/merge must be distinct")

    allowed_repositories = policy.get("allowed_repositories")
    if not isinstance(allowed_repositories, list) or repository not in allowed_repositories:
        raise ValueError("repository outside policy")

    production_mutation = state.get("production_mutation", False)
    if production_mutation is not False:
        raise ValueError("production mutation is not compiler-authorized")

    raw_forbidden_paths = policy.get("forbidden_paths", [])
    if not isinstance(raw_forbidden_paths, list):
        raise ValueError("invalid forbidden_paths policy")
    forbidden_paths = {
        require_repo_path("forbidden path", value) for value in raw_forbidden_paths
    }

    mentor_names: list[str] = []
    blockers: list[str] = []
    required_tests: set[str] = set()
    allowed_paths: set[str] = set()

    if not mentors:
        raise ValueError("at least one mentor report is required")
    for report in mentors:
        if not isinstance(report, dict):
            raise ValueError("mentor report must be an object")
        name = report.get("mentor")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", name):
            raise ValueError("invalid mentor identity")
        if name in mentor_names:
            raise ValueError("duplicate mentor identity")
        mentor_names.append(name)
        if require_sha(f"mentor {name} head", report.get("head")) != head:
            raise ValueError("stale mentor report")
        recommendation = report.get("recommendation")
        if recommendation not in ALLOWED_STATES:
            raise ValueError("invalid mentor recommendation")
        if recommendation != "READY":
            reason = report.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError("non-ready mentor report requires reason")
            blockers.append(f"{name}:{reason.strip()}")
        tests = report.get("required_tests", [])
        paths = report.get("allowed_paths", [])
        if not isinstance(tests, list) or not all(
            isinstance(value, str) and TEST.fullmatch(value) for value in tests
        ):
            raise ValueError("invalid required_tests")
        if not isinstance(paths, list):
            raise ValueError("invalid allowed_paths")
        normalized_paths = {
            require_repo_path(f"mentor {name} allowed path", value) for value in paths
        }
        required_tests.update(tests)
        allowed_paths.update(normalized_paths)

    required_mentors = set(policy.get("required_mentors", []))
    missing = sorted(required_mentors - set(mentor_names))
    if missing:
        raise ValueError(f"missing required mentors: {','.join(missing)}")

    for allowed_path in allowed_paths:
        if any(path_ranges_overlap(allowed_path, forbidden_path) for forbidden_path in forbidden_paths):
            raise ValueError("mentor attempted to authorize a forbidden path")

    status = "BLOCKED" if blockers else "READY"
    manifest_core = {
        "schema": "amazingbecca.predator-compiler.v1",
        "status": status,
        "repository": repository,
        "head": head,
        "base": base,
        "merge": merge,
        "production_mutation": False,
        "mentor_set": sorted(mentor_names),
        "required_tests": sorted(required_tests),
        "allowed_paths": sorted(allowed_paths),
        "forbidden_paths": sorted(forbidden_paths),
        "blockers": sorted(blockers),
    }
    execution_id = hashlib.sha256(canonical_bytes(manifest_core)).hexdigest()
    return {**manifest_core, "execution_id": execution_id}


def load_json(path: pathlib.Path):
    raw = path.read_bytes()
    value = json.loads(raw)
    if canonical_bytes(value) != raw:
        raise ValueError(f"{path} is not canonical JSON")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=pathlib.Path, required=True)
    parser.add_argument("--mentors", type=pathlib.Path, required=True)
    parser.add_argument("--policy", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        manifest = compile_manifest(load_json(args.state), load_json(args.mentors), load_json(args.policy))
        data = canonical_bytes(manifest)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(data)
    except Exception as exc:
        print(f"predator compiler rejected input: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
