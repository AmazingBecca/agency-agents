from __future__ import annotations

import argparse
import json
import pathlib
import sys

import verify_authenticated_runner_bundle as authenticated
import verify_bound_candidate_test_authority as bound
import verify_detached_descendant_lifecycle as descendant
import verify_nested_suite_dispatch_authority as nested

_SCHEMA = "amazingbecca.terminal-candidate-authority.v1"
_AUTHORITY_LEVEL = "diagnostic-bundle-dispatch-bound-not-terminal"
_NESTED_SCHEMA = "amazingbecca.nested-suite-dispatch-authority.v1"
_DESCENDANT_SCHEMA = "amazingbecca.detached-descendant-lifecycle.v1"


def _validate_nested_report(report: dict[str, object]) -> None:
    if report.get("schema") != _NESTED_SCHEMA:
        raise RuntimeError("nested dispatch authority schema is unexpected")
    if not isinstance(report.get("passed"), bool):
        raise RuntimeError("nested dispatch authority decision is malformed")
    if not isinstance(report.get("case_count"), int):
        raise RuntimeError("nested dispatch authority case count is malformed")
    for key in ("accepted_attacks", "rejected_clean"):
        value = report.get(key)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise RuntimeError(f"nested dispatch authority {key} is malformed")


def _validate_descendant_report(report: dict[str, object]) -> None:
    if report.get("schema") != _DESCENDANT_SCHEMA:
        raise RuntimeError("detached-descendant authority schema is unexpected")
    if report.get("passed") is not True:
        raise RuntimeError("detached-descendant authority did not pass")
    if report.get("detached_session_started") is not True:
        raise RuntimeError("detached-descendant authority did not start the hostile session")
    if report.get("heartbeat_stable_after_namespace_exit") is not True:
        raise RuntimeError("detached-descendant authority did not prove namespace teardown")


def verify_terminal_bundle(
    *,
    runner_root: pathlib.Path,
    entrypoint: str,
    python_executable: pathlib.Path,
    expected_python_sha256: str,
    expected_runner_sha256: str,
    expected_bundle_sha256: str,
    repository: str,
    head_sha: str,
    base_sha: str,
    merge_sha: str,
    timeout_seconds: int = 20,
    sandbox_user: str | None = "nobody",
) -> dict[str, object]:
    descendant_report: dict[str, object] | None = None
    if sandbox_user is not None:
        descendant_report = descendant.verify_detached_descendant_lifecycle(
            sandbox_user=sandbox_user,
            timeout_seconds=min(max(timeout_seconds, 2), 30),
        )
        _validate_descendant_report(descendant_report)

    base_report = authenticated.verify_authenticated_bundle(
        runner_root=runner_root,
        entrypoint=entrypoint,
        python_executable=python_executable,
        expected_python_sha256=expected_python_sha256,
        expected_runner_sha256=expected_runner_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
        repository=repository,
        head_sha=head_sha,
        base_sha=base_sha,
        merge_sha=merge_sha,
        timeout_seconds=timeout_seconds,
        sandbox_user=sandbox_user,
    )
    if not isinstance(base_report.get("passed"), bool):
        raise RuntimeError("authenticated bundle decision is malformed")

    before_bundle = authenticated.snapshot_bundle(runner_root)
    if before_bundle.sha256 != expected_bundle_sha256:
        raise RuntimeError("runner bundle authority drifted before terminal dispatch verification")
    runtime_before = authenticated._snapshot_python_executable(python_executable)
    if runtime_before.sha256 != expected_python_sha256:
        raise RuntimeError("Python authority drifted before terminal dispatch verification")

    authenticated._assert_bundle_not_writable_by_sandbox(before_bundle, sandbox_user)
    authenticated._assert_runtime_not_writable_by_sandbox(runtime_before, sandbox_user)

    closure_before = None
    if sandbox_user is not None:
        sandbox_identity = bound.boundary.resolve_identity(sandbox_user)
        closure_before = authenticated.runtime_closure.snapshot_runtime_closure(runtime_before.path)
        authenticated.runtime_closure.assert_closure_not_writable_by_identity(
            closure_before,
            uid=sandbox_identity.uid,
            gid=sandbox_identity.gid,
        )

    runner = (before_bundle.root / pathlib.PurePosixPath(entrypoint)).resolve(strict=True)
    if before_bundle.root not in runner.parents:
        raise RuntimeError("runner entrypoint escaped authenticated bundle before terminal verification")
    if sandbox_user is not None:
        bound._assert_sandbox_runner_access(runner)

    with bound._sandboxed_candidate_execution(sandbox_user):
        nested_report = nested.verify(
            runner=runner,
            python_executable=runtime_before.path,
            timeout_seconds=timeout_seconds,
        )
    _validate_nested_report(nested_report)

    runtime_after = authenticated._snapshot_python_executable(runtime_before.path)
    if runtime_after != runtime_before:
        raise RuntimeError("Python executable authority changed during terminal dispatch verification")
    if closure_before is not None:
        closure_after = authenticated.runtime_closure.snapshot_runtime_closure(runtime_before.path)
        if closure_after != closure_before:
            raise RuntimeError("Python runtime closure changed during terminal dispatch verification")

    after_bundle = authenticated.snapshot_bundle(before_bundle.root)
    if after_bundle != before_bundle:
        raise RuntimeError("runner bundle authority changed during terminal dispatch verification")

    accepted_attacks = sorted(
        set(base_report.get("accepted_attacks", []))
        | set(nested_report.get("accepted_attacks", []))
    )
    rejected_clean = sorted(
        set(base_report.get("rejected_clean", []))
        | set(nested_report.get("rejected_clean", []))
    )
    base_total = base_report.get("total_case_count", 0)
    if not isinstance(base_total, int):
        raise RuntimeError("authenticated bundle case count is malformed")
    nested_count = int(nested_report["case_count"])
    descendant_passed = descendant_report is None or descendant_report.get("passed") is True

    report = dict(base_report)
    report.update(
        {
            "terminal_schema": _SCHEMA,
            "authority_level": _AUTHORITY_LEVEL,
            "nested_dispatch_schema": nested_report["schema"],
            "nested_dispatch_authority_level": nested_report.get("authority_level"),
            "nested_dispatch_case_count": nested_count,
            "nested_dispatch_cases": list(nested_report.get("cases", [])),
            "terminal_total_case_count": base_total + nested_count,
            "detached_descendant_schema": (
                descendant_report.get("schema") if descendant_report is not None else None
            ),
            "detached_descendant_verified": descendant_report is not None,
            "detached_descendant_report": descendant_report,
            "accepted_attacks": accepted_attacks,
            "rejected_clean": rejected_clean,
            "passed": bool(base_report["passed"])
            and bool(nested_report["passed"])
            and descendant_passed
            and not accepted_attacks
            and not rejected_clean,
        }
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner-root", type=pathlib.Path, required=True)
    parser.add_argument("--entrypoint", default="isolated_unittest_runner.py")
    parser.add_argument("--python", dest="python_executable", type=pathlib.Path, default=pathlib.Path(sys.executable))
    parser.add_argument("--expected-python-sha256", required=True)
    parser.add_argument("--expected-runner-sha256", required=True)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--merge-sha", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=20)
    parser.add_argument("--sandbox-user", default="nobody")
    args = parser.parse_args(argv)

    try:
        report = verify_terminal_bundle(
            runner_root=args.runner_root,
            entrypoint=args.entrypoint,
            python_executable=args.python_executable,
            expected_python_sha256=args.expected_python_sha256,
            expected_runner_sha256=args.expected_runner_sha256,
            expected_bundle_sha256=args.expected_bundle_sha256,
            repository=args.repository,
            head_sha=args.head_sha,
            base_sha=args.base_sha,
            merge_sha=args.merge_sha,
            timeout_seconds=args.timeout_seconds,
            sandbox_user=args.sandbox_user or None,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
