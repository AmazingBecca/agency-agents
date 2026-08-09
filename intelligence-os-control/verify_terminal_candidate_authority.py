from __future__ import annotations

import argparse
import json
import pathlib
import sys

import verify_terminal_attestation_process_creation as process_creation
import verify_terminal_candidate_authority_legacy as _legacy

# Preserve the established public/internal surface for existing callers and tests,
# then override the terminal composition entry points below. Keeping the prior
# implementation in an immutable sibling blob makes this change narrow while
# ensuring the new process-creation proof encloses the entire legacy diagnostic.
for _name in dir(_legacy):
    if _name.startswith("__") or _name in {
        "main",
        "verify_terminal_bundle",
        "_verify_terminal_bundle_diagnostic",
    }:
        continue
    globals()[_name] = getattr(_legacy, _name)

_PROCESS_CREATION_SCHEMA = "amazingbecca.terminal-attestation-process-creation.v1"
_PROCESS_CREATION_AUTHORITY_LEVEL = "source-process-topology-diagnostic-not-terminal"


def _validate_process_creation_report(report: dict[str, object]) -> None:
    if report.get("schema") != _PROCESS_CREATION_SCHEMA:
        raise RuntimeError("terminal-attestation process-creation schema is unexpected")
    if report.get("authority_level") != _PROCESS_CREATION_AUTHORITY_LEVEL:
        raise RuntimeError("terminal-attestation process-creation authority level is unexpected")
    for key in ("passed", "control_flow_passed"):
        if not isinstance(report.get(key), bool):
            raise RuntimeError(f"terminal-attestation process-creation {key} is malformed")
    for key in ("control_flow_finding_count", "terminal_attestor_count", "finding_count"):
        if not isinstance(report.get(key), int):
            raise RuntimeError(f"terminal-attestation process-creation {key} is malformed")
    findings = report.get("findings")
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise RuntimeError("terminal-attestation process-creation findings are malformed")

    # Preserve the stronger, already-published control-flow failure contract when
    # the process-creation proof is red only because its control-flow prerequisite
    # is red. This keeps failure provenance stable while still ensuring the new
    # process-creation proof runs before candidate diagnostics.
    if report.get("control_flow_passed") is not True:
        raise RuntimeError("runner bundle lacks reviewed terminal-attestation control flow")
    if report.get("control_flow_finding_count") != 0:
        raise RuntimeError("terminal-attestation process-creation control-flow prerequisite reported findings")
    if report.get("passed") is not True:
        raise RuntimeError("runner bundle exposes alternate process-creation authority")
    if report.get("terminal_attestor_count") != 1:
        raise RuntimeError("terminal-attestation process-creation attestor authority is ambiguous")
    if report.get("finding_count") != 0 or findings:
        raise RuntimeError("terminal-attestation process-creation contains findings despite PASS")


def _verify_terminal_bundle_diagnostic(**kwargs: object) -> dict[str, object]:
    runner_root = kwargs.get("runner_root")
    if not isinstance(runner_root, pathlib.Path):
        raise RuntimeError("terminal candidate authority runner root is malformed")

    process_before = process_creation.verify(runner_root)
    _validate_process_creation_report(process_before)

    report = _legacy._verify_terminal_bundle_diagnostic(**kwargs)
    if not isinstance(report, dict):
        raise RuntimeError("legacy terminal candidate diagnostic report is malformed")

    process_after = process_creation.verify(runner_root)
    _validate_process_creation_report(process_after)
    if process_after != process_before:
        raise RuntimeError("terminal-attestation process-creation authority changed during terminal verification")

    diagnostic_passed = report.get("diagnostic_passed")
    if not isinstance(diagnostic_passed, bool):
        raise RuntimeError("terminal candidate diagnostic decision is malformed")

    hardened = dict(report)
    hardened.update(
        {
            "terminal_attestation_process_creation_schema": process_before["schema"],
            "terminal_attestation_process_creation_authority_level": process_before["authority_level"],
            "terminal_attestation_process_creation_verified": True,
            "terminal_attestation_process_creation_control_flow_passed": process_before["control_flow_passed"],
            "terminal_attestation_process_creation_control_flow_finding_count": process_before["control_flow_finding_count"],
            "terminal_attestation_process_creation_attestor_count": process_before["terminal_attestor_count"],
            "terminal_attestation_process_creation_finding_count": process_before["finding_count"],
            "diagnostic_passed": diagnostic_passed and bool(process_before["passed"]),
            "passed": False,
        }
    )
    if not hardened["diagnostic_passed"]:
        hardened["containment_passed"] = False
    return hardened


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
    sandbox_user: str = "nobody",
) -> dict[str, object]:
    sandbox_user = _legacy._require_production_sandbox_user(sandbox_user)
    report = _verify_terminal_bundle_diagnostic(
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
    return _legacy._force_nonterminal_authority(report)


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
            sandbox_user=args.sandbox_user,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
