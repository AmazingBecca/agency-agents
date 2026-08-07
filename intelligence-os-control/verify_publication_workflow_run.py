from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

CONTROL_DIR = Path(__file__).resolve().parent
if str(CONTROL_DIR) not in sys.path:
    sys.path.insert(0, str(CONTROL_DIR))

import publication_attestation as attestation
import verify_publication_artifact_metadata as artifact_metadata_verifier

MAX_RUN_METADATA_BYTES = 256 * 1024
PULL_REF_RE = re.compile(r"^refs/pull/([1-9][0-9]*)/merge$")


class WorkflowRunMetadataVerificationError(RuntimeError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WorkflowRunMetadataVerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise WorkflowRunMetadataVerificationError(f"{label} is malformed")
    return value


def _load_run_metadata(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_RUN_METADATA_BYTES:
        raise WorkflowRunMetadataVerificationError(
            "workflow-run metadata size is outside policy"
        )
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkflowRunMetadataVerificationError(
            "workflow-run metadata is not valid JSON"
        ) from exc
    if not isinstance(value, dict):
        raise WorkflowRunMetadataVerificationError(
            "workflow-run metadata must be an object"
        )
    return value


def _expected_workflow_path(expected: dict[str, str]) -> str:
    workflow_ref = expected["workflow_ref"]
    path_with_repo, separator, git_ref = workflow_ref.rpartition("@")
    if separator != "@":
        raise WorkflowRunMetadataVerificationError("workflow ref is malformed")
    prefix = f"{expected['repository']}/"
    if not path_with_repo.startswith(prefix):
        raise WorkflowRunMetadataVerificationError(
            "workflow ref repository does not match expected authority"
        )
    if PULL_REF_RE.fullmatch(git_ref) is None:
        raise WorkflowRunMetadataVerificationError(
            "workflow run authority requires a pull-request merge ref"
        )
    return path_with_repo[len(prefix):]


def _expected_pull_number(expected: dict[str, str]) -> int:
    git_ref = expected["workflow_ref"].rpartition("@")[2]
    match = PULL_REF_RE.fullmatch(git_ref)
    if match is None:
        raise WorkflowRunMetadataVerificationError(
            "workflow run authority requires a pull-request merge ref"
        )
    return int(match.group(1))


def _repository_identity(value: Any, label: str, expected_name: str) -> int:
    if not isinstance(value, dict):
        raise WorkflowRunMetadataVerificationError(f"{label} is malformed")
    repository_id = _positive_int(value.get("id"), f"{label} ID")
    if value.get("full_name") != expected_name:
        raise WorkflowRunMetadataVerificationError(
            f"{label} does not match expected repository"
        )
    return repository_id


def _pull_request_matches(
    value: Any, expected: dict[str, str], expected_number: int
) -> bool:
    if not isinstance(value, dict) or value.get("number") != expected_number:
        return False
    head = value.get("head")
    base = value.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        return False
    if head.get("sha") != expected["reviewed_head"]:
        return False
    if base.get("sha") != expected["reviewed_base"]:
        return False
    for side in (head, base):
        repository = side.get("repo")
        if (
            repository is not None
            and (
                not isinstance(repository, dict)
                or repository.get("full_name") != expected["repository"]
            )
        ):
            return False
    return True


def validate_github_workflow_run_metadata(
    run_metadata: dict[str, Any],
    artifact_metadata: dict[str, Any],
    expected: dict[str, str],
) -> None:
    try:
        expected = attestation.authority(**expected)
    except attestation.AttestationError as exc:
        raise WorkflowRunMetadataVerificationError(str(exc)) from exc

    if not isinstance(run_metadata, dict):
        raise WorkflowRunMetadataVerificationError(
            "workflow-run metadata must be an object"
        )
    required = {
        "id",
        "head_sha",
        "event",
        "status",
        "conclusion",
        "workflow_id",
        "path",
        "run_attempt",
        "url",
        "artifacts_url",
        "workflow_url",
        "repository",
        "head_repository",
        "pull_requests",
        "head_branch",
    }
    if not required.issubset(run_metadata):
        raise WorkflowRunMetadataVerificationError(
            "workflow-run metadata is missing required authority fields"
        )

    run_id = _positive_int(run_metadata.get("id"), "workflow run ID")
    if run_id != int(expected["run_id"]):
        raise WorkflowRunMetadataVerificationError(
            "workflow run ID does not match expected authority"
        )
    attempt = _positive_int(run_metadata.get("run_attempt"), "workflow run attempt")
    if attempt != int(expected["run_attempt"]):
        raise WorkflowRunMetadataVerificationError(
            "workflow run attempt does not match expected authority"
        )
    if run_metadata.get("event") != "pull_request":
        raise WorkflowRunMetadataVerificationError(
            "workflow run event is not pull_request"
        )
    if (
        run_metadata.get("status") != "completed"
        or run_metadata.get("conclusion") != "success"
    ):
        raise WorkflowRunMetadataVerificationError(
            "workflow run is not completed successfully"
        )
    if run_metadata.get("head_sha") != expected["reviewed_head"]:
        raise WorkflowRunMetadataVerificationError(
            "workflow run head does not match reviewed head"
        )

    expected_path = _expected_workflow_path(expected)
    if run_metadata.get("path") != expected_path:
        raise WorkflowRunMetadataVerificationError(
            "workflow run path does not match expected workflow"
        )

    repository = expected["repository"]
    base_url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
    if run_metadata.get("url") != base_url:
        raise WorkflowRunMetadataVerificationError(
            "workflow run URL does not match expected authority"
        )
    if run_metadata.get("artifacts_url") != f"{base_url}/artifacts":
        raise WorkflowRunMetadataVerificationError(
            "workflow run artifacts URL does not match expected authority"
        )

    workflow_id = _positive_int(run_metadata.get("workflow_id"), "workflow ID")
    workflow_url = (
        f"https://api.github.com/repos/{repository}/actions/workflows/{workflow_id}"
    )
    if run_metadata.get("workflow_url") != workflow_url:
        raise WorkflowRunMetadataVerificationError(
            "workflow URL does not match expected authority"
        )

    repository_id = _repository_identity(
        run_metadata.get("repository"), "workflow repository", repository
    )
    head_repository_id = _repository_identity(
        run_metadata.get("head_repository"), "workflow head repository", repository
    )
    if repository_id != head_repository_id:
        raise WorkflowRunMetadataVerificationError(
            "workflow run crosses repository authority"
        )

    head_branch = run_metadata.get("head_branch")
    if not isinstance(head_branch, str) or not head_branch or not head_branch.isascii():
        raise WorkflowRunMetadataVerificationError(
            "workflow run head branch is malformed"
        )

    pull_requests = run_metadata.get("pull_requests")
    expected_number = _expected_pull_number(expected)
    if (
        not isinstance(pull_requests, list)
        or len(pull_requests) != 1
        or not _pull_request_matches(pull_requests[0], expected, expected_number)
    ):
        raise WorkflowRunMetadataVerificationError(
            "workflow run pull-request identity does not match reviewed authority"
        )

    workflow_run = (
        artifact_metadata.get("workflow_run")
        if isinstance(artifact_metadata, dict)
        else None
    )
    if not isinstance(workflow_run, dict):
        raise WorkflowRunMetadataVerificationError(
            "artifact workflow-run metadata is malformed"
        )
    if workflow_run.get("id") != run_id:
        raise WorkflowRunMetadataVerificationError(
            "artifact metadata and workflow-run metadata disagree on run ID"
        )
    if workflow_run.get("repository_id") != repository_id:
        raise WorkflowRunMetadataVerificationError(
            "artifact metadata and workflow-run metadata disagree on repository"
        )
    if workflow_run.get("head_repository_id") != head_repository_id:
        raise WorkflowRunMetadataVerificationError(
            "artifact metadata and workflow-run metadata disagree on head repository"
        )
    if workflow_run.get("head_sha") != run_metadata.get("head_sha"):
        raise WorkflowRunMetadataVerificationError(
            "artifact metadata and workflow-run metadata disagree on head"
        )
    if workflow_run.get("head_branch") != head_branch:
        raise WorkflowRunMetadataVerificationError(
            "artifact metadata and workflow-run metadata disagree on head branch"
        )


def verify_artifact_from_github_authority(
    artifact_raw: bytes,
    artifact_metadata: dict[str, Any],
    run_metadata: dict[str, Any],
    expected_publisher_sha: str,
    expected: dict[str, str],
) -> dict[str, str]:
    validate_github_workflow_run_metadata(run_metadata, artifact_metadata, expected)
    try:
        return artifact_metadata_verifier.verify_artifact_from_metadata(
            artifact_raw,
            artifact_metadata,
            expected_publisher_sha,
            expected,
        )
    except artifact_metadata_verifier.ArtifactMetadataVerificationError as exc:
        raise WorkflowRunMetadataVerificationError(str(exc)) from exc


def verify_artifact_files(
    artifact_path: Path,
    artifact_metadata_path: Path,
    run_metadata_path: Path,
    expected_publisher_sha: str,
    expected: dict[str, str],
) -> dict[str, str]:
    artifact_raw = artifact_metadata_verifier._read_bounded_regular(
        artifact_path,
        artifact_metadata_verifier.artifact_verifier.MAX_ARTIFACT_BYTES,
        "artifact",
    )
    artifact_metadata_raw = artifact_metadata_verifier._read_bounded_regular(
        artifact_metadata_path,
        artifact_metadata_verifier.MAX_METADATA_BYTES,
        "artifact metadata",
    )
    run_metadata_raw = artifact_metadata_verifier._read_bounded_regular(
        run_metadata_path,
        MAX_RUN_METADATA_BYTES,
        "workflow-run metadata",
    )
    artifact_metadata = artifact_metadata_verifier._load_metadata(artifact_metadata_raw)
    run_metadata = _load_run_metadata(run_metadata_raw)
    return verify_artifact_from_github_authority(
        artifact_raw,
        artifact_metadata,
        run_metadata,
        expected_publisher_sha,
        expected,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--artifact-metadata", type=Path, required=True)
    parser.add_argument("--workflow-run-metadata", type=Path, required=True)
    parser.add_argument("--expected-publisher-sha", required=True)
    for name in (
        "repository",
        "reviewed-head",
        "reviewed-base",
        "synthetic-merge",
        "workflow-ref",
        "workflow-sha",
        "run-id",
        "run-attempt",
    ):
        parser.add_argument(f"--{name}", required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    expected = {
        "repository": args.repository,
        "reviewed_head": args.reviewed_head,
        "reviewed_base": args.reviewed_base,
        "synthetic_merge": args.synthetic_merge,
        "workflow_ref": args.workflow_ref,
        "workflow_sha": args.workflow_sha,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
    }
    try:
        result = verify_artifact_files(
            args.artifact,
            args.artifact_metadata,
            args.workflow_run_metadata,
            args.expected_publisher_sha,
            expected,
        )
    except (OSError, WorkflowRunMetadataVerificationError) as exc:
        print(f"workflow-run authority verification error: {exc}", file=sys.stderr)
        return 2
    print(result["publication_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
