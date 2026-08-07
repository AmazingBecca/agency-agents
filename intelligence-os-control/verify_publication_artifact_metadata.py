from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Iterable

CONTROL_DIR = Path(__file__).resolve().parent
if str(CONTROL_DIR) not in sys.path:
    sys.path.insert(0, str(CONTROL_DIR))

import publication_attestation as attestation
import verify_publication_artifact as artifact_verifier

MAX_METADATA_BYTES = 64 * 1024
METADATA_REQUIRED_KEYS = {
    "id",
    "name",
    "size_in_bytes",
    "url",
    "archive_download_url",
    "expired",
    "created_at",
    "expires_at",
    "updated_at",
    "digest",
    "workflow_run",
}
METADATA_OPTIONAL_KEYS = {"node_id"}
WORKFLOW_RUN_KEYS = {
    "id",
    "repository_id",
    "head_repository_id",
    "head_branch",
    "head_sha",
}


class ArtifactMetadataVerificationError(RuntimeError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactMetadataVerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ArtifactMetadataVerificationError(f"{label} is malformed")
    return value


def _publisher_sha(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ArtifactMetadataVerificationError("expected publisher SHA is malformed")
    return value


def _read_bounded_regular(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArtifactMetadataVerificationError(f"unable to open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > maximum
        ):
            raise ArtifactMetadataVerificationError(f"{label} metadata is outside policy")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ArtifactMetadataVerificationError(f"{label} size is outside policy")
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or total != before.st_size:
            raise ArtifactMetadataVerificationError(f"{label} changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_metadata(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_METADATA_BYTES:
        raise ArtifactMetadataVerificationError("artifact metadata size is outside policy")
    try:
        metadata = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactMetadataVerificationError("artifact metadata is not valid JSON") from exc
    if not isinstance(metadata, dict):
        raise ArtifactMetadataVerificationError("artifact metadata must be an object")
    keys = set(metadata)
    if not METADATA_REQUIRED_KEYS.issubset(keys) or not keys.issubset(
        METADATA_REQUIRED_KEYS | METADATA_OPTIONAL_KEYS
    ):
        raise ArtifactMetadataVerificationError("artifact metadata inventory is not exact")
    return metadata


def _expected_artifact_name(expected: dict[str, str], publisher_sha: str) -> str:
    return (
        "intelligence-os-retained-evidence-publication-"
        f"head-{expected['reviewed_head']}-"
        f"merge-{expected['synthetic_merge']}-"
        f"publisher-{publisher_sha}-"
        f"run-{expected['run_id']}-{expected['run_attempt']}"
    )


def validate_github_artifact_metadata(
    metadata: dict[str, Any],
    artifact_raw: bytes,
    expected_publisher_sha: str,
    expected: dict[str, str],
) -> str:
    try:
        expected = attestation.authority(**expected)
    except attestation.AttestationError as exc:
        raise ArtifactMetadataVerificationError(str(exc)) from exc
    publisher_sha = _publisher_sha(expected_publisher_sha)

    keys = set(metadata) if isinstance(metadata, dict) else set()
    if not isinstance(metadata, dict) or not METADATA_REQUIRED_KEYS.issubset(keys) or not keys.issubset(
        METADATA_REQUIRED_KEYS | METADATA_OPTIONAL_KEYS
    ):
        raise ArtifactMetadataVerificationError("artifact metadata inventory is not exact")

    artifact_id = _positive_int(metadata.get("id"), "artifact ID")
    size = _positive_int(metadata.get("size_in_bytes"), "artifact byte count")
    if size > artifact_verifier.MAX_ARTIFACT_BYTES or size != len(artifact_raw):
        raise ArtifactMetadataVerificationError("artifact byte count does not match downloaded archive")
    if metadata.get("expired") is not False:
        raise ArtifactMetadataVerificationError("artifact metadata is expired or malformed")

    digest = metadata.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ArtifactMetadataVerificationError("artifact metadata digest is malformed")
    digest_hex = digest.removeprefix("sha256:")
    try:
        digest_hex = artifact_verifier._hex64(digest_hex, "artifact metadata SHA-256")
    except artifact_verifier.ArtifactVerificationError as exc:
        raise ArtifactMetadataVerificationError(str(exc)) from exc
    if hashlib.sha256(artifact_raw).hexdigest() != digest_hex:
        raise ArtifactMetadataVerificationError("downloaded archive does not match GitHub artifact digest")

    expected_name = _expected_artifact_name(expected, publisher_sha)
    if metadata.get("name") != expected_name:
        raise ArtifactMetadataVerificationError("artifact name does not match expected authority")

    repository = expected["repository"]
    expected_url = f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}"
    if metadata.get("url") != expected_url:
        raise ArtifactMetadataVerificationError("artifact metadata repository URL does not match expected authority")
    if metadata.get("archive_download_url") != f"{expected_url}/zip":
        raise ArtifactMetadataVerificationError("artifact download URL does not match expected authority")

    for field in ("created_at", "expires_at", "updated_at"):
        value = metadata.get(field)
        if not isinstance(value, str) or not value or not value.isascii():
            raise ArtifactMetadataVerificationError(f"artifact metadata {field} is malformed")
    if "node_id" in metadata:
        node_id = metadata["node_id"]
        if not isinstance(node_id, str) or not node_id or not node_id.isascii():
            raise ArtifactMetadataVerificationError("artifact metadata node_id is malformed")

    workflow_run = metadata.get("workflow_run")
    if not isinstance(workflow_run, dict) or set(workflow_run) != WORKFLOW_RUN_KEYS:
        raise ArtifactMetadataVerificationError("artifact workflow-run metadata inventory is not exact")
    run_id = _positive_int(workflow_run.get("id"), "artifact workflow run ID")
    if run_id != int(expected["run_id"]):
        raise ArtifactMetadataVerificationError("artifact workflow run does not match expected run")
    repository_id = _positive_int(workflow_run.get("repository_id"), "artifact repository ID")
    head_repository_id = _positive_int(
        workflow_run.get("head_repository_id"), "artifact head repository ID"
    )
    if repository_id != head_repository_id:
        raise ArtifactMetadataVerificationError("artifact workflow run crosses repository authority")
    if workflow_run.get("head_sha") != expected["reviewed_head"]:
        raise ArtifactMetadataVerificationError("artifact workflow head does not match reviewed head")
    head_branch = workflow_run.get("head_branch")
    if not isinstance(head_branch, str) or not head_branch or not head_branch.isascii():
        raise ArtifactMetadataVerificationError("artifact workflow head branch is malformed")

    return digest_hex


def verify_artifact_from_metadata(
    artifact_raw: bytes,
    metadata: dict[str, Any],
    expected_publisher_sha: str,
    expected: dict[str, str],
) -> dict[str, str]:
    digest = validate_github_artifact_metadata(
        metadata,
        artifact_raw,
        expected_publisher_sha,
        expected,
    )
    try:
        return artifact_verifier.verify_artifact(
            artifact_raw,
            digest,
            expected_publisher_sha,
            expected,
        )
    except artifact_verifier.ArtifactVerificationError as exc:
        raise ArtifactMetadataVerificationError(str(exc)) from exc


def verify_artifact_files(
    artifact_path: Path,
    metadata_path: Path,
    expected_publisher_sha: str,
    expected: dict[str, str],
) -> dict[str, str]:
    artifact_raw = _read_bounded_regular(
        artifact_path, artifact_verifier.MAX_ARTIFACT_BYTES, "artifact"
    )
    metadata_raw = _read_bounded_regular(
        metadata_path, MAX_METADATA_BYTES, "artifact metadata"
    )
    metadata = _load_metadata(metadata_raw)
    return verify_artifact_from_metadata(
        artifact_raw,
        metadata,
        expected_publisher_sha,
        expected,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--artifact-metadata", type=Path, required=True)
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
            args.expected_publisher_sha,
            expected,
        )
    except (OSError, ArtifactMetadataVerificationError) as exc:
        print(f"artifact metadata verification error: {exc}", file=sys.stderr)
        return 2
    print(result["publication_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
