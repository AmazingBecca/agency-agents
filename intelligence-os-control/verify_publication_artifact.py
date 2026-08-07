from __future__ import annotations

import argparse
import hashlib
import io
import os
import stat
import sys
import zipfile
from pathlib import Path
from typing import Iterable

CONTROL_DIR = Path(__file__).resolve().parent
if str(CONTROL_DIR) not in sys.path:
    sys.path.insert(0, str(CONTROL_DIR))

import publication_attestation as attestation
import verify_publication_attestation as publication_verifier

MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_MEMBER_BYTES = attestation.MAX_PUBLICATION_BYTES
ARTIFACT_MEMBER_NAME = attestation.OUTPUT_NAME


class ArtifactVerificationError(RuntimeError):
    pass


def _hex64(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ArtifactVerificationError(f"{label} is malformed")
    return value


def _read_bounded_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArtifactVerificationError(f"unable to open artifact: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > MAX_ARTIFACT_BYTES
        ):
            raise ArtifactVerificationError("artifact metadata is outside policy")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_ARTIFACT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise ArtifactVerificationError("artifact size is outside policy")
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
            raise ArtifactVerificationError("artifact changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _publication_member(archive_raw: bytes) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(archive_raw), mode="r") as archive:
            members = archive.infolist()
            if len(members) != 1:
                raise ArtifactVerificationError("artifact member inventory is not exact")
            member = members[0]
            if (
                member.filename != ARTIFACT_MEMBER_NAME
                or member.is_dir()
                or member.flag_bits & 0x1
                or member.file_size < 1
                or member.file_size > MAX_MEMBER_BYTES
                or member.compress_size < 1
                or member.compress_size > MAX_ARTIFACT_BYTES
            ):
                raise ArtifactVerificationError("artifact publication member is outside policy")
            try:
                raw = archive.read(member)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise ArtifactVerificationError("artifact publication member is unreadable") from exc
    except zipfile.BadZipFile as exc:
        raise ArtifactVerificationError("artifact is not a valid ZIP archive") from exc
    if len(raw) != member.file_size:
        raise ArtifactVerificationError("artifact publication member size is inconsistent")
    return raw


def verify_artifact(
    artifact_raw: bytes,
    expected_artifact_sha256: str,
    expected_publisher_sha: str,
    expected: dict[str, str],
) -> dict[str, str]:
    expected_archive_digest = _hex64(
        expected_artifact_sha256, "expected artifact SHA-256"
    )
    observed_archive_digest = hashlib.sha256(artifact_raw).hexdigest()
    if observed_archive_digest != expected_archive_digest:
        raise ArtifactVerificationError("artifact digest does not match GitHub authority")
    publication_raw = _publication_member(artifact_raw)
    publication_sha256 = hashlib.sha256(publication_raw).hexdigest()
    try:
        receipt_sha256 = publication_verifier.verify_publication(
            publication_raw,
            publication_sha256,
            expected_publisher_sha,
            expected,
        )
    except publication_verifier.VerificationError as exc:
        raise ArtifactVerificationError(str(exc)) from exc
    return {
        "artifact_sha256": observed_archive_digest,
        "publication_sha256": publication_sha256,
        "receipt_sha256": receipt_sha256,
    }


def verify_artifact_file(
    artifact_path: Path,
    expected_artifact_sha256: str,
    expected_publisher_sha: str,
    expected: dict[str, str],
) -> dict[str, str]:
    raw = _read_bounded_regular(artifact_path)
    return verify_artifact(
        raw,
        expected_artifact_sha256,
        expected_publisher_sha,
        expected,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--expected-artifact-sha256", required=True)
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
        result = verify_artifact_file(
            args.artifact,
            args.expected_artifact_sha256,
            args.expected_publisher_sha,
            expected,
        )
    except (OSError, ArtifactVerificationError) as exc:
        print(f"artifact verification error: {exc}", file=sys.stderr)
        return 2
    print(result["publication_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
