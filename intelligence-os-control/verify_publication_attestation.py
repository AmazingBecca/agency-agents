from __future__ import annotations

import argparse
import base64
import binascii
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
import publish_retained_evidence as receipt_verifier

PUBLICATION_KEYS = {
    "schema",
    "publisher_authority",
    "caller_authority",
    "verification_receipt",
}
PUBLISHER_KEYS = {"repository", "workflow_path", "workflow_ref", "workflow_sha"}
RECEIPT_RECORD_KEYS = {"name", "encoding", "bytes", "sha256", "data"}
MAX_PUBLICATION_BYTES = attestation.MAX_PUBLICATION_BYTES
MAX_RECEIPT_BYTES = attestation.MAX_RECEIPT_BYTES
MAX_RECEIPT_B64_BYTES = ((MAX_RECEIPT_BYTES + 2) // 3) * 4


class VerificationError(RuntimeError):
    pass


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _hex40(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise VerificationError(f"{label} identity is malformed")
    return value


def _hex64(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise VerificationError(f"{label} is malformed")
    return value


def _load_publication(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_PUBLICATION_BYTES:
        raise VerificationError("publication size is outside policy")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("publication is not canonical JSON") from exc
    if not isinstance(value, dict) or raw != _canonical_json(value):
        raise VerificationError("publication is not canonical JSON")
    if set(value) != PUBLICATION_KEYS:
        raise VerificationError("publication inventory is not exact")
    if value.get("schema") != attestation.PUBLICATION_SCHEMA:
        raise VerificationError("publication schema is invalid")
    return value


def _read_bounded_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VerificationError(f"unable to open publication: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > MAX_PUBLICATION_BYTES
        ):
            raise VerificationError("publication metadata is outside policy")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor, min(64 * 1024, MAX_PUBLICATION_BYTES + 1 - total)
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_PUBLICATION_BYTES:
                raise VerificationError("publication size is outside policy")
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
            raise VerificationError("publication changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_receipt_record(record: Any, expected: dict[str, str]) -> str:
    if not isinstance(record, dict) or set(record) != RECEIPT_RECORD_KEYS:
        raise VerificationError("verification receipt record inventory is not exact")
    if record.get("name") != attestation.RECEIPT_NAME:
        raise VerificationError("verification receipt name is invalid")
    if record.get("encoding") != "base64":
        raise VerificationError("verification receipt encoding is invalid")
    size = record.get("bytes")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size < 1
        or size > MAX_RECEIPT_BYTES
    ):
        raise VerificationError("verification receipt byte count is malformed")
    digest = _hex64(record.get("sha256"), "verification receipt SHA-256")
    encoded = record.get("data")
    if (
        not isinstance(encoded, str)
        or not encoded.isascii()
        or not encoded
        or len(encoded) > MAX_RECEIPT_B64_BYTES
    ):
        raise VerificationError("verification receipt base64 is malformed")
    try:
        receipt_raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError("verification receipt base64 is malformed") from exc
    if base64.b64encode(receipt_raw).decode("ascii") != encoded:
        raise VerificationError("verification receipt base64 is not canonical")
    if len(receipt_raw) != size:
        raise VerificationError("verification receipt byte count does not match data")
    if hashlib.sha256(receipt_raw).hexdigest() != digest:
        raise VerificationError("verification receipt digest does not match data")
    try:
        receipt_verifier._validate_receipt(receipt_raw, expected)
    except receipt_verifier.PublicationError as exc:
        raise VerificationError(str(exc)) from exc
    return digest


def verify_publication(
    publication_raw: bytes,
    expected_publication_sha256: str,
    expected_publisher_sha: str,
    expected: dict[str, str],
) -> str:
    expected_digest = _hex64(
        expected_publication_sha256, "expected publication SHA-256"
    )
    observed_digest = hashlib.sha256(publication_raw).hexdigest()
    if observed_digest != expected_digest:
        raise VerificationError("publication digest does not match external authority")
    publisher_sha = _hex40(expected_publisher_sha, "expected publisher SHA")
    try:
        expected = attestation.authority(**expected)
    except attestation.AttestationError as exc:
        raise VerificationError(str(exc)) from exc
    publication = _load_publication(publication_raw)
    if publication.get("caller_authority") != expected:
        raise VerificationError("caller authority does not match external authority")
    expected_publisher = {
        "repository": attestation.CONTROL_REPOSITORY,
        "workflow_path": attestation.CONTROL_WORKFLOW_PATH,
        "workflow_ref": (
            f"{attestation.CONTROL_REPOSITORY}/"
            f"{attestation.CONTROL_WORKFLOW_PATH}@{publisher_sha}"
        ),
        "workflow_sha": publisher_sha,
    }
    publisher = publication.get("publisher_authority")
    if not isinstance(publisher, dict) or set(publisher) != PUBLISHER_KEYS:
        raise VerificationError("publisher authority inventory is not exact")
    if publisher != expected_publisher:
        raise VerificationError("publisher authority does not match external authority")
    return _validate_receipt_record(publication.get("verification_receipt"), expected)


def verify_publication_file(
    publication_path: Path,
    expected_publication_sha256: str,
    expected_publisher_sha: str,
    expected: dict[str, str],
) -> str:
    raw = _read_bounded_regular(publication_path)
    return verify_publication(
        raw,
        expected_publication_sha256,
        expected_publisher_sha,
        expected,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--publication", type=Path, required=True)
    parser.add_argument("--expected-publication-sha256", required=True)
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
        receipt_sha256 = verify_publication_file(
            args.publication,
            args.expected_publication_sha256,
            args.expected_publisher_sha,
            expected,
        )
    except (OSError, VerificationError) as exc:
        print(f"publication verification error: {exc}", file=sys.stderr)
        return 2
    print(receipt_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
