from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Iterable

PUBLICATION_SCHEMA = "amazingbecca.intelligence-os-retained-evidence-publication.v1"
RECEIPT_SCHEMA = "amazingbecca.intelligence-os-wheelhouse-verification.v1"
CONTROL_REPOSITORY = "AmazingBecca/agency-agents"
CONTROL_WORKFLOW_PATH = ".github/workflows/publish-retained-evidence.yml"
RECEIPT_NAME = "intelligence-os-wheelhouse-verification.json"
OUTPUT_NAME = "intelligence-os-retained-evidence-publication.json"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_PUBLICATION_BYTES = 192 * 1024
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
DECIMAL_RE = re.compile(r"^[1-9][0-9]*$")
AUTHORITY_KEYS = {
    "repository",
    "reviewed_head",
    "reviewed_base",
    "synthetic_merge",
    "workflow_ref",
    "workflow_sha",
    "run_id",
    "run_attempt",
}
RECEIPT_KEYS = {
    "schema",
    "repository",
    "reviewed_head",
    "reviewed_base",
    "synthetic_merge",
    "workflow_authority",
    "workflow_run",
    "archive_manifest",
    "archive_canonicality",
    "members",
    "synthetic_merge_commit",
    "verifier_components",
}


class AttestationError(RuntimeError):
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
            raise AttestationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_canonical_object(raw: bytes, label: str, maximum: int) -> dict[str, Any]:
    if not raw or len(raw) > maximum:
        raise AttestationError(f"{label} size is outside policy")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationError(f"{label} is not canonical JSON") from exc
    if not isinstance(value, dict) or raw != _canonical_json(value):
        raise AttestationError(f"{label} is not canonical JSON")
    return value


def _hex40(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX40_RE.fullmatch(value):
        raise AttestationError(f"{label} identity is malformed")
    return value


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise AttestationError(f"{label} is malformed")
    return value


def _validate_workflow_ref(repository: str, value: Any) -> str:
    if not isinstance(value, str) or not value.isascii():
        raise AttestationError("workflow ref is malformed")
    path, separator, git_ref = value.rpartition("@")
    prefix = f"{repository}/.github/workflows/"
    relative = path.removeprefix(prefix)
    if (
        separator != "@"
        or not path.startswith(prefix)
        or not relative
        or relative.startswith(("/", "."))
        or "/" in relative
        or "\\" in relative
        or not relative.endswith((".yml", ".yaml"))
        or not git_ref.startswith("refs/")
        or "@" in git_ref
        or any(character.isspace() or ord(character) < 0x21 for character in value)
    ):
        raise AttestationError("workflow ref is malformed")
    return value


def authority(**values: str) -> dict[str, str]:
    if set(values) != AUTHORITY_KEYS:
        raise AttestationError("caller authority inventory is not exact")
    repository = values["repository"]
    if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
        raise AttestationError("repository identity is malformed")
    for key, label in (
        ("reviewed_head", "reviewed head"),
        ("reviewed_base", "reviewed base"),
        ("synthetic_merge", "synthetic merge"),
        ("workflow_sha", "workflow SHA"),
    ):
        _hex40(values[key], label)
    if len(
        {
            values["reviewed_head"],
            values["reviewed_base"],
            values["synthetic_merge"],
        }
    ) != 3:
        raise AttestationError("reviewed source identities must be distinct")
    _validate_workflow_ref(repository, values["workflow_ref"])
    for key, label in (("run_id", "run ID"), ("run_attempt", "run attempt")):
        value = values[key]
        if not isinstance(value, str) or not DECIMAL_RE.fullmatch(value):
            raise AttestationError(f"{label} identity is malformed")
    return dict(values)


def _publisher_authority(
    expected: dict[str, str], environment: dict[str, str]
) -> dict[str, str]:
    if environment.get("GITHUB_EVENT_NAME") != "pull_request":
        raise AttestationError("publication attestation requires a pull_request event")
    for environment_name, expected_value, label in (
        ("GITHUB_REPOSITORY", expected["repository"], "caller repository"),
        ("GITHUB_WORKFLOW_REF", expected["workflow_ref"], "caller workflow ref"),
        ("GITHUB_WORKFLOW_SHA", expected["workflow_sha"], "caller workflow SHA"),
        ("GITHUB_RUN_ID", expected["run_id"], "caller run ID"),
        ("GITHUB_RUN_ATTEMPT", expected["run_attempt"], "caller run attempt"),
    ):
        if environment.get(environment_name) != expected_value:
            raise AttestationError(f"{label} does not match attestation input")

    repository = environment.get("CONTROL_WORKFLOW_REPOSITORY")
    path = environment.get("CONTROL_WORKFLOW_FILE_PATH")
    workflow_ref = environment.get("CONTROL_WORKFLOW_REF")
    workflow_sha = environment.get("CONTROL_WORKFLOW_SHA")
    if repository != CONTROL_REPOSITORY:
        raise AttestationError("publisher control repository is not authoritative")
    if path != CONTROL_WORKFLOW_PATH:
        raise AttestationError("publisher control workflow path is not authoritative")
    _hex40(workflow_sha, "publisher control workflow SHA")
    required_ref = f"{CONTROL_REPOSITORY}/{CONTROL_WORKFLOW_PATH}@{workflow_sha}"
    if workflow_ref != required_ref:
        raise AttestationError("publisher control workflow ref is not exact")

    event_path = environment.get("GITHUB_EVENT_PATH")
    if not event_path:
        raise AttestationError("GitHub event path is missing")
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationError("GitHub event payload is unreadable") from exc
    pull_request = event.get("pull_request") if isinstance(event, dict) else None
    if not isinstance(pull_request, dict):
        raise AttestationError("GitHub event does not contain a pull request")
    observed = {
        "reviewed_head": pull_request.get("head", {}).get("sha"),
        "reviewed_base": pull_request.get("base", {}).get("sha"),
        "synthetic_merge": pull_request.get("merge_commit_sha"),
    }
    required = {
        "reviewed_head": expected["reviewed_head"],
        "reviewed_base": expected["reviewed_base"],
        "synthetic_merge": expected["synthetic_merge"],
    }
    if observed != required:
        raise AttestationError("publisher source identities do not match GitHub event")
    return {
        "repository": repository,
        "workflow_path": path,
        "workflow_ref": workflow_ref,
        "workflow_sha": workflow_sha,
    }


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AttestationError(f"unable to open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size < 1
            or before.st_size > maximum
        ):
            raise AttestationError(f"{label} metadata is outside policy")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise AttestationError(f"{label} size is outside policy")
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
            raise AttestationError(f"{label} changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_receipt(receipt_raw: bytes, expected: dict[str, str]) -> None:
    receipt = _load_canonical_object(
        receipt_raw, "verification receipt", MAX_RECEIPT_BYTES
    )
    if set(receipt) != RECEIPT_KEYS:
        raise AttestationError("verification receipt inventory is not exact")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise AttestationError("verification receipt schema is invalid")
    if receipt.get("repository") != expected["repository"]:
        raise AttestationError("verification receipt repository is invalid")
    for field in ("reviewed_head", "reviewed_base", "synthetic_merge"):
        if receipt.get(field) != expected[field]:
            raise AttestationError(f"verification receipt {field} is invalid")
    if receipt.get("workflow_authority") != {
        "ref": expected["workflow_ref"],
        "sha": expected["workflow_sha"],
    }:
        raise AttestationError("verification receipt workflow authority is invalid")
    if receipt.get("workflow_run") != {
        "id": expected["run_id"],
        "attempt": int(expected["run_attempt"]),
    }:
        raise AttestationError("verification receipt workflow run is invalid")


def _verify_published_path(parent_fd: int, leaf: str, descriptor: int, size: int) -> None:
    bound = os.fstat(descriptor)
    try:
        published = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise AttestationError(f"publication path is unavailable: {exc}") from exc
    if (
        not stat.S_ISREG(bound.st_mode)
        or not stat.S_ISREG(published.st_mode)
        or (bound.st_dev, bound.st_ino) != (published.st_dev, published.st_ino)
        or bound.st_nlink != 1
        or published.st_nlink != 1
        or stat.S_IMODE(bound.st_mode) != 0o600
        or stat.S_IMODE(published.st_mode) != 0o600
        or bound.st_size != size
        or published.st_size != size
    ):
        raise AttestationError("publication path does not reference verified descriptor")


def _materialize(publication_raw: bytes, output: Path, runner_temp: str) -> None:
    runner_path = Path(runner_temp)
    if (
        not output.is_absolute()
        or not runner_path.is_absolute()
        or output.name != OUTPUT_NAME
        or output.parent != runner_path
    ):
        raise AttestationError("publication output path is not canonical")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        parent_fd = os.open(runner_path, flags)
    except OSError as exc:
        raise AttestationError(f"unable to open publication parent: {exc}") from exc
    descriptor: int | None = None
    created = False
    published = False
    try:
        create_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(output.name, create_flags, 0o600, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise AttestationError("publication output already exists") from exc
        created = True
        view = memoryview(publication_raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AttestationError("publication write failed")
            view = view[written:]
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = bytearray()
        while len(observed) < len(publication_raw):
            chunk = os.read(descriptor, len(publication_raw) - len(observed))
            if not chunk:
                break
            observed.extend(chunk)
        if bytes(observed) != publication_raw:
            raise AttestationError("publication changed during descriptor-bound write")
        _verify_published_path(parent_fd, output.name, descriptor, len(publication_raw))
        os.fsync(parent_fd)
        published = True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if created and not published:
            try:
                os.unlink(output.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def attest(
    receipt_path: Path,
    output: Path,
    expected_receipt_sha256: str,
    expected: dict[str, str],
    environment: dict[str, str] | None = None,
) -> str:
    expected = authority(**expected)
    environment = dict(os.environ if environment is None else environment)
    publisher = _publisher_authority(expected, environment)
    receipt_raw = _read_regular(receipt_path, MAX_RECEIPT_BYTES, "verification receipt")
    expected_digest = _hex64(expected_receipt_sha256, "expected receipt SHA-256")
    observed_digest = hashlib.sha256(receipt_raw).hexdigest()
    if observed_digest != expected_digest:
        raise AttestationError("verification receipt digest does not match publisher output")
    _validate_receipt(receipt_raw, expected)
    publication = {
        "schema": PUBLICATION_SCHEMA,
        "publisher_authority": publisher,
        "caller_authority": expected,
        "verification_receipt": {
            "name": RECEIPT_NAME,
            "encoding": "base64",
            "bytes": len(receipt_raw),
            "sha256": observed_digest,
            "data": base64.b64encode(receipt_raw).decode("ascii"),
        },
    }
    publication_raw = _canonical_json(publication)
    if len(publication_raw) > MAX_PUBLICATION_BYTES:
        raise AttestationError("publication attestation exceeds policy")
    runner_temp = environment.get("RUNNER_TEMP")
    if not runner_temp:
        raise AttestationError("runner temporary path is missing")
    _materialize(publication_raw, output, runner_temp)
    return hashlib.sha256(publication_raw).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-receipt-sha256", required=True)
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
        digest = attest(
            args.receipt,
            args.output,
            args.expected_receipt_sha256,
            expected,
        )
    except (OSError, AttestationError) as exc:
        print(f"publication attestation error: {exc}", file=sys.stderr)
        return 2
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
