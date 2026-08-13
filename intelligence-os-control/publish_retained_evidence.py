from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Iterable

TRANSFER_SCHEMA = "amazingbecca.intelligence-os-verification-transfer.v1"
RECEIPT_SCHEMA = "amazingbecca.intelligence-os-wheelhouse-verification.v1"
WHEELHOUSE_SCHEMA = "amazingbecca.intelligence-os-wheelhouse.v4"
MERGE_COMMIT_SCHEMA = "amazingbecca.intelligence-os-synthetic-merge-commit.v1"
COMPONENT_SCHEMA = "amazingbecca.intelligence-os-verifier-components.v1"
CONTROL_REPOSITORY = "AmazingBecca/agency-agents"
CONTROL_WORKFLOW_PATH = ".github/workflows/publish-retained-evidence.yml"
MANIFEST_NAME = "WHEELHOUSE_MANIFEST.json"
SOURCE_IDENTITY_NAME = "intelligence-os-source-identity.json"
WHEELHOUSE_ARCHIVE_NAME = "intelligence-os-wheelhouse.tar"
BINDING_NAME = "intelligence-os-wheelhouse-binding.json"
OUTPUT_NAME = "intelligence-os-wheelhouse-verification.json"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_ENVELOPE_BYTES = 96 * 1024
MAX_TRANSPORT_B64_BYTES = 132 * 1024
MAX_JSON_MEMBER_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 600 * 1024 * 1024
MAX_COMPONENT_BYTES = 4 * 1024 * 1024
MAX_COMMIT_BYTES = 4 * 1024 * 1024
MAX_WHEELS = 255
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
DECIMAL_RE = re.compile(r"^[1-9][0-9]*$")
WHEEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+!-]*\.whl$")
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
CANONICALITY_KEYS = {
    "schema",
    "archive_bytes",
    "archive_sha256",
    "manifest_bytes",
    "manifest_sha256",
    "execution",
    "wheel_count",
    "wheel_names",
}
EVIDENCE_MEMBERS = {
    SOURCE_IDENTITY_NAME,
    WHEELHOUSE_ARCHIVE_NAME,
    BINDING_NAME,
}
COMPONENT_NAMES = {
    "retained_wheelhouse_evidence.py",
    "retained_wheelhouse_evidence_core.py",
    "archive_canonicality.py",
}


class PublicationError(RuntimeError):
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
            raise PublicationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_canonical_object(raw: bytes, label: str, maximum: int) -> dict[str, Any]:
    if not raw or len(raw) > maximum:
        raise PublicationError(f"{label} size is outside policy")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicationError(f"{label} is not canonical JSON") from exc
    if not isinstance(value, dict) or raw != _canonical_json(value):
        raise PublicationError(f"{label} is not canonical JSON")
    return value


def _hex40(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX40_RE.fullmatch(value):
        raise PublicationError(f"{label} identity is malformed")
    return value


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise PublicationError(f"{label} is malformed")
    return value


def _positive_int(value: Any, label: str, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > maximum
    ):
        raise PublicationError(f"{label} is malformed")
    return value


def _validate_workflow_ref(repository: str, value: Any) -> str:
    if not isinstance(value, str) or not value.isascii():
        raise PublicationError("workflow ref is malformed")
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
        raise PublicationError("workflow ref is malformed")
    return value


def authority(**values: str) -> dict[str, str]:
    if set(values) != AUTHORITY_KEYS:
        raise PublicationError("publisher authority inventory is not exact")
    repository = values["repository"]
    if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
        raise PublicationError("repository identity is malformed")
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
        raise PublicationError("reviewed source identities must be distinct")
    _validate_workflow_ref(repository, values["workflow_ref"])
    for key, label in (("run_id", "run ID"), ("run_attempt", "run attempt")):
        value = values[key]
        if not isinstance(value, str) or not DECIMAL_RE.fullmatch(value):
            raise PublicationError(f"{label} identity is malformed")
    return dict(values)


def _event_authority(expected: dict[str, str], environment: dict[str, str]) -> None:
    if environment.get("GITHUB_EVENT_NAME") != "pull_request":
        raise PublicationError("publisher requires a pull_request event")
    if environment.get("GITHUB_REPOSITORY") != expected["repository"]:
        raise PublicationError("caller repository does not match publisher input")
    if environment.get("GITHUB_WORKFLOW_REF") != expected["workflow_ref"]:
        raise PublicationError("caller workflow ref does not match publisher input")
    if environment.get("GITHUB_WORKFLOW_SHA") != expected["workflow_sha"]:
        raise PublicationError("caller workflow SHA does not match publisher input")
    if environment.get("GITHUB_RUN_ID") != expected["run_id"]:
        raise PublicationError("caller run ID does not match publisher input")
    if environment.get("GITHUB_RUN_ATTEMPT") != expected["run_attempt"]:
        raise PublicationError("caller run attempt does not match publisher input")

    control_repository = environment.get("CONTROL_WORKFLOW_REPOSITORY")
    control_path = environment.get("CONTROL_WORKFLOW_FILE_PATH")
    control_sha = environment.get("CONTROL_WORKFLOW_SHA")
    if control_repository != CONTROL_REPOSITORY:
        raise PublicationError("publisher control repository is not authoritative")
    if control_path != CONTROL_WORKFLOW_PATH:
        raise PublicationError("publisher control workflow path is not authoritative")
    _hex40(control_sha, "publisher control workflow SHA")

    event_path = environment.get("GITHUB_EVENT_PATH")
    if not event_path:
        raise PublicationError("GitHub event path is missing")
    try:
        raw = Path(event_path).read_bytes()
        event = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicationError("GitHub event payload is unreadable") from exc
    pull_request = event.get("pull_request") if isinstance(event, dict) else None
    if not isinstance(pull_request, dict):
        raise PublicationError("GitHub event does not contain a pull request")
    observed = {
        "reviewed_head": pull_request.get("head", {}).get("sha"),
        "reviewed_base": pull_request.get("base", {}).get("sha"),
        "synthetic_merge": pull_request.get("merge_commit_sha"),
    }
    if observed != {
        "reviewed_head": expected["reviewed_head"],
        "reviewed_base": expected["reviewed_base"],
        "synthetic_merge": expected["synthetic_merge"],
    }:
        raise PublicationError("publisher source identities do not match GitHub event")


def _validate_execution(value: Any, expected: dict[str, str], label: str) -> dict[str, str]:
    expected_execution = {
        "repository": expected["repository"],
        "workflow_ref": expected["workflow_ref"],
        "workflow_sha": expected["workflow_sha"],
        "run_id": expected["run_id"],
        "run_attempt": expected["run_attempt"],
        "head_sha": expected["reviewed_head"],
        "reviewed_base": expected["reviewed_base"],
        "synthetic_merge": expected["synthetic_merge"],
    }
    if value != expected_execution:
        raise PublicationError(f"{label} execution authority is invalid")
    return expected_execution


def _digest_record(value: Any, label: str, maximum: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"bytes", "sha256"}:
        raise PublicationError(f"{label} inventory is not exact")
    _positive_int(value.get("bytes"), f"{label} byte count", maximum)
    _hex64(value.get("sha256"), f"{label} SHA-256")
    return value


def _validate_archive_summary(receipt: dict[str, Any], expected: dict[str, str]) -> None:
    manifest = receipt.get("archive_manifest")
    if not isinstance(manifest, dict) or set(manifest) != {
        "name",
        "bytes",
        "sha256",
        "execution",
    }:
        raise PublicationError("archive manifest inventory is not exact")
    if manifest.get("name") != MANIFEST_NAME:
        raise PublicationError("archive manifest name is invalid")
    _positive_int(manifest.get("bytes"), "archive manifest byte count", MAX_MANIFEST_BYTES)
    _hex64(manifest.get("sha256"), "archive manifest SHA-256")
    execution = _validate_execution(manifest.get("execution"), expected, "archive manifest")

    canonicality = receipt.get("archive_canonicality")
    if not isinstance(canonicality, dict) or set(canonicality) != CANONICALITY_KEYS:
        raise PublicationError("archive canonicality inventory is not exact")
    if canonicality.get("schema") != WHEELHOUSE_SCHEMA:
        raise PublicationError("archive canonicality schema is invalid")
    _positive_int(canonicality.get("archive_bytes"), "archive byte count", MAX_ARCHIVE_BYTES)
    _hex64(canonicality.get("archive_sha256"), "archive SHA-256")
    _positive_int(canonicality.get("manifest_bytes"), "manifest byte count", MAX_MANIFEST_BYTES)
    _hex64(canonicality.get("manifest_sha256"), "manifest SHA-256")
    if canonicality.get("execution") != execution:
        raise PublicationError("archive canonicality execution authority is invalid")
    wheel_count = _positive_int(
        canonicality.get("wheel_count"), "archive wheel count", MAX_WHEELS
    )
    wheel_names = canonicality.get("wheel_names")
    if (
        not isinstance(wheel_names, list)
        or len(wheel_names) != wheel_count
        or not all(
            isinstance(name, str)
            and name.isascii()
            and WHEEL_NAME_RE.fullmatch(name)
            for name in wheel_names
        )
        or wheel_names != sorted(wheel_names)
        or len({name.casefold() for name in wheel_names}) != len(wheel_names)
    ):
        raise PublicationError("archive wheel inventory is malformed")
    if (
        manifest["bytes"] != canonicality["manifest_bytes"]
        or manifest["sha256"] != canonicality["manifest_sha256"]
    ):
        raise PublicationError("archive manifest and canonicality summary disagree")

    members = receipt.get("members")
    if not isinstance(members, dict) or set(members) != EVIDENCE_MEMBERS:
        raise PublicationError("retained evidence member inventory is not exact")
    _digest_record(members[SOURCE_IDENTITY_NAME], "source identity member", MAX_JSON_MEMBER_BYTES)
    archive_record = _digest_record(
        members[WHEELHOUSE_ARCHIVE_NAME], "wheelhouse archive member", MAX_ARCHIVE_BYTES
    )
    _digest_record(members[BINDING_NAME], "wheelhouse binding member", MAX_JSON_MEMBER_BYTES)
    if (
        archive_record["bytes"] != canonicality["archive_bytes"]
        or archive_record["sha256"] != canonicality["archive_sha256"]
    ):
        raise PublicationError("archive member and canonicality summary disagree")


def _validate_merge(value: Any, expected: dict[str, str]) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "name",
        "bytes",
        "sha256",
        "git_commit",
        "parents",
    }:
        raise PublicationError("synthetic merge receipt inventory is not exact")
    if value.get("schema") != MERGE_COMMIT_SCHEMA:
        raise PublicationError("synthetic merge receipt schema is invalid")
    if value.get("name") != "intelligence-os-synthetic-merge.commit":
        raise PublicationError("synthetic merge receipt name is invalid")
    _positive_int(value.get("bytes"), "synthetic merge byte count", MAX_COMMIT_BYTES)
    _hex64(value.get("sha256"), "synthetic merge SHA-256")
    if value.get("git_commit") != expected["synthetic_merge"]:
        raise PublicationError("synthetic merge identity is invalid")
    if value.get("parents") != [expected["reviewed_base"], expected["reviewed_head"]]:
        raise PublicationError("synthetic merge ordered parents are invalid")


def _validate_components(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"schema", "components"}:
        raise PublicationError("verifier component receipt inventory is not exact")
    if value.get("schema") != COMPONENT_SCHEMA:
        raise PublicationError("verifier component receipt schema is invalid")
    components = value.get("components")
    if not isinstance(components, dict) or set(components) != COMPONENT_NAMES:
        raise PublicationError("verifier component inventory is not exact")
    for name in sorted(COMPONENT_NAMES):
        record = components[name]
        if not isinstance(record, dict) or set(record) != {
            "name",
            "bytes",
            "sha256",
            "git_blob",
        }:
            raise PublicationError(f"verifier component record is malformed: {name}")
        if record.get("name") != name:
            raise PublicationError(f"verifier component name is invalid: {name}")
        _positive_int(record.get("bytes"), f"component byte count: {name}", MAX_COMPONENT_BYTES)
        _hex64(record.get("sha256"), f"component SHA-256: {name}")
        _hex40(record.get("git_blob"), f"component Git blob: {name}")


def _validate_receipt(receipt_raw: bytes, expected: dict[str, str]) -> dict[str, Any]:
    receipt = _load_canonical_object(receipt_raw, "verification receipt", MAX_RECEIPT_BYTES)
    if set(receipt) != RECEIPT_KEYS:
        raise PublicationError("verification receipt inventory is not exact")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise PublicationError("verification receipt schema is invalid")
    if receipt.get("repository") != expected["repository"]:
        raise PublicationError("verification receipt repository is invalid")
    for field in ("reviewed_head", "reviewed_base", "synthetic_merge"):
        if receipt.get(field) != expected[field]:
            raise PublicationError(f"verification receipt {field} is invalid")
    if receipt.get("workflow_authority") != {
        "ref": expected["workflow_ref"],
        "sha": expected["workflow_sha"],
    }:
        raise PublicationError("verification receipt workflow authority is invalid")
    if receipt.get("workflow_run") != {
        "id": expected["run_id"],
        "attempt": int(expected["run_attempt"]),
    }:
        raise PublicationError("verification receipt workflow run is invalid")
    _validate_merge(receipt.get("synthetic_merge_commit"), expected)
    _validate_archive_summary(receipt, expected)
    _validate_components(receipt.get("verifier_components"))
    return receipt


def decode_transport(envelope_b64: str, expected: dict[str, str]) -> bytes:
    if (
        not isinstance(envelope_b64, str)
        or not envelope_b64
        or len(envelope_b64) > MAX_TRANSPORT_B64_BYTES
        or not envelope_b64.isascii()
    ):
        raise PublicationError("transfer transport is outside policy")
    try:
        envelope_raw = base64.b64decode(envelope_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PublicationError("transfer transport base64 is malformed") from exc
    if base64.b64encode(envelope_raw).decode("ascii") != envelope_b64:
        raise PublicationError("transfer transport base64 is not canonical")
    envelope = _load_canonical_object(
        envelope_raw, "verification transfer envelope", MAX_ENVELOPE_BYTES
    )
    if set(envelope) != {"schema", "authority", "receipt"}:
        raise PublicationError("verification transfer inventory is not exact")
    if envelope.get("schema") != TRANSFER_SCHEMA:
        raise PublicationError("verification transfer schema is invalid")
    observed_authority = envelope.get("authority")
    if not isinstance(observed_authority, dict) or set(observed_authority) != AUTHORITY_KEYS:
        raise PublicationError("verification transfer authority inventory is not exact")
    if authority(**observed_authority) != expected:
        raise PublicationError("verification transfer authority does not match publisher")
    record = envelope.get("receipt")
    if not isinstance(record, dict) or set(record) != {
        "encoding",
        "bytes",
        "sha256",
        "data",
    }:
        raise PublicationError("verification transfer receipt record is malformed")
    if record.get("encoding") != "base64":
        raise PublicationError("verification transfer receipt encoding is invalid")
    if (
        not isinstance(record.get("bytes"), int)
        or isinstance(record["bytes"], bool)
        or not (0 < record["bytes"] <= MAX_RECEIPT_BYTES)
        or not isinstance(record.get("data"), str)
        or not record["data"].isascii()
    ):
        raise PublicationError("verification transfer receipt identity is malformed")
    _hex64(record.get("sha256"), "verification transfer receipt SHA-256")
    try:
        receipt_raw = base64.b64decode(record["data"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PublicationError("verification transfer receipt base64 is malformed") from exc
    if base64.b64encode(receipt_raw).decode("ascii") != record["data"]:
        raise PublicationError("verification transfer receipt base64 is not canonical")
    if len(receipt_raw) != record["bytes"]:
        raise PublicationError("verification transfer receipt length mismatch")
    if hashlib.sha256(receipt_raw).hexdigest() != record["sha256"]:
        raise PublicationError("verification transfer receipt digest mismatch")
    _validate_receipt(receipt_raw, expected)
    return receipt_raw


def _verify_published_path(parent_fd: int, leaf: str, descriptor: int, size: int) -> None:
    bound = os.fstat(descriptor)
    try:
        published = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise PublicationError(f"published receipt path is unavailable: {exc}") from exc
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
        raise PublicationError("published receipt path does not reference verified descriptor")


def materialize(receipt_raw: bytes, output: Path) -> str:
    if not output.is_absolute() or output.name != OUTPUT_NAME:
        raise PublicationError("publisher output path is not canonical")
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp or output.parent.resolve() != Path(runner_temp).resolve():
        raise PublicationError("publisher output is outside runner temporary storage")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_fd = os.open(output.parent, flags)
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
            raise PublicationError("publisher output already exists") from exc
        created = True
        view = memoryview(receipt_raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PublicationError("publisher receipt write failed")
            view = view[written:]
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = bytearray()
        while len(observed) < len(receipt_raw):
            chunk = os.read(descriptor, len(receipt_raw) - len(observed))
            if not chunk:
                break
            observed.extend(chunk)
        if bytes(observed) != receipt_raw:
            raise PublicationError("publisher receipt changed during descriptor-bound write")
        _verify_published_path(parent_fd, output.name, descriptor, len(receipt_raw))
        os.fsync(parent_fd)
        published = True
        return hashlib.sha256(receipt_raw).hexdigest()
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


def publish(
    envelope_b64: str,
    output: Path,
    expected: dict[str, str],
    environment: dict[str, str] | None = None,
) -> str:
    expected = authority(**expected)
    environment = dict(os.environ if environment is None else environment)
    _event_authority(expected, environment)
    receipt_raw = decode_transport(envelope_b64, expected)
    return materialize(receipt_raw, output)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
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
    envelope_b64 = os.environ.get("TRANSFER_ENVELOPE_B64", "")
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
        digest = publish(envelope_b64, args.output, expected)
    except (OSError, PublicationError) as exc:
        print(f"retained evidence publication error: {exc}", file=sys.stderr)
        return 2
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
