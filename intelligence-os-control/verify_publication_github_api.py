from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

CONTROL_DIR = Path(__file__).resolve().parent
if str(CONTROL_DIR) not in sys.path:
    sys.path.insert(0, str(CONTROL_DIR))

import publication_attestation as attestation
import verify_publication_artifact as artifact_verifier
import verify_publication_artifact_metadata as artifact_metadata_verifier
import verify_publication_workflow_run as run_verifier

API_ORIGIN = "https://api.github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "amazingbecca-intelligence-os-control/1"
MAX_ARTIFACT_LIST_BYTES = 512 * 1024
MAX_TOKEN_BYTES = 4096
MAX_ARTIFACTS_PER_RUN = 100
ALLOWED_ARCHIVE_HOST_SUFFIXES = (
    ".blob.core.windows.net",
    ".githubusercontent.com",
)


class GithubApiAuthorityVerificationError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GithubApiAuthorityVerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _token(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > MAX_TOKEN_BYTES
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
    ):
        raise GithubApiAuthorityVerificationError("GitHub API token is malformed")
    return value


def _api_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {_token(token)}",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": USER_AGENT,
    }


def _anonymous_headers() -> dict[str, str]:
    return {"User-Agent": USER_AGENT}


def _open_no_redirect(request: urllib.request.Request):
    opener = urllib.request.build_opener(_NoRedirect())
    return opener.open(request, timeout=20)


def _read_bounded_response(response: Any, maximum: int, label: str) -> bytes:
    length = response.headers.get("Content-Length")
    if length is not None:
        try:
            declared = int(length)
        except ValueError as exc:
            raise GithubApiAuthorityVerificationError(
                f"{label} Content-Length is malformed"
            ) from exc
        if declared < 1 or declared > maximum:
            raise GithubApiAuthorityVerificationError(f"{label} size is outside policy")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(64 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise GithubApiAuthorityVerificationError(f"{label} size is outside policy")
    if total < 1:
        raise GithubApiAuthorityVerificationError(f"{label} is empty")
    if length is not None and total != int(length):
        raise GithubApiAuthorityVerificationError(f"{label} byte count changed in transit")
    return b"".join(chunks)


def _api_get(url: str, token: str, maximum: int, label: str) -> bytes:
    if not url.startswith(f"{API_ORIGIN}/"):
        raise GithubApiAuthorityVerificationError(f"{label} API URL is outside policy")
    request = urllib.request.Request(url, headers=_api_headers(token), method="GET")
    try:
        with _open_no_redirect(request) as response:
            if response.status != 200:
                raise GithubApiAuthorityVerificationError(
                    f"{label} API response status is {response.status}"
                )
            return _read_bounded_response(response, maximum, label)
    except urllib.error.HTTPError as exc:
        raise GithubApiAuthorityVerificationError(
            f"{label} API request failed with status {exc.code}"
        ) from exc
    except urllib.error.URLError as exc:
        raise GithubApiAuthorityVerificationError(f"{label} API request failed") from exc


def _archive_location(value: Any) -> str:
    if not isinstance(value, str) or not value.isascii():
        raise GithubApiAuthorityVerificationError("artifact redirect location is malformed")
    parsed = urllib.parse.urlsplit(value)
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or not parsed.path
        or not parsed.query
        or hostname == "api.github.com"
        or not any(hostname.endswith(suffix) for suffix in ALLOWED_ARCHIVE_HOST_SUFFIXES)
    ):
        raise GithubApiAuthorityVerificationError(
            "artifact redirect location is outside trusted HTTPS storage policy"
        )
    return value


def _download_artifact(api_url: str, token: str) -> bytes:
    if not api_url.startswith(f"{API_ORIGIN}/") or not api_url.endswith("/zip"):
        raise GithubApiAuthorityVerificationError("artifact API download URL is outside policy")
    request = urllib.request.Request(api_url, headers=_api_headers(token), method="GET")
    try:
        response = _open_no_redirect(request)
    except urllib.error.HTTPError as exc:
        if exc.code not in (301, 302, 303, 307, 308):
            raise GithubApiAuthorityVerificationError(
                f"artifact API request failed with status {exc.code}"
            ) from exc
        location = _archive_location(exc.headers.get("Location"))
    except urllib.error.URLError as exc:
        raise GithubApiAuthorityVerificationError("artifact API request failed") from exc
    else:
        with response:
            if response.status == 200:
                return _read_bounded_response(
                    response, artifact_verifier.MAX_ARTIFACT_BYTES, "artifact archive"
                )
            raise GithubApiAuthorityVerificationError(
                f"artifact API response status is {response.status}"
            )

    anonymous = urllib.request.Request(
        location,
        headers=_anonymous_headers(),
        method="GET",
    )
    try:
        with _open_no_redirect(anonymous) as response:
            if response.status != 200:
                raise GithubApiAuthorityVerificationError(
                    f"artifact storage response status is {response.status}"
                )
            return _read_bounded_response(
                response, artifact_verifier.MAX_ARTIFACT_BYTES, "artifact archive"
            )
    except urllib.error.HTTPError as exc:
        raise GithubApiAuthorityVerificationError(
            f"artifact storage request failed with status {exc.code}"
        ) from exc
    except urllib.error.URLError as exc:
        raise GithubApiAuthorityVerificationError("artifact storage request failed") from exc


def _load_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GithubApiAuthorityVerificationError(f"{label} is not valid JSON") from exc


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GithubApiAuthorityVerificationError(f"{label} is malformed")
    return value


def _select_artifact(
    listing: Any,
    expected_name: str,
    repository: str,
) -> dict[str, Any]:
    if not isinstance(listing, dict):
        raise GithubApiAuthorityVerificationError("artifact listing must be an object")
    total = _positive_int(listing.get("total_count"), "artifact listing total_count")
    artifacts = listing.get("artifacts")
    if not isinstance(artifacts, list):
        raise GithubApiAuthorityVerificationError("artifact listing artifacts is malformed")
    if total != len(artifacts) or total > MAX_ARTIFACTS_PER_RUN:
        raise GithubApiAuthorityVerificationError(
            "artifact listing is incomplete or exceeds one-page authority policy"
        )
    matches = [item for item in artifacts if isinstance(item, dict) and item.get("name") == expected_name]
    if len(matches) != 1:
        raise GithubApiAuthorityVerificationError(
            "exact retained-evidence artifact is missing or ambiguous"
        )
    metadata = matches[0]
    keys = set(metadata)
    if (
        not artifact_metadata_verifier.METADATA_REQUIRED_KEYS.issubset(keys)
        or not keys.issubset(
            artifact_metadata_verifier.METADATA_REQUIRED_KEYS
            | artifact_metadata_verifier.METADATA_OPTIONAL_KEYS
        )
    ):
        raise GithubApiAuthorityVerificationError("artifact metadata inventory is not exact")
    artifact_id = _positive_int(metadata.get("id"), "artifact ID")
    expected_url = f"{API_ORIGIN}/repos/{repository}/actions/artifacts/{artifact_id}"
    if metadata.get("url") != expected_url or metadata.get("archive_download_url") != f"{expected_url}/zip":
        raise GithubApiAuthorityVerificationError("artifact metadata URL does not match exact repository authority")
    if metadata.get("expired") is not False:
        raise GithubApiAuthorityVerificationError("artifact metadata is expired or malformed")
    size = _positive_int(metadata.get("size_in_bytes"), "artifact byte count")
    if size > artifact_verifier.MAX_ARTIFACT_BYTES:
        raise GithubApiAuthorityVerificationError("artifact byte count exceeds policy")
    digest = metadata.get("digest")
    if (
        not isinstance(digest, str)
        or len(digest) != len("sha256:") + 64
        or not digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in digest[7:])
    ):
        raise GithubApiAuthorityVerificationError("artifact metadata digest is malformed")
    return metadata


def verify_from_github_api(
    token: str,
    expected_publisher_sha: str,
    expected: dict[str, str],
) -> dict[str, str]:
    try:
        expected = attestation.authority(**expected)
        publisher_sha = artifact_metadata_verifier._publisher_sha(expected_publisher_sha)
    except (attestation.AttestationError, artifact_metadata_verifier.ArtifactMetadataVerificationError) as exc:
        raise GithubApiAuthorityVerificationError(str(exc)) from exc
    token = _token(token)

    repository = expected["repository"]
    run_id = int(expected["run_id"])
    run_url = f"{API_ORIGIN}/repos/{repository}/actions/runs/{run_id}"
    run_raw = _api_get(
        run_url,
        token,
        run_verifier.MAX_RUN_METADATA_BYTES,
        "workflow-run metadata",
    )
    try:
        run_metadata = run_verifier._load_run_metadata(run_raw)
    except run_verifier.WorkflowRunMetadataVerificationError as exc:
        raise GithubApiAuthorityVerificationError(str(exc)) from exc

    list_url = f"{run_url}/artifacts?per_page={MAX_ARTIFACTS_PER_RUN}"
    listing = _load_json(
        _api_get(list_url, token, MAX_ARTIFACT_LIST_BYTES, "artifact listing"),
        "artifact listing",
    )
    expected_name = artifact_metadata_verifier._expected_artifact_name(expected, publisher_sha)
    artifact_metadata = _select_artifact(listing, expected_name, repository)

    try:
        run_verifier.validate_github_workflow_run_metadata(
            run_metadata,
            artifact_metadata,
            expected,
        )
    except run_verifier.WorkflowRunMetadataVerificationError as exc:
        raise GithubApiAuthorityVerificationError(str(exc)) from exc

    artifact_id = int(artifact_metadata["id"])
    artifact_api_url = f"{API_ORIGIN}/repos/{repository}/actions/artifacts/{artifact_id}/zip"
    artifact_raw = _download_artifact(artifact_api_url, token)
    try:
        return run_verifier.verify_artifact_from_github_authority(
            artifact_raw,
            artifact_metadata,
            run_metadata,
            publisher_sha,
            expected,
        )
    except run_verifier.WorkflowRunMetadataVerificationError as exc:
        raise GithubApiAuthorityVerificationError(str(exc)) from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
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
        token = os.environ.get("GITHUB_TOKEN", "")
        result = verify_from_github_api(token, args.expected_publisher_sha, expected)
    except GithubApiAuthorityVerificationError as exc:
        print(f"GitHub API authority verification error: {exc}", file=sys.stderr)
        return 2
    print(result["publication_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
