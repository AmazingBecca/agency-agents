from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Iterable

SCHEMA = "amazingbecca-tasklet-ephemeral-runner/v1"
REQUIRED_LABELS = ("linux", "oracle", "codex", "zo")
MAX_ARCHIVE_BYTES = 600 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
ALLOWED_DOWNLOAD_HOSTS = (
    "github.com",
    "githubusercontent.com",
)

class BootstrapError(RuntimeError):
    pass


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _validate_repo(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise BootstrapError("repo must be owner/name")
    owner, repo = value.split("/", 1)
    if owner in {".", ".."} or repo in {".", ".."} or owner.startswith("-") or repo.startswith("-"):
        raise BootstrapError("repo contains unsafe path-like component")
    return value


def _validate_version(value: str) -> str:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise BootstrapError("runner version must be N.N.N")
    return value


def _validate_sha256(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise BootstrapError("runner sha256 must be 64 lowercase hex")
    return value


def _validate_runner_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
        raise BootstrapError("runner name contains unsafe characters")
    return value


def _download_url(version: str) -> str:
    return (
        "https://github.com/actions/runner/releases/download/"
        f"v{version}/actions-runner-linux-x64-{version}.tar.gz"
    )


def _host_allowed(host: str | None) -> bool:
    if not host:
        return False
    host = host.lower().rstrip(".")
    return host == "github.com" or any(host == suffix or host.endswith("." + suffix) for suffix in ALLOWED_DOWNLOAD_HOSTS[1:])


class _PinnedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or not _host_allowed(parsed.hostname):
            raise BootstrapError(f"runner download redirect refused: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(),
        _PinnedRedirect(),
    )


def _download_and_hash(url: str, destination: Path) -> tuple[int, str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not _host_allowed(parsed.hostname):
        raise BootstrapError("runner download must use an allowlisted HTTPS GitHub host")
    digest = hashlib.sha256()
    total = 0
    request = urllib.request.Request(url, headers={"User-Agent": "AmazingBecca-Runner-Bootstrap/1"})
    with _opener().open(request, timeout=30) as response, destination.open("xb") as out:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise BootstrapError("runner archive exceeds maximum size")
            digest.update(chunk)
            out.write(chunk)
        out.flush()
        os.fsync(out.fileno())
    if total == 0:
        raise BootstrapError("runner archive is empty")
    return total, digest.hexdigest()


def _safe_member_name(name: str) -> PurePosixPath:
    if "\\" in name or "\x00" in name:
        raise BootstrapError(f"unsafe archive member name: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise BootstrapError(f"unsafe archive member path: {name!r}")
    return path


def _safe_extract(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        if not members:
            raise BootstrapError("runner archive has no members")
        extracted_bytes = sum(member.size for member in members if member.isfile())
        if extracted_bytes < 1 or extracted_bytes > MAX_EXTRACTED_BYTES:
            raise BootstrapError("runner archive extracted size is outside policy")
        for member in members:
            _safe_member_name(member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise BootstrapError(f"unsafe archive member type: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise BootstrapError(f"unsupported archive member type: {member.name}")
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            resolved_parent = target.parent.resolve()
            if destination.resolve() != resolved_parent and destination.resolve() not in resolved_parent.parents:
                raise BootstrapError(f"archive escapes destination: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tf.extractfile(member)
            if source is None:
                raise BootstrapError(f"archive file has no content: {member.name}")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(target, flags, member.mode & 0o777)
            try:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    os.write(fd, chunk)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(target, member.mode & 0o777)


def _require_regular_executable(path: Path, label: str) -> None:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise BootstrapError(f"{label} must be a regular non-symlink file")
    if not (st.st_mode & stat.S_IXUSR):
        os.chmod(path, st.st_mode | stat.S_IXUSR)


def _child_env(*, home: Path, tmpdir: Path) -> dict[str, str]:
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if os.geteuid() == 0:
        env["RUNNER_ALLOW_RUNASROOT"] = "1"
    return env


def _run_checked(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=True,
    )


def bootstrap(args: argparse.Namespace) -> dict[str, object]:
    repo = _validate_repo(args.repo)
    version = _validate_version(args.runner_version)
    expected_sha = _validate_sha256(args.runner_sha256)
    name = _validate_runner_name(args.runner_name)
    token = os.environ.pop("GITHUB_RUNNER_REGISTRATION_TOKEN", "")
    if not token or len(token) < 20 or any(ch.isspace() for ch in token):
        raise BootstrapError("GITHUB_RUNNER_REGISTRATION_TOKEN is required")
    if os.environ.get("TASKLET_ZERO_SPEND_ONLY") != "1":
        raise BootstrapError("TASKLET_ZERO_SPEND_ONLY=1 is required")

    root = Path(args.root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    started = time.time()
    tmp = Path(tempfile.mkdtemp(prefix="ab-ephemeral-runner-", dir=root))
    os.chmod(tmp, 0o700)
    archive = tmp / "runner.tar.gz"
    install = tmp / "runner"
    install.mkdir(mode=0o700)
    receipt: dict[str, object] = {
        "schema": SCHEMA,
        "repository": repo,
        "runner_name": name,
        "runner_version": version,
        "labels": list(REQUIRED_LABELS),
        "ephemeral": True,
        "zero_spend_only": True,
        "archive_sha256": expected_sha,
        "run_returncode": None,
        "status": "prepared",
    }
    try:
        size, observed_sha = _download_and_hash(_download_url(version), archive)
        if observed_sha != expected_sha:
            raise BootstrapError(f"runner archive sha256 mismatch: expected={expected_sha} observed={observed_sha}")
        receipt["archive_size"] = size
        _safe_extract(archive, install)
        config = install / "config.sh"
        run = install / "run.sh"
        _require_regular_executable(config, "config.sh")
        _require_regular_executable(run, "run.sh")
        isolated_home = tmp / "home"
        isolated_tmp = tmp / "tmp"
        isolated_home.mkdir(mode=0o700)
        isolated_tmp.mkdir(mode=0o700)
        env = _child_env(home=isolated_home, tmpdir=isolated_tmp)
        config_result = _run_checked(
            [
                str(config),
                "--unattended",
                "--ephemeral",
                "--disableupdate",
                "--url", f"https://github.com/{repo}",
                "--token", token,
                "--name", name,
                "--labels", ",".join(REQUIRED_LABELS),
                "--work", "_work",
            ],
            cwd=install,
            env=env,
            timeout=120,
        )
        receipt["configuration_output_sha256"] = hashlib.sha256(config_result.stdout.encode("utf-8")).hexdigest()
        receipt["status"] = "configured"
        try:
            run_result = subprocess.run(
                [str(run)],
                cwd=install,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=args.max_seconds,
                check=False,
            )
            receipt["run_returncode"] = run_result.returncode
            receipt["runner_output_sha256"] = hashlib.sha256(run_result.stdout.encode("utf-8")).hexdigest()
            receipt["status"] = "runner_exited"
        except subprocess.TimeoutExpired as exc:
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            receipt["runner_output_sha256"] = hashlib.sha256(output.encode("utf-8")).hexdigest()
            receipt["status"] = "runner_timeout_no_terminal_job"
        receipt["duration_seconds"] = round(time.time() - started, 3)
        return receipt
    finally:
        # Never retain the registration token or runner credential files locally.
        token = ""
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Zero-spend one-job Tasklet GitHub runner bootstrap")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--runner-version", required=True)
    parser.add_argument("--runner-sha256", required=True)
    parser.add_argument("--runner-name", required=True)
    parser.add_argument("--root", default="/tasklet/agent/home")
    parser.add_argument("--max-seconds", type=int, default=1800)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.max_seconds < 60 or args.max_seconds > 3600:
        raise BootstrapError("max-seconds must be between 60 and 3600")
    receipt = bootstrap(args)
    print(_canonical_json(receipt))
    return 0 if receipt.get("run_returncode") == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
