from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCHEMA = "amazingbecca-tasklet-jit-runner-payload/v1"
TARGET_REPOSITORY = "AmazingBecca/Zo"
RUNNER_VERSION = "2.336.0"
RUNNER_ARCHIVE_SHA256 = "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d"
RUNNER_ROOT_PREFIX = "ab-jit-runner-"
MAX_ARCHIVE_BYTES = 600 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
ALLOWED_DOWNLOAD_HOSTS = ("github.com", "githubusercontent.com")


class PayloadError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PayloadError(f"not one regular file: {path.name}")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        stable = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if not stable:
            raise PayloadError(f"file changed while hashing: {path.name}")
        return digest.hexdigest()
    finally:
        os.close(fd)


def download_url() -> str:
    return (
        "https://github.com/actions/runner/releases/download/"
        f"v{RUNNER_VERSION}/actions-runner-linux-x64-{RUNNER_VERSION}.tar.gz"
    )


def host_allowed(host: str | None) -> bool:
    if not host:
        return False
    host = host.lower().rstrip(".")
    return host == "github.com" or any(
        host == suffix or host.endswith("." + suffix)
        for suffix in ALLOWED_DOWNLOAD_HOSTS[1:]
    )


class PinnedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or not host_allowed(parsed.hostname):
            raise PayloadError(f"runner download redirect refused: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(),
        PinnedRedirect(),
    )


def download_and_hash(url: str, destination: Path) -> tuple[int, str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not host_allowed(parsed.hostname):
        raise PayloadError("runner download must use an allowlisted HTTPS GitHub host")
    digest = hashlib.sha256()
    total = 0
    request = urllib.request.Request(url, headers={"User-Agent": "AmazingBecca-JIT-Runner-Payload/1"})
    with opener().open(request, timeout=30) as response, destination.open("xb") as out:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise PayloadError("runner archive exceeds maximum compressed size")
            digest.update(chunk)
            out.write(chunk)
        out.flush()
        os.fsync(out.fileno())
    if total == 0:
        raise PayloadError("runner archive is empty")
    return total, digest.hexdigest()


def safe_member_name(name: str) -> PurePosixPath:
    if "\\" in name or "\x00" in name:
        raise PayloadError(f"unsafe archive member name: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise PayloadError(f"unsafe archive member path: {name!r}")
    return path


def safe_extract(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        if not members:
            raise PayloadError("runner archive has no members")
        extracted_bytes = sum(member.size for member in members if member.isfile())
        if extracted_bytes < 1 or extracted_bytes > MAX_EXTRACTED_BYTES:
            raise PayloadError("runner archive extracted size is outside policy")
        seen: set[str] = set()
        for member in members:
            path = safe_member_name(member.name)
            normalized = str(path)
            if normalized in seen:
                raise PayloadError(f"duplicate archive member: {normalized}")
            seen.add(normalized)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise PayloadError(f"unsafe archive member type: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise PayloadError(f"unsupported archive member type: {member.name}")
        for member in members:
            path = PurePosixPath(member.name)
            target = destination.joinpath(*path.parts)
            parent = target.parent.resolve()
            if parent != root and root not in parent.parents:
                raise PayloadError(f"archive escapes destination: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tf.extractfile(member)
            if source is None:
                raise PayloadError(f"archive file has no content: {member.name}")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(target, flags, member.mode & 0o777)
            try:
                written = 0
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > member.size:
                        raise PayloadError(f"archive member exceeded declared size: {member.name}")
                    os.write(fd, chunk)
                if written != member.size:
                    raise PayloadError(f"archive member size mismatch: {member.name}")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(target, member.mode & 0o777)


def require_regular_executable(path: Path, label: str) -> None:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise PayloadError(f"{label} must be one regular non-symlink file")
    if not (st.st_mode & stat.S_IXUSR):
        os.chmod(path, st.st_mode | stat.S_IXUSR)


def validate_runner_root(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if resolved.parent != Path("/tmp"):
        raise PayloadError("runner root must be a direct child of /tmp")
    if not resolved.name.startswith(RUNNER_ROOT_PREFIX):
        raise PayloadError("runner root does not use the enrolled prefix")
    st = os.lstat(resolved)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise PayloadError("runner root must be a real directory")
    if st.st_uid != os.geteuid():
        raise PayloadError("runner root ownership mismatch")
    return resolved


def prepare_payload() -> dict[str, Any]:
    root = Path(tempfile.mkdtemp(prefix=RUNNER_ROOT_PREFIX, dir="/tmp"))
    os.chmod(root, 0o700)
    archive = root / "runner.tar.gz"
    install = root / "runner"
    install.mkdir(mode=0o700)
    try:
        archive_size, observed_sha = download_and_hash(download_url(), archive)
        if observed_sha != RUNNER_ARCHIVE_SHA256:
            raise PayloadError(
                f"runner archive sha256 mismatch: expected={RUNNER_ARCHIVE_SHA256} observed={observed_sha}"
            )
        safe_extract(archive, install)
        archive.unlink()
        run_sh = install / "run.sh"
        listener = install / "bin" / "Runner.Listener"
        require_regular_executable(run_sh, "run.sh")
        require_regular_executable(listener, "Runner.Listener")
        result = {
            "schema": SCHEMA,
            "repository": TARGET_REPOSITORY,
            "runner_version": RUNNER_VERSION,
            "runner_archive_sha256": RUNNER_ARCHIVE_SHA256,
            "runner_root": str(root),
            "install_root": str(install),
            "run_sh_sha256": sha256_file(run_sh),
            "listener_sha256": sha256_file(listener),
            "secret_transport": "none",
            "registration_token_handling": "none",
            "jit_config_handling": "none",
            "status": "payload_ready",
        }
        return result
    except BaseException:
        shutil.rmtree(root)
        if root.exists() or root.is_symlink():
            raise PayloadError("failed to remove incomplete runner payload")
        raise


def cleanup_payload(path_text: str) -> dict[str, Any]:
    if not re.fullmatch(r"/tmp/ab-jit-runner-[A-Za-z0-9_-]+", path_text):
        raise PayloadError("cleanup path is outside enrolled runner roots")
    root = validate_runner_root(Path(path_text))
    shutil.rmtree(root)
    if root.exists() or root.is_symlink():
        raise PayloadError("runner payload cleanup did not remove the root")
    return {
        "schema": SCHEMA,
        "runner_root": path_text,
        "status": "payload_removed",
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare or remove a pinned GitHub JIT runner payload without handling credentials"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    cleanup = sub.add_parser("cleanup")
    cleanup.add_argument("--runner-root", required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "prepare":
        result = prepare_payload()
    else:
        result = cleanup_payload(args.runner_root)
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
