from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

import distinct_principal_boundary as boundary

_SCHEMA = "amazingbecca.detached-descendant-lifecycle.v1"
_DEFAULT_TIMEOUT_SECONDS = 8
_SETTLE_SECONDS = 0.35
_MAX_OUTPUT_BYTES = 16 * 1024

_PROBE_SOURCE = r'''
from __future__ import annotations

import os
import pathlib
import sys
import time

heartbeat = pathlib.Path(sys.argv[1])
read_fd, write_fd = os.pipe()

try:
    child_pid = os.fork()
except OSError as exc:
    os.close(read_fd)
    os.close(write_fd)
    raise SystemExit(70) from exc

if child_pid == 0:
    os.close(read_fd)
    try:
        os.setsid()
        devnull = os.open(os.devnull, os.O_RDWR)
        try:
            for descriptor in (0, 1, 2):
                os.dup2(devnull, descriptor)
        finally:
            if devnull > 2:
                os.close(devnull)
        heartbeat.write_text("0\n", encoding="ascii")
        os.write(write_fd, b"1")
        os.close(write_fd)
        for index in range(1, 200):
            time.sleep(0.05)
            heartbeat.write_text(f"{index}\n", encoding="ascii")
    finally:
        os._exit(0)

os.close(write_fd)
marker = os.read(read_fd, 1)
os.close(read_fd)
if marker != b"1":
    raise SystemExit(71)

# Deliberately abandon a detached session.  The trusted outer PID namespace
# must synchronously destroy it when namespace init exits.
os._exit(0)
'''.lstrip()


def _heartbeat_value(path: pathlib.Path) -> tuple[int, int]:
    metadata = path.lstat()
    if not path.is_file() or path.is_symlink() or metadata.st_nlink != 1:
        raise RuntimeError("detached-descendant heartbeat lost regular-file authority")
    payload = path.read_text(encoding="ascii")
    if not payload.endswith("\n") or payload.count("\n") != 1:
        raise RuntimeError("detached-descendant heartbeat framing is malformed")
    value_text = payload[:-1]
    if not value_text.isdecimal():
        raise RuntimeError("detached-descendant heartbeat value is malformed")
    value = int(value_text)
    if value < 0 or value >= 200:
        raise RuntimeError("detached-descendant heartbeat value is outside policy")
    return value, metadata.st_mtime_ns


def verify_detached_descendant_lifecycle(
    *,
    sandbox_user: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    if sys.platform != "linux":
        raise RuntimeError("detached-descendant authority is currently defined only for Linux")
    if timeout_seconds < 2 or timeout_seconds > 30:
        raise RuntimeError("detached-descendant timeout is outside policy")

    identity = boundary.resolve_identity(sandbox_user)
    with tempfile.TemporaryDirectory(prefix="descendant-lifecycle-") as directory:
        root = pathlib.Path(directory).resolve(strict=True)
        root.chmod(0o777)
        heartbeat = root / "heartbeat"
        heartbeat.write_text("0\n", encoding="ascii")
        heartbeat.chmod(0o666)
        probe = root / "probe.py"
        probe.write_text(_PROBE_SOURCE, encoding="utf-8")
        probe.chmod(0o444)

        command = boundary.wrap_command(
            [
                str(pathlib.Path(sys.executable).resolve(strict=True)),
                "-I",
                str(probe),
                str(heartbeat),
            ],
            identity,
        )
        started = time.monotonic()
        completed = subprocess.run(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")},
            timeout=timeout_seconds,
            check=False,
            start_new_session=True,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if len(completed.stdout) + len(completed.stderr) > _MAX_OUTPUT_BYTES:
            raise RuntimeError("detached-descendant probe exceeded output ceiling")
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace")[:1000]
            raise RuntimeError(
                f"detached-descendant probe failed with exit {completed.returncode}: {detail}"
            )

        first_value, first_mtime_ns = _heartbeat_value(heartbeat)
        time.sleep(_SETTLE_SECONDS)
        second_value, second_mtime_ns = _heartbeat_value(heartbeat)
        if second_value != first_value or second_mtime_ns != first_mtime_ns:
            raise RuntimeError(
                "detached candidate session survived trusted PID-namespace teardown"
            )

    return {
        "schema": _SCHEMA,
        "sandbox_user": identity.user,
        "sandbox_uid": identity.uid,
        "sandbox_gid": identity.gid,
        "detached_session_started": True,
        "heartbeat_final_value": first_value,
        "heartbeat_stable_after_namespace_exit": True,
        "settle_ms": int(_SETTLE_SECONDS * 1000),
        "elapsed_ms": elapsed_ms,
        "passed": True,
    }


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--sandbox-user", default="nobody")
    parser.add_argument("--timeout-seconds", type=int, default=_DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    try:
        report = verify_detached_descendant_lifecycle(
            sandbox_user=args.sandbox_user,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(_canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
