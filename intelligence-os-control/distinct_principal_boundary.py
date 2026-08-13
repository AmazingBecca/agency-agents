from __future__ import annotations

import argparse
import json
import os
import pathlib
import pwd
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass

_SCHEMA = "amazingbecca.distinct-principal-boundary.v6"
_MAX_OUTPUT_BYTES = 64 * 1024
_DEFAULT_TIMEOUT_SECONDS = 10
_PROCESS_LIMIT = 2
_SECRET_ENV_NAMES = (
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "OPENAI_API_KEY",
)
_MOUNT_SETUP_SCRIPT = r'''
mount_bin=$1
shift
hidden_count=$1
shift
"$mount_bin" --make-rprivate /
i=0
while [ "$i" -lt "$hidden_count" ]; do
    target=$1
    shift
    "$mount_bin" -t tmpfs -o mode=000,size=4096 tmpfs "$target"
    i=$((i + 1))
done
exec "$@"
'''.strip()


@dataclass(frozen=True)
class SandboxIdentity:
    user: str
    uid: int
    gid: int
    sudo: pathlib.Path


def _trusted_tool(name: str) -> pathlib.Path:
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"{name} is required for distinct-principal execution")
    path = pathlib.Path(resolved).resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"{name} authority is not a regular file")
    if metadata.st_uid != 0:
        raise RuntimeError(f"{name} authority is not root-owned")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError(f"{name} authority is group/world writable")
    return path


def _trusted_sudo() -> pathlib.Path:
    return _trusted_tool("sudo")


def resolve_identity(user: str) -> SandboxIdentity:
    if not user or any(character.isspace() for character in user):
        raise RuntimeError("sandbox user is malformed")
    try:
        account = pwd.getpwnam(user)
    except KeyError as exc:
        raise RuntimeError(f"sandbox user does not exist: {user}") from exc
    if account.pw_uid == 0:
        raise RuntimeError("sandbox user must not be root")
    if account.pw_uid == os.geteuid():
        raise RuntimeError("sandbox user must differ from control euid")
    return SandboxIdentity(user=user, uid=account.pw_uid, gid=account.pw_gid, sudo=_trusted_sudo())


def _validated_hidden_paths(hidden_paths: tuple[pathlib.Path, ...] | list[pathlib.Path]) -> tuple[pathlib.Path, ...]:
    validated: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    for item in hidden_paths:
        if not isinstance(item, pathlib.Path):
            raise RuntimeError("hidden filesystem path must be a pathlib.Path")
        if not item.is_absolute():
            raise RuntimeError("hidden filesystem path must be absolute")
        if item == pathlib.Path("/"):
            raise RuntimeError("sandbox root may not be hidden")
        try:
            metadata = item.lstat()
        except FileNotFoundError as exc:
            raise RuntimeError("hidden filesystem path does not exist") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("hidden filesystem path must be a real directory")
        resolved = item.resolve(strict=True)
        if resolved != item:
            raise RuntimeError("hidden filesystem path must be canonical")
        if resolved in seen:
            raise RuntimeError("hidden filesystem paths must be unique")
        seen.add(resolved)
        validated.append(resolved)
    return tuple(validated)


def wrap_command(
    command: list[str],
    identity: SandboxIdentity,
    *,
    hidden_paths: tuple[pathlib.Path, ...] | list[pathlib.Path] = (),
) -> list[str]:
    if not command or any(not isinstance(item, str) or not item for item in command):
        raise RuntimeError("candidate command is malformed")
    hidden = _validated_hidden_paths(hidden_paths)
    unshare = _trusted_tool("unshare")
    prlimit = _trusted_tool("prlimit")
    setpriv = _trusted_tool("setpriv")
    env = _trusted_tool("env")
    environment = (
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "PYTHONWARNINGS=error",
        "OPENBLAS_NUM_THREADS=1",
        "OMP_NUM_THREADS=1",
        "MKL_NUM_THREADS=1",
    )
    constrained = [
        str(prlimit),
        f"--nproc={_PROCESS_LIMIT}:{_PROCESS_LIMIT}",
        "--core=0:0",
        "--",
        str(setpriv),
        f"--reuid={identity.uid}",
        f"--regid={identity.gid}",
        "--clear-groups",
        "--no-new-privs",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--",
        str(env),
        "-i",
        *environment,
        *command,
    ]
    namespace = [
        str(identity.sudo),
        "-n",
        "--",
        str(unshare),
        "--mount",
        "--net",
        "--pid",
        "--fork",
        "--mount-proc",
        "--",
    ]
    if not hidden:
        return [*namespace, *constrained]

    shell = _trusted_tool("sh")
    mount = _trusted_tool("mount")
    return [
        *namespace,
        str(shell),
        "-ceu",
        _MOUNT_SETUP_SCRIPT,
        "mount-setup",
        str(mount),
        str(len(hidden)),
        *(str(path) for path in hidden),
        *constrained,
    ]


def _probe_source() -> str:
    return r'''from __future__ import annotations
import json
import os
import pathlib
import resource
import socket
import sys

control_pid = int(sys.argv[1])
sentinel = pathlib.Path(sys.argv[2])
control_net_ns = int(sys.argv[3])
control_pid_ns = int(sys.argv[4])
control_mnt_ns = int(sys.argv[5])
public_sentinel = pathlib.Path(sys.argv[6])

def readable(path: pathlib.Path) -> bool:
    try:
        with path.open('rb', buffering=0) as handle:
            handle.read(1)
        return True
    except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
        return False

def status_value(name: str) -> str:
    prefix = name + ':'
    for line in pathlib.Path('/proc/self/status').read_text(encoding='utf-8').splitlines():
        if line.startswith(prefix):
            return line.split(':', 1)[1].strip()
    raise RuntimeError('missing proc status field: ' + name)

try:
    os.kill(control_pid, 0)
    signal_allowed = True
except (PermissionError, ProcessLookupError):
    signal_allowed = False

spawn_one_allowed = False
second_concurrent_spawn_blocked = False
read_fd, write_fd = os.pipe()
try:
    child_pid = os.fork()
except OSError:
    os.close(read_fd)
    os.close(write_fd)
else:
    spawn_one_allowed = True
    if child_pid == 0:
        os.close(read_fd)
        nested_blocked = False
        try:
            grandchild_pid = os.fork()
        except OSError as exc:
            nested_blocked = exc.errno in (11, 1)
        else:
            if grandchild_pid == 0:
                os._exit(0)
            os.waitpid(grandchild_pid, 0)
        try:
            os.write(write_fd, b'1' if nested_blocked else b'0')
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    marker = os.read(read_fd, 2)
    os.close(read_fd)
    os.waitpid(child_pid, 0)
    second_concurrent_spawn_blocked = marker == b'1'

soft_nproc, hard_nproc = resource.getrlimit(resource.RLIMIT_NPROC)
proc_visible_pids = sorted(int(item.name) for item in pathlib.Path('/proc').iterdir() if item.name.isdecimal())
payload = {
    'candidate_euid': os.geteuid(),
    'candidate_egid': os.getegid(),
    'candidate_groups': os.getgroups(),
    'candidate_pid': os.getpid(),
    'signal_control_allowed': signal_allowed,
    'sentinel_readable': readable(sentinel),
    'public_sentinel_readable': readable(public_sentinel),
    'control_pid_visible': (pathlib.Path('/proc') / str(control_pid)).exists(),
    'proc_environ_readable': readable(pathlib.Path('/proc') / str(control_pid) / 'environ'),
    'proc_mem_readable': readable(pathlib.Path('/proc') / str(control_pid) / 'mem'),
    'proc_visible_pids': proc_visible_pids,
    'secret_env_names': sorted(name for name in %r if name in os.environ),
    'no_new_privs': status_value('NoNewPrivs'),
    'cap_eff': status_value('CapEff'),
    'cap_bnd': status_value('CapBnd'),
    'nproc_soft': soft_nproc,
    'nproc_hard': hard_nproc,
    'spawn_one_allowed': spawn_one_allowed,
    'second_concurrent_spawn_blocked': second_concurrent_spawn_blocked,
    'control_net_ns': control_net_ns,
    'candidate_net_ns': os.stat('/proc/self/ns/net').st_ino,
    'control_pid_ns': control_pid_ns,
    'candidate_pid_ns': os.stat('/proc/self/ns/pid').st_ino,
    'control_mnt_ns': control_mnt_ns,
    'candidate_mnt_ns': os.stat('/proc/self/ns/mnt').st_ino,
    'network_interfaces': sorted(name for _index, name in socket.if_nameindex()),
}
sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(',', ':')) + '\n')
''' % (_SECRET_ENV_NAMES,)


def _evaluate_probe(payload: dict[str, object], identity: SandboxIdentity) -> None:
    expected_keys = {
        "candidate_euid",
        "candidate_egid",
        "candidate_groups",
        "candidate_pid",
        "signal_control_allowed",
        "sentinel_readable",
        "public_sentinel_readable",
        "control_pid_visible",
        "proc_environ_readable",
        "proc_mem_readable",
        "proc_visible_pids",
        "secret_env_names",
        "no_new_privs",
        "cap_eff",
        "cap_bnd",
        "nproc_soft",
        "nproc_hard",
        "spawn_one_allowed",
        "second_concurrent_spawn_blocked",
        "control_net_ns",
        "candidate_net_ns",
        "control_pid_ns",
        "candidate_pid_ns",
        "control_mnt_ns",
        "candidate_mnt_ns",
        "network_interfaces",
    }
    if set(payload) != expected_keys:
        raise RuntimeError("sandbox probe schema drifted")
    if payload["candidate_euid"] != identity.uid or payload["candidate_egid"] != identity.gid:
        raise RuntimeError("candidate did not execute under the requested sandbox identity")
    if payload["candidate_groups"] != []:
        raise RuntimeError("candidate retained supplementary groups")
    for name in (
        "signal_control_allowed",
        "sentinel_readable",
        "public_sentinel_readable",
        "control_pid_visible",
        "proc_environ_readable",
        "proc_mem_readable",
    ):
        if payload[name] is not False:
            raise RuntimeError(f"distinct-principal boundary failed: {name}")
    if payload["candidate_pid"] != 1 or payload["proc_visible_pids"] != [1]:
        raise RuntimeError("candidate proc view is not reduced to the isolated PID namespace")
    if payload["secret_env_names"] != []:
        raise RuntimeError("candidate inherited a control secret environment name")
    if payload["no_new_privs"] != "1":
        raise RuntimeError("candidate no-new-privileges policy is not active")
    for name in ("cap_eff", "cap_bnd"):
        if payload[name] != "0000000000000000":
            raise RuntimeError(f"candidate retained Linux capabilities: {name}")
    if payload["nproc_soft"] != _PROCESS_LIMIT or payload["nproc_hard"] != _PROCESS_LIMIT:
        raise RuntimeError("candidate process-count ceiling is not locked to the supervised-worker budget")
    if payload["spawn_one_allowed"] is not True:
        raise RuntimeError("candidate supervisor cannot create its single worker process")
    if payload["second_concurrent_spawn_blocked"] is not True:
        raise RuntimeError("candidate process budget permits an unsupervised concurrent descendant")
    for control_name, candidate_name, label in (
        ("control_net_ns", "candidate_net_ns", "network"),
        ("control_pid_ns", "candidate_pid_ns", "PID"),
        ("control_mnt_ns", "candidate_mnt_ns", "mount"),
    ):
        control_ns = payload[control_name]
        candidate_ns = payload[candidate_name]
        if (
            not isinstance(control_ns, int)
            or isinstance(control_ns, bool)
            or control_ns <= 0
            or not isinstance(candidate_ns, int)
            or isinstance(candidate_ns, bool)
            or candidate_ns <= 0
            or candidate_ns == control_ns
        ):
            raise RuntimeError(f"candidate {label} namespace is not isolated from control")
    if payload["network_interfaces"] != ["lo"]:
        raise RuntimeError("candidate network namespace exposes unexpected interfaces")


def verify_boundary(*, sandbox_user: str, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS) -> dict[str, object]:
    if sys.platform != "linux":
        raise RuntimeError("distinct-principal boundary is currently defined only for Linux")
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise RuntimeError("sandbox probe timeout is outside policy")
    identity = resolve_identity(sandbox_user)
    control_pid = os.getpid()
    control_net_ns = pathlib.Path("/proc/self/ns/net").stat().st_ino
    control_pid_ns = pathlib.Path("/proc/self/ns/pid").stat().st_ino
    control_mnt_ns = pathlib.Path("/proc/self/ns/mnt").stat().st_ino

    with tempfile.TemporaryDirectory(prefix="control-private-") as private_directory, tempfile.TemporaryDirectory(prefix="candidate-probe-") as probe_directory:
        private_root = pathlib.Path(private_directory).resolve(strict=True)
        private_root.chmod(0o755)
        sentinel = private_root / "sentinel"
        sentinel.write_bytes(secrets.token_bytes(32))
        sentinel.chmod(0o600)
        public_sentinel = private_root / "public-sentinel"
        public_sentinel.write_bytes(secrets.token_bytes(32))
        public_sentinel.chmod(0o444)

        probe_root = pathlib.Path(probe_directory)
        probe_root.chmod(0o755)
        probe = probe_root / "probe.py"
        probe.write_text(_probe_source(), encoding="utf-8")
        probe.chmod(0o444)

        command = wrap_command(
            [
                str(pathlib.Path(sys.executable).resolve(strict=True)),
                "-I",
                str(probe),
                str(control_pid),
                str(sentinel),
                str(control_net_ns),
                str(control_pid_ns),
                str(control_mnt_ns),
                str(public_sentinel),
            ],
            identity,
            hidden_paths=(private_root,),
        )
        completed = subprocess.run(
            command,
            cwd=probe_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")},
            timeout=timeout_seconds,
            check=False,
            start_new_session=True,
        )
        if len(completed.stdout) + len(completed.stderr) > _MAX_OUTPUT_BYTES:
            raise RuntimeError("sandbox probe exceeded output ceiling")
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace")[:1000]
            raise RuntimeError(f"sandbox probe failed with exit {completed.returncode}: {detail}")
        try:
            rendered = completed.stdout.decode("utf-8")
            if rendered.count("\n") != 1 or not rendered.endswith("\n"):
                raise ValueError("noncanonical line framing")
            payload = json.loads(rendered)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError("sandbox probe output is not canonical JSON") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("sandbox probe payload must be an object")
        _evaluate_probe(payload, identity)

    return {
        "schema": _SCHEMA,
        "control_euid": os.geteuid(),
        "sandbox_user": identity.user,
        "sandbox_uid": identity.uid,
        "sandbox_gid": identity.gid,
        "supplementary_groups": [],
        "signal_control_allowed": False,
        "sentinel_readable": False,
        "public_sentinel_readable": False,
        "filesystem_mask_active": True,
        "control_pid_visible": False,
        "proc_environ_readable": False,
        "proc_mem_readable": False,
        "proc_visible_pids": [1],
        "secret_env_names": [],
        "no_new_privs": True,
        "effective_capabilities": "0000000000000000",
        "bounding_capabilities": "0000000000000000",
        "nproc_soft": _PROCESS_LIMIT,
        "nproc_hard": _PROCESS_LIMIT,
        "spawn_one_allowed": True,
        "second_concurrent_spawn_blocked": True,
        "single_worker_slot": True,
        "control_net_ns": control_net_ns,
        "candidate_net_ns": payload["candidate_net_ns"],
        "network_namespace_distinct": True,
        "control_pid_ns": control_pid_ns,
        "candidate_pid_ns": payload["candidate_pid_ns"],
        "pid_namespace_distinct": True,
        "control_mnt_ns": control_mnt_ns,
        "candidate_mnt_ns": payload["candidate_mnt_ns"],
        "mount_namespace_distinct": True,
        "network_interfaces": ["lo"],
        "passed": True,
    }


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sandbox-user", default="nobody")
    parser.add_argument("--timeout-seconds", type=int, default=_DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    try:
        report = verify_boundary(sandbox_user=args.sandbox_user, timeout_seconds=args.timeout_seconds)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(_canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
