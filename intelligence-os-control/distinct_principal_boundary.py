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

_SCHEMA = "amazingbecca.distinct-principal-boundary.v3"
_MAX_OUTPUT_BYTES = 64 * 1024
_DEFAULT_TIMEOUT_SECONDS = 10
_SECRET_ENV_NAMES = (
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "OPENAI_API_KEY",
)


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


def wrap_command(command: list[str], identity: SandboxIdentity) -> list[str]:
    if not command or any(not isinstance(item, str) or not item for item in command):
        raise RuntimeError("candidate command is malformed")
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
    return [
        str(identity.sudo),
        "-n",
        "--",
        str(unshare),
        "--net",
        "--",
        str(prlimit),
        "--nproc=1:1",
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
except PermissionError:
    signal_allowed = False
except ProcessLookupError:
    signal_allowed = False

try:
    child_pid = os.fork()
except OSError as exc:
    fork_blocked = exc.errno in (11, 1)
else:
    if child_pid == 0:
        os._exit(0)
    os.waitpid(child_pid, 0)
    fork_blocked = False

soft_nproc, hard_nproc = resource.getrlimit(resource.RLIMIT_NPROC)
payload = {
    'candidate_euid': os.geteuid(),
    'candidate_egid': os.getegid(),
    'candidate_groups': os.getgroups(),
    'signal_control_allowed': signal_allowed,
    'sentinel_readable': readable(sentinel),
    'proc_environ_readable': readable(pathlib.Path('/proc') / str(control_pid) / 'environ'),
    'proc_mem_readable': readable(pathlib.Path('/proc') / str(control_pid) / 'mem'),
    'secret_env_names': sorted(name for name in %r if name in os.environ),
    'no_new_privs': status_value('NoNewPrivs'),
    'cap_eff': status_value('CapEff'),
    'cap_bnd': status_value('CapBnd'),
    'nproc_soft': soft_nproc,
    'nproc_hard': hard_nproc,
    'fork_blocked': fork_blocked,
    'control_net_ns': control_net_ns,
    'candidate_net_ns': os.stat('/proc/self/ns/net').st_ino,
    'network_interfaces': sorted(name for _index, name in socket.if_nameindex()),
}
sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(',', ':')) + '\n')
''' % (_SECRET_ENV_NAMES,)


def _evaluate_probe(payload: dict[str, object], identity: SandboxIdentity) -> None:
    expected_keys = {
        "candidate_euid",
        "candidate_egid",
        "candidate_groups",
        "signal_control_allowed",
        "sentinel_readable",
        "proc_environ_readable",
        "proc_mem_readable",
        "secret_env_names",
        "no_new_privs",
        "cap_eff",
        "cap_bnd",
        "nproc_soft",
        "nproc_hard",
        "fork_blocked",
        "control_net_ns",
        "candidate_net_ns",
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
        "proc_environ_readable",
        "proc_mem_readable",
    ):
        if payload[name] is not False:
            raise RuntimeError(f"distinct-principal boundary failed: {name}")
    if payload["secret_env_names"] != []:
        raise RuntimeError("candidate inherited a control secret environment name")
    if payload["no_new_privs"] != "1":
        raise RuntimeError("candidate no-new-privileges policy is not active")
    for name in ("cap_eff", "cap_bnd"):
        if payload[name] != "0000000000000000":
            raise RuntimeError(f"candidate retained Linux capabilities: {name}")
    if payload["nproc_soft"] != 1 or payload["nproc_hard"] != 1:
        raise RuntimeError("candidate process-count ceiling is not locked to one")
    if payload["fork_blocked"] is not True:
        raise RuntimeError("candidate can create descendant processes")
    control_net_ns = payload["control_net_ns"]
    candidate_net_ns = payload["candidate_net_ns"]
    if (
        not isinstance(control_net_ns, int)
        or isinstance(control_net_ns, bool)
        or control_net_ns <= 0
        or not isinstance(candidate_net_ns, int)
        or isinstance(candidate_net_ns, bool)
        or candidate_net_ns <= 0
        or candidate_net_ns == control_net_ns
    ):
        raise RuntimeError("candidate network namespace is not isolated from control")
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

    with tempfile.TemporaryDirectory(prefix="control-private-") as private_directory, tempfile.TemporaryDirectory(prefix="candidate-probe-") as probe_directory:
        private_root = pathlib.Path(private_directory)
        private_root.chmod(0o700)
        sentinel = private_root / "sentinel"
        sentinel.write_bytes(secrets.token_bytes(32))
        sentinel.chmod(0o600)

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
            ],
            identity,
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
        "proc_environ_readable": False,
        "proc_mem_readable": False,
        "secret_env_names": [],
        "no_new_privs": True,
        "effective_capabilities": "0000000000000000",
        "bounding_capabilities": "0000000000000000",
        "nproc_soft": 1,
        "nproc_hard": 1,
        "fork_blocked": True,
        "control_net_ns": control_net_ns,
        "candidate_net_ns": payload["candidate_net_ns"],
        "network_namespace_distinct": True,
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
