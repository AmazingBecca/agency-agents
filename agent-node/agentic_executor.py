#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from typing import Any, Callable

SCHEMA_TASK = "amazingbecca-agentic-task/v1"
SCHEMA_RECEIPT = "amazingbecca-agentic-receipt/v1"
QUEUE_ROOT = pathlib.Path(os.environ.get("AB_AGENT_QUEUE_ROOT", f"/tmp/amazingbecca-agentic-queue-{os.getuid()}"))
CAPLAB = pathlib.Path(os.environ.get("AB_CAPLAB_BIN", "/home/oai/.local/bin/ab-caplab"))
MAX_OUTPUT = 20000
SAFE_OBJECTIVES = {
    "capability_discovery",
    "runtime_audit",
    "browser_stack_probe",
    "static_python_audit",
    "python_repo_validation",
}
CODE_EXEC_OBJECTIVES = {"static_python_audit", "python_repo_validation"}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def executable_identity(name: str) -> dict[str, Any]:
    found = shutil.which(name)
    if not found:
        return {"name": name, "available": False}
    p = pathlib.Path(found).resolve()
    ident = {"name": name, "available": True, "path": str(p)}
    try:
        ident["sha256"] = file_sha256(p)
    except OSError:
        ident["sha256"] = None
    return ident


def run_fixed(argv: list[str], *, cwd: pathlib.Path | None = None, timeout: int = 300) -> dict[str, Any]:
    started = time.time()
    cp = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    out = cp.stdout[-MAX_OUTPUT:]
    return {
        "argv": argv,
        "returncode": cp.returncode,
        "stdout": out,
        "stdout_sha256": sha256_bytes(out.encode()),
        "elapsed_ms": round((time.time() - started) * 1000),
    }


def configured_workspace_roots() -> tuple[pathlib.Path, ...]:
    raw = os.environ.get("AB_AGENT_WORKSPACE_ROOTS", "")
    roots: list[pathlib.Path] = []
    for item in raw.split(os.pathsep):
        if not item:
            continue
        roots.append(pathlib.Path(item).resolve(strict=True))
    return tuple(roots)


def normalize_workspace(raw: str | None, *, require_allowlist: bool = False) -> pathlib.Path:
    root = pathlib.Path(raw or os.getcwd()).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("workspace must be an existing directory")
    roots = configured_workspace_roots()
    if require_allowlist and not roots:
        raise ValueError("code-executing objectives require AB_AGENT_WORKSPACE_ROOTS")
    if roots and not any(root == allowed or allowed in root.parents for allowed in roots):
        raise ValueError("workspace is outside executor-authorized roots")
    return root


def safe_selector(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_./:-]+", value):
        raise ValueError("selector contains unsupported characters")
    return value


def inventory() -> dict[str, Any]:
    tools = ["python3", "git", "rg", "jq", "node", "pytest", "ruff", "ast-grep", "chromium", "jupyter", "libreoffice"]
    return {
        "tools": [executable_identity(x) for x in tools],
        "feature_set": os.environ.get("ACE_TOOLS_FEATURE_SET", ""),
        "cluster": os.environ.get("OPENAI_CLUSTER", ""),
        "vm_build": os.environ.get("CUA_DD_VM_BUILD", ""),
        "vm_commit_sha": os.environ.get("CUA_DD_VM_COMMIT_SHA", ""),
        "product_gates": {k: v for k, v in sorted(os.environ.items()) if k.startswith("CUA_DD_")},
        "caplab_installed": CAPLAB.exists(),
    }


def caplab(action: str) -> dict[str, Any]:
    if not CAPLAB.exists():
        raise RuntimeError("capability lab launcher is not installed")
    return run_fixed([str(CAPLAB), action], timeout=60)


def caplab_manifest() -> dict[str, Any]:
    result = caplab("manifest")
    if result["returncode"] != 0:
        raise RuntimeError("capability manifest failed")
    try:
        return json.loads(result["stdout"].splitlines()[-1])
    except Exception as exc:
        raise RuntimeError("capability manifest is not JSON") from exc


def probe_url(url: str, timeout: float = 3.0, headers: dict[str, str] | None = None) -> dict[str, Any]:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        data = response.read()
        return {"status": response.status, "sha256": sha256_bytes(data), "body": data[:4096].decode("utf-8", "replace")}


def probe_socket(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(2)
        return s.connect_ex(("127.0.0.1", port)) == 0


def read_caplab_env() -> dict[str, str]:
    state_root = pathlib.Path(os.environ.get("AB_CAPLAB_STATE_ROOT", f"/tmp/amazingbecca-caplab-{os.getuid()}"))
    env_file = state_root / "state" / "env.sh"
    if not env_file.exists():
        return {}
    values: dict[str, str] = {}
    for line in env_file.read_text().splitlines():
        if not line.startswith("export ") or "=" not in line:
            continue
        key, value = line[len("export "):].split("=", 1)
        values[key] = subprocess.run(["bash", "-lc", f"printf '%s' {value}"], text=True, stdout=subprocess.PIPE, check=True).stdout
    return values


def action_capability_discovery(_: pathlib.Path, __: dict[str, Any]) -> dict[str, Any]:
    return inventory()


def action_runtime_audit(_: pathlib.Path, __: dict[str, Any]) -> dict[str, Any]:
    inv = inventory()
    if CAPLAB.exists():
        caplab("start")
        manifest = caplab_manifest()
    else:
        manifest = None
    return {"inventory": inv, "capability_manifest": manifest}


def action_browser_probe(_: pathlib.Path, __: dict[str, Any]) -> dict[str, Any]:
    caplab("start")
    values = read_caplab_env()
    cdp = int(values["AB_CAPLAB_CDP_PORT"])
    jupyter = int(values["AB_CAPLAB_JUPYTER_PORT"])
    lo = int(values["AB_CAPLAB_LIBREOFFICE_PORT"])
    token = values["AB_CAPLAB_JUPYTER_TOKEN"]
    cdp_result = probe_url(f"http://127.0.0.1:{cdp}/json/version")
    jupyter_result = probe_url(f"http://127.0.0.1:{jupyter}/api", headers={"Authorization": f"token {token}"})
    return {
        "cdp": cdp_result,
        "jupyter": {"status": jupyter_result["status"], "sha256": jupyter_result["sha256"]},
        "libreoffice_socket": probe_socket(lo),
        "manifest": caplab_manifest(),
    }


def python_files(workspace: pathlib.Path) -> list[pathlib.Path]:
    ignored = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
    out: list[pathlib.Path] = []
    for p in workspace.rglob("*.py"):
        if any(part in ignored for part in p.parts):
            continue
        if p.is_file():
            out.append(p)
    return out[:5000]


def action_static_python(workspace: pathlib.Path, _: dict[str, Any]) -> dict[str, Any]:
    files = python_files(workspace)
    if not files:
        raise RuntimeError("no Python files found")
    rels = [str(p.relative_to(workspace)) for p in files]
    checks: list[dict[str, Any]] = []
    checks.append(run_fixed([sys.executable, "-B", "-m", "compileall", "-q", *rels], cwd=workspace, timeout=300))
    if shutil.which("ruff"):
        checks.append(run_fixed([shutil.which("ruff") or "ruff", "check", "--select", "E9,F63,F7,F82", "."], cwd=workspace, timeout=300))
    else:
        script = "import ast,pathlib,sys; [ast.parse(pathlib.Path(p).read_text(encoding='utf-8'), filename=p) for p in sys.argv[1:]]"
        checks.append(run_fixed([sys.executable, "-B", "-c", script, *rels], cwd=workspace, timeout=300))
    patterns = ["subprocess.run", "os.system", "eval(", "exec("]
    if shutil.which("rg"):
        rg = run_fixed(["rg", "-n", "--glob", "*.py", "|".join(re.escape(x) for x in patterns), "."], cwd=workspace, timeout=120)
        rg["acceptable"] = rg["returncode"] in {0, 1}
        checks.append(rg)
    success = all((c["returncode"] == 0 or c.get("acceptable")) for c in checks)
    return {"python_file_count": len(files), "checks": checks, "success": success}


def action_python_repo(workspace: pathlib.Path, task: dict[str, Any]) -> dict[str, Any]:
    static = action_static_python(workspace, task)
    attempts: list[dict[str, Any]] = []
    selector = task.get("selector")
    if selector:
        selector = safe_selector(str(selector))
    has_pytest_shape = any(workspace.glob("test_*.py")) or (workspace / "tests").exists() or (workspace / "pyproject.toml").exists()
    if shutil.which("pytest") and has_pytest_shape:
        argv = [shutil.which("pytest") or "pytest", "-q"]
        if selector:
            argv.append(selector)
        attempts.append(run_fixed(argv, cwd=workspace, timeout=600))
        if attempts[-1]["returncode"] == 0:
            return {"static": static, "test_route": "pytest", "attempts": attempts, "success": bool(static["success"])}
    if selector and re.fullmatch(r"[A-Za-z0-9_.]+", selector):
        argv = [sys.executable, "-I", "-B", "-m", "unittest", selector, "-v"]
    else:
        argv = [sys.executable, "-I", "-B", "-m", "unittest", "discover", "-v"]
    attempts.append(run_fixed(argv, cwd=workspace, timeout=600))
    return {"static": static, "test_route": "unittest", "attempts": attempts, "success": bool(static["success"] and attempts[-1]["returncode"] == 0)}


ACTIONS: dict[str, Callable[[pathlib.Path, dict[str, Any]], dict[str, Any]]] = {
    "capability_discovery": action_capability_discovery,
    "runtime_audit": action_runtime_audit,
    "browser_stack_probe": action_browser_probe,
    "static_python_audit": action_static_python,
    "python_repo_validation": action_python_repo,
}


def validate_task(task: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(task, dict):
        raise ValueError("task must be an object")
    allowed = {"schema", "task_id", "objective", "workspace", "selector", "max_attempts", "network_access", "advisory_only", "promotion_authorized", "completion_authorized"}
    if set(task) - allowed:
        raise ValueError("task schema drift")
    if task.get("schema") != SCHEMA_TASK:
        raise ValueError("unsupported task schema")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(task.get("task_id", ""))):
        raise ValueError("invalid task_id")
    if task.get("objective") not in SAFE_OBJECTIVES:
        raise ValueError("objective not allowlisted")
    if task.get("network_access", "none") != "none":
        raise ValueError("network authority widening is not allowed")
    if task.get("advisory_only", True) is not True or task.get("promotion_authorized", False) is not False or task.get("completion_authorized", False) is not False:
        raise ValueError("authority boundary weakened")
    max_attempts = task.get("max_attempts", 2)
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or not 1 <= max_attempts <= 5:
        raise ValueError("max_attempts must be 1..5")
    task = dict(task)
    task["network_access"] = "none"
    task["advisory_only"] = True
    task["promotion_authorized"] = False
    task["completion_authorized"] = False
    task["max_attempts"] = max_attempts
    return task


def execute_task(task: dict[str, Any]) -> dict[str, Any]:
    task = validate_task(task)
    workspace = normalize_workspace(task.get("workspace"), require_allowlist=task["objective"] in CODE_EXEC_OBJECTIVES)
    task_bytes = canonical(task)
    attempts = []
    outcome: dict[str, Any] | None = None
    error: str | None = None
    started = time.time()
    for attempt in range(1, task["max_attempts"] + 1):
        try:
            outcome = ACTIONS[task["objective"]](workspace, task)
            attempts.append({"attempt": attempt, "ok": True})
            if outcome.get("success", True):
                error = None
                break
            error = "objective returned unsuccessful result"
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            attempts.append({"attempt": attempt, "ok": False, "error": error})
        time.sleep(min(0.25 * attempt, 1.0))
    success = outcome is not None and outcome.get("success", True) is True and error is None
    receipt = {
        "schema": SCHEMA_RECEIPT,
        "task_id": task["task_id"],
        "task_sha256": sha256_bytes(task_bytes),
        "objective": task["objective"],
        "workspace": str(workspace),
        "attempts": attempts,
        "success": success,
        "error": error,
        "outcome": outcome,
        "elapsed_ms": round((time.time() - started) * 1000),
        "executor": {
            "python": sys.version.split()[0],
            "script_sha256": file_sha256(pathlib.Path(__file__).resolve()),
            "capability_inventory_sha256": sha256_bytes(canonical(inventory())),
        },
        "advisory_only": True,
        "promotion_authorized": False,
        "completion_authorized": False,
    }
    receipt["receipt_sha256"] = sha256_bytes(canonical(receipt))
    return receipt


def load_json(path: pathlib.Path) -> dict[str, Any]:
    raw = path.read_bytes()
    def hook(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate JSON key")
        return dict(items)
    value = json.loads(raw, object_pairs_hook=hook)
    if raw != canonical(value):
        raise ValueError("task JSON must be canonical")
    return value


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(canonical(value))
    os.replace(tmp, path)


def submit(path: pathlib.Path) -> pathlib.Path:
    task = validate_task(load_json(path))
    QUEUE_ROOT.mkdir(parents=True, exist_ok=True)
    dest = QUEUE_ROOT / f"{task['task_id']}.pending.json"
    if any(QUEUE_ROOT.glob(f"{task['task_id']}.*.json")):
        raise RuntimeError("task_id already exists in queue history")
    write_json(dest, task)
    return dest


def work_once() -> pathlib.Path | None:
    QUEUE_ROOT.mkdir(parents=True, exist_ok=True)
    pending = sorted(QUEUE_ROOT.glob("*.pending.json"))
    if not pending:
        return None
    src = pending[0]
    running = src.with_name(src.name.replace(".pending.json", ".running.json"))
    try:
        os.replace(src, running)
    except FileNotFoundError:
        return None
    try:
        task = load_json(running)
        receipt = execute_task(task)
        done = running.with_name(running.name.replace(".running.json", ".done.json"))
        write_json(done, receipt)
        running.unlink(missing_ok=True)
        return done
    except Exception as exc:
        failed = running.with_name(running.name.replace(".running.json", ".failed.json"))
        failure = {
            "schema": SCHEMA_RECEIPT,
            "task_id": running.name.removesuffix(".running.json"),
            "success": False,
            "error": f"{type(exc).__name__}: {exc}",
            "advisory_only": True,
            "promotion_authorized": False,
            "completion_authorized": False,
        }
        failure["receipt_sha256"] = sha256_bytes(canonical(failure))
        write_json(failed, failure)
        running.unlink(missing_ok=True)
        return failed


def worker_loop(interval: float = 0.5) -> None:
    while True:
        result = work_once()
        if result is None:
            time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(prog="ab-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities")
    runp = sub.add_parser("run"); runp.add_argument("task")
    subp = sub.add_parser("submit"); subp.add_argument("task")
    sub.add_parser("work-once")
    wp = sub.add_parser("worker"); wp.add_argument("--interval", type=float, default=0.5)
    sub.add_parser("queue")
    args = parser.parse_args()
    if args.command == "capabilities":
        print(canonical(inventory()).decode(), end="")
    elif args.command == "run":
        receipt = execute_task(load_json(pathlib.Path(args.task)))
        print(canonical(receipt).decode(), end="")
        raise SystemExit(0 if receipt["success"] else 1)
    elif args.command == "submit":
        print(submit(pathlib.Path(args.task)))
    elif args.command == "work-once":
        result = work_once(); print(result or "idle")
    elif args.command == "worker":
        worker_loop(args.interval)
    elif args.command == "queue":
        QUEUE_ROOT.mkdir(parents=True, exist_ok=True)
        for path in sorted(QUEUE_ROOT.glob("*.json")):
            print(path.name)

if __name__ == "__main__":
    main()
