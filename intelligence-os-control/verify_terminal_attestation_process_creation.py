from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys
from dataclasses import asdict, dataclass

import verify_terminal_attestation_control_flow as control_flow

_SCHEMA = "amazingbecca.terminal-attestation-process-creation.v1"
_ATTESTOR_NAME = "_run_attestor"
_WORKER_FLAG = "--worker"

# The reviewed attestor may launch exactly one candidate through an explicit
# subprocess.Popen call. Alternate process creation/replacement APIs are not part
# of this authority profile because they can create an unreviewed candidate or
# survivor path outside the canonical wait/readiness/challenge/receipt sequence.
_FORBIDDEN_PROCESS_PRIMITIVES = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "concurrent.futures.ProcessPoolExecutor",
        "multiprocessing.Process",
        "multiprocessing.Pool",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.fork",
        "os.forkpty",
        "os.popen",
        "os.posix_spawn",
        "os.posix_spawnp",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.system",
        "pty.fork",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
    }
)
_DYNAMIC_PROCESS_ROOTS = frozenset(
    {
        "asyncio",
        "concurrent.futures",
        "multiprocessing",
        "os",
        "pty",
        "subprocess",
    }
)
_DYNAMIC_PROCESS_ATTRIBUTES = frozenset(
    name.rsplit(".", 1)[-1] for name in _FORBIDDEN_PROCESS_PRIMITIVES
) | frozenset({"Popen"})
_NATIVE_ESCAPE_ROOTS = frozenset({"ctypes", "cffi", "ffi", "libc"})


@dataclass(frozen=True)
class Finding:
    path: str
    function: str
    line: int
    kind: str
    detail: str


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                local = item.asname or item.name.split(".", 1)[0]
                aliases[local] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name == "*":
                    continue
                local = item.asname or item.name
                aliases[local] = f"{node.module}.{item.name}"
    return aliases


def _resolve_alias(name: str | None, aliases: dict[str, str]) -> str | None:
    if not name:
        return None
    first, separator, rest = name.partition(".")
    resolved = aliases.get(first, first)
    return resolved + (separator + rest if separator else "")


def _constant_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_string(node.left)
        right = _constant_string(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                return None
            parts.append(value.value)
        return "".join(parts)
    return None


def _string_literals(node: ast.AST) -> set[str]:
    return {
        item.value
        for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }


def _top_level_functions(tree: ast.Module) -> dict[str, list[ast.FunctionDef]]:
    result: dict[str, list[ast.FunctionDef]] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            result.setdefault(node.name, []).append(node)
    return result


def _finding(path: str, function: str, line: int, kind: str, detail: str) -> Finding:
    return Finding(path=path, function=function, line=line, kind=kind, detail=detail)


def _getattr_process_primitive(call: ast.Call, aliases: dict[str, str]) -> str | None:
    if _dotted_name(call.func) not in {"getattr", "builtins.getattr"}:
        return None
    if len(call.args) < 2:
        return None
    root = _resolve_alias(_dotted_name(call.args[0]), aliases)
    attribute = _constant_string(call.args[1])
    if root not in _DYNAMIC_PROCESS_ROOTS or attribute not in _DYNAMIC_PROCESS_ATTRIBUTES:
        return None
    return f"{root}.{attribute}"


def _referenced_local_helpers(
    function: ast.FunctionDef,
    functions: dict[str, list[ast.FunctionDef]],
) -> set[str]:
    names: set[str] = set()
    for call in ast.walk(function):
        if not isinstance(call, ast.Call):
            continue
        name = _dotted_name(call.func)
        if name in functions and len(functions[name]) == 1:
            names.add(name)
    return names


def _reachable_functions(
    attestor: ast.FunctionDef,
    functions: dict[str, list[ast.FunctionDef]],
) -> tuple[ast.FunctionDef, ...]:
    reachable: list[ast.FunctionDef] = [attestor]
    seen = {attestor.name}
    pending = [attestor]
    while pending:
        current = pending.pop()
        for name in sorted(_referenced_local_helpers(current, functions)):
            if name in seen or name == attestor.name:
                continue
            definition = functions[name][0]
            seen.add(name)
            reachable.append(definition)
            pending.append(definition)
    return tuple(reachable)


def _inspect_process_surface(
    function: ast.FunctionDef,
    path: str,
    aliases: dict[str, str],
    *,
    attestor: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    canonical_popen: list[ast.Call] = []

    for node in ast.walk(function):
        if isinstance(node, ast.Attribute):
            resolved = _resolve_alias(_dotted_name(node), aliases)
            if resolved in _FORBIDDEN_PROCESS_PRIMITIVES:
                findings.append(
                    _finding(
                        path,
                        function.name,
                        node.lineno,
                        "alternate-process-primitive-referenced",
                        f"unreviewed process primitive is reachable from attestor authority: {resolved}",
                    )
                )
            root = resolved.split(".", 1)[0] if resolved else None
            if root in _NATIVE_ESCAPE_ROOTS:
                findings.append(
                    _finding(
                        path,
                        function.name,
                        node.lineno,
                        "native-process-escape-surface-referenced",
                        f"native process-control surface is reachable from attestor authority: {resolved}",
                    )
                )

        if not isinstance(node, ast.Call):
            continue
        raw_name = _dotted_name(node.func)
        resolved = _resolve_alias(raw_name, aliases)

        dynamic = _getattr_process_primitive(node, aliases)
        if dynamic is not None:
            findings.append(
                _finding(
                    path,
                    function.name,
                    node.lineno,
                    "dynamic-process-primitive-recovery",
                    f"attestor recovers process authority dynamically through getattr: {dynamic}",
                )
            )

        if resolved in _FORBIDDEN_PROCESS_PRIMITIVES:
            findings.append(
                _finding(
                    path,
                    function.name,
                    node.lineno,
                    "alternate-process-creation-call",
                    f"attestor authority reaches forbidden process primitive: {resolved}",
                )
            )

        if resolved == "subprocess.Popen":
            if not attestor:
                findings.append(
                    _finding(
                        path,
                        function.name,
                        node.lineno,
                        "candidate-process-launch-hidden-in-helper",
                        "reachable helper must not create another process; only _run_attestor may launch the candidate",
                    )
                )
            elif raw_name != "subprocess.Popen":
                findings.append(
                    _finding(
                        path,
                        function.name,
                        node.lineno,
                        "candidate-process-launch-aliased",
                        "candidate launch must use explicit subprocess.Popen rather than an imported or rebound alias",
                    )
                )
            else:
                canonical_popen.append(node)

        root = resolved.split(".", 1)[0] if resolved else None
        if root in _NATIVE_ESCAPE_ROOTS:
            findings.append(
                _finding(
                    path,
                    function.name,
                    node.lineno,
                    "native-process-escape-call",
                    f"native process-control recovery is outside the reviewed attestor profile: {resolved}",
                )
            )

    if attestor:
        worker_launches = [
            call for call in canonical_popen if _WORKER_FLAG in _string_literals(call)
        ]
        if len(canonical_popen) != 1 or len(worker_launches) != 1:
            findings.append(
                _finding(
                    path,
                    function.name,
                    function.lineno,
                    "candidate-process-creation-authority-ambiguous",
                    "attestor must contain exactly one explicit subprocess.Popen and it must be the --worker launch",
                )
            )

    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    base_report = control_flow.verify(root)
    findings: list[Finding] = []
    attestors: list[tuple[str, ast.Module, ast.FunctionDef]] = []

    for source in control_flow._source_files(root):
        relative = source.relative_to(root).as_posix()
        raw = source.read_bytes()
        try:
            tree = ast.parse(raw, filename=str(source))
        except (SyntaxError, ValueError, TypeError) as exc:
            raise RuntimeError(f"runner source cannot be parsed: {source}") from exc
        functions = _top_level_functions(tree)
        definitions = functions.get(_ATTESTOR_NAME, [])
        for definition in definitions:
            attestors.append((relative, tree, definition))

    if len(attestors) != 1:
        findings.append(
            _finding(
                "<bundle>",
                _ATTESTOR_NAME,
                0,
                "terminal-attestor-authority-ambiguous",
                "runner bundle must contain exactly one top-level _run_attestor",
            )
        )
    else:
        relative, tree, attestor = attestors[0]
        aliases = _import_aliases(tree)
        functions = _top_level_functions(tree)
        for function in _reachable_functions(attestor, functions):
            findings.extend(
                _inspect_process_surface(
                    function,
                    relative,
                    aliases,
                    attestor=function is attestor,
                )
            )

    rendered = [
        asdict(item)
        for item in sorted(
            set(findings),
            key=lambda item: (item.path, item.function, item.line, item.kind, item.detail),
        )
    ]
    return {
        "schema": _SCHEMA,
        "authority_level": "source-process-topology-diagnostic-not-terminal",
        "control_flow_passed": bool(base_report.get("passed")),
        "control_flow_finding_count": int(base_report.get("finding_count", 0)),
        "terminal_attestor_count": len(attestors),
        "finding_count": len(rendered),
        "findings": rendered,
        "passed": (
            bool(base_report.get("passed"))
            and len(attestors) == 1
            and not rendered
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner-root", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = verify(args.runner_root)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
