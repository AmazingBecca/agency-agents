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

# The reviewed attestor may launch exactly one candidate through one explicit
# subprocess.Popen call. Every other process-creation/replacement surface is
# outside this authority profile because it can create an unreviewed candidate
# or survivor path outside wait -> readiness -> challenge -> receipt.
_FORBIDDEN_PROCESS_PRIMITIVES = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "concurrent.futures.ProcessPoolExecutor",
        "multiprocessing.Process",
        "multiprocessing.Pool",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
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
_PROCESS_MODULES = frozenset(
    {
        "asyncio",
        "concurrent.futures",
        "multiprocessing",
        "os",
        "pty",
        "subprocess",
    }
)
_PROCESS_ATTRIBUTES = frozenset(
    name.rsplit(".", 1)[-1] for name in _FORBIDDEN_PROCESS_PRIMITIVES
) | frozenset({"Popen"})
_NATIVE_ESCAPE_ROOTS = frozenset({"ctypes", "cffi", "ffi", "libc"})
_DYNAMIC_NAMESPACE_CALLS = frozenset(
    {
        "globals",
        "locals",
        "vars",
        "builtins.globals",
        "builtins.locals",
        "builtins.vars",
    }
)
_DYNAMIC_CODE_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "builtins.eval",
        "builtins.exec",
        "builtins.compile",
    }
)


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


def _bind_import(aliases: dict[str, str], item: ast.alias, module: str | None) -> None:
    if module is None:
        if item.asname:
            aliases[item.asname] = item.name
        else:
            # ``import a.b`` binds ``a``, not ``a.b``. Mapping the root to the
            # complete dotted import would turn a later ``a.fork`` into the
            # fictitious ``a.b.fork`` and create an alias-poisoning escape.
            root = item.name.split(".", 1)[0]
            aliases[root] = root
        return
    if item.name == "*":
        return
    aliases[item.asname or item.name] = f"{module}.{item.name}"


def _scope_import_aliases(tree: ast.Module, function: ast.FunctionDef) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                _bind_import(aliases, item, None)
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                _bind_import(aliases, item, node.module)

    # Function-local imports are legitimate Python authority and must not evade
    # review merely because they are not module-level imports.
    for node in ast.walk(function):
        if isinstance(node, ast.Import):
            for item in node.names:
                _bind_import(aliases, item, None)
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                _bind_import(aliases, item, node.module)
    return aliases


def _resolve_alias(name: str | None, aliases: dict[str, str]) -> str | None:
    if not name:
        return None
    seen: set[str] = set()
    current = name
    while True:
        first, separator, rest = current.partition(".")
        replacement = aliases.get(first)
        if replacement is None or replacement == first or first in seen:
            return current
        seen.add(first)
        current = replacement + (separator + rest if separator else "")


def _dynamic_module(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    call_name = _resolve_alias(_dotted_name(node.func), aliases)
    if call_name in {"__import__", "builtins.__import__", "importlib.import_module"}:
        if not node.args:
            return None
        module = _constant_string(node.args[0])
        if module in _PROCESS_MODULES:
            return module
    return None


def _primitive_expression(node: ast.AST, aliases: dict[str, str]) -> str | None:
    dotted = _resolve_alias(_dotted_name(node), aliases)
    if dotted in _FORBIDDEN_PROCESS_PRIMITIVES or dotted == "subprocess.Popen":
        return dotted

    if isinstance(node, ast.Attribute):
        module = _dynamic_module(node.value, aliases)
        if module is not None and node.attr in _PROCESS_ATTRIBUTES:
            return f"{module}.{node.attr}"

    if isinstance(node, ast.Call):
        call_name = _resolve_alias(_dotted_name(node.func), aliases)
        if call_name in {"getattr", "builtins.getattr"} and len(node.args) >= 2:
            attribute = _constant_string(node.args[1])
            root = _resolve_alias(_dotted_name(node.args[0]), aliases)
            if root in _PROCESS_MODULES and attribute in _PROCESS_ATTRIBUTES:
                return f"{root}.{attribute}"
            module = _dynamic_module(node.args[0], aliases)
            if module is not None and attribute in _PROCESS_ATTRIBUTES:
                return f"{module}.{attribute}"
    return None


def _propagate_primitive_aliases(
    function: ast.FunctionDef, aliases: dict[str, str]
) -> dict[str, str]:
    result = dict(aliases)
    assignments: list[tuple[ast.Name, ast.AST]] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            assignments.append((node.targets[0], node.value))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            assignments.append((node.target, node.value))
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            assignments.append((node.target, node.value))

    changed = True
    while changed:
        changed = False
        for target, value in assignments:
            primitive = _primitive_expression(value, result)
            if primitive is not None and result.get(target.id) != primitive:
                result[target.id] = primitive
                changed = True
                continue
            value_name = _resolve_alias(_dotted_name(value), result)
            if value_name in _PROCESS_MODULES and result.get(target.id) != value_name:
                result[target.id] = value_name
                changed = True
            dynamic_module = _dynamic_module(value, result)
            if dynamic_module is not None and result.get(target.id) != dynamic_module:
                result[target.id] = dynamic_module
                changed = True
    return result


_MAX_RECOVERED_STRING_VALUES = 64
_MAX_RECOVERED_STRING_LENGTH = 512
_REFLECTION_CALLS = frozenset({"getattr", "builtins.getattr", "operator.attrgetter"})


def _function_scope_nodes(function: ast.FunctionDef) -> tuple[ast.AST, ...]:
    """Return nodes in one function scope without borrowing nested bindings."""
    nodes: list[ast.AST] = []
    pending = list(reversed(function.body))
    nested_scopes = (
        ast.AsyncFunctionDef,
        ast.ClassDef,
        ast.DictComp,
        ast.GeneratorExp,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
    )
    while pending:
        node = pending.pop()
        nodes.append(node)
        if isinstance(node, nested_scopes) or (
            isinstance(node, ast.FunctionDef) and node is not function
        ):
            continue
        pending.extend(reversed(tuple(ast.iter_child_nodes(node))))
    return tuple(nodes)


def _string_values(
    node: ast.AST,
    bindings: dict[str, set[str] | None],
) -> set[str] | None:
    """Resolve a bounded set of statically materializable string values."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Name):
        values = bindings.get(node.id)
        return None if values is None else set(values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_values(node.left, bindings)
        right = _string_values(node.right, bindings)
        if left is None or right is None:
            return None
        combined = {a + b for a in left for b in right}
        if (
            len(combined) > _MAX_RECOVERED_STRING_VALUES
            or any(len(value) > _MAX_RECOVERED_STRING_LENGTH for value in combined)
        ):
            return None
        return combined
    if isinstance(node, ast.IfExp):
        body = _string_values(node.body, bindings)
        other = _string_values(node.orelse, bindings)
        if body is None or other is None:
            return None
        combined = body | other
        return (
            combined
            if len(combined) <= _MAX_RECOVERED_STRING_VALUES
            else None
        )
    if isinstance(node, ast.JoinedStr):
        values = {""}
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                part_values = {part.value}
            elif (
                isinstance(part, ast.FormattedValue)
                and part.conversion == -1
                and part.format_spec is None
            ):
                part_values = _string_values(part.value, bindings)
                if part_values is None:
                    return None
            else:
                return None
            values = {prefix + suffix for prefix in values for suffix in part_values}
            if (
                len(values) > _MAX_RECOVERED_STRING_VALUES
                or any(len(value) > _MAX_RECOVERED_STRING_LENGTH for value in values)
            ):
                return None
        return values
    return None


def _local_string_bindings(
    function: ast.FunctionDef,
) -> dict[str, set[str] | None]:
    """Over-approximate local constant strings; unknown assignments stay unknown."""
    bindings: dict[str, set[str] | None] = {}
    assignments: list[tuple[int, int, str, ast.AST]] = []
    for node in _function_scope_nodes(function):
        target: ast.Name | None = None
        value: ast.AST | None = None
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            target, value = node.targets[0], node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            target, value = node.target, node.value
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            target, value = node.target, node.value
        if target is not None and value is not None:
            assignments.append(
                (node.lineno, getattr(node, "col_offset", 0), target.id, value)
            )

    for _, _, name, value in sorted(assignments):
        resolved = _string_values(value, bindings)
        if name not in bindings:
            bindings[name] = None if resolved is None else set(resolved)
            continue
        previous = bindings[name]
        if previous is None or resolved is None:
            bindings[name] = None
            continue
        combined = previous | resolved
        bindings[name] = (
            combined
            if len(combined) <= _MAX_RECOVERED_STRING_VALUES
            else None
        )
    return bindings


def _propagate_reflection_aliases(
    function: ast.FunctionDef,
    aliases: dict[str, str],
) -> dict[str, str]:
    """Resolve simple local aliases of reviewed reflection callables."""
    result = dict(aliases)
    assignments: list[tuple[str, ast.AST]] = []
    for node in _function_scope_nodes(function):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            assignments.append((node.targets[0].id, node.value))
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            assignments.append((node.target.id, node.value))
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            assignments.append((node.target.id, node.value))

    changed = True
    while changed:
        changed = False
        for target, value in assignments:
            resolved = _resolve_alias(_dotted_name(value), result)
            if resolved in _REFLECTION_CALLS and result.get(target) != resolved:
                result[target] = resolved
                changed = True
    return result


def _reflection_namespace_aliases(function: ast.FunctionDef) -> set[str]:
    """Track aliases of object namespace maps used for reflected lookup."""
    aliases: set[str] = set()
    assignments: list[tuple[str, ast.AST]] = []
    for node in _function_scope_nodes(function):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            assignments.append((node.targets[0].id, node.value))
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            assignments.append((node.target.id, node.value))
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            assignments.append((node.target.id, node.value))

    changed = True
    while changed:
        changed = False
        for target, value in assignments:
            namespace = isinstance(value, ast.Attribute) and value.attr == "__dict__"
            chained = isinstance(value, ast.Name) and value.id in aliases
            if (namespace or chained) and target not in aliases:
                aliases.add(target)
                changed = True
    return aliases


def _is_namespace_map(node: ast.AST, namespace_aliases: set[str]) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "__dict__"
    ) or (
        isinstance(node, ast.Name)
        and node.id in namespace_aliases
    )


def _namespace_lookup_target(
    call: ast.Call,
    aliases: dict[str, str],
    namespace_aliases: set[str],
) -> ast.AST | None:
    if isinstance(call.func, ast.Attribute) and call.func.attr in {"get", "__getitem__"}:
        if _is_namespace_map(call.func.value, namespace_aliases) and call.args:
            return call.args[0]
    call_name = _resolve_alias(_dotted_name(call.func), aliases)
    if call_name == "operator.getitem" and len(call.args) >= 2:
        if _is_namespace_map(call.args[0], namespace_aliases):
            return call.args[1]
    return None


def _reflection_target(
    call: ast.Call,
    aliases: dict[str, str],
) -> ast.AST | None:
    call_name = _resolve_alias(_dotted_name(call.func), aliases)
    if call_name in {"getattr", "builtins.getattr"} and len(call.args) >= 2:
        return call.args[1]
    if call_name in {"operator.attrgetter"} and call.args:
        return call.args[0]
    return None


def _referenced_local_helpers(
    tree: ast.Module,
    function: ast.FunctionDef,
    functions: dict[str, list[ast.FunctionDef]],
) -> set[str]:
    # Treat every statically recoverable reference to a unique top-level helper
    # as reachable, not only a syntactically direct ``helper()`` call. Local
    # string derivation is propagated through assignments, and unresolved
    # reflection fails closed to every unique helper because a runtime-computed
    # name could select any of them.
    unique = {name for name, definitions in functions.items() if len(definitions) == 1}
    referenced: set[str] = set()
    bindings = _local_string_bindings(function)
    aliases = _propagate_reflection_aliases(
        function, _scope_import_aliases(tree, function)
    )
    namespace_aliases = _reflection_namespace_aliases(function)

    for node in ast.walk(function):
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in unique
        ):
            referenced.add(node.id)
            continue
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Load)
            and node.attr in unique
        ):
            referenced.add(node.attr)
            continue
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            recovered = _string_values(node.slice, bindings)
            if recovered is not None:
                referenced.update(recovered & unique)
            elif (
                (isinstance(node.value, ast.Attribute) and node.value.attr == "__dict__")
                or (isinstance(node.value, ast.Name) and node.value.id in namespace_aliases)
            ):
                referenced.update(unique)
            continue
        if isinstance(node, ast.Call):
            reflection_target = _reflection_target(node, aliases)
            namespace_target = _namespace_lookup_target(
                node, aliases, namespace_aliases
            )
            for target in (reflection_target, namespace_target):
                if target is None:
                    continue
                recovered = _string_values(target, bindings)
                if recovered is None:
                    referenced.update(unique)
                else:
                    referenced.update(recovered & unique)

            for argument in (
                *node.args,
                *(keyword.value for keyword in node.keywords),
            ):
                recovered = _string_values(argument, bindings)
                if recovered is not None:
                    referenced.update(recovered & unique)
    return referenced


def _reachable_functions(
    tree: ast.Module,
    attestor: ast.FunctionDef,
    functions: dict[str, list[ast.FunctionDef]],
) -> tuple[ast.FunctionDef, ...]:
    reachable: list[ast.FunctionDef] = [attestor]
    seen = {attestor.name}
    pending = [attestor]
    while pending:
        current = pending.pop()
        for name in sorted(_referenced_local_helpers(tree, current, functions)):
            if name in seen or name == attestor.name:
                continue
            definition = functions[name][0]
            seen.add(name)
            reachable.append(definition)
            pending.append(definition)
    return tuple(reachable)


def _inspect_process_surface(
    tree: ast.Module,
    function: ast.FunctionDef,
    path: str,
    *,
    attestor: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    aliases = _propagate_primitive_aliases(
        function, _scope_import_aliases(tree, function)
    )
    canonical_popen: list[ast.Call] = []

    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            primitive = _primitive_expression(node.func, aliases)
            if primitive is None:
                # ``getattr(os, 'fork')`` and ``__import__('os').fork`` are
                # themselves authority-recovery expressions even if a later
                # alias invokes them.
                primitive = _primitive_expression(node, aliases)
            raw_name = _dotted_name(node.func)
            call_name = _resolve_alias(raw_name, aliases)

            if call_name in _DYNAMIC_NAMESPACE_CALLS:
                findings.append(
                    _finding(
                        path,
                        function.name,
                        node.lineno,
                        "dynamic-namespace-authority-recovery",
                        f"dynamic namespace access is not reviewable attestor authority: {call_name}",
                    )
                )
            elif call_name in _DYNAMIC_CODE_CALLS:
                findings.append(
                    _finding(
                        path,
                        function.name,
                        node.lineno,
                        "dynamic-code-authority-recovery",
                        f"dynamic code execution/compilation is not reviewable attestor authority: {call_name}",
                    )
                )

            if primitive in _FORBIDDEN_PROCESS_PRIMITIVES:
                findings.append(
                    _finding(
                        path,
                        function.name,
                        node.lineno,
                        "alternate-process-creation-call",
                        f"attestor authority reaches forbidden process primitive: {primitive}",
                    )
                )
            elif primitive == "subprocess.Popen":
                if not attestor:
                    findings.append(
                        _finding(
                            path,
                            function.name,
                            node.lineno,
                            "candidate-process-launch-hidden-in-helper",
                            "reachable helper must not create a process; only _run_attestor may launch the candidate",
                        )
                    )
                elif raw_name != "subprocess.Popen":
                    findings.append(
                        _finding(
                            path,
                            function.name,
                            node.lineno,
                            "candidate-process-launch-aliased",
                            "candidate launch must use explicit subprocess.Popen rather than an imported, assigned, or dynamically recovered alias",
                        )
                    )
                else:
                    canonical_popen.append(node)

            dynamic_primitive = _primitive_expression(node, aliases)
            if (
                dynamic_primitive is not None
                and isinstance(node.func, ast.Name)
                and node.func.id in {"getattr", "__import__"}
            ):
                findings.append(
                    _finding(
                        path,
                        function.name,
                        node.lineno,
                        "dynamic-process-primitive-recovery",
                        f"attestor recovers process authority dynamically: {dynamic_primitive}",
                    )
                )

        if isinstance(node, (ast.Name, ast.Attribute)):
            resolved = _resolve_alias(_dotted_name(node), aliases)
            root = resolved.split(".", 1)[0] if resolved else None
            if root in _NATIVE_ESCAPE_ROOTS:
                findings.append(
                    _finding(
                        path,
                        function.name,
                        getattr(node, "lineno", function.lineno),
                        "native-process-escape-surface-referenced",
                        f"native process-control surface is reachable from attestor authority: {resolved}",
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
        for definition in functions.get(_ATTESTOR_NAME, []):
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
        functions = _top_level_functions(tree)
        for function in _reachable_functions(tree, attestor, functions):
            findings.extend(
                _inspect_process_surface(
                    tree,
                    function,
                    relative,
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
