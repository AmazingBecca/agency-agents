from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

import verify_terminal_attestation_process_creation_v4_base as _v4


Finding = _v4.Finding
_SCHEMA = _v4._SCHEMA
_ATTESTOR_NAME = _v4._ATTESTOR_NAME
_base = _v4._base

_CARRIER_CALLS = {
    "next",
    "builtins.next",
    "iter",
    "builtins.iter",
    "list",
    "builtins.list",
    "tuple",
    "builtins.tuple",
    "set",
    "builtins.set",
    "frozenset",
    "builtins.frozenset",
    "dict",
    "builtins.dict",
    "enumerate",
    "builtins.enumerate",
    "reversed",
    "builtins.reversed",
}

_SCOPE_BARRIERS = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Lambda,
    ast.GeneratorExp,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
)


def __getattr__(name: str):
    return getattr(_v4, name)


def _simple_assignments(nodes: list[ast.AST]) -> dict[str, list[ast.AST]]:
    assignments: dict[str, list[ast.AST]] = {}
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(node.value)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            assignments.setdefault(node.target.id, []).append(node.value)
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            assignments.setdefault(node.target.id, []).append(node.value)
    return assignments


def _assigned_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Starred):
        return _assigned_names(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for item in target.elts:
            names.update(_assigned_names(item))
        return names
    return set()


def _match_binding_names(pattern: ast.AST) -> set[str]:
    names: set[str] = set()
    if isinstance(pattern, ast.MatchAs):
        if pattern.name:
            names.add(pattern.name)
        if pattern.pattern is not None:
            names.update(_match_binding_names(pattern.pattern))
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name:
            names.add(pattern.name)
    elif isinstance(pattern, ast.MatchMapping):
        if pattern.rest:
            names.add(pattern.rest)
        for child in pattern.patterns:
            names.update(_match_binding_names(child))
    elif isinstance(pattern, ast.MatchSequence):
        for child in pattern.patterns:
            names.update(_match_binding_names(child))
    elif isinstance(pattern, ast.MatchClass):
        for child in [*pattern.patterns, *pattern.kwd_patterns]:
            names.update(_match_binding_names(child))
    elif isinstance(pattern, ast.MatchOr):
        for child in pattern.patterns:
            names.update(_match_binding_names(child))
    return names


def _module_scope_nodes(tree: ast.Module) -> list[ast.AST]:
    """Walk executable module scope without crossing lexical scope barriers."""
    nodes: list[ast.AST] = []
    stack: list[ast.AST] = list(reversed(tree.body))
    while stack:
        node = stack.pop()
        nodes.append(node)
        if isinstance(node, _SCOPE_BARRIERS):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return nodes


def _module_binding_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    if isinstance(node, ast.Assign):
        for target in node.targets:
            names.update(_assigned_names(target))
    elif isinstance(node, ast.AnnAssign):
        names.update(_assigned_names(node.target))
    elif isinstance(node, ast.AugAssign):
        names.update(_assigned_names(node.target))
    elif isinstance(node, ast.NamedExpr):
        names.update(_assigned_names(node.target))
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        names.update(_assigned_names(node.target))
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None:
                names.update(_assigned_names(item.optional_vars))
    elif isinstance(node, ast.ExceptHandler):
        if node.name:
            names.add(node.name)
    elif isinstance(node, ast.Import):
        for alias in node.names:
            names.add(alias.asname or alias.name.split(".", 1)[0])
    elif isinstance(node, ast.ImportFrom):
        for alias in node.names:
            if alias.name != "*":
                names.add(alias.asname or alias.name)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names.add(node.name)
    elif isinstance(
        node,
        (
            ast.MatchAs,
            ast.MatchStar,
            ast.MatchMapping,
            ast.MatchSequence,
            ast.MatchClass,
            ast.MatchOr,
        ),
    ):
        names.update(_match_binding_names(node))
    return names


def _reachable_global_class_rebinds(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    class_names: set[str],
) -> set[str]:
    """Return reviewed class names rebound globally by one reachable helper.

    A function-level ``global`` declaration makes assignments in that function
    mutate module identity at runtime. Source position is irrelevant: a helper
    defined before a reviewed class can still replace it when called later by
    the attestor. Only attestor-reachable functions are considered so dormant
    helpers do not poison an otherwise secure runner.
    """
    scope_nodes = list(_base._function_scope_nodes(function))
    declared: set[str] = set()
    rebound: set[str] = set()
    for node in scope_nodes:
        if isinstance(node, ast.Global):
            declared.update(node.names)
        rebound.update(_module_binding_names(node))
    return class_names & declared & rebound


def _decorated_class_replacement_findings(root: pathlib.Path) -> list[dict[str, object]]:
    """Reject attestor calls through runtime-replaceable reviewed classes."""
    findings: list[dict[str, object]] = []

    for source in _base.control_flow._source_files(root):
        relative = source.relative_to(root).as_posix()
        raw = source.read_bytes()
        try:
            tree = ast.parse(raw, filename=str(source))
        except (SyntaxError, ValueError, TypeError) as exc:
            raise RuntimeError(f"runner source cannot be parsed: {source}") from exc

        class_definitions = [
            node for node in tree.body if isinstance(node, ast.ClassDef)
        ]
        class_names = {node.name for node in class_definitions}
        if not class_names:
            continue

        first_class_line: dict[str, int] = {}
        for node in class_definitions:
            first_class_line[node.name] = min(
                first_class_line.get(node.name, node.lineno),
                node.lineno,
            )

        dynamic_classes = {
            node.name for node in class_definitions if node.decorator_list
        }

        # Control-flow blocks execute in module scope. Any later binding of a
        # reviewed class name can replace the reviewed object, including match
        # captures, destructuring, loop/with/except aliases, and imports.
        for node in _module_scope_nodes(tree):
            line = getattr(node, "lineno", 0)
            for name in _module_binding_names(node):
                first_line = first_class_line.get(name)
                if first_line is not None and line > first_line:
                    dynamic_classes.add(name)

        functions = _base._top_level_functions(tree)
        attestors = functions.get(_ATTESTOR_NAME, [])
        if len(attestors) != 1:
            continue
        attestor = attestors[0]
        reachable_functions = list(
            _base._reachable_functions(tree, attestor, functions)
        )

        # A reachable helper can replace module identity without a module-scope
        # assignment by declaring the class global and assigning to it at call
        # time. Treat those writes as equivalent runtime replacement authority.
        for function in reachable_functions:
            dynamic_classes.update(
                _reachable_global_class_rebinds(function, class_names)
            )

        if not dynamic_classes:
            continue

        import_aliases = _base._scope_import_aliases(tree, attestor)
        factory_cache: dict[str, bool] = {}

        def resolved_name(value: ast.AST) -> str | None:
            dotted = _base._dotted_name(value)
            return _base._resolve_alias(dotted, import_aliases)

        def factory_carries_dynamic(
            name: str,
            depth: int = 0,
            seen_functions: set[str] | None = None,
        ) -> bool:
            if depth > 8:
                return True
            if name in factory_cache:
                return factory_cache[name]
            seen_functions = set() if seen_functions is None else set(seen_functions)
            if name in seen_functions:
                return False
            definitions = functions.get(name, [])
            if len(definitions) != 1:
                return False
            definition = definitions[0]
            local_nodes = list(_base._function_scope_nodes(definition))
            local_assignments = _simple_assignments(local_nodes)
            next_seen = set(seen_functions)
            next_seen.add(name)
            factory_cache[name] = False
            for node in ast.walk(definition):
                if not isinstance(node, ast.Return) or node.value is None:
                    continue
                if expression_carries_dynamic(
                    node.value,
                    local_assignments,
                    depth=depth + 1,
                    seen_functions=next_seen,
                ):
                    factory_cache[name] = True
                    return True
            return False

        def expression_carries_dynamic(
            value: ast.AST,
            assignments: dict[str, list[ast.AST]],
            *,
            depth: int = 0,
            seen_names: set[str] | None = None,
            seen_functions: set[str] | None = None,
        ) -> bool:
            if depth > 10:
                return True
            seen_names = set() if seen_names is None else set(seen_names)
            seen_functions = set() if seen_functions is None else set(seen_functions)

            if isinstance(value, ast.Name):
                if value.id in dynamic_classes:
                    return True
                if value.id in seen_names:
                    return False
                candidates = assignments.get(value.id, [])
                if not candidates:
                    return False
                next_seen = set(seen_names)
                next_seen.add(value.id)
                return any(
                    expression_carries_dynamic(
                        candidate,
                        assignments,
                        depth=depth + 1,
                        seen_names=next_seen,
                        seen_functions=seen_functions,
                    )
                    for candidate in candidates
                )

            if isinstance(value, ast.NamedExpr):
                return expression_carries_dynamic(
                    value.value,
                    assignments,
                    depth=depth + 1,
                    seen_names=seen_names,
                    seen_functions=seen_functions,
                )

            if isinstance(value, ast.IfExp):
                return any(
                    expression_carries_dynamic(
                        branch,
                        assignments,
                        depth=depth + 1,
                        seen_names=seen_names,
                        seen_functions=seen_functions,
                    )
                    for branch in (value.body, value.orelse)
                )

            if isinstance(value, ast.BoolOp):
                return any(
                    expression_carries_dynamic(
                        item,
                        assignments,
                        depth=depth + 1,
                        seen_names=seen_names,
                        seen_functions=seen_functions,
                    )
                    for item in value.values
                )

            if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                return any(
                    expression_carries_dynamic(
                        item,
                        assignments,
                        depth=depth + 1,
                        seen_names=seen_names,
                        seen_functions=seen_functions,
                    )
                    for item in value.elts
                )

            if isinstance(value, ast.Dict):
                return any(
                    expression_carries_dynamic(
                        item,
                        assignments,
                        depth=depth + 1,
                        seen_names=seen_names,
                        seen_functions=seen_functions,
                    )
                    for item in [*value.keys, *value.values]
                    if item is not None
                )

            if isinstance(value, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
                if expression_carries_dynamic(
                    value.elt,
                    assignments,
                    depth=depth + 1,
                    seen_names=seen_names,
                    seen_functions=seen_functions,
                ):
                    return True
                return any(
                    expression_carries_dynamic(
                        generator.iter,
                        assignments,
                        depth=depth + 1,
                        seen_names=seen_names,
                        seen_functions=seen_functions,
                    )
                    for generator in value.generators
                )

            if isinstance(value, ast.DictComp):
                if expression_carries_dynamic(
                    value.key,
                    assignments,
                    depth=depth + 1,
                    seen_names=seen_names,
                    seen_functions=seen_functions,
                ) or expression_carries_dynamic(
                    value.value,
                    assignments,
                    depth=depth + 1,
                    seen_names=seen_names,
                    seen_functions=seen_functions,
                ):
                    return True
                return any(
                    expression_carries_dynamic(
                        generator.iter,
                        assignments,
                        depth=depth + 1,
                        seen_names=seen_names,
                        seen_functions=seen_functions,
                    )
                    for generator in value.generators
                )

            if isinstance(value, ast.Subscript):
                return expression_carries_dynamic(
                    value.value,
                    assignments,
                    depth=depth + 1,
                    seen_names=seen_names,
                    seen_functions=seen_functions,
                )

            if isinstance(value, ast.Call):
                wrapper = resolved_name(value.func)
                if wrapper in functions and wrapper not in seen_functions:
                    next_seen_functions = set(seen_functions)
                    next_seen_functions.add(wrapper)
                    if factory_carries_dynamic(
                        wrapper,
                        depth + 1,
                        next_seen_functions,
                    ):
                        return True

                if expression_carries_dynamic(
                    value.func,
                    assignments,
                    depth=depth + 1,
                    seen_names=seen_names,
                    seen_functions=seen_functions,
                ):
                    return True

                if wrapper in _CARRIER_CALLS:
                    carried = [*value.args, *(kw.value for kw in value.keywords)]
                    return any(
                        expression_carries_dynamic(
                            item,
                            assignments,
                            depth=depth + 1,
                            seen_names=seen_names,
                            seen_functions=seen_functions,
                        )
                        for item in carried
                    )
                return False

            return False

        for function in reachable_functions:
            scope_nodes = list(_base._function_scope_nodes(function))
            assignments = _simple_assignments(scope_nodes)
            for node in scope_nodes:
                if not isinstance(node, ast.Call):
                    continue
                if not expression_carries_dynamic(node.func, assignments):
                    continue
                findings.append(
                    {
                        "path": relative,
                        "function": function.name,
                        "line": node.lineno,
                        "kind": "alternate-process-creation-call",
                        "detail": (
                            "attestor-reachable call uses runtime-replaceable class "
                            "identity transported through aliases, factories, or containers: "
                            + ",".join(sorted(dynamic_classes))
                        ),
                    }
                )

    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    report = dict(_v4.verify(root))
    existing = list(report.get("findings", []))
    extras = _decorated_class_replacement_findings(root)

    unique: dict[tuple[object, ...], dict[str, object]] = {}
    for item in existing + extras:
        key = (
            item.get("path"),
            item.get("function"),
            item.get("line"),
            item.get("kind"),
            item.get("detail"),
        )
        unique[key] = item
    findings = [
        unique[key]
        for key in sorted(unique, key=lambda value: tuple(str(x) for x in value))
    ]
    report["findings"] = findings
    report["finding_count"] = len(findings)
    report["passed"] = bool(report.get("passed")) and not extras
    return report


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
