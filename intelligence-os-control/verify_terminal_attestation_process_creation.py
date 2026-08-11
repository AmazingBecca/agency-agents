from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

import verify_terminal_attestation_process_creation_v3_base as _v3


Finding = _v3.Finding
_SCHEMA = _v3._SCHEMA
_ATTESTOR_NAME = _v3._ATTESTOR_NAME
_base = _v3._base
_MAPPING_TRANSPORT_METHODS = {
    "update",
    "setdefault",
    "__setitem__",
    "get",
    "__getitem__",
}
_DYNAMIC_CLASS_METHODS = {"__call__", "__new__"}
_CONTAINER_RETURNERS = {
    "list",
    "tuple",
    "set",
    "frozenset",
    "dict",
    "next",
    "builtins.list",
    "builtins.tuple",
    "builtins.set",
    "builtins.frozenset",
    "builtins.dict",
    "builtins.next",
}


def __getattr__(name: str):
    return getattr(_v3, name)


def _bound_mapping_method_authority_findings(root: pathlib.Path) -> list[dict[str, object]]:
    """Fail closed on wrapped or dynamically reconstructed mapping transport."""
    findings: list[dict[str, object]] = []

    for source in _base.control_flow._source_files(root):
        relative = source.relative_to(root).as_posix()
        raw = source.read_bytes()
        try:
            tree = ast.parse(raw, filename=str(source))
        except (SyntaxError, ValueError, TypeError) as exc:
            raise RuntimeError(f"runner source cannot be parsed: {source}") from exc

        functions = _base._top_level_functions(tree)
        attestors = functions.get(_ATTESTOR_NAME, [])
        if len(attestors) != 1:
            continue
        attestor = attestors[0]

        class_definitions: dict[str, list[ast.ClassDef]] = {}
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                class_definitions.setdefault(node.name, []).append(node)

        dynamic_classes = {
            name
            for name, definitions in class_definitions.items()
            if len(definitions) == 1
            and (
                bool(definitions[0].decorator_list)
                or any(
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name in _DYNAMIC_CLASS_METHODS
                    for item in definitions[0].body
                )
                or any(keyword.arg == "metaclass" for keyword in definitions[0].keywords)
            )
        }

        # A class can become dynamically callable after definition. Treat writes to
        # __call__ or __new__ as authority-bearing even when wrapped by staticmethod,
        # classmethod, or another descriptor.
        for node in tree.body:
            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                targets.extend(node.targets)
            elif isinstance(node, ast.AnnAssign):
                targets.append(node.target)
            elif isinstance(node, ast.AugAssign):
                targets.append(node.target)
            for target in targets:
                if not isinstance(target, ast.Attribute):
                    continue
                if target.attr not in _DYNAMIC_CLASS_METHODS:
                    continue
                if isinstance(target.value, ast.Name) and target.value.id in class_definitions:
                    dynamic_classes.add(target.value.id)

        # Subclasses inherit constructor/call authority. Keep the closure bounded by
        # the finite reviewed top-level class graph.
        changed = True
        while changed:
            changed = False
            for name, definitions in class_definitions.items():
                if name in dynamic_classes or len(definitions) != 1:
                    continue
                bases = {
                    _base._dotted_name(base)
                    for base in definitions[0].bases
                    if _base._dotted_name(base)
                }
                if bases & dynamic_classes:
                    dynamic_classes.add(name)
                    changed = True

        def assignment_map(function: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, list[ast.AST]]:
            assignments: dict[str, list[ast.AST]] = {}

            def remember(target: ast.AST, value: ast.AST) -> None:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(value)
                    return
                if isinstance(target, ast.Starred):
                    remember(target.value, value)
                    return
                if isinstance(target, (ast.Tuple, ast.List)):
                    if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
                        for left, right in zip(target.elts, value.elts):
                            remember(left, right)
                    else:
                        for left in target.elts:
                            remember(left, value)

            for node in _base._function_scope_nodes(function):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        remember(target, node.value)
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    remember(node.target, node.value)
                elif isinstance(node, ast.NamedExpr):
                    remember(node.target, node.value)
            return assignments

        factory_cache: dict[str, set[str]] = {}

        for function in _base._reachable_functions(tree, attestor, functions):
            import_aliases = _base._scope_import_aliases(tree, function)
            scope_nodes = list(_base._function_scope_nodes(function))
            assignments = assignment_map(function)

            def resolved_name(value: ast.AST) -> str | None:
                dotted = _base._dotted_name(value)
                return _base._resolve_alias(dotted, import_aliases)

            def static_strings(
                value: ast.AST,
                assignment_candidates: dict[str, list[ast.AST]],
                seen: set[str] | None = None,
            ) -> set[str]:
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return {value.value}
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return set()
                    candidates = assignment_candidates.get(value.id, [])
                    if not candidates:
                        return set()
                    next_seen = set(seen)
                    next_seen.add(value.id)
                    recovered: set[str] = set()
                    for candidate in candidates:
                        recovered.update(static_strings(candidate, assignment_candidates, next_seen))
                        if len(recovered) >= 32:
                            return set(sorted(recovered)[:32])
                    return recovered
                if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
                    left = static_strings(value.left, assignment_candidates, seen)
                    right = static_strings(value.right, assignment_candidates, seen)
                    return {
                        prefix + suffix
                        for prefix in left
                        for suffix in right
                        if len(prefix) + len(suffix) <= 128
                    }
                if isinstance(value, ast.JoinedStr):
                    parts: list[set[str]] = []
                    for item in value.values:
                        if isinstance(item, ast.Constant) and isinstance(item.value, str):
                            parts.append({item.value})
                        elif isinstance(item, ast.FormattedValue):
                            parts.append(static_strings(item.value, assignment_candidates, seen))
                        else:
                            return set()
                    combined = {""}
                    for part in parts:
                        if not part:
                            return set()
                        combined = {
                            prefix + suffix
                            for prefix in combined
                            for suffix in part
                            if len(prefix) + len(suffix) <= 128
                        }
                        if len(combined) > 32:
                            combined = set(sorted(combined)[:32])
                    return combined
                return set()

            def factory_dynamic_classes(
                name: str,
                depth: int = 0,
                seen_factories: set[str] | None = None,
            ) -> set[str]:
                if name in factory_cache:
                    return set(factory_cache[name])
                if depth > 8:
                    return {"unresolved-factory-depth"}
                seen_factories = set() if seen_factories is None else set(seen_factories)
                if name in seen_factories:
                    return set()
                definitions = functions.get(name, [])
                if len(definitions) != 1:
                    return set()
                next_seen = set(seen_factories)
                next_seen.add(name)
                definition = definitions[0]
                local_assignments = assignment_map(definition)
                local_aliases = _base._scope_import_aliases(tree, definition)

                def local_resolved(value: ast.AST) -> str | None:
                    return _base._resolve_alias(_base._dotted_name(value), local_aliases)

                def recover(
                    value: ast.AST,
                    seen_names: set[str] | None = None,
                    inner_depth: int = 0,
                ) -> set[str]:
                    if inner_depth > 12:
                        return {"unresolved-expression-depth"}
                    seen_names = set() if seen_names is None else set(seen_names)
                    if isinstance(value, ast.Name):
                        if value.id in dynamic_classes:
                            return {value.id}
                        if value.id in seen_names:
                            return set()
                        candidates = local_assignments.get(value.id, [])
                        if not candidates:
                            return set()
                        next_names = set(seen_names)
                        next_names.add(value.id)
                        recovered: set[str] = set()
                        for candidate in candidates:
                            recovered.update(recover(candidate, next_names, inner_depth + 1))
                            if len(recovered) >= 32:
                                return set(sorted(recovered)[:32])
                        return recovered
                    if isinstance(value, ast.Attribute):
                        if value.attr in _MAPPING_TRANSPORT_METHODS:
                            return {f"bound:{value.attr}"}
                        return set()
                    if isinstance(value, ast.Call):
                        wrapper = local_resolved(value.func)
                        if wrapper in dynamic_classes:
                            return {wrapper}
                        if wrapper in functions:
                            return factory_dynamic_classes(wrapper, depth + 1, next_seen)
                        if wrapper in {"getattr", "builtins.getattr"} and len(value.args) >= 2:
                            methods = static_strings(value.args[1], local_assignments)
                            dangerous = methods & _MAPPING_TRANSPORT_METHODS
                            if dangerous:
                                return {"reflected:" + "/".join(sorted(dangerous))}
                        if wrapper == "operator.attrgetter" and value.args:
                            dangerous = static_strings(value.args[0], local_assignments) & _MAPPING_TRANSPORT_METHODS
                            if dangerous:
                                return {"attrgetter:" + "/".join(sorted(dangerous))}
                        if wrapper == "operator.methodcaller" and value.args:
                            dangerous = static_strings(value.args[0], local_assignments) & _MAPPING_TRANSPORT_METHODS
                            if dangerous:
                                return {"methodcaller:" + "/".join(sorted(dangerous))}
                        if wrapper == "functools.partial" and value.args:
                            recovered = recover(value.args[0], seen_names, inner_depth + 1)
                            if recovered:
                                return {"partial:" + item for item in recovered}
                        if wrapper in _CONTAINER_RETURNERS:
                            recovered: set[str] = set()
                            for argument in value.args:
                                recovered.update(recover(argument, seen_names, inner_depth + 1))
                            for keyword in value.keywords:
                                recovered.update(recover(keyword.value, seen_names, inner_depth + 1))
                            return recovered
                        return set()
                    if isinstance(value, ast.Subscript):
                        return recover(value.value, seen_names, inner_depth + 1)
                    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                        recovered: set[str] = set()
                        for item in value.elts:
                            recovered.update(recover(item, seen_names, inner_depth + 1))
                        return recovered
                    if isinstance(value, ast.Dict):
                        recovered: set[str] = set()
                        for item in value.values:
                            recovered.update(recover(item, seen_names, inner_depth + 1))
                        return recovered
                    if isinstance(value, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                        return recover(value.elt, seen_names, inner_depth + 1)
                    if isinstance(value, ast.DictComp):
                        return recover(value.value, seen_names, inner_depth + 1)
                    if isinstance(value, ast.IfExp):
                        return recover(value.body, seen_names, inner_depth + 1) | recover(
                            value.orelse, seen_names, inner_depth + 1
                        )
                    if isinstance(value, ast.Lambda):
                        recovered: set[str] = set()
                        for wrapped in ast.walk(value.body):
                            if isinstance(wrapped, ast.Attribute) and wrapped.attr in _MAPPING_TRANSPORT_METHODS:
                                recovered.add(f"lambda-bound:{wrapped.attr}")
                            elif isinstance(wrapped, ast.Call):
                                recovered.update(recover(wrapped.func, seen_names, inner_depth + 1))
                        return recovered
                    return set()

                recovered: set[str] = set()
                for node in ast.walk(definition):
                    if isinstance(node, ast.Return) and node.value is not None:
                        recovered.update(recover(node.value))
                        if len(recovered) >= 32:
                            recovered = set(sorted(recovered)[:32])
                            break
                factory_cache[name] = set(recovered)
                return recovered

            def expression_dynamic(
                value: ast.AST,
                seen_names: set[str] | None = None,
                depth: int = 0,
            ) -> set[str]:
                if depth > 12:
                    return {"unresolved-expression-depth"}
                seen_names = set() if seen_names is None else set(seen_names)
                if isinstance(value, ast.Name):
                    if value.id in dynamic_classes:
                        return {f"class:{value.id}"}
                    if value.id in seen_names:
                        return set()
                    candidates = assignments.get(value.id, [])
                    if not candidates:
                        resolved = resolved_name(value)
                        if resolved in {"operator.getitem", "operator.setitem"}:
                            return {resolved}
                        return set()
                    next_seen = set(seen_names)
                    next_seen.add(value.id)
                    recovered: set[str] = set()
                    for candidate in candidates:
                        recovered.update(expression_dynamic(candidate, next_seen, depth + 1))
                        if len(recovered) >= 32:
                            return set(sorted(recovered)[:32])
                    return recovered
                if isinstance(value, ast.Attribute):
                    if value.attr in _MAPPING_TRANSPORT_METHODS:
                        receiver = _base._dotted_name(value.value)
                        return {f"bound:{value.attr}:{receiver or '<dynamic>'}"}
                    resolved = resolved_name(value)
                    if resolved in {"operator.getitem", "operator.setitem"}:
                        return {resolved}
                    return set()
                if isinstance(value, ast.Call):
                    wrapper = resolved_name(value.func)
                    if wrapper in dynamic_classes:
                        return {f"custom-callable-object:{wrapper}"}
                    if wrapper in functions:
                        produced = factory_dynamic_classes(wrapper)
                        if produced:
                            return {"factory:" + item for item in produced}
                    if wrapper in {"getattr", "builtins.getattr"} and len(value.args) >= 2:
                        dangerous = static_strings(value.args[1], assignments) & _MAPPING_TRANSPORT_METHODS
                        if dangerous:
                            receiver = _base._dotted_name(value.args[0])
                            return {
                                "reflected:"
                                + "/".join(sorted(dangerous))
                                + ":"
                                + (receiver or "<dynamic>")
                            }
                    if wrapper == "operator.attrgetter" and value.args:
                        dangerous = static_strings(value.args[0], assignments) & _MAPPING_TRANSPORT_METHODS
                        if dangerous:
                            return {"attrgetter:" + "/".join(sorted(dangerous))}
                    if wrapper == "operator.methodcaller" and value.args:
                        dangerous = static_strings(value.args[0], assignments) & _MAPPING_TRANSPORT_METHODS
                        if dangerous:
                            return {"methodcaller:" + "/".join(sorted(dangerous))}
                    if wrapper == "functools.partial" and value.args:
                        if (
                            resolved_name(value.args[0]) in {"getattr", "builtins.getattr"}
                            and len(value.args) >= 3
                        ):
                            dangerous = static_strings(value.args[2], assignments) & _MAPPING_TRANSPORT_METHODS
                            if dangerous:
                                return {"partial-reflected:" + "/".join(sorted(dangerous))}
                        inner = expression_dynamic(value.args[0], seen_names, depth + 1)
                        if inner:
                            return {"partial:" + item for item in inner}
                    if wrapper in _CONTAINER_RETURNERS:
                        recovered: set[str] = set()
                        for argument in value.args:
                            recovered.update(expression_dynamic(argument, seen_names, depth + 1))
                        for keyword in value.keywords:
                            recovered.update(expression_dynamic(keyword.value, seen_names, depth + 1))
                        return recovered
                    return set()
                if isinstance(value, ast.Subscript):
                    return expression_dynamic(value.value, seen_names, depth + 1)
                if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                    recovered: set[str] = set()
                    for item in value.elts:
                        recovered.update(expression_dynamic(item, seen_names, depth + 1))
                    return recovered
                if isinstance(value, ast.Dict):
                    recovered: set[str] = set()
                    for item in value.values:
                        recovered.update(expression_dynamic(item, seen_names, depth + 1))
                    return recovered
                if isinstance(value, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                    return expression_dynamic(value.elt, seen_names, depth + 1)
                if isinstance(value, ast.DictComp):
                    return expression_dynamic(value.value, seen_names, depth + 1)
                if isinstance(value, ast.IfExp):
                    return expression_dynamic(value.body, seen_names, depth + 1) | expression_dynamic(
                        value.orelse, seen_names, depth + 1
                    )
                if isinstance(value, ast.Lambda):
                    recovered: set[str] = set()
                    for wrapped in ast.walk(value.body):
                        if isinstance(wrapped, ast.Attribute) and wrapped.attr in _MAPPING_TRANSPORT_METHODS:
                            recovered.add(f"lambda-bound:{wrapped.attr}")
                        elif isinstance(wrapped, ast.Call):
                            recovered.update(expression_dynamic(wrapped.func, seen_names, depth + 1))
                    return recovered
                return set()

            for node in scope_nodes:
                if not isinstance(node, ast.Call):
                    continue
                targets = expression_dynamic(node.func)
                if not targets:
                    continue
                findings.append(
                    {
                        "path": relative,
                        "function": function.name,
                        "line": node.lineno,
                        "kind": "alternate-process-creation-call",
                        "detail": (
                            "attestor-reachable mapping transport is invoked through "
                            "aliased, wrapped, factory, container, or dynamic class authority: "
                            + ",".join(sorted(targets))
                        ),
                    }
                )

    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    report = dict(_v3.verify(root))
    existing = list(report.get("findings", []))
    extras = _bound_mapping_method_authority_findings(root)

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
