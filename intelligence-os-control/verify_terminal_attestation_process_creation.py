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


def _decorated_class_replacement_findings(root: pathlib.Path) -> list[dict[str, object]]:
    """Reject attestor calls through runtime-replaceable class identity.

    A decorated class is not the reviewed class object after definition. The same
    is true when a reviewed class name is rebound at module scope. Track that
    authority through bounded local aliases, helper returns, conditional values,
    literal/container transport, generator/comprehension transport, and calls
    whose callee already carries the dynamic class identity.
    """
    findings: list[dict[str, object]] = []

    for source in _base.control_flow._source_files(root):
        relative = source.relative_to(root).as_posix()
        raw = source.read_bytes()
        try:
            tree = ast.parse(raw, filename=str(source))
        except (SyntaxError, ValueError, TypeError) as exc:
            raise RuntimeError(f"runner source cannot be parsed: {source}") from exc

        class_names = {
            node.name for node in tree.body if isinstance(node, ast.ClassDef)
        }
        dynamic_classes = {
            node.name
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.decorator_list
        }

        # A later module-scope write replaces the reviewed class identity even
        # if the original class body itself had no decorator or custom call hook.
        for node in tree.body:
            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                targets.extend(node.targets)
            elif isinstance(node, ast.AnnAssign):
                targets.append(node.target)
            for target in targets:
                if isinstance(target, ast.Name) and target.id in class_names:
                    dynamic_classes.add(target.id)

        if not dynamic_classes:
            continue

        functions = _base._top_level_functions(tree)
        attestors = functions.get(_ATTESTOR_NAME, [])
        if len(attestors) != 1:
            continue
        attestor = attestors[0]
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
                # The comprehension target can rename authority from its iterable
                # (for example: ``item for item in (_Mutator,)``). Conservatively
                # retain authority from every iterable rather than treating the
                # target name as a fresh untainted local.
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
                # A projection from a dynamic carrier can recover the class
                # object. False negatives are worse here than conservative
                # rejection because the result is later invoked as authority.
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

                # Calling a transported dynamic class can itself produce the
                # callable object later invoked by the attestor.
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

        for function in _base._reachable_functions(tree, attestor, functions):
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
