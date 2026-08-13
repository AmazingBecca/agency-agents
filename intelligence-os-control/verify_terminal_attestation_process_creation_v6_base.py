from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

import verify_terminal_attestation_process_creation_v5_base as _v5

Finding = _v5.Finding
_SCHEMA = _v5._SCHEMA
_ATTESTOR_NAME = _v5._ATTESTOR_NAME
_base = _v5._base


def __getattr__(name: str):
    return getattr(_v5, name)


def _assignments(nodes: list[ast.AST]) -> dict[str, list[ast.AST]]:
    out: dict[str, list[ast.AST]] = {}

    def projection(value: ast.AST, index: int) -> ast.Subscript:
        return ast.Subscript(value=value, slice=ast.Constant(index), ctx=ast.Load())

    def bind(target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            out.setdefault(target.id, []).append(value)
            return
        if isinstance(target, ast.Starred):
            # A starred capture represents a variable-length projection. Preserve the
            # entire source conservatively so authority analysis remains fail closed.
            bind(target.value, value)
            return
        if not isinstance(target, (ast.Tuple, ast.List)):
            return
        star_positions = [index for index, item in enumerate(target.elts) if isinstance(item, ast.Starred)]
        if len(star_positions) > 1:
            for item in target.elts:
                bind(item, value)
            return
        star = star_positions[0] if star_positions else None
        for index, item in enumerate(target.elts):
            if star is None or index < star:
                bind(item, projection(value, index))
            elif index > star:
                bind(item, projection(value, index - len(target.elts)))
            else:
                bind(item, value)

    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            bind(node.target, node.value)
        elif isinstance(node, ast.NamedExpr):
            bind(node.target, node.value)
    return out


def _namespace_rebind_findings(root: pathlib.Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for source in _base.control_flow._source_files(root):
        relative = source.relative_to(root).as_posix()
        try:
            tree = ast.parse(source.read_bytes(), filename=str(source))
        except (SyntaxError, ValueError, TypeError) as exc:
            raise RuntimeError(f"runner source cannot be parsed: {source}") from exc
        class_names = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}
        if not class_names:
            continue
        functions = _base._top_level_functions(tree)
        attestors = functions.get(_ATTESTOR_NAME, [])
        if len(attestors) != 1:
            continue
        for function in _base._reachable_functions(tree, attestors[0], functions):
            nodes = list(_base._function_scope_nodes(function))
            assigns = _assignments(nodes)
            imports = _base._scope_import_aliases(tree, function)
            strings = _base._local_string_bindings(function)

            def resolved(value: ast.AST) -> str | None:
                return _base._resolve_alias(_base._dotted_name(value), imports)

            def callee_is(value: ast.AST, expected: set[str], depth: int = 0, seen: set[str] | None = None) -> bool:
                if depth > 8:
                    return False
                direct = resolved(value)
                if direct in expected:
                    return True
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(callee_is(v, expected, depth + 1, nxt) for v in assigns.get(value.id, []))
                return False

            def builtins_object(value: ast.AST, depth: int = 0, seen: set[str] | None = None) -> bool:
                if depth > 8:
                    return False
                if resolved(value) == "builtins":
                    return True
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(builtins_object(v, depth + 1, nxt) for v in assigns.get(value.id, []))
                return False

            def builtins_namespace(value: ast.AST, depth: int = 0, seen: set[str] | None = None) -> bool:
                if depth > 8:
                    return False
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(builtins_namespace(v, depth + 1, nxt) for v in assigns.get(value.id, []))
                if isinstance(value, ast.Attribute) and value.attr == "__dict__":
                    return builtins_object(value.value, depth + 1, seen)
                if isinstance(value, ast.Call):
                    if callee_is(value.func, {"vars", "builtins.vars"}, depth + 1, seen) and len(value.args) == 1:
                        return builtins_object(value.args[0], depth + 1, seen)
                    if callee_is(value.func, {"getattr", "builtins.getattr"}, depth + 1, seen) and len(value.args) >= 2:
                        attrs = _base._string_values(value.args[1], strings)
                        return builtins_object(value.args[0], depth + 1, seen) and (attrs is None or "__dict__" in attrs)
                return False

            def builtins_lookup(value: ast.AST, depth: int = 0, seen: set[str] | None = None) -> bool:
                if depth > 8:
                    return False
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Attribute) and value.attr in {"get", "__getitem__"}:
                    return builtins_namespace(value.value, depth + 1, seen)
                if isinstance(value, ast.Call) and callee_is(value.func, {"getattr", "builtins.getattr"}, depth + 1, seen) and len(value.args) >= 2:
                    attrs = _base._string_values(value.args[1], strings)
                    return builtins_namespace(value.args[0], depth + 1, seen) and (attrs is None or bool({"get", "__getitem__"} & attrs))
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(builtins_lookup(v, depth + 1, nxt) for v in assigns.get(value.id, []))
                return False

            def globals_factory(value: ast.AST, depth: int = 0, seen: set[str] | None = None) -> bool:
                if depth > 8:
                    return False
                if callee_is(value, {"globals", "builtins.globals"}, depth, seen):
                    return True
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(globals_factory(v, depth + 1, nxt) for v in assigns.get(value.id, []))
                if isinstance(value, ast.Call):
                    if callee_is(value.func, {"getattr", "builtins.getattr"}, depth + 1, seen) and len(value.args) >= 2:
                        attrs = _base._string_values(value.args[1], strings)
                        return builtins_object(value.args[0], depth + 1, seen) and (attrs is None or "globals" in attrs)
                    if callee_is(value.func, {"operator.getitem"}, depth + 1, seen) and len(value.args) >= 2:
                        keys = _base._string_values(value.args[1], strings)
                        return builtins_namespace(value.args[0], depth + 1, seen) and (keys is None or "globals" in keys)
                    if builtins_lookup(value.func, depth + 1, seen) and value.args:
                        keys = _base._string_values(value.args[0], strings)
                        return keys is None or "globals" in keys
                if isinstance(value, ast.Subscript) and builtins_namespace(value.value, depth + 1, seen):
                    keys = _base._string_values(value.slice, strings)
                    return keys is None or "globals" in keys
                return False

            def module(value: ast.AST, depth: int = 0, seen: set[str] | None = None) -> bool:
                if depth > 8:
                    return False
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(module(v, depth + 1, nxt) for v in assigns.get(value.id, []))
                if isinstance(value, ast.Subscript):
                    return resolved(value.value) == "sys.modules" and isinstance(value.slice, ast.Name) and value.slice.id == "__name__"
                if isinstance(value, ast.Call):
                    return resolved(value.func) == "sys.modules.get" and bool(value.args) and isinstance(value.args[0], ast.Name) and value.args[0].id == "__name__"
                return False

            helper_namespace_cache: dict[str, bool] = {}

            def helper_returns_namespace(name: str, depth: int = 0, seen_helpers: set[str] | None = None) -> bool:
                if depth > 8:
                    return True
                if name in helper_namespace_cache:
                    return helper_namespace_cache[name]
                definitions = functions.get(name, [])
                if len(definitions) != 1:
                    return False
                seen_helpers = set() if seen_helpers is None else set(seen_helpers)
                if name in seen_helpers:
                    return False
                definition = definitions[0]
                helper_nodes = list(_base._function_scope_nodes(definition))
                helper_assigns = _assignments(helper_nodes)
                helper_imports = _base._scope_import_aliases(tree, definition)
                helper_strings = _base._local_string_bindings(definition)
                next_helpers = seen_helpers | {name}
                helper_namespace_cache[name] = False

                def helper_resolved(value: ast.AST) -> str | None:
                    return _base._resolve_alias(_base._dotted_name(value), helper_imports)

                def helper_projection_is_namespace(
                    container: ast.AST,
                    key: ast.AST,
                    level: int,
                    seen_names: set[str],
                ) -> bool:
                    if level > 8:
                        return True
                    if isinstance(container, ast.Name):
                        if container.id in seen_names:
                            return False
                        candidates = helper_assigns.get(container.id, [])
                        if not candidates:
                            return False
                        nxt = seen_names | {container.id}
                        return any(
                            helper_projection_is_namespace(candidate, key, level + 1, nxt)
                            for candidate in candidates
                        )
                    if isinstance(container, ast.Call):
                        call_name = helper_resolved(container.func)
                        if call_name in functions and call_name not in next_helpers:
                            return helper_returns_namespace(call_name, depth + 1, next_helpers)
                        return False
                    if isinstance(container, (ast.Tuple, ast.List)):
                        if isinstance(key, ast.Constant) and isinstance(key.value, int):
                            index = key.value
                            if index < 0:
                                index += len(container.elts)
                            if index < 0 or index >= len(container.elts):
                                return False
                            return helper_value_is_namespace(
                                container.elts[index],
                                level + 1,
                                seen_names,
                            )
                        return any(
                            helper_value_is_namespace(item, level + 1, seen_names)
                            for item in container.elts
                        )
                    if isinstance(container, ast.Dict):
                        requested = _base._string_values(key, helper_strings)
                        if requested is None:
                            return any(
                                value is not None
                                and helper_value_is_namespace(value, level + 1, seen_names)
                                for value in container.values
                            )
                        for dict_key, dict_value in zip(container.keys, container.values):
                            if dict_value is None:
                                continue
                            if dict_key is None:
                                if helper_value_is_namespace(dict_value, level + 1, seen_names):
                                    return True
                                continue
                            candidate_keys = _base._string_values(dict_key, helper_strings)
                            if candidate_keys is None or requested & candidate_keys:
                                if helper_value_is_namespace(dict_value, level + 1, seen_names):
                                    return True
                        return False
                    return False

                def helper_value_is_namespace(value: ast.AST, level: int = 0, seen_names: set[str] | None = None) -> bool:
                    if level > 8:
                        return True
                    seen_names = set() if seen_names is None else set(seen_names)
                    if isinstance(value, ast.Name):
                        if value.id in seen_names:
                            return False
                        candidates = helper_assigns.get(value.id, [])
                        if not candidates:
                            return False
                        nxt = seen_names | {value.id}
                        return any(helper_value_is_namespace(candidate, level + 1, nxt) for candidate in candidates)
                    if isinstance(value, (ast.Tuple, ast.List)):
                        return any(helper_value_is_namespace(item, level + 1, seen_names) for item in value.elts)
                    if isinstance(value, ast.Dict):
                        return any(
                            item is not None and helper_value_is_namespace(item, level + 1, seen_names)
                            for item in value.values
                        )
                    if isinstance(value, ast.Attribute) and value.attr == "__globals__":
                        return True
                    if isinstance(value, ast.Subscript):
                        return helper_projection_is_namespace(value.value, value.slice, level + 1, seen_names)
                    if isinstance(value, ast.NamedExpr):
                        return helper_value_is_namespace(value.value, level + 1, seen_names)
                    if isinstance(value, ast.IfExp):
                        return helper_value_is_namespace(value.body, level + 1, seen_names) or helper_value_is_namespace(value.orelse, level + 1, seen_names)
                    if isinstance(value, ast.BoolOp):
                        return any(helper_value_is_namespace(item, level + 1, seen_names) for item in value.values)
                    if isinstance(value, ast.Call):
                        call_name = helper_resolved(value.func)
                        if call_name in {"globals", "builtins.globals"} and not value.args and not value.keywords:
                            return True
                        if call_name in functions and call_name not in next_helpers:
                            if helper_returns_namespace(call_name, depth + 1, next_helpers):
                                return True
                        if call_name in {"getattr", "builtins.getattr"} and len(value.args) >= 2:
                            attrs = _base._string_values(value.args[1], helper_strings)
                            if attrs is None or "__globals__" in attrs:
                                return True
                    return False

                for helper_node in helper_nodes:
                    if isinstance(helper_node, ast.Return) and helper_node.value is not None:
                        if helper_value_is_namespace(helper_node.value):
                            helper_namespace_cache[name] = True
                            return True
                return False

            def namespace(value: ast.AST, depth: int = 0, seen: set[str] | None = None) -> bool:
                if depth > 8:
                    return False
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(namespace(v, depth + 1, nxt) for v in assigns.get(value.id, []))
                if isinstance(value, ast.Subscript):
                    return namespace(value.value, depth + 1, seen)
                if isinstance(value, ast.Attribute):
                    if value.attr == "__globals__":
                        return True
                    if value.attr == "__dict__":
                        return module(value.value, depth + 1, seen)
                if isinstance(value, ast.Call):
                    if not value.args and not value.keywords and globals_factory(value.func, depth + 1, seen):
                        return True
                    if callee_is(value.func, {"vars", "builtins.vars"}, depth + 1, seen) and value.args:
                        return module(value.args[0], depth + 1, seen)
                    if callee_is(value.func, {"getattr", "builtins.getattr"}, depth + 1, seen) and len(value.args) >= 2:
                        attrs = _base._string_values(value.args[1], strings)
                        if attrs is None or "__globals__" in attrs:
                            return True
                    for helper_name in functions:
                        if callee_is(value.func, {helper_name}, depth + 1, seen) and helper_returns_namespace(helper_name, depth + 1):
                            return True
                return False

            def names(value: ast.AST) -> set[str]:
                values = _base._string_values(value, strings)
                return set(class_names) if values is None else class_names & values

            def map_names(value: ast.AST) -> set[str]:
                if isinstance(value, ast.Dict):
                    found: set[str] = set()
                    for key in value.keys:
                        if key is None:
                            return set(class_names)
                        found.update(names(key))
                    return found
                if isinstance(value, ast.Name) and assigns.get(value.id):
                    found: set[str] = set()
                    for candidate in assigns[value.id]:
                        found.update(map_names(candidate))
                    return found
                return set(class_names)

            def bound_module_setattr(value: ast.AST, depth: int = 0, seen: set[str] | None = None) -> bool:
                if depth > 8:
                    return False
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Attribute) and value.attr == "__setattr__" and module(value.value):
                    return True
                if isinstance(value, ast.Call) and callee_is(value.func, {"getattr", "builtins.getattr"}, depth + 1, seen) and len(value.args) >= 2:
                    attrs = _base._string_values(value.args[1], strings)
                    return module(value.args[0]) and (attrs is None or "__setattr__" in attrs)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(bound_module_setattr(v, depth + 1, nxt) for v in assigns.get(value.id, []))
                return False

            def partial_names(value: ast.AST, depth: int = 0, seen: set[str] | None = None) -> set[str] | None:
                if depth > 8:
                    return set(class_names)
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return None
                    nxt = seen | {value.id}
                    results = [partial_names(v, depth + 1, nxt) for v in assigns.get(value.id, [])]
                    hits = [r for r in results if r is not None]
                    return None if not hits else set().union(*hits)
                if not isinstance(value, ast.Call) or resolved(value.func) != "functools.partial" or not value.args:
                    return None
                target = value.args[0]
                if callee_is(target, {"setattr", "builtins.setattr"}, depth + 1, seen) and len(value.args) >= 3 and module(value.args[1]):
                    return names(value.args[2])
                if bound_module_setattr(target) and len(value.args) >= 2:
                    return names(value.args[1])
                return None

            def bound_update(value: ast.AST, depth: int = 0, seen: set[str] | None = None) -> bool:
                if depth > 8:
                    return False
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Attribute) and value.attr == "update" and namespace(value.value):
                    return True
                if isinstance(value, ast.Call) and callee_is(value.func, {"getattr", "builtins.getattr"}, depth + 1, seen) and len(value.args) >= 2:
                    attrs = _base._string_values(value.args[1], strings)
                    return namespace(value.args[0]) and (attrs is None or "update" in attrs)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(bound_update(v, depth + 1, nxt) for v in assigns.get(value.id, []))
                return False

            def add(node: ast.AST, affected: set[str], mechanism: str) -> None:
                if affected:
                    findings.append({"path": relative, "function": function.name, "line": getattr(node, "lineno", 0), "kind": "alternate-process-creation-call", "detail": f"attestor-reachable {mechanism} can replace reviewed class identity: {','.join(sorted(affected))}"})

            def assignment_targets(node: ast.AST) -> list[ast.AST]:
                if isinstance(node, ast.Assign):
                    return list(node.targets)
                if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                    return [node.target]
                return []

            for node in nodes:
                for target in assignment_targets(node):
                    if isinstance(target, ast.Subscript) and namespace(target.value):
                        add(node, names(target.slice), "module namespace subscript write")
                if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr) and namespace(node.target):
                    add(node, map_names(node.value), "module namespace |=")
                    continue
                if not isinstance(node, ast.Call):
                    continue
                partial = partial_names(node.func)
                if partial is not None:
                    add(node, partial, "partial setattr")
                    continue
                if bound_module_setattr(node.func) and node.args:
                    add(node, names(node.args[0]), "bound/reflected module __setattr__")
                    continue
                call = resolved(node.func)
                if call == "types.ModuleType.__setattr__" and len(node.args) >= 2 and module(node.args[0]):
                    add(node, names(node.args[1]), "ModuleType.__setattr__")
                    continue
                if bound_update(node.func):
                    affected: set[str] = set()
                    if node.args:
                        affected.update(map_names(node.args[0]))
                    for kw in node.keywords:
                        affected.update(map_names(kw.value) if kw.arg is None else ({kw.arg} & class_names))
                    add(node, affected or set(class_names), "module namespace update")
                    continue
                if isinstance(node.func, ast.Attribute) and node.func.attr == "__setitem__" and namespace(node.func.value) and node.args:
                    add(node, names(node.args[0]), "module namespace __setitem__")
                    continue
                if call == "operator.setitem" and len(node.args) >= 2 and namespace(node.args[0]):
                    add(node, names(node.args[1]), "operator.setitem module namespace write")
                    continue
                if call == "operator.ior" and len(node.args) >= 2 and namespace(node.args[0]):
                    add(node, map_names(node.args[1]), "operator.ior module namespace update")
    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    report = dict(_v5.verify(root))
    extras = _namespace_rebind_findings(root)
    merged = list(report.get("findings", [])) + extras
    unique = {(i.get("path"), i.get("function"), i.get("line"), i.get("kind"), i.get("detail")): i for i in merged}
    findings = [unique[k] for k in sorted(unique, key=lambda v: tuple(str(x) for x in v))]
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
