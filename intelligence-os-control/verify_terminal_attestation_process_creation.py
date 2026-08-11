from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

import verify_terminal_attestation_process_creation_v6_base as _v6

Finding = _v6.Finding
_SCHEMA = _v6._SCHEMA
_ATTESTOR_NAME = _v6._ATTESTOR_NAME
_base = _v6._base


def __getattr__(name: str):
    return getattr(_v6, name)


def _frame_namespace_rebind_findings(root: pathlib.Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for source in _base.control_flow._source_files(root):
        relative = source.relative_to(root).as_posix()
        try:
            tree = ast.parse(source.read_bytes(), filename=str(source))
        except (SyntaxError, ValueError, TypeError) as exc:
            raise RuntimeError(f"runner source cannot be parsed: {source}") from exc

        class_names = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
        if not class_names:
            continue
        functions = _base._top_level_functions(tree)
        attestors = functions.get(_ATTESTOR_NAME, [])
        if len(attestors) != 1:
            continue

        for function in _base._reachable_functions(tree, attestors[0], functions):
            nodes = list(_base._function_scope_nodes(function))
            imports = _base._scope_import_aliases(tree, function)
            strings = _base._local_string_bindings(function)
            assigns = _v6._assignments(nodes)

            def resolved(value: ast.AST) -> str | None:
                return _base._resolve_alias(_base._dotted_name(value), imports)

            def callee_is(
                value: ast.AST,
                expected: set[str],
                depth: int = 0,
                seen: set[str] | None = None,
            ) -> bool:
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
                    return any(callee_is(candidate, expected, depth + 1, nxt) for candidate in assigns.get(value.id, []))
                return False

            def authority_name(value: ast.AST, local_strings: dict[str, set[str]] | None = None) -> bool:
                values = _base._string_values(value, strings if local_strings is None else local_strings)
                return values is None or bool({"__globals__", "f_globals"} & values)

            def attrgetter_namespace_factory(
                value: ast.AST,
                depth: int = 0,
                seen: set[str] | None = None,
            ) -> bool:
                if depth > 8:
                    return False
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(attrgetter_namespace_factory(candidate, depth + 1, nxt) for candidate in assigns.get(value.id, []))
                if not isinstance(value, ast.Call) or not value.args:
                    return False
                if not callee_is(value.func, {"operator.attrgetter"}, depth + 1, seen):
                    return False
                attrs = _base._string_values(value.args[0], strings)
                return attrs is None or bool({"__globals__", "f_globals"} & attrs)

            helper_namespace_cache: dict[str, bool] = {}

            def helper_returns_namespace(
                name: str,
                depth: int = 0,
                seen_helpers: set[str] | None = None,
            ) -> bool:
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
                helper_imports = _base._scope_import_aliases(tree, definition)
                helper_strings = _base._local_string_bindings(definition)
                helper_assigns = _v6._assignments(helper_nodes)
                next_helpers = seen_helpers | {name}
                helper_namespace_cache[name] = False

                def helper_resolved(value: ast.AST) -> str | None:
                    return _base._resolve_alias(_base._dotted_name(value), helper_imports)

                def helper_callee_is(
                    value: ast.AST,
                    expected: set[str],
                    level: int = 0,
                    seen_names: set[str] | None = None,
                ) -> bool:
                    if level > 8:
                        return False
                    direct = helper_resolved(value)
                    if direct in expected:
                        return True
                    seen_names = set() if seen_names is None else set(seen_names)
                    if isinstance(value, ast.Name):
                        if value.id in seen_names:
                            return False
                        nxt = seen_names | {value.id}
                        return any(
                            helper_callee_is(candidate, expected, level + 1, nxt)
                            for candidate in helper_assigns.get(value.id, [])
                        )
                    return False

                def helper_attrgetter_factory(
                    value: ast.AST,
                    level: int = 0,
                    seen_names: set[str] | None = None,
                ) -> bool:
                    if level > 8:
                        return False
                    seen_names = set() if seen_names is None else set(seen_names)
                    if isinstance(value, ast.Name):
                        if value.id in seen_names:
                            return False
                        nxt = seen_names | {value.id}
                        return any(
                            helper_attrgetter_factory(candidate, level + 1, nxt)
                            for candidate in helper_assigns.get(value.id, [])
                        )
                    if not isinstance(value, ast.Call) or not value.args:
                        return False
                    if not helper_callee_is(value.func, {"operator.attrgetter"}, level + 1, seen_names):
                        return False
                    attrs = _base._string_values(value.args[0], helper_strings)
                    return attrs is None or bool({"__globals__", "f_globals"} & attrs)

                def helper_value_is_namespace(
                    value: ast.AST,
                    level: int = 0,
                    seen_names: set[str] | None = None,
                ) -> bool:
                    if level > 8:
                        return True
                    seen_names = set() if seen_names is None else set(seen_names)
                    if isinstance(value, ast.Name):
                        if value.id in seen_names:
                            return False
                        nxt = seen_names | {value.id}
                        return any(
                            helper_value_is_namespace(candidate, level + 1, nxt)
                            for candidate in helper_assigns.get(value.id, [])
                        )
                    if isinstance(value, (ast.Tuple, ast.List)):
                        return any(helper_value_is_namespace(item, level + 1, seen_names) for item in value.elts)
                    if isinstance(value, ast.Dict):
                        return any(
                            item is not None and helper_value_is_namespace(item, level + 1, seen_names)
                            for item in value.values
                        )
                    if isinstance(value, ast.Attribute):
                        return value.attr in {"__globals__", "f_globals"}
                    if isinstance(value, ast.Subscript):
                        return helper_value_is_namespace(value.value, level + 1, seen_names)
                    if isinstance(value, ast.NamedExpr):
                        return helper_value_is_namespace(value.value, level + 1, seen_names)
                    if isinstance(value, ast.IfExp):
                        return helper_value_is_namespace(value.body, level + 1, seen_names) or helper_value_is_namespace(
                            value.orelse, level + 1, seen_names
                        )
                    if isinstance(value, ast.BoolOp):
                        return any(helper_value_is_namespace(item, level + 1, seen_names) for item in value.values)
                    if not isinstance(value, ast.Call):
                        return False

                    if helper_callee_is(
                        value.func,
                        {"getattr", "builtins.getattr", "object.__getattribute__"},
                        level + 1,
                        seen_names,
                    ) and len(value.args) >= 2:
                        return authority_name(value.args[1], helper_strings)
                    if isinstance(value.func, ast.Attribute) and value.func.attr == "__getattribute__" and value.args:
                        return authority_name(value.args[0], helper_strings)
                    if helper_attrgetter_factory(value.func, level + 1, seen_names):
                        return True
                    call_name = helper_resolved(value.func)
                    if call_name in functions and call_name not in next_helpers:
                        return helper_returns_namespace(call_name, depth + 1, next_helpers)
                    return False

                for helper_node in helper_nodes:
                    if isinstance(helper_node, ast.Return) and helper_node.value is not None:
                        if helper_value_is_namespace(helper_node.value):
                            helper_namespace_cache[name] = True
                            return True
                return False

            def namespace(value: ast.AST, depth: int = 0, seen: set[str] | None = None) -> bool:
                if depth > 8:
                    return True
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(namespace(candidate, depth + 1, nxt) for candidate in assigns.get(value.id, []))
                if isinstance(value, ast.Attribute):
                    return value.attr in {"__globals__", "f_globals"}
                if isinstance(value, ast.Subscript):
                    return namespace(value.value, depth + 1, seen)
                if not isinstance(value, ast.Call):
                    return False

                if callee_is(
                    value.func,
                    {"getattr", "builtins.getattr", "object.__getattribute__"},
                    depth + 1,
                    seen,
                ) and len(value.args) >= 2:
                    return authority_name(value.args[1])
                if isinstance(value.func, ast.Attribute) and value.func.attr == "__getattribute__" and value.args:
                    return authority_name(value.args[0])
                if attrgetter_namespace_factory(value.func, depth + 1, seen):
                    return True
                for helper_name in functions:
                    if callee_is(value.func, {helper_name}, depth + 1, seen) and helper_returns_namespace(
                        helper_name, depth + 1
                    ):
                        return True
                return False

            def affected_name(value: ast.AST) -> set[str]:
                values = _base._string_values(value, strings)
                return set(class_names) if values is None else class_names & values

            def affected_map(value: ast.AST) -> set[str]:
                if not isinstance(value, ast.Dict):
                    return set(class_names)
                affected: set[str] = set()
                for key in value.keys:
                    if key is None:
                        return set(class_names)
                    affected.update(affected_name(key))
                return affected

            def add(node: ast.AST, affected: set[str], mechanism: str) -> None:
                if not affected:
                    return
                findings.append(
                    {
                        "path": relative,
                        "function": function.name,
                        "line": getattr(node, "lineno", 0),
                        "kind": "alternate-process-creation-call",
                        "detail": (
                            f"attestor-reachable {mechanism} can replace reviewed class identity: "
                            f"{','.join(sorted(affected))}"
                        ),
                    }
                )

            for node in nodes:
                targets: list[ast.AST] = []
                if isinstance(node, ast.Assign):
                    targets.extend(node.targets)
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                    targets.append(node.target)
                for target in targets:
                    if isinstance(target, ast.Subscript) and namespace(target.value):
                        add(node, affected_name(target.slice), "frame/function module namespace subscript write")

                if not isinstance(node, ast.Call):
                    continue
                call = resolved(node.func)
                if isinstance(node.func, ast.Attribute) and node.func.attr == "update" and namespace(node.func.value):
                    affected = set(class_names)
                    if node.args:
                        affected = affected_map(node.args[0])
                    add(node, affected, "frame/function module namespace update")
                    continue
                if isinstance(node.func, ast.Attribute) and node.func.attr == "__setitem__" and namespace(node.func.value) and node.args:
                    add(node, affected_name(node.args[0]), "frame/function module namespace __setitem__")
                    continue
                if call in {"operator.setitem", "dict.__setitem__"} and len(node.args) >= 2 and namespace(node.args[0]):
                    add(node, affected_name(node.args[1]), f"{call} module namespace write")
                    continue
                if call == "dict.update" and len(node.args) >= 2 and namespace(node.args[0]):
                    add(node, affected_map(node.args[1]), "dict.update module namespace write")

    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    report = dict(_v6.verify(root))
    extras = _frame_namespace_rebind_findings(root)
    merged = list(report.get("findings", [])) + extras
    unique = {
        (item.get("path"), item.get("function"), item.get("line"), item.get("kind"), item.get("detail")): item
        for item in merged
    }
    findings = [unique[key] for key in sorted(unique, key=lambda value: tuple(str(part) for part in value))]
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
