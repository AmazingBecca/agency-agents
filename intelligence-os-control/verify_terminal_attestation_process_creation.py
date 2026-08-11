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
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out.setdefault(target.id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            out.setdefault(node.target.id, []).append(node.value)
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            out.setdefault(node.target.id, []).append(node.value)
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

            def namespace(value: ast.AST, depth: int = 0, seen: set[str] | None = None) -> bool:
                if depth > 8:
                    return False
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return False
                    nxt = seen | {value.id}
                    return any(namespace(v, depth + 1, nxt) for v in assigns.get(value.id, []))
                if isinstance(value, ast.Attribute) and value.attr == "__dict__":
                    return module(value.value, depth + 1, seen)
                if isinstance(value, ast.Call) and resolved(value.func) in {"vars", "builtins.vars"} and value.args:
                    return module(value.args[0], depth + 1, seen)
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
                if isinstance(value, ast.Call) and resolved(value.func) in {"getattr", "builtins.getattr"} and len(value.args) >= 2:
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
                if resolved(target) in {"setattr", "builtins.setattr"} and len(value.args) >= 3 and module(value.args[1]):
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
                if isinstance(value, ast.Call) and resolved(value.func) in {"getattr", "builtins.getattr"} and len(value.args) >= 2:
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

            for node in nodes:
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
