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
            assigns: dict[str, list[ast.AST]] = {}
            for node in nodes:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assigns.setdefault(target.id, []).append(node.value)
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                    assigns.setdefault(node.target.id, []).append(node.value)
                elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                    assigns.setdefault(node.target.id, []).append(node.value)

            def resolved(value: ast.AST) -> str | None:
                return _base._resolve_alias(_base._dotted_name(value), imports)

            def authority_name(value: ast.AST) -> bool:
                values = _base._string_values(value, strings)
                return values is None or bool({"__globals__", "f_globals"} & values)

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
                    if value.attr in {"__globals__", "f_globals"}:
                        return True
                    return False
                if isinstance(value, ast.Subscript):
                    return namespace(value.value, depth + 1, seen)
                if not isinstance(value, ast.Call):
                    return False

                call = resolved(value.func)
                if call in {"getattr", "builtins.getattr", "object.__getattribute__"} and len(value.args) >= 2:
                    return authority_name(value.args[1])
                if isinstance(value.func, ast.Attribute) and value.func.attr == "__getattribute__" and value.args:
                    return authority_name(value.args[0])
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
