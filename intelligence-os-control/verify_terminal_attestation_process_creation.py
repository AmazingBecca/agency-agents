from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

import verify_terminal_attestation_process_creation_v2 as _v2


Finding = _v2.Finding
_SCHEMA = _v2._SCHEMA
_ATTESTOR_NAME = _v2._ATTESTOR_NAME
_base = _v2._base


def __getattr__(name: str):
    return getattr(_v2, name)


def _container_alias_authority_findings(root: pathlib.Path) -> list[dict[str, object]]:
    """Close mapping-identity laundering through destructuring and containers."""
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
        unique = {name for name, definitions in functions.items() if len(definitions) == 1}

        for function in _base._reachable_functions(tree, attestor, functions):
            import_aliases = _base._scope_import_aliases(tree, function)
            scope_nodes = list(_base._function_scope_nodes(function))
            assignment_nodes = [
                node for node in scope_nodes if isinstance(node, ast.Assign)
            ]
            assignments: list[tuple[ast.AST, ast.AST]] = []
            assigned_values: dict[str, ast.AST] = {}

            for node in scope_nodes:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        assignments.append((target, node.value))
                        if isinstance(target, ast.Name):
                            assigned_values[target.id] = node.value
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    assignments.append((node.target, node.value))
                    if isinstance(node.target, ast.Name):
                        assigned_values[node.target.id] = node.value
                elif isinstance(node, ast.NamedExpr):
                    assignments.append((node.target, node.value))
                    if isinstance(node.target, ast.Name):
                        assigned_values[node.target.id] = node.value

            mapping_aliases: dict[str, set[str]] = {}

            def link(left: str, right: str) -> None:
                if left == right:
                    return
                mapping_aliases.setdefault(left, set()).add(right)
                mapping_aliases.setdefault(right, set()).add(left)

            def resolve_sequence(value: ast.AST, seen: set[str] | None = None) -> ast.AST:
                seen = set() if seen is None else set(seen)
                current = value
                for _ in range(16):
                    if not isinstance(current, ast.Name):
                        return current
                    if current.id in seen or current.id not in assigned_values:
                        return current
                    seen.add(current.id)
                    current = assigned_values[current.id]
                return current

            def projected(value: ast.Subscript) -> ast.AST | None:
                container = resolve_sequence(value.value)
                index_node = value.slice

                if isinstance(container, (ast.List, ast.Tuple)):
                    if not (
                        isinstance(index_node, ast.Constant)
                        and isinstance(index_node.value, int)
                        and not isinstance(index_node.value, bool)
                    ):
                        return None
                    index = index_node.value
                    if index < 0:
                        index += len(container.elts)
                    if index < 0 or index >= len(container.elts):
                        return None
                    return container.elts[index]

                if isinstance(container, ast.Dict):
                    if not isinstance(index_node, ast.Constant):
                        return None
                    for key, item in zip(container.keys, container.values):
                        if not isinstance(key, ast.Constant):
                            continue
                        try:
                            matches = key.value == index_node.value
                        except Exception:
                            matches = False
                        if matches and type(key.value) is type(index_node.value):
                            return item
                return None

            def connect(left: ast.AST, right: ast.AST) -> None:
                if isinstance(left, ast.Name) and isinstance(right, ast.Name):
                    link(left.id, right.id)
                    return
                if isinstance(left, ast.Name) and isinstance(right, ast.Subscript):
                    member = projected(right)
                    if member is not None:
                        connect(left, member)
                    return
                if not (
                    isinstance(left, (ast.Tuple, ast.List))
                    and isinstance(right, (ast.Tuple, ast.List))
                ):
                    return

                star_positions = [
                    index for index, item in enumerate(left.elts) if isinstance(item, ast.Starred)
                ]
                if not star_positions:
                    if len(left.elts) != len(right.elts):
                        return
                    for left_item, right_item in zip(left.elts, right.elts):
                        connect(left_item, right_item)
                    return
                if len(star_positions) != 1:
                    return

                star = star_positions[0]
                minimum = len(left.elts) - 1
                if len(right.elts) < minimum:
                    return
                for index in range(star):
                    connect(left.elts[index], right.elts[index])
                suffix = len(left.elts) - star - 1
                for offset in range(1, suffix + 1):
                    connect(left.elts[-offset], right.elts[-offset])

            for node in assignment_nodes:
                for target in node.targets:
                    connect(target, node.value)
                simple_targets = [
                    target for target in node.targets if isinstance(target, ast.Name)
                ]
                if len(simple_targets) > 1:
                    anchor = simple_targets[0]
                    for target in simple_targets[1:]:
                        link(anchor.id, target.id)

            for target, value in assignments:
                connect(target, value)

            def closure(name: str) -> set[str]:
                seen = {name}
                pending = [name]
                while pending:
                    current = pending.pop()
                    for alias in mapping_aliases.get(current, set()):
                        if alias in seen:
                            continue
                        seen.add(alias)
                        pending.append(alias)
                return seen

            def helper_result_in(value: ast.AST) -> bool:
                for item in ast.walk(value):
                    if not isinstance(item, ast.Call):
                        continue
                    call_name = _base._resolve_alias(
                        _base._dotted_name(item.func), import_aliases
                    )
                    if call_name in unique and call_name != _ATTESTOR_NAME:
                        return True
                return False

            mapping_keys: dict[str, set[str]] = {}
            unknown_mapping: set[str] = set()

            def add_mapping(name: str, keys: set[str], unknown: bool = False) -> None:
                for alias in closure(name):
                    mapping_keys.setdefault(alias, set()).update(keys)
                    if unknown:
                        unknown_mapping.add(alias)

            for target, value in assignments:
                if not (isinstance(target, ast.Subscript) and helper_result_in(value)):
                    continue
                root_name = _base._dotted_name(target.value)
                if not root_name:
                    continue
                if (
                    isinstance(target.slice, ast.Constant)
                    and isinstance(target.slice.value, str)
                ):
                    add_mapping(root_name, {target.slice.value})
                else:
                    add_mapping(root_name, set(), True)

            for node in scope_nodes:
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                root_name = _base._dotted_name(node.func.value)
                if not root_name:
                    continue
                if node.func.attr == "update":
                    keys: set[str] = set()
                    unknown = False
                    for argument in node.args:
                        if not isinstance(argument, ast.Dict):
                            continue
                        for key, item in zip(argument.keys, argument.values):
                            if not helper_result_in(item):
                                continue
                            if (
                                isinstance(key, ast.Constant)
                                and isinstance(key.value, str)
                            ):
                                keys.add(key.value)
                            else:
                                unknown = True
                    for keyword in node.keywords:
                        if keyword.arg is not None and helper_result_in(keyword.value):
                            keys.add(keyword.arg)
                    if keys or unknown:
                        add_mapping(root_name, keys, unknown)
                elif node.func.attr in {"setdefault", "__setitem__"} and len(node.args) >= 2:
                    if not helper_result_in(node.args[1]):
                        continue
                    key = node.args[0]
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        add_mapping(root_name, {key.value})
                    else:
                        add_mapping(root_name, set(), True)

            object_attributes: dict[str, set[str]] = {}
            for target, value in assignments:
                if not (isinstance(target, ast.Name) and isinstance(value, ast.Call)):
                    continue
                dangerous: set[str] = set()
                unresolved = False
                for keyword in value.keywords:
                    if keyword.arg is not None:
                        continue
                    if not isinstance(keyword.value, ast.Name):
                        continue
                    for alias in closure(keyword.value.id):
                        dangerous.update(mapping_keys.get(alias, set()))
                        unresolved = unresolved or alias in unknown_mapping
                if unresolved:
                    findings.append(
                        {
                            "path": relative,
                            "function": function.name,
                            "line": value.lineno,
                            "kind": "alternate-process-creation-call",
                            "detail": (
                                "attestor-reachable helper authority reaches a constructor "
                                "through container-carried mapping identity with unresolved key"
                            ),
                        }
                    )
                if not dangerous:
                    continue
                recovered = _v2._v1._constructor_authority_attributes(
                    tree, value, [], dangerous
                )
                if recovered:
                    object_attributes.setdefault(target.id, set()).update(recovered)

            for node in scope_nodes:
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                root_name = _base._dotted_name(node.func.value)
                if not root_name:
                    continue
                if node.func.attr not in object_attributes.get(root_name, set()):
                    continue
                findings.append(
                    {
                        "path": relative,
                        "function": function.name,
                        "line": node.lineno,
                        "kind": "alternate-process-creation-call",
                        "detail": (
                            "attestor-reachable helper return becomes dynamic dispatch "
                            "authority through starred/container mapping alias recovery "
                            f"{root_name}.{node.func.attr}"
                        ),
                    }
                )

    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    report = dict(_v2.verify(root))
    existing = list(report.get("findings", []))
    extras = _container_alias_authority_findings(root)

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
