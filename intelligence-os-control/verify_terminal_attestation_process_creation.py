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
            assigned_value_candidates: dict[str, list[ast.AST]] = {}

            def remember_assignment(target: ast.AST, value: ast.AST) -> None:
                assignments.append((target, value))
                if isinstance(target, ast.Name):
                    assigned_values[target.id] = value
                    assigned_value_candidates.setdefault(target.id, []).append(value)

            for node in scope_nodes:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        remember_assignment(target, node.value)
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    remember_assignment(node.target, node.value)
                elif isinstance(node, ast.NamedExpr):
                    remember_assignment(node.target, node.value)

            mapping_aliases: dict[str, set[str]] = {}

            def link(left: str, right: str) -> None:
                if left == right:
                    return
                mapping_aliases.setdefault(left, set()).add(right)
                mapping_aliases.setdefault(right, set()).add(left)

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

            # Seed direct object-identity aliases before projection analysis so
            # later container mutations remain visible through simple aliases.
            for target, value in assignments:
                if isinstance(target, ast.Name) and isinstance(value, ast.Name):
                    link(target.id, value.id)
            for node in assignment_nodes:
                simple_targets = [
                    target for target in node.targets if isinstance(target, ast.Name)
                ]
                if len(simple_targets) > 1:
                    anchor = simple_targets[0]
                    for target in simple_targets[1:]:
                        link(anchor.id, target.id)

            def resolve_sequence_candidates(
                value: ast.AST,
                seen: set[str] | None = None,
            ) -> list[ast.AST]:
                seen = set() if seen is None else set(seen)
                if not isinstance(value, ast.Name):
                    return [value]
                if value.id in seen:
                    return [value]
                candidates = assigned_value_candidates.get(value.id, [])
                if not candidates:
                    return [value]
                seen.add(value.id)
                resolved: list[ast.AST] = []
                for candidate in candidates:
                    resolved.extend(resolve_sequence_candidates(candidate, seen))
                    if len(resolved) > 64:
                        return resolved[:64]
                return resolved

            def static_key_values(
                value: ast.AST,
                seen: set[str] | None = None,
            ) -> set[tuple[type[object], object]]:
                """Recover a bounded set of builtin, immutable mapping-key values."""
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return set()
                    candidates = assigned_value_candidates.get(value.id, [])
                    if not candidates:
                        return set()
                    seen.add(value.id)
                    results: set[tuple[type[object], object]] = set()
                    for candidate in candidates:
                        results.update(static_key_values(candidate, seen))
                        if len(results) > 64:
                            return set()
                    return results
                if isinstance(value, ast.Constant):
                    item = value.value
                    if isinstance(item, (str, bytes, int, float, complex, bool)) or item is None:
                        return {(type(item), item)}
                    return set()
                if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
                    left = static_key_values(value.left, seen)
                    right = static_key_values(value.right, seen)
                    results: set[tuple[type[object], object]] = set()
                    for left_type, left_value in left:
                        for right_type, right_value in right:
                            if left_type is not right_type:
                                continue
                            if left_type not in {str, bytes}:
                                continue
                            combined = left_value + right_value
                            results.add((left_type, combined))
                            if len(results) > 64:
                                return set()
                    return results
                if isinstance(value, ast.JoinedStr):
                    possibilities = {""}
                    for part in value.values:
                        if isinstance(part, ast.Constant) and isinstance(part.value, str):
                            fragments = {part.value}
                        elif (
                            isinstance(part, ast.FormattedValue)
                            and part.conversion in {-1, 115}
                            and part.format_spec is None
                        ):
                            recovered = static_key_values(part.value, seen)
                            fragments = {
                                str(item)
                                for item_type, item in recovered
                                if item_type in {str, bytes, int, float, complex, bool, type(None)}
                            }
                        else:
                            return set()
                        possibilities = {
                            prefix + suffix
                            for prefix in possibilities
                            for suffix in fragments
                        }
                        if not possibilities or len(possibilities) > 64:
                            return set()
                    return {(str, item) for item in possibilities}
                return set()

            def sequence_elements(container: ast.AST) -> list[ast.AST] | None:
                """Recover bounded positional elements from literal/builtin sequences."""
                if isinstance(container, (ast.List, ast.Tuple)):
                    return list(container.elts)
                if not isinstance(container, ast.Call):
                    return None
                call_name = _base._resolve_alias(
                    _base._dotted_name(container.func), import_aliases
                )
                if call_name not in {"list", "tuple"} or len(container.args) != 1 or container.keywords:
                    return None
                candidates = resolve_sequence_candidates(container.args[0])
                recovered: list[ast.AST] = []
                for candidate in candidates:
                    if not isinstance(candidate, (ast.List, ast.Tuple)):
                        return None
                    recovered.extend(candidate.elts)
                    if len(recovered) > 64:
                        return None
                return recovered

            def mapping_items(container: ast.AST) -> list[tuple[ast.AST, ast.AST]]:
                """Recover bounded key/value pairs from literal and builtin-dict construction."""
                if isinstance(container, ast.Dict):
                    return [
                        (key, value)
                        for key, value in zip(container.keys, container.values)
                        if key is not None
                    ]
                if not isinstance(container, ast.Call):
                    return []
                call_name = _base._resolve_alias(
                    _base._dotted_name(container.func), import_aliases
                )
                if call_name != "dict":
                    return []

                items: list[tuple[ast.AST, ast.AST]] = []
                for keyword in container.keywords:
                    if keyword.arg is None:
                        for candidate in resolve_sequence_candidates(keyword.value):
                            items.extend(mapping_items(candidate))
                            if len(items) > 64:
                                return items[:64]
                    else:
                        items.append((ast.Constant(value=keyword.arg), keyword.value))
                        if len(items) > 64:
                            return items[:64]

                if not container.args:
                    return items
                if len(container.args) != 1:
                    return items

                for candidate in resolve_sequence_candidates(container.args[0]):
                    direct = mapping_items(candidate)
                    if direct:
                        items.extend(direct)
                        if len(items) > 64:
                            return items[:64]
                        continue
                    elements = sequence_elements(candidate)
                    if elements is None:
                        continue
                    for element in elements:
                        pair_candidates = resolve_sequence_candidates(element)
                        for pair in pair_candidates:
                            pair_elements = sequence_elements(pair)
                            if pair_elements is None or len(pair_elements) != 2:
                                continue
                            items.append((pair_elements[0], pair_elements[1]))
                            if len(items) > 64:
                                return items[:64]
                return items

            container_mutations: dict[str, list[tuple[ast.AST, ast.AST]]] = {}

            def record_container_member(root_name: str, key: ast.AST, item: ast.AST) -> None:
                for alias in closure(root_name):
                    container_mutations.setdefault(alias, []).append((key, item))

            # Preserve container identity across post-construction mutation.
            for target, value in assignments:
                if not isinstance(target, ast.Subscript):
                    continue
                root_name = _base._dotted_name(target.value)
                if root_name:
                    record_container_member(root_name, target.slice, value)

            for node in scope_nodes:
                if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr):
                    root_name = _base._dotted_name(node.target)
                    if root_name:
                        for key, item in mapping_items(node.value):
                            record_container_member(root_name, key, item)
                    continue
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                root_name = _base._dotted_name(node.func.value)
                if not root_name:
                    continue
                if node.func.attr == "update":
                    for argument in node.args:
                        for candidate in resolve_sequence_candidates(argument):
                            for key, item in mapping_items(candidate):
                                record_container_member(root_name, key, item)
                    for keyword in node.keywords:
                        if keyword.arg is not None:
                            record_container_member(
                                root_name, ast.Constant(value=keyword.arg), keyword.value
                            )
                        else:
                            for candidate in resolve_sequence_candidates(keyword.value):
                                for key, item in mapping_items(candidate):
                                    record_container_member(root_name, key, item)
                elif node.func.attr in {"setdefault", "__setitem__"} and len(node.args) >= 2:
                    record_container_member(root_name, node.args[0], node.args[1])

            def projection_containers(value: ast.AST) -> list[ast.AST]:
                """Resolve names and nested static projections to their possible containers."""
                if isinstance(value, ast.Name):
                    return resolve_sequence_candidates(value)
                if isinstance(value, ast.Subscript):
                    return projected_members(value)
                if isinstance(value, ast.Call):
                    return projected_call_members(value)
                return [value]

            def projected_members(value: ast.Subscript) -> list[ast.AST]:
                containers = projection_containers(value.value)
                index_node = value.slice
                matches: list[ast.AST] = []
                wanted = static_key_values(index_node)

                if isinstance(value.value, ast.Name) and wanted:
                    for receiver in closure(value.value.id):
                        for key, item in container_mutations.get(receiver, []):
                            if wanted.intersection(static_key_values(key)):
                                matches.append(item)
                                if len(matches) >= 64:
                                    return matches

                for container in containers:
                    elements = sequence_elements(container)
                    if elements is not None:
                        if not (
                            isinstance(index_node, ast.Constant)
                            and isinstance(index_node.value, int)
                            and not isinstance(index_node.value, bool)
                        ):
                            continue
                        index = index_node.value
                        if index < 0:
                            index += len(elements)
                        if 0 <= index < len(elements):
                            matches.append(elements[index])
                        continue

                    if not wanted:
                        continue
                    for key, item in mapping_items(container):
                        if wanted.intersection(static_key_values(key)):
                            matches.append(item)
                return matches[:64]

            def projected_call_members(value: ast.Call) -> list[ast.AST]:
                if not isinstance(value.func, ast.Attribute):
                    return []
                if value.func.attr == "setdefault":
                    if len(value.args) < 2:
                        return []
                    # setdefault returns either the existing value or the supplied
                    # default. Conservatively retain the default object identity.
                    matches = [value.args[1]]
                    lookup = ast.Call(
                        func=ast.Attribute(
                            value=value.func.value,
                            attr="get",
                            ctx=ast.Load(),
                        ),
                        args=[value.args[0]],
                        keywords=[],
                    )
                    matches.extend(projected_call_members(lookup))
                    return matches[:64]
                if value.func.attr not in {"get", "__getitem__"}:
                    return []
                if len(value.args) != 1 or value.keywords:
                    return []
                wanted = static_key_values(value.args[0])
                if not wanted:
                    return []

                matches: list[ast.AST] = []
                if isinstance(value.func.value, ast.Name):
                    for receiver in closure(value.func.value.id):
                        for key, item in container_mutations.get(receiver, []):
                            if wanted.intersection(static_key_values(key)):
                                matches.append(item)
                                if len(matches) >= 64:
                                    return matches
                for container in projection_containers(value.func.value):
                    for key, item in mapping_items(container):
                        if wanted.intersection(static_key_values(key)):
                            matches.append(item)
                            if len(matches) >= 64:
                                return matches
                return matches

            def connect(left: ast.AST, right: ast.AST) -> None:
                if isinstance(left, ast.Name) and isinstance(right, ast.Name):
                    link(left.id, right.id)
                    return
                if isinstance(left, ast.Name) and isinstance(right, ast.Subscript):
                    for member in projected_members(right):
                        connect(left, member)
                    return
                if isinstance(left, ast.Name) and isinstance(right, ast.Call):
                    for member in projected_call_members(right):
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

            def static_string_keys(value: ast.AST) -> set[str]:
                return {
                    item
                    for item_type, item in static_key_values(value)
                    if item_type is str and isinstance(item, str)
                }

            for target, value in assignments:
                if not (isinstance(target, ast.Subscript) and helper_result_in(value)):
                    continue
                root_name = _base._dotted_name(target.value)
                if not root_name:
                    continue
                keys = static_string_keys(target.slice)
                if keys:
                    add_mapping(root_name, keys)
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
                            if key is None:
                                unknown = True
                                continue
                            recovered = static_string_keys(key)
                            if recovered:
                                keys.update(recovered)
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
                    keys = static_string_keys(node.args[0])
                    if keys:
                        add_mapping(root_name, keys)
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
