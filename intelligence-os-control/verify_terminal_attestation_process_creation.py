from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

import verify_terminal_attestation_process_creation_v1 as _v1


Finding = _v1.Finding
_SCHEMA = _v1._SCHEMA
_ATTESTOR_NAME = _v1._ATTESTOR_NAME
_base = _v1._base


def __getattr__(name: str):
    return getattr(_v1, name)


def _mapping_union_authority_findings(root: pathlib.Path) -> list[dict[str, object]]:
    """Close callable-authority laundering through constructor mapping flows.

    In addition to literal/aliased ``**kwargs`` recovery, track mapping unions,
    computed constant keys, ``dict(...)`` construction, static pair sequences,
    and in-place mapping mutation. If helper-produced callable authority is
    inserted under a runtime-derived key and the mapping is later unpacked into
    a reviewed constructor, fail closed because the binding cannot be proven.
    """
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
            assignments: list[tuple[ast.AST, ast.AST]] = []
            for node in scope_nodes:
                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    assignments.append((node.targets[0], node.value))
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    assignments.append((node.target, node.value))
                elif isinstance(node, ast.NamedExpr):
                    assignments.append((node.target, node.value))

            authority_aliases: set[str] = set()
            mapping_authority: dict[str, set[str]] = {}
            unknown_mapping_authority: set[str] = set()
            object_attributes: dict[str, set[str]] = {}
            callable_aliases: set[str] = set()
            string_values: dict[str, set[str]] = {}

            def static_strings(value: ast.AST) -> set[str]:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return {value.value}
                if isinstance(value, ast.Name):
                    return set(string_values.get(value.id, set()))
                if isinstance(value, ast.FormattedValue):
                    return static_strings(value.value)
                if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
                    left = static_strings(value.left)
                    right = static_strings(value.right)
                    if not left or not right:
                        return set()
                    combined = {a + b for a in left for b in right}
                    return combined if len(combined) <= 64 else set()
                if isinstance(value, ast.JoinedStr):
                    possibilities = {""}
                    for part in value.values:
                        part_values = static_strings(part)
                        if not part_values:
                            return set()
                        possibilities = {
                            prefix + suffix
                            for prefix in possibilities
                            for suffix in part_values
                        }
                        if len(possibilities) > 64:
                            return set()
                    return possibilities
                return set()

            strings_changed = True
            while strings_changed:
                strings_changed = False
                for target, value in assignments:
                    if not isinstance(target, ast.Name):
                        continue
                    values = static_strings(value)
                    if not values:
                        continue
                    before = set(string_values.get(target.id, set()))
                    string_values.setdefault(target.id, set()).update(values)
                    if string_values[target.id] != before:
                        strings_changed = True

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

            def authority_value(value: ast.AST) -> bool:
                if helper_result_in(value):
                    return True
                if isinstance(value, ast.Name):
                    return value.id in authority_aliases or value.id in callable_aliases
                if isinstance(value, ast.Attribute):
                    root_name = _base._dotted_name(value.value)
                    return bool(
                        root_name
                        and value.attr in object_attributes.get(root_name, set())
                    )
                return False

            def pair_sequence_state(value: ast.AST) -> tuple[set[str], bool]:
                if not isinstance(value, (ast.List, ast.Tuple)):
                    return set(), False
                keys: set[str] = set()
                unknown = False
                for element in value.elts:
                    if not (
                        isinstance(element, (ast.List, ast.Tuple))
                        and len(element.elts) == 2
                    ):
                        return set(), False
                    key_node, item = element.elts
                    if not authority_value(item):
                        continue
                    values = static_strings(key_node)
                    if values:
                        keys.update(values)
                    else:
                        unknown = True
                return keys, unknown

            def mapping_state(value: ast.AST) -> tuple[set[str], bool]:
                if isinstance(value, ast.Name):
                    return (
                        set(mapping_authority.get(value.id, set())),
                        value.id in unknown_mapping_authority,
                    )
                if isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr):
                    left_keys, left_unknown = mapping_state(value.left)
                    right_keys, right_unknown = mapping_state(value.right)
                    return left_keys | right_keys, left_unknown or right_unknown
                if isinstance(value, ast.Dict):
                    keys: set[str] = set()
                    unknown = False
                    for key, item in zip(value.keys, value.values):
                        if key is None:
                            nested_keys, nested_unknown = mapping_state(item)
                            keys.update(nested_keys)
                            unknown = unknown or nested_unknown
                            continue
                        if not authority_value(item):
                            continue
                        values = static_strings(key)
                        if values:
                            keys.update(values)
                        else:
                            unknown = True
                    return keys, unknown
                sequence_keys, sequence_unknown = pair_sequence_state(value)
                if sequence_keys or sequence_unknown:
                    return sequence_keys, sequence_unknown
                if isinstance(value, ast.Call):
                    call_name = _base._resolve_alias(
                        _base._dotted_name(value.func), import_aliases
                    )
                    if call_name not in {"dict", "builtins.dict"}:
                        return set(), False
                    keys: set[str] = set()
                    unknown = False
                    for argument in value.args:
                        nested_keys, nested_unknown = mapping_state(argument)
                        keys.update(nested_keys)
                        unknown = unknown or nested_unknown
                    for keyword in value.keywords:
                        if keyword.arg is None:
                            nested_keys, nested_unknown = mapping_state(keyword.value)
                            keys.update(nested_keys)
                            unknown = unknown or nested_unknown
                        elif authority_value(keyword.value):
                            keys.add(keyword.arg)
                    return keys, unknown
                return set(), False

            def add_mapping_state(name: str, keys: set[str], unknown: bool) -> bool:
                changed_local = False
                if keys:
                    before = set(mapping_authority.get(name, set()))
                    mapping_authority.setdefault(name, set()).update(keys)
                    changed_local = mapping_authority[name] != before
                if unknown and name not in unknown_mapping_authority:
                    unknown_mapping_authority.add(name)
                    changed_local = True
                return changed_local

            changed = True
            while changed:
                changed = False

                for target, value in assignments:
                    if isinstance(target, ast.Name):
                        name = target.id
                        if authority_value(value) and name not in authority_aliases:
                            authority_aliases.add(name)
                            changed = True

                        keys, unknown = mapping_state(value)
                        if add_mapping_state(name, keys, unknown):
                            changed = True

                        if isinstance(value, ast.Name):
                            if value.id in object_attributes:
                                before = set(object_attributes.get(name, set()))
                                object_attributes.setdefault(name, set()).update(
                                    object_attributes[value.id]
                                )
                                if object_attributes[name] != before:
                                    changed = True
                            if value.id in callable_aliases and name not in callable_aliases:
                                callable_aliases.add(name)
                                changed = True

                        if isinstance(value, ast.Attribute):
                            root_name = _base._dotted_name(value.value)
                            if (
                                root_name
                                and value.attr in object_attributes.get(root_name, set())
                                and name not in callable_aliases
                            ):
                                callable_aliases.add(name)
                                changed = True

                        if isinstance(value, ast.Call):
                            dangerous_keywords: set[str] = set()
                            unresolved_mapping = False
                            for keyword in value.keywords:
                                if keyword.arg is None:
                                    nested_keys, nested_unknown = mapping_state(keyword.value)
                                    dangerous_keywords.update(nested_keys)
                                    unresolved_mapping = unresolved_mapping or nested_unknown
                                elif authority_value(keyword.value):
                                    dangerous_keywords.add(keyword.arg)
                            if unresolved_mapping:
                                findings.append(
                                    {
                                        "path": relative,
                                        "function": function.name,
                                        "line": value.lineno,
                                        "kind": "alternate-process-creation-call",
                                        "detail": (
                                            "attestor-reachable helper return enters constructor "
                                            "through **mapping with runtime-derived authority key"
                                        ),
                                    }
                                )
                            if dangerous_keywords:
                                recovered = _v1._constructor_authority_attributes(
                                    tree, value, [], dangerous_keywords
                                )
                                if recovered:
                                    before = set(object_attributes.get(name, set()))
                                    object_attributes.setdefault(name, set()).update(recovered)
                                    if object_attributes[name] != before:
                                        changed = True
                        continue

                    if isinstance(target, ast.Subscript):
                        root_name = _base._dotted_name(target.value)
                        if root_name and authority_value(value):
                            keys = static_strings(target.slice)
                            if add_mapping_state(root_name, keys, not bool(keys)):
                                changed = True

                for node in scope_nodes:
                    if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr):
                        root_name = _base._dotted_name(node.target)
                        if root_name:
                            keys, unknown = mapping_state(node.value)
                            if add_mapping_state(root_name, keys, unknown):
                                changed = True
                        continue

                    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                        continue
                    root_name = _base._dotted_name(node.func.value)
                    if not root_name:
                        continue

                    if node.func.attr == "update":
                        keys: set[str] = set()
                        unknown = False
                        for argument in node.args:
                            nested_keys, nested_unknown = mapping_state(argument)
                            keys.update(nested_keys)
                            unknown = unknown or nested_unknown
                        for keyword in node.keywords:
                            if keyword.arg is None:
                                nested_keys, nested_unknown = mapping_state(keyword.value)
                                keys.update(nested_keys)
                                unknown = unknown or nested_unknown
                            elif authority_value(keyword.value):
                                keys.add(keyword.arg)
                        if add_mapping_state(root_name, keys, unknown):
                            changed = True
                    elif node.func.attr in {"setdefault", "__setitem__"} and len(node.args) >= 2:
                        if authority_value(node.args[1]):
                            keys = static_strings(node.args[0])
                            if add_mapping_state(root_name, keys, not bool(keys)):
                                changed = True

            for node in scope_nodes:
                if not isinstance(node, ast.Call):
                    continue
                authority: str | None = None
                if isinstance(node.func, ast.Name) and node.func.id in callable_aliases:
                    authority = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    root_name = _base._dotted_name(node.func.value)
                    if (
                        root_name
                        and node.func.attr in object_attributes.get(root_name, set())
                    ):
                        authority = f"{root_name}.{node.func.attr}"
                if authority is None:
                    continue
                findings.append(
                    {
                        "path": relative,
                        "function": function.name,
                        "line": node.lineno,
                        "kind": "alternate-process-creation-call",
                        "detail": (
                            "attestor-reachable helper return becomes dynamic callable or "
                            "namespace dispatch authority through recovered mapping "
                            f"constructor flow {authority}"
                        ),
                    }
                )

    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    report = dict(_v1.verify(root))
    existing = list(report.get("findings", []))
    extras = _mapping_union_authority_findings(root)

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
