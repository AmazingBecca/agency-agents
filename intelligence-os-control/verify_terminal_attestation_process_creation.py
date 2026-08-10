from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

import verify_terminal_attestation_process_creation_base as _base


Finding = _base.Finding
_SCHEMA = _base._SCHEMA
_ATTESTOR_NAME = _base._ATTESTOR_NAME


def __getattr__(name: str):
    return getattr(_base, name)


def _contains_factory_authority(
    node: ast.AST,
    aliases: set[str],
    containers: set[str],
) -> bool:
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and item.id in aliases | containers:
            return True
    return False


def _factory_authority_state(
    tree: ast.Module,
    function: ast.FunctionDef,
    functions: dict[str, list[ast.FunctionDef]],
) -> tuple[set[str], set[str], dict[str, set[str]]]:
    """Propagate helper-produced first-class authority through local storage."""
    unique = {name for name, definitions in functions.items() if len(definitions) == 1}
    import_aliases = _base._scope_import_aliases(tree, function)
    aliases: set[str] = set()
    containers: set[str] = set()
    object_attributes: dict[str, set[str]] = {}
    assignments: list[tuple[ast.AST, ast.AST]] = []

    for node in _base._function_scope_nodes(function):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            assignments.append((node.targets[0], node.value))
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            assignments.append((node.target, node.value))
        elif isinstance(node, ast.NamedExpr):
            assignments.append((node.target, node.value))

    changed = True
    while changed:
        changed = False
        for target, value in assignments:
            helper_result = False
            if isinstance(value, ast.Call):
                call_name = _base._resolve_alias(
                    _base._dotted_name(value.func), import_aliases
                )
                helper_result = call_name in unique and call_name != _ATTESTOR_NAME

            if isinstance(target, ast.Name):
                if helper_result or (
                    isinstance(value, ast.Name) and value.id in aliases
                ):
                    if target.id not in aliases:
                        aliases.add(target.id)
                        changed = True
                    continue

                if isinstance(value, ast.Name) and value.id in containers:
                    if target.id not in containers:
                        containers.add(target.id)
                        changed = True
                    continue

                if isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict)) and _contains_factory_authority(
                    value, aliases, containers
                ):
                    if target.id not in containers:
                        containers.add(target.id)
                        changed = True
                    continue

                if isinstance(value, ast.Call):
                    dangerous_keywords = {
                        keyword.arg
                        for keyword in value.keywords
                        if keyword.arg is not None
                        and _contains_factory_authority(keyword.value, aliases, containers)
                    }
                    if dangerous_keywords:
                        before = set(object_attributes.get(target.id, set()))
                        object_attributes.setdefault(target.id, set()).update(dangerous_keywords)
                        if object_attributes[target.id] != before:
                            changed = True
                        continue

                if isinstance(value, ast.Name) and value.id in object_attributes:
                    before = set(object_attributes.get(target.id, set()))
                    object_attributes.setdefault(target.id, set()).update(
                        object_attributes[value.id]
                    )
                    if object_attributes[target.id] != before:
                        changed = True
                    continue

            if isinstance(target, ast.Attribute):
                root = _base._dotted_name(target.value)
                if root and _contains_factory_authority(value, aliases, containers):
                    before = set(object_attributes.get(root, set()))
                    object_attributes.setdefault(root, set()).add(target.attr)
                    if object_attributes[root] != before:
                        changed = True
                continue

            if isinstance(target, ast.Subscript):
                root = _base._dotted_name(target.value)
                if root and _contains_factory_authority(value, aliases, containers):
                    if root not in containers:
                        containers.add(root)
                        changed = True

    return aliases, containers, object_attributes


def _factory_authority_dispatch(
    call: ast.Call,
    aliases: set[str],
    containers: set[str],
    object_attributes: dict[str, set[str]],
) -> str | None:
    func = call.func
    if isinstance(func, ast.Name) and func.id in aliases:
        return func.id

    if isinstance(func, ast.Subscript):
        root = _base._dotted_name(func.value)
        if root in containers:
            return root

    if isinstance(func, ast.Attribute):
        root = _base._dotted_name(func.value)
        if root in containers and func.attr in {"get", "__getitem__", "__getattribute__"}:
            return root
        if root and func.attr in object_attributes.get(root, set()):
            return f"{root}.{func.attr}"
    return None


def _factory_authority_findings(root: pathlib.Path) -> list[dict[str, object]]:
    """Reject helper-return values only when they become dynamic dispatch authority.

    Trusted attestor code may legitimately consume a helper's ordinary data
    result, such as a semantic observation. What is not reviewable is using a
    helper-produced object itself, or an alias/container/attribute carrying it,
    as callable or namespace lookup authority. That object can be getattr, a
    module namespace, functools.partial(getattr, ...), or an equivalent resolver
    that hides process authority from the base syntax-oriented verifier.
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

        for function in _base._reachable_functions(tree, attestor, functions):
            aliases, containers, object_attributes = _factory_authority_state(
                tree, function, functions
            )
            if not aliases and not containers and not object_attributes:
                continue
            for node in _base._function_scope_nodes(function):
                if not isinstance(node, ast.Call):
                    continue
                authority = _factory_authority_dispatch(
                    node, aliases, containers, object_attributes
                )
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
                            f"namespace dispatch authority through {authority}"
                        ),
                    }
                )
    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    report = dict(_base.verify(root))
    existing = list(report.get("findings", []))
    extras = _factory_authority_findings(root)

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
