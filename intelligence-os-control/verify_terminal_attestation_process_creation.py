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
    """Close constructor-authority laundering through statically recoverable mappings.

    The prior verifier tracks literal and aliased ``**kwargs`` mappings, but a
    mapping expression can preserve the same reviewed keys while changing AST
    shape, notably ``left | right`` and ``dict(...)`` construction.  Recover
    those keys and carry helper-produced callable authority through constructor
    fields/aliases before checking dynamic dispatch.
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
            assignments: list[tuple[ast.AST, ast.AST]] = []
            for node in _base._function_scope_nodes(function):
                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    assignments.append((node.targets[0], node.value))
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    assignments.append((node.target, node.value))
                elif isinstance(node, ast.NamedExpr):
                    assignments.append((node.target, node.value))

            authority_aliases: set[str] = set()
            mapping_authority: dict[str, set[str]] = {}
            object_attributes: dict[str, set[str]] = {}
            callable_aliases: set[str] = set()

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

            def mapping_keys(value: ast.AST) -> set[str]:
                if isinstance(value, ast.Name):
                    return set(mapping_authority.get(value.id, set()))
                if isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr):
                    return mapping_keys(value.left) | mapping_keys(value.right)
                if isinstance(value, ast.Dict):
                    keys: set[str] = set()
                    for key, item in zip(value.keys, value.values):
                        if key is None:
                            keys.update(mapping_keys(item))
                            continue
                        if (
                            isinstance(key, ast.Constant)
                            and isinstance(key.value, str)
                            and authority_value(item)
                        ):
                            keys.add(key.value)
                    return keys
                if isinstance(value, ast.Call):
                    call_name = _base._resolve_alias(
                        _base._dotted_name(value.func), import_aliases
                    )
                    if call_name not in {"dict", "builtins.dict"}:
                        return set()
                    keys: set[str] = set()
                    for argument in value.args:
                        keys.update(mapping_keys(argument))
                    for keyword in value.keywords:
                        if keyword.arg is None:
                            keys.update(mapping_keys(keyword.value))
                        elif authority_value(keyword.value):
                            keys.add(keyword.arg)
                    return keys
                return set()

            changed = True
            while changed:
                changed = False
                for target, value in assignments:
                    if not isinstance(target, ast.Name):
                        continue
                    name = target.id

                    if authority_value(value) and name not in authority_aliases:
                        authority_aliases.add(name)
                        changed = True

                    keys = mapping_keys(value)
                    if keys:
                        before = set(mapping_authority.get(name, set()))
                        mapping_authority.setdefault(name, set()).update(keys)
                        if mapping_authority[name] != before:
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

                    if not isinstance(value, ast.Call):
                        continue
                    dangerous_keywords: set[str] = set()
                    for keyword in value.keywords:
                        if keyword.arg is None:
                            dangerous_keywords.update(mapping_keys(keyword.value))
                        elif authority_value(keyword.value):
                            dangerous_keywords.add(keyword.arg)
                    if not dangerous_keywords:
                        continue
                    recovered = _v1._constructor_authority_attributes(
                        tree, value, [], dangerous_keywords
                    )
                    if recovered:
                        before = set(object_attributes.get(name, set()))
                        object_attributes.setdefault(name, set()).update(recovered)
                        if object_attributes[name] != before:
                            changed = True

            for node in _base._function_scope_nodes(function):
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
                            "namespace dispatch authority through statically recovered "
                            f"mapping constructor flow {authority}"
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
