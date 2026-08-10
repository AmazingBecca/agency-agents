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


def _factory_result_aliases(
    tree: ast.Module,
    function: ast.FunctionDef,
    functions: dict[str, list[ast.FunctionDef]],
) -> set[str]:
    """Track local names that receive a unique top-level helper return value."""
    unique = {name for name, definitions in functions.items() if len(definitions) == 1}
    import_aliases = _base._scope_import_aliases(tree, function)
    factory_aliases: set[str] = set()
    assignments: list[tuple[str, ast.AST]] = []

    for node in _base._function_scope_nodes(function):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            assignments.append((node.targets[0].id, node.value))
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            assignments.append((node.target.id, node.value))
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            assignments.append((node.target.id, node.value))

    changed = True
    while changed:
        changed = False
        for target, value in assignments:
            if isinstance(value, ast.Call):
                call_name = _base._resolve_alias(
                    _base._dotted_name(value.func), import_aliases
                )
                if call_name in unique and call_name != _ATTESTOR_NAME:
                    if target not in factory_aliases:
                        factory_aliases.add(target)
                        changed = True
                    continue
            if isinstance(value, ast.Name) and value.id in factory_aliases:
                if target not in factory_aliases:
                    factory_aliases.add(target)
                    changed = True
    return factory_aliases


def _factory_alias_is_dispatched(call: ast.Call, aliases: set[str]) -> str | None:
    func = call.func
    if isinstance(func, ast.Name) and func.id in aliases:
        return func.id
    if isinstance(func, ast.Subscript):
        value = func.value
        if isinstance(value, ast.Name) and value.id in aliases:
            return value.id
    if isinstance(func, ast.Attribute):
        value = func.value
        if (
            isinstance(value, ast.Name)
            and value.id in aliases
            and func.attr in {"get", "__getitem__", "__getattribute__"}
        ):
            return value.id
    return None


def _factory_authority_findings(root: pathlib.Path) -> list[dict[str, object]]:
    """Reject helper-return values only when they become dynamic dispatch authority.

    Trusted attestor code may legitimately consume a helper's ordinary data
    result, such as a semantic observation. What is not reviewable is using a
    helper-produced object itself as a callable or namespace lookup surface:
    that object can be getattr, a module namespace, functools.partial(getattr,
    ...), or an equivalent resolver that hides process authority from the base
    syntax-oriented verifier.
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
            aliases = _factory_result_aliases(tree, function, functions)
            if not aliases:
                continue
            for node in _base._function_scope_nodes(function):
                if not isinstance(node, ast.Call):
                    continue
                alias = _factory_alias_is_dispatched(node, aliases)
                if alias is None:
                    continue
                findings.append(
                    {
                        "path": relative,
                        "function": function.name,
                        "line": node.lineno,
                        "kind": "alternate-process-creation-call",
                        "detail": (
                            "attestor-reachable helper return becomes dynamic callable or "
                            f"namespace dispatch authority through {alias}"
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
