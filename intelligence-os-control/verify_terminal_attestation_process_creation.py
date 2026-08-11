from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

import verify_terminal_attestation_process_creation_v3_base as _v3


Finding = _v3.Finding
_SCHEMA = _v3._SCHEMA
_ATTESTOR_NAME = _v3._ATTESTOR_NAME
_base = _v3._base


def __getattr__(name: str):
    return getattr(_v3, name)


def _bound_mapping_method_authority_findings(root: pathlib.Path) -> list[dict[str, object]]:
    """Fail closed on aliased mapping transport in attestor-reachable authority flow."""
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
            import_aliases = _base._scope_import_aliases(tree, function)
            scope_nodes = list(_base._function_scope_nodes(function))
            assignments: dict[str, list[ast.AST]] = {}
            for node in scope_nodes:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assignments.setdefault(target.id, []).append(node.value)
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                    assignments.setdefault(node.target.id, []).append(node.value)
                elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                    assignments.setdefault(node.target.id, []).append(node.value)

            def callable_candidates(value: ast.AST, seen: set[str] | None = None) -> list[ast.AST]:
                seen = set() if seen is None else set(seen)
                if not isinstance(value, ast.Name):
                    return [value]
                if value.id in seen:
                    return []
                candidates = assignments.get(value.id, [])
                if not candidates:
                    return [value]
                seen.add(value.id)
                resolved: list[ast.AST] = []
                for candidate in candidates:
                    resolved.extend(callable_candidates(candidate, seen))
                    if len(resolved) >= 64:
                        return resolved[:64]
                return resolved

            def transport_target(value: ast.AST) -> str | None:
                dotted = _base._dotted_name(value)
                resolved = _base._resolve_alias(dotted, import_aliases)
                if resolved in {"operator.getitem", "operator.setitem"}:
                    return resolved
                if isinstance(value, ast.Attribute) and value.attr in {
                    "update",
                    "setdefault",
                    "__setitem__",
                    "get",
                    "__getitem__",
                }:
                    receiver = _base._dotted_name(value.value)
                    if receiver:
                        return f"bound:{value.attr}:{receiver}"
                return None

            for node in scope_nodes:
                if not isinstance(node, ast.Call):
                    continue
                targets = {
                    target
                    for candidate in callable_candidates(node.func)
                    if (target := transport_target(candidate)) is not None
                }
                if not targets:
                    continue
                findings.append(
                    {
                        "path": relative,
                        "function": function.name,
                        "line": node.lineno,
                        "kind": "alternate-process-creation-call",
                        "detail": (
                            "attestor-reachable mapping transport is invoked through "
                            "aliased/bound callable authority: " + ",".join(sorted(targets))
                        ),
                    }
                )

    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    report = dict(_v3.verify(root))
    existing = list(report.get("findings", []))
    extras = _bound_mapping_method_authority_findings(root)

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
