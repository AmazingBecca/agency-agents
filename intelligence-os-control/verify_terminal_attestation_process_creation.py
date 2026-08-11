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
_MAPPING_TRANSPORT_METHODS = {
    "update",
    "setdefault",
    "__setitem__",
    "get",
    "__getitem__",
}


def __getattr__(name: str):
    return getattr(_v3, name)


def _bound_mapping_method_authority_findings(root: pathlib.Path) -> list[dict[str, object]]:
    """Fail closed on wrapped/aliased mapping transport in attestor-reachable flow."""
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

            def static_strings(value: ast.AST, seen: set[str] | None = None) -> set[str]:
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return {value.value}
                if isinstance(value, ast.Name):
                    if value.id in seen:
                        return set()
                    values = assignments.get(value.id, [])
                    if not values:
                        return set()
                    seen.add(value.id)
                    result: set[str] = set()
                    for candidate in values:
                        result.update(static_strings(candidate, seen))
                        if len(result) >= 32:
                            return set(sorted(result)[:32])
                    return result
                if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
                    left = static_strings(value.left, seen)
                    right = static_strings(value.right, seen)
                    return {a + b for a in left for b in right if len(a) + len(b) <= 128}
                if isinstance(value, ast.JoinedStr):
                    parts: list[set[str]] = []
                    for item in value.values:
                        if isinstance(item, ast.Constant) and isinstance(item.value, str):
                            parts.append({item.value})
                        elif isinstance(item, ast.FormattedValue):
                            parts.append(static_strings(item.value, seen))
                        else:
                            return set()
                    combined = {""}
                    for part in parts:
                        if not part:
                            return set()
                        combined = {a + b for a in combined for b in part if len(a) + len(b) <= 128}
                        if len(combined) > 32:
                            combined = set(sorted(combined)[:32])
                    return combined
                return set()

            def resolved_name(value: ast.AST) -> str | None:
                dotted = _base._dotted_name(value)
                return _base._resolve_alias(dotted, import_aliases)

            def callable_candidates(value: ast.AST, seen: set[str] | None = None) -> list[ast.AST]:
                seen = set() if seen is None else set(seen)
                if isinstance(value, ast.Name):
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
                return [value]

            def transport_target(value: ast.AST, depth: int = 0) -> str | None:
                if depth > 8:
                    return "unresolved-wrapped-mapping-transport"
                resolved = resolved_name(value)
                if resolved in {"operator.getitem", "operator.setitem"}:
                    return resolved
                if isinstance(value, ast.Attribute) and value.attr in _MAPPING_TRANSPORT_METHODS:
                    receiver = _base._dotted_name(value.value)
                    return f"bound:{value.attr}:{receiver or '<dynamic>'}"
                if isinstance(value, ast.Call):
                    wrapper = resolved_name(value.func)
                    if wrapper in {"getattr", "builtins.getattr"} and len(value.args) >= 2:
                        names = static_strings(value.args[1])
                        dangerous = sorted(names & _MAPPING_TRANSPORT_METHODS)
                        if dangerous:
                            receiver = _base._dotted_name(value.args[0])
                            return f"reflected:{'/'.join(dangerous)}:{receiver or '<dynamic>'}"
                    if wrapper == "functools.partial" and value.args:
                        inner_targets = {
                            target
                            for candidate in callable_candidates(value.args[0])
                            if (target := transport_target(candidate, depth + 1)) is not None
                        }
                        if inner_targets:
                            return "partial:" + ",".join(sorted(inner_targets))
                if isinstance(value, ast.Lambda):
                    inner_targets: set[str] = set()
                    for wrapped in ast.walk(value.body):
                        if isinstance(wrapped, ast.Call):
                            for candidate in callable_candidates(wrapped.func):
                                target = transport_target(candidate, depth + 1)
                                if target is not None:
                                    inner_targets.add(target)
                        elif isinstance(wrapped, ast.Attribute) and wrapped.attr in _MAPPING_TRANSPORT_METHODS:
                            receiver = _base._dotted_name(wrapped.value)
                            inner_targets.add(f"bound:{wrapped.attr}:{receiver or '<dynamic>'}")
                    if inner_targets:
                        return "lambda:" + ",".join(sorted(inner_targets))
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
                            "aliased/bound/wrapped callable authority: " + ",".join(sorted(targets))
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
