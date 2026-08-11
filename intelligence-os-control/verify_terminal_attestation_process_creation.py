from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

import verify_terminal_attestation_process_creation_v4_base as _v4


Finding = _v4.Finding
_SCHEMA = _v4._SCHEMA
_ATTESTOR_NAME = _v4._ATTESTOR_NAME
_base = _v4._base


def __getattr__(name: str):
    return getattr(_v4, name)


def _decorated_class_replacement_findings(root: pathlib.Path) -> list[dict[str, object]]:
    """Reject attestor calls through class names whose decorators can replace identity."""
    findings: list[dict[str, object]] = []

    for source in _base.control_flow._source_files(root):
        relative = source.relative_to(root).as_posix()
        raw = source.read_bytes()
        try:
            tree = ast.parse(raw, filename=str(source))
        except (SyntaxError, ValueError, TypeError) as exc:
            raise RuntimeError(f"runner source cannot be parsed: {source}") from exc

        decorated_classes = {
            node.name
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.decorator_list
        }
        if not decorated_classes:
            continue

        functions = _base._top_level_functions(tree)
        attestors = functions.get(_ATTESTOR_NAME, [])
        if len(attestors) != 1:
            continue
        attestor = attestors[0]

        for function in _base._reachable_functions(tree, attestor, functions):
            assignments: dict[str, list[ast.AST]] = {}
            scope_nodes = list(_base._function_scope_nodes(function))
            for node in scope_nodes:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assignments.setdefault(target.id, []).append(node.value)
                elif (
                    isinstance(node, ast.AnnAssign)
                    and isinstance(node.target, ast.Name)
                    and node.value is not None
                ):
                    assignments.setdefault(node.target.id, []).append(node.value)
                elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                    assignments.setdefault(node.target.id, []).append(node.value)

            def possible_names(value: ast.AST, seen: set[str] | None = None) -> set[str]:
                if not isinstance(value, ast.Name):
                    return set()
                seen = set() if seen is None else set(seen)
                if value.id in seen:
                    return set()
                candidates = assignments.get(value.id, [])
                if not candidates:
                    return {value.id}
                next_seen = set(seen)
                next_seen.add(value.id)
                recovered: set[str] = set()
                for candidate in candidates:
                    recovered.update(possible_names(candidate, next_seen))
                    if len(recovered) >= 32:
                        return set(sorted(recovered)[:32])
                return recovered

            for node in scope_nodes:
                if not isinstance(node, ast.Call):
                    continue
                targets = possible_names(node.func) & decorated_classes
                if not targets:
                    continue
                findings.append(
                    {
                        "path": relative,
                        "function": function.name,
                        "line": node.lineno,
                        "kind": "alternate-process-creation-call",
                        "detail": (
                            "attestor-reachable call uses a decorated class name whose "
                            "runtime identity may have been replaced: "
                            + ",".join(sorted(targets))
                        ),
                    }
                )

    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    report = dict(_v4.verify(root))
    existing = list(report.get("findings", []))
    extras = _decorated_class_replacement_findings(root)

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
