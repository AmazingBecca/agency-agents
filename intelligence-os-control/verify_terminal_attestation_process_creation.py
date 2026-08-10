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


def _call_result_is_discarded(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
    parent = parents.get(call)
    return isinstance(parent, ast.Expr) and parent.value is call


def _factory_authority_findings(root: pathlib.Path) -> list[dict[str, object]]:
    """Fail closed when attestor-reachable helpers manufacture first-class authority.

    The base process-topology verifier resolves direct helper aliases and reflected
    helper names. A separate closure is required for a helper *return value* that
    is consumed by trusted attestor code: the returned object can be getattr, a
    module namespace, functools.partial(getattr, ...), or another callable
    resolver without exposing a recognizable reflection primitive at the call
    site. The terminal attestor contract has no reviewed need to consume a
    top-level helper return, so such a path is rejected rather than guessed.
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
            aliases = _base._scope_import_aliases(tree, function)
            scope_nodes = _base._function_scope_nodes(function)
            parents = {
                child: parent
                for parent in scope_nodes
                for child in ast.iter_child_nodes(parent)
            }
            for node in scope_nodes:
                if not isinstance(node, ast.Call):
                    continue
                call_name = _base._resolve_alias(_base._dotted_name(node.func), aliases)
                if call_name not in unique or call_name == _ATTESTOR_NAME:
                    continue
                if _call_result_is_discarded(node, parents):
                    continue
                findings.append(
                    {
                        "path": relative,
                        "function": function.name,
                        "line": node.lineno,
                        "kind": "alternate-process-creation-call",
                        "detail": (
                            "attestor-reachable code consumes a top-level helper return; "
                            f"{call_name} can manufacture callable or namespace process authority"
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
    findings = [unique[key] for key in sorted(unique, key=lambda value: tuple(str(x) for x in value))]

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
