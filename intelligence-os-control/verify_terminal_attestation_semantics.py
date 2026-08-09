from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys
from dataclasses import asdict, dataclass

import verify_completion_secret_boundary as completion_boundary

_SCHEMA = "amazingbecca.terminal-attestation-semantics.v1"
_CANDIDATE_WORKER_NAME = "_run_worker"
_ATTESTOR_NAME = "_run_attestor"
_SEMANTIC_VERIFIER_NAMES = {
    "_verify_candidate_semantics",
    "_verify_execution_semantics",
    "_verify_terminal_semantics",
}


@dataclass(frozen=True)
class Finding:
    path: str
    function: str
    line: int
    kind: str
    detail: str


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _terminal_name(node: ast.AST) -> str | None:
    dotted = _dotted_name(node)
    return dotted.rsplit(".", 1)[-1] if dotted else None


def _top_level_functions(
    tree: ast.Module,
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    duplicates: set[str] = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name in functions:
            duplicates.add(node.name)
        functions[node.name] = node
    for name in duplicates:
        functions.pop(name, None)
    return functions


def _calls(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.Call]:
    return [node for node in ast.walk(function) if isinstance(node, ast.Call)]


def _arguments(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    args = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    if function.args.vararg is not None:
        args.append(function.args.vararg)
    if function.args.kwarg is not None:
        args.append(function.args.kwarg)
    return {argument.arg for argument in args}


def _assigned_name(call: ast.Call, function: ast.AST) -> str | None:
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        if node.value is not call:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            return None
        return targets[0].id
    return None


def _string_literals(node: ast.AST) -> set[str]:
    return {
        item.value
        for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }


def _keyword(call: ast.Call, name: str) -> ast.keyword | None:
    matches = [item for item in call.keywords if item.arg == name]
    return matches[0] if len(matches) == 1 else None


def _names(node: ast.AST) -> set[str]:
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}


def _candidate_importing_worker(
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    worker = functions.get(_CANDIDATE_WORKER_NAME)
    if worker is None:
        return None
    if any(_dotted_name(call.func) == "_load_worker" for call in _calls(worker)):
        return worker
    return None


def _finding(
    path: str,
    function: str,
    line: int,
    kind: str,
    detail: str,
) -> Finding:
    return Finding(
        path=path,
        function=function,
        line=line,
        kind=kind,
        detail=detail,
    )


def _attestation_findings(tree: ast.Module, path: str) -> list[Finding]:
    functions = _top_level_functions(tree)
    worker = _candidate_importing_worker(functions)
    if worker is None:
        return []

    findings: list[Finding] = []
    attestor = functions.get(_ATTESTOR_NAME)
    if attestor is None:
        findings.append(
            _finding(
                path,
                _CANDIDATE_WORKER_NAME,
                worker.lineno,
                "terminal-attestor-missing",
                "candidate-importing runner has no separate terminal attestor",
            )
        )
        return findings

    attestor_args = _arguments(attestor)
    if not {"challenge_fd", "receipt_fd"}.issubset(attestor_args):
        findings.append(
            _finding(
                path,
                attestor.name,
                attestor.lineno,
                "terminal-attestor-completion-authority-incomplete",
                "attestor does not directly own both reviewed completion descriptors",
            )
        )

    calls = _calls(attestor)
    popen_calls = [
        call for call in calls if _dotted_name(call.func) == "subprocess.Popen"
    ]
    candidate_launches = [
        call for call in popen_calls if "--worker" in _string_literals(call)
    ]
    if len(candidate_launches) != 1:
        findings.append(
            _finding(
                path,
                attestor.name,
                attestor.lineno,
                "candidate-launch-authority-ambiguous",
                "attestor must launch exactly one explicit --worker candidate",
            )
        )
        return findings

    launch = candidate_launches[0]
    close_fds = _keyword(launch, "close_fds")
    if close_fds is None or not (
        isinstance(close_fds.value, ast.Constant) and close_fds.value.value is True
    ):
        findings.append(
            _finding(
                path,
                attestor.name,
                launch.lineno,
                "candidate-descriptor-closure-not-enforced",
                "candidate launch must use close_fds=True",
            )
        )
    pass_fds = _keyword(launch, "pass_fds")
    if pass_fds is not None and _names(pass_fds.value).intersection(
        {"challenge_fd", "receipt_fd"}
    ):
        findings.append(
            _finding(
                path,
                attestor.name,
                launch.lineno,
                "trusted-completion-descriptor-leaked-to-candidate",
                "candidate inherits a trusted challenge or receipt descriptor",
            )
        )

    wait_calls = [
        call
        for call in calls
        if _terminal_name(call.func) == "wait"
        and isinstance(call.func, ast.Attribute)
    ]
    wait_lines = sorted(call.lineno for call in wait_calls)
    if not wait_lines:
        findings.append(
            _finding(
                path,
                attestor.name,
                attestor.lineno,
                "candidate-completion-wait-missing",
                "attestor does not wait for candidate process termination",
            )
        )
        return findings
    first_wait = wait_lines[0]

    exit_names = {
        name
        for call in wait_calls
        if (name := _assigned_name(call, attestor)) is not None
    }

    receipt_writes = [
        call
        for call in calls
        if _terminal_name(call.func) in {"_write_all", "write", "send", "sendall"}
        and any(
            isinstance(argument, ast.Name) and argument.id == "receipt_fd"
            for argument in call.args[:1]
        )
    ]
    if len(receipt_writes) != 1:
        findings.append(
            _finding(
                path,
                attestor.name,
                attestor.lineno,
                "terminal-receipt-write-ambiguous",
                "attestor must emit exactly one reviewed completion receipt",
            )
        )
        return findings
    receipt_write = receipt_writes[0]
    if receipt_write.lineno <= first_wait:
        findings.append(
            _finding(
                path,
                attestor.name,
                receipt_write.lineno,
                "terminal-receipt-before-candidate-completion",
                "attestor can emit a completion receipt before candidate termination",
            )
        )

    semantic_calls = [
        call
        for call in calls
        if _terminal_name(call.func) in _SEMANTIC_VERIFIER_NAMES
        and first_wait < call.lineno < receipt_write.lineno
    ]
    if not semantic_calls:
        findings.append(
            _finding(
                path,
                attestor.name,
                receipt_write.lineno,
                "candidate-exit-code-only-attestation",
                "receipt is emitted after wait without an independent semantic-completion verifier; a candidate os._exit(0) can satisfy process completion",
            )
        )
    else:
        for semantic_call in semantic_calls:
            referenced = set().union(
                *(_names(argument) for argument in semantic_call.args),
                *(_names(keyword.value) for keyword in semantic_call.keywords),
            )
            if referenced and referenced.issubset(exit_names):
                findings.append(
                    _finding(
                        path,
                        attestor.name,
                        semantic_call.lineno,
                        "semantic-verifier-derived-only-from-candidate-exit-state",
                        "semantic verifier receives only candidate-controlled process-exit state",
                    )
                )

    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    base_report = completion_boundary.verify(root)
    findings: list[Finding] = []
    files = completion_boundary._source_files(root)
    for source in files:
        raw = completion_boundary._read_regular(source)
        try:
            tree = ast.parse(raw, filename=str(source))
        except (SyntaxError, ValueError, TypeError) as exc:
            raise RuntimeError(
                f"runner source cannot be parsed for terminal-attestation review: {source}"
            ) from exc
        relative = source.relative_to(root).as_posix()
        findings.extend(_attestation_findings(tree, relative))

    rendered = [
        asdict(item)
        for item in sorted(
            findings,
            key=lambda item: (item.path, item.function, item.line, item.kind),
        )
    ]
    return {
        "schema": _SCHEMA,
        "authority_level": "source-topology-diagnostic-not-terminal",
        "completion_boundary_passed": bool(base_report.get("passed")),
        "completion_boundary_finding_count": int(
            base_report.get("finding_count", 0)
        ),
        "attestation_finding_count": len(rendered),
        "attestation_findings": rendered,
        "passed": bool(base_report.get("passed")) and not rendered,
    }


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
