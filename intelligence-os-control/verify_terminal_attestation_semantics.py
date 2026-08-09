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


def _top_level_definitions(
    tree: ast.Module,
) -> dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]]:
    definitions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            definitions.setdefault(node.name, []).append(node)
    return definitions


def _unique_top_level_functions(
    tree: ast.Module,
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        name: definitions[0]
        for name, definitions in _top_level_definitions(tree).items()
        if len(definitions) == 1
    }


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


def _direct_candidate_loader(
    worker: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    return any(_dotted_name(call.func) == "_load_worker" for call in _calls(worker))


def _semantic_verifier_findings(
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    path: str,
    semantic_names: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for name in sorted(semantic_names):
        verifier = functions.get(name)
        if verifier is None:
            findings.append(
                _finding(
                    path,
                    name,
                    0,
                    "semantic-verifier-definition-missing",
                    "attestor references a semantic verifier without one unique top-level definition",
                )
            )
            continue
        calls = _calls(verifier)
        if any(_dotted_name(call.func) == "_load_worker" for call in calls):
            findings.append(
                _finding(
                    path,
                    name,
                    verifier.lineno,
                    "semantic-verifier-imports-candidate",
                    "semantic verifier must not import candidate worker source",
                )
            )
        if any(
            _terminal_name(call.func) in {"run", "_run", "run_tests", "execute", "execute_tests"}
            for call in calls
        ):
            findings.append(
                _finding(
                    path,
                    name,
                    verifier.lineno,
                    "semantic-verifier-executes-candidate",
                    "semantic verifier must not execute candidate-controlled test code",
                )
            )
        if any(
            isinstance(node, (ast.Name, ast.Attribute))
            and (_dotted_name(node) or "").startswith("unittest")
            for node in ast.walk(verifier)
        ):
            findings.append(
                _finding(
                    path,
                    name,
                    verifier.lineno,
                    "semantic-verifier-derives-from-live-unittest-state",
                    "semantic verifier must not derive terminal authority from live unittest state",
                )
            )
    return findings


def _attestation_findings(
    tree: ast.Module,
    path: str,
    worker: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[Finding]:
    functions = _unique_top_level_functions(tree)
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
    candidate_name = _assigned_name(launch, attestor)
    if candidate_name is None:
        findings.append(
            _finding(
                path,
                attestor.name,
                launch.lineno,
                "candidate-process-identity-unbound",
                "attestor must bind the launched candidate process to one local authority name",
            )
        )

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
        if candidate_name is not None
        and _dotted_name(call.func) == f"{candidate_name}.wait"
    ]
    if len(wait_calls) != 1:
        findings.append(
            _finding(
                path,
                attestor.name,
                attestor.lineno,
                "candidate-completion-wait-ambiguous",
                "attestor must wait exactly once on the specific candidate process it launched",
            )
        )
        return findings
    wait_call = wait_calls[0]
    first_wait = wait_call.lineno
    exit_name = _assigned_name(wait_call, attestor)
    exit_names = {exit_name} if exit_name is not None else set()

    challenge_reads = [
        call
        for call in calls
        if _dotted_name(call.func) == "os.read"
        and call.args
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "challenge_fd"
    ]
    challenge_read_line: int | None = None
    if len(challenge_reads) != 1:
        findings.append(
            _finding(
                path,
                attestor.name,
                attestor.lineno,
                "terminal-challenge-read-ambiguous",
                "attestor must materialize the supervisor challenge exactly once",
            )
        )
    else:
        challenge_read_line = challenge_reads[0].lineno
        if challenge_read_line <= first_wait:
            findings.append(
                _finding(
                    path,
                    attestor.name,
                    challenge_read_line,
                    "terminal-challenge-live-during-candidate-execution",
                    "attestor must keep the trusted challenge unread until the candidate process has terminated",
                )
            )

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
    if challenge_read_line is not None and receipt_write.lineno <= challenge_read_line:
        findings.append(
            _finding(
                path,
                attestor.name,
                receipt_write.lineno,
                "terminal-receipt-before-challenge-materialization",
                "attestor can emit a terminal receipt before reading the reviewed supervisor challenge",
            )
        )

    semantic_calls = [
        call
        for call in calls
        if _terminal_name(call.func) in _SEMANTIC_VERIFIER_NAMES
        and first_wait < call.lineno < receipt_write.lineno
    ]
    semantic_names = {
        name
        for call in semantic_calls
        if (name := _terminal_name(call.func)) is not None
    }
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
            if referenced and exit_names and referenced.issubset(exit_names):
                findings.append(
                    _finding(
                        path,
                        attestor.name,
                        semantic_call.lineno,
                        "semantic-verifier-derived-only-from-candidate-exit-state",
                        "semantic verifier receives only candidate-controlled process-exit state",
                    )
                )
        findings.extend(_semantic_verifier_findings(functions, path, semantic_names))

    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    base_report = completion_boundary.verify(root)
    findings: list[Finding] = []
    candidate_runners: list[tuple[str, int]] = []
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
        definitions = _top_level_definitions(tree)
        worker_definitions = definitions.get(_CANDIDATE_WORKER_NAME, [])
        if len(worker_definitions) > 1:
            findings.append(
                _finding(
                    relative,
                    _CANDIDATE_WORKER_NAME,
                    worker_definitions[0].lineno,
                    "candidate-worker-definition-ambiguous",
                    "candidate runner contains multiple top-level _run_worker definitions",
                )
            )
            continue
        if not worker_definitions:
            continue

        worker = worker_definitions[0]
        if not _direct_candidate_loader(worker):
            findings.append(
                _finding(
                    relative,
                    _CANDIDATE_WORKER_NAME,
                    worker.lineno,
                    "candidate-worker-loader-topology-unreviewed",
                    "_run_worker exists but does not directly invoke the reviewed _load_worker candidate loader",
                )
            )
            continue

        candidate_runners.append((relative, worker.lineno))
        findings.extend(_attestation_findings(tree, relative, worker))

    if not candidate_runners:
        findings.append(
            _finding(
                "<bundle>",
                _CANDIDATE_WORKER_NAME,
                0,
                "candidate-runner-missing",
                "runner bundle contains no uniquely reviewable candidate-importing _run_worker topology",
            )
        )
    elif len(candidate_runners) != 1:
        findings.append(
            _finding(
                "<bundle>",
                _CANDIDATE_WORKER_NAME,
                0,
                "candidate-runner-authority-ambiguous",
                "runner bundle contains more than one candidate-importing _run_worker authority",
            )
        )

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
        "candidate_runner_count": len(candidate_runners),
        "attestation_finding_count": len(rendered),
        "attestation_findings": rendered,
        "passed": (
            bool(base_report.get("passed"))
            and len(candidate_runners) == 1
            and not rendered
        ),
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
