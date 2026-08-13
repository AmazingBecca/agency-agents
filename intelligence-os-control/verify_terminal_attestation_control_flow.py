from __future__ import annotations

import argparse
import ast
import json
import pathlib
import stat
import sys
from dataclasses import asdict, dataclass

_SCHEMA = "amazingbecca.terminal-attestation-control-flow.v1"
_READY_MARKER = b"candidate-exited\n"
_AUTHORITY_DESCRIPTORS = frozenset({"challenge_fd", "receipt_fd", "ready_fd"})
_AUTHORITY_TERMINALS = frozenset(
    {"Popen", "wait", "read", "_write_all", "write", "send", "sendall"}
)


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


def _names(node: ast.AST) -> set[str]:
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}


def _string_literals(node: ast.AST) -> set[str | bytes]:
    return {
        item.value
        for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, (str, bytes))
    }


def _keyword(call: ast.Call, name: str) -> ast.keyword | None:
    matches = [item for item in call.keywords if item.arg == name]
    return matches[0] if len(matches) == 1 else None


def _top_level_functions(tree: ast.Module) -> dict[str, list[ast.FunctionDef]]:
    functions: dict[str, list[ast.FunctionDef]] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            functions.setdefault(node.name, []).append(node)
    return functions


def _call_from_statement(statement: ast.stmt) -> tuple[ast.Call, str | None] | None:
    if isinstance(statement, ast.Assign):
        if len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
            return None
        if isinstance(statement.value, ast.Call):
            return statement.value, statement.targets[0].id
        return None
    if isinstance(statement, ast.AnnAssign):
        if isinstance(statement.target, ast.Name) and isinstance(statement.value, ast.Call):
            return statement.value, statement.target.id
        return None
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
        return statement.value, None
    return None


def _direct_calls(function: ast.FunctionDef) -> list[tuple[int, ast.Call, str | None]]:
    records: list[tuple[int, ast.Call, str | None]] = []
    for index, statement in enumerate(function.body):
        record = _call_from_statement(statement)
        if record is not None:
            call, assigned = record
            records.append((index, call, assigned))
    return records


def _scope_calls(function: ast.FunctionDef) -> list[ast.Call]:
    """Return calls in the attestor execution scope, excluding deferred scopes."""
    calls: list[ast.Call] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is function:
                for statement in node.body:
                    self.visit(statement)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Call(self, node: ast.Call) -> None:
            calls.append(node)
            self.generic_visit(node)

    Visitor().visit(function)
    return calls


def _nested_scope_calls(function: ast.FunctionDef) -> list[ast.Call]:
    nested: list[ast.Call] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is function:
                for statement in node.body:
                    self.visit(statement)
                return
            nested.extend(item for item in ast.walk(node) if isinstance(item, ast.Call))

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            nested.extend(item for item in ast.walk(node) if isinstance(item, ast.Call))

        def visit_Lambda(self, node: ast.Lambda) -> None:
            nested.extend(item for item in ast.walk(node) if isinstance(item, ast.Call))

    Visitor().visit(function)
    return nested


def _storage_roots(node: ast.AST) -> set[str]:
    """Return conservative local roots that can retain a value written to target."""
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Starred):
        return _storage_roots(node.value)
    if isinstance(node, (ast.Tuple, ast.List)):
        roots: set[str] = set()
        for item in node.elts:
            roots.update(_storage_roots(item))
        return roots
    if isinstance(node, ast.Attribute):
        return _storage_roots(node.value)
    if isinstance(node, ast.Subscript):
        return _storage_roots(node.value)
    return set()


def _descriptor_taint(
    function: ast.FunctionDef,
) -> tuple[set[str], tuple[tuple[int, str], ...]]:
    """Propagate trusted descriptor aliases through names and object/container storage.

    Attribute/subscript writes taint their root object. Writes into storage with no
    stable local root are rejected rather than silently escaping the review model.
    """
    tainted = set(_AUTHORITY_DESCRIPTORS)
    assignments: list[tuple[tuple[ast.AST, ...], ast.AST, int]] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is function:
                for statement in node.body:
                    self.visit(statement)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_Assign(self, node: ast.Assign) -> None:
            assignments.append((tuple(node.targets), node.value, node.lineno))
            self.visit(node.value)
            for target in node.targets:
                self.visit(target)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if node.value is not None:
                assignments.append(((node.target,), node.value, node.lineno))
                self.visit(node.value)
                self.visit(node.target)

        def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
            assignments.append(((node.target,), node.value, node.lineno))
            self.visit(node.value)
            self.visit(node.target)

    Visitor().visit(function)

    changed = True
    while changed:
        changed = False
        for targets, value, _ in assignments:
            if not _names(value).intersection(tainted):
                continue
            roots: set[str] = set()
            for target in targets:
                roots.update(_storage_roots(target))
            for root in roots:
                if root not in tainted:
                    tainted.add(root)
                    changed = True

    untrackable: list[tuple[int, str]] = []
    for targets, value, line in assignments:
        if not _names(value).intersection(tainted):
            continue
        roots: set[str] = set()
        for target in targets:
            roots.update(_storage_roots(target))
        if roots:
            continue
        rendered = ", ".join(
            ast.unparse(target) if hasattr(ast, "unparse") else target.__class__.__name__
            for target in targets
        )
        untrackable.append((line, rendered or "<dynamic-storage>"))

    return tainted, tuple(sorted(set(untrackable)))


def _captured_authority_scopes(
    function: ast.FunctionDef,
    descriptor_taint: set[str],
) -> tuple[tuple[int, str, str, tuple[str, ...]], ...]:
    """Inventory deferred/class scopes that retain trusted descriptor authority.

    Nested function defaults, closures, async functions, lambdas, and class bodies
    can retain a trusted descriptor without leaving the descriptor name on the
    eventual candidate launch. The reviewed attestor profile has no legitimate
    reason to capture those descriptors outside the canonical top-level lifecycle,
    so any such capture fails closed.
    """
    captured: list[tuple[int, str, str, tuple[str, ...]]] = []

    class Visitor(ast.NodeVisitor):
        def _record(self, node: ast.AST, scope_kind: str, scope_name: str) -> None:
            references = tuple(sorted(_names(node).intersection(descriptor_taint)))
            if references:
                captured.append((node.lineno, scope_kind, scope_name, references))

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is function:
                for statement in node.body:
                    self.visit(statement)
                return
            self._record(node, "function", node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._record(node, "async-function", node.name)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            self._record(node, "lambda", "<lambda>")

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self._record(node, "class", node.name)

    Visitor().visit(function)
    return tuple(sorted(set(captured)))


def _finding(path: str, function: str, line: int, kind: str, detail: str) -> Finding:
    return Finding(path=path, function=function, line=line, kind=kind, detail=detail)


def _source_files(root: pathlib.Path) -> tuple[pathlib.Path, ...]:
    files: list[pathlib.Path] = []
    for candidate in sorted(root.rglob("*.py")):
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"runner source must be a regular non-symlink file: {candidate}")
        if metadata.st_nlink != 1:
            raise RuntimeError(f"hard-linked runner source is forbidden: {candidate}")
        files.append(candidate)
    if not files:
        raise RuntimeError("runner bundle contains no Python source")
    return tuple(files)


def _verify_attestor(function: ast.FunctionDef, path: str) -> list[Finding]:
    findings: list[Finding] = []
    direct = _direct_calls(function)
    descriptor_taint, untrackable_storage = _descriptor_taint(function)
    captured_scopes = _captured_authority_scopes(function, descriptor_taint)

    for line, target in untrackable_storage:
        findings.append(
            _finding(
                path,
                function.name,
                line,
                "attestor-authority-descriptor-stored-outside-review-model",
                "trusted descriptor value is written through storage without a stable local root: "
                + target,
            )
        )

    for line, scope_kind, scope_name, references in captured_scopes:
        if scope_kind == "class":
            kind = "attestor-authority-descriptor-stored-in-class-scope"
            detail = (
                "trusted descriptor authority must not be retained in a class body "
                f"inside the attestor: scope={scope_name} references={','.join(references)}"
            )
        else:
            kind = "attestor-authority-descriptor-captured-by-deferred-scope"
            detail = (
                "trusted descriptor authority must not be captured by a deferred callable "
                f"inside the attestor: scope={scope_name} references={','.join(references)}"
            )
        findings.append(_finding(path, function.name, line, kind, detail))

    nested_sensitive = [
        call
        for call in _nested_scope_calls(function)
        if _terminal_name(call.func) in _AUTHORITY_TERMINALS
        or bool(_names(call).intersection(descriptor_taint))
    ]
    for call in nested_sensitive:
        findings.append(
            _finding(
                path,
                function.name,
                call.lineno,
                "attestor-authority-call-hidden-in-nested-scope",
                "candidate completion authority must not be satisfied or receive trusted descriptors in a nested function, lambda, or deferred scope",
            )
        )

    launches = [
        (index, call, assigned)
        for index, call, assigned in direct
        if _dotted_name(call.func) == "subprocess.Popen"
        and "--worker" in _string_literals(call)
    ]
    if len(launches) != 1:
        findings.append(
            _finding(
                path,
                function.name,
                function.lineno,
                "candidate-launch-not-canonical-top-level",
                "attestor must have exactly one top-level assigned subprocess.Popen launch for --worker",
            )
        )
        return findings
    launch_index, launch, candidate_name = launches[0]
    if candidate_name is None:
        findings.append(
            _finding(
                path,
                function.name,
                launch.lineno,
                "candidate-process-identity-unbound",
                "candidate launch must bind the process object to one local name",
            )
        )
        return findings

    close_fds = _keyword(launch, "close_fds")
    if close_fds is None or not (
        isinstance(close_fds.value, ast.Constant) and close_fds.value.value is True
    ):
        findings.append(
            _finding(
                path,
                function.name,
                launch.lineno,
                "candidate-descriptor-closure-not-enforced",
                "candidate launch must use close_fds=True",
            )
        )

    launch_taint = sorted(_names(launch).intersection(descriptor_taint))
    if launch_taint:
        findings.append(
            _finding(
                path,
                function.name,
                launch.lineno,
                "attestor-authority-descriptor-leaked-to-candidate",
                "candidate launch must not reference challenge, receipt, readiness descriptors or any aliases derived from them: "
                + ",".join(launch_taint),
            )
        )

    waits = [
        (index, call, assigned)
        for index, call, assigned in direct
        if _dotted_name(call.func) == f"{candidate_name}.wait"
    ]
    if len(waits) != 1:
        findings.append(
            _finding(
                path,
                function.name,
                function.lineno,
                "candidate-wait-not-canonical-top-level",
                "attestor must have exactly one top-level wait on the launched candidate",
            )
        )
        return findings
    wait_index, wait_call, _ = waits[0]

    ready_writes = [
        (index, call)
        for index, call, _ in direct
        if _terminal_name(call.func) == "_write_all"
        and call.args
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "ready_fd"
    ]
    challenge_reads = [
        (index, call, assigned)
        for index, call, assigned in direct
        if _dotted_name(call.func) == "os.read"
        and call.args
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "challenge_fd"
    ]
    receipt_writes = [
        (index, call)
        for index, call, _ in direct
        if _terminal_name(call.func) == "_write_all"
        and call.args
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "receipt_fd"
    ]

    if len(ready_writes) != 1:
        findings.append(
            _finding(
                path,
                function.name,
                function.lineno,
                "post-exit-readiness-not-canonical-top-level",
                "attestor must emit exactly one top-level fixed readiness marker",
            )
        )
        return findings
    if len(challenge_reads) != 1:
        findings.append(
            _finding(
                path,
                function.name,
                function.lineno,
                "challenge-read-not-canonical-top-level",
                "attestor must read the supervisor challenge exactly once at top level",
            )
        )
        return findings
    if len(receipt_writes) != 1:
        findings.append(
            _finding(
                path,
                function.name,
                function.lineno,
                "receipt-write-not-canonical-top-level",
                "attestor must emit exactly one top-level terminal receipt",
            )
        )
        return findings

    ready_index, ready_call = ready_writes[0]
    challenge_index, challenge_call, token_name = challenge_reads[0]
    receipt_index, receipt_call = receipt_writes[0]

    if _READY_MARKER not in _string_literals(ready_call):
        findings.append(
            _finding(
                path,
                function.name,
                ready_call.lineno,
                "post-exit-readiness-marker-drift",
                "attestor readiness marker must be the fixed candidate-exited marker",
            )
        )
    if token_name is None:
        findings.append(
            _finding(
                path,
                function.name,
                challenge_call.lineno,
                "challenge-identity-unbound",
                "attestor challenge read must bind the token to one local name",
            )
        )
    elif not (
        len(receipt_call.args) >= 2
        and isinstance(receipt_call.args[1], ast.Name)
        and receipt_call.args[1].id == token_name
    ):
        findings.append(
            _finding(
                path,
                function.name,
                receipt_call.lineno,
                "receipt-not-bound-to-challenge",
                "terminal receipt must relay the exact post-exit challenge value",
            )
        )

    if not (launch_index < wait_index < ready_index < challenge_index < receipt_index):
        findings.append(
            _finding(
                path,
                function.name,
                function.lineno,
                "attestor-authority-order-not-dominating",
                "reviewed top-level authority order must be launch -> wait -> readiness -> challenge read -> receipt",
            )
        )

    canonical_call_ids = {
        id(launch),
        id(wait_call),
        id(ready_call),
        id(challenge_call),
        id(receipt_call),
    }
    for call in _scope_calls(function):
        if id(call) in canonical_call_ids:
            continue
        terminal = _terminal_name(call.func)
        descriptor_use = sorted(_names(call).intersection(descriptor_taint))
        if terminal in _AUTHORITY_TERMINALS or descriptor_use:
            detail = (
                "attestor authority must have exactly one canonical top-level path; "
                f"unexpected call={_dotted_name(call.func) or terminal or '<dynamic>'}"
            )
            if descriptor_use:
                detail += f" trusted_descriptor_taint={','.join(descriptor_use)}"
            findings.append(
                _finding(
                    path,
                    function.name,
                    call.lineno,
                    "attestor-authority-call-outside-canonical-path",
                    detail,
                )
            )

    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    findings: list[Finding] = []
    candidates: list[tuple[str, ast.FunctionDef]] = []
    attestors: list[tuple[str, ast.FunctionDef]] = []

    for source in _source_files(root):
        relative = source.relative_to(root).as_posix()
        raw = source.read_bytes()
        try:
            tree = ast.parse(raw, filename=str(source))
        except (SyntaxError, ValueError, TypeError) as exc:
            raise RuntimeError(f"runner source cannot be parsed: {source}") from exc

        functions = _top_level_functions(tree)
        for worker in functions.get("_run_worker", []):
            if any(
                _dotted_name(call.func) == "_load_worker"
                for call in ast.walk(worker)
                if isinstance(call, ast.Call)
            ):
                candidates.append((relative, worker))
        for attestor in functions.get("_run_attestor", []):
            attestors.append((relative, attestor))

    if len(candidates) != 1:
        findings.append(
            _finding(
                "<bundle>",
                "_run_worker",
                0,
                "candidate-runner-authority-ambiguous",
                "runner bundle must contain exactly one direct candidate-importing _run_worker",
            )
        )
    if len(attestors) != 1:
        findings.append(
            _finding(
                "<bundle>",
                "_run_attestor",
                0,
                "terminal-attestor-authority-ambiguous",
                "runner bundle must contain exactly one top-level _run_attestor",
            )
        )

    if len(candidates) == 1 and len(attestors) == 1:
        candidate_path, _ = candidates[0]
        attestor_path, attestor = attestors[0]
        if candidate_path != attestor_path:
            findings.append(
                _finding(
                    attestor_path,
                    attestor.name,
                    attestor.lineno,
                    "candidate-attestor-source-split-unreviewed",
                    "candidate runner and terminal attestor must share one reviewed source unit for this authority profile",
                )
            )
        findings.extend(_verify_attestor(attestor, attestor_path))

    rendered = [
        asdict(item)
        for item in sorted(
            findings,
            key=lambda item: (item.path, item.function, item.line, item.kind),
        )
    ]
    return {
        "schema": _SCHEMA,
        "authority_level": "source-control-flow-diagnostic-not-terminal",
        "candidate_runner_count": len(candidates),
        "terminal_attestor_count": len(attestors),
        "finding_count": len(rendered),
        "findings": rendered,
        "passed": len(candidates) == 1 and len(attestors) == 1 and not rendered,
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
