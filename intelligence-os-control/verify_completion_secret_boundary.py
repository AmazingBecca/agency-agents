from __future__ import annotations

import argparse
import ast
import json
import os
import pathlib
import stat
import sys
from dataclasses import asdict, dataclass

_SCHEMA = "amazingbecca.completion-secret-boundary.v1"
_MAX_SOURCE_BYTES = 4 * 1024 * 1024
_MAX_SOURCE_FILES = 256
_SECRET_FACTORIES = {
    "os.read",
    "secrets.token_bytes",
    "secrets.token_hex",
    "secrets.token_urlsafe",
}
_CANDIDATE_CALL_NAMES = {"run", "_run", "run_tests", "execute", "execute_tests"}
_RECEIPT_WRITE_NAMES = {"_write_all", "write", "send", "sendall"}


@dataclass(frozen=True)
class Finding:
    path: str
    function: str
    secret_name: str
    secret_line: int
    candidate_line: int
    receipt_line: int | None
    exposure_kind: str


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _terminal_name(node: ast.AST) -> str | None:
    dotted = _dotted_name(node)
    if dotted is None:
        return None
    return dotted.rsplit(".", 1)[-1]


def _read_regular(path: pathlib.Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError(f"runner source must be one regular non-hard-linked file: {path}")
        if before.st_size < 1 or before.st_size > _MAX_SOURCE_BYTES:
            raise RuntimeError(f"runner source size is outside policy: {path}")
        payload = bytearray()
        while len(payload) <= _MAX_SOURCE_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_SOURCE_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(before) != identity(after) or len(payload) != before.st_size:
            raise RuntimeError(f"runner source changed during completion-boundary read: {path}")
        if len(payload) > _MAX_SOURCE_BYTES:
            raise RuntimeError(f"runner source size is outside policy: {path}")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _source_files(root: pathlib.Path) -> tuple[pathlib.Path, ...]:
    resolved = root.resolve(strict=True)
    metadata = resolved.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("runner root must be one real directory")
    sources: list[pathlib.Path] = []
    for current, directories, files in os.walk(resolved, topdown=True, followlinks=False):
        current_path = pathlib.Path(current)
        for directory in list(directories):
            candidate = current_path / directory
            child = candidate.lstat()
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode):
                raise RuntimeError(f"unsafe runner directory in completion-boundary inventory: {candidate}")
        for name in files:
            if not name.endswith(".py"):
                continue
            source = current_path / name
            child = source.lstat()
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISREG(child.st_mode) or child.st_nlink != 1:
                raise RuntimeError(f"unsafe runner source in completion-boundary inventory: {source}")
            sources.append(source)
            if len(sources) > _MAX_SOURCE_FILES:
                raise RuntimeError("runner source inventory exceeds completion-boundary file policy")
    if not sources:
        raise RuntimeError("runner bundle contains no Python source for completion-boundary review")
    return tuple(sorted(sources))


def _assigned_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    if isinstance(node, ast.Name):
        names.add(node.id)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            names.update(_assigned_names(item))
    elif isinstance(node, ast.Attribute):
        names.update(_referenced_names(node.value))
    elif isinstance(node, ast.Subscript):
        names.update(_referenced_names(node.value))
    return names


def _referenced_names(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _receipt_line_after(
    receipt_uses: list[tuple[str, int]], secret_name: str, candidate_line: int
) -> int | None:
    later = [line for name, line in receipt_uses if name == secret_name and line > candidate_line]
    return min(later) if later else None


def _function_findings(function: ast.FunctionDef | ast.AsyncFunctionDef, path: str) -> list[Finding]:
    statements = sorted(
        (
            node
            for node in ast.walk(function)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Delete, ast.Call))
        ),
        key=lambda node: getattr(node, "lineno", 0),
    )
    tainted: dict[str, int] = {}
    candidate_snapshots: list[tuple[int, dict[str, int]]] = []
    receipt_uses: list[tuple[str, int]] = []

    for node in statements:
        if isinstance(node, ast.Delete):
            for target in node.targets:
                for name in _assigned_names(target):
                    tainted.pop(name, None)
            continue

        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            assigned = set().union(*(_assigned_names(target) for target in targets))
            source_line: int | None = None
            if isinstance(value, ast.Call) and _dotted_name(value.func) in _SECRET_FACTORIES:
                source_line = node.lineno
            else:
                referenced = _referenced_names(value)
                source_lines = [tainted[name] for name in referenced if name in tainted]
                if source_lines:
                    source_line = min(source_lines)
            if source_line is not None:
                for name in assigned:
                    tainted[name] = source_line
            else:
                # A direct name overwrite destroys the Python-level alias. Attribute
                # and subscript writes intentionally do not clear their container's
                # taint because other secret-bearing members may still exist.
                for target in targets:
                    if isinstance(target, ast.Name):
                        tainted.pop(target.id, None)
            continue

        if not isinstance(node, ast.Call):
            continue

        terminal = _terminal_name(node.func)

        # Explicit mutation helpers can move a secret into an object without an
        # Assign node (for example setattr(state, "token", token)). Conservatively
        # taint the receiving object when a tainted value is stored this way.
        if terminal == "setattr" and len(node.args) >= 3:
            value_names = _referenced_names(node.args[2])
            source_lines = [tainted[name] for name in value_names if name in tainted]
            if source_lines:
                for name in _referenced_names(node.args[0]):
                    tainted[name] = min(source_lines)
        elif terminal == "__setitem__" and len(node.args) >= 2:
            value_names = _referenced_names(node.args[-1])
            source_lines = [tainted[name] for name in value_names if name in tainted]
            if source_lines:
                receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
                if receiver is not None:
                    for name in _referenced_names(receiver):
                        tainted[name] = min(source_lines)

        if terminal in _RECEIPT_WRITE_NAMES:
            referenced = set().union(*(_referenced_names(argument) for argument in node.args))
            for name in sorted(referenced.intersection(tainted)):
                receipt_uses.append((name, node.lineno))

        if terminal in _CANDIDATE_CALL_NAMES:
            candidate_snapshots.append((node.lineno, dict(tainted)))

    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for candidate_line, live_taint in candidate_snapshots:
        for name, secret_line in sorted(live_taint.items()):
            if secret_line >= candidate_line:
                continue
            identity = (name, candidate_line)
            if identity in seen:
                continue
            seen.add(identity)
            findings.append(
                Finding(
                    path=path,
                    function=function.name,
                    secret_name=name,
                    secret_line=secret_line,
                    candidate_line=candidate_line,
                    receipt_line=_receipt_line_after(receipt_uses, name, candidate_line),
                    exposure_kind="secret-live-at-candidate-execution",
                )
            )
    return findings


def verify(runner_root: pathlib.Path) -> dict[str, object]:
    root = runner_root.resolve(strict=True)
    findings: list[Finding] = []
    files = _source_files(root)
    for source in files:
        raw = _read_regular(source)
        try:
            tree = ast.parse(raw, filename=str(source))
        except (SyntaxError, ValueError, TypeError) as exc:
            raise RuntimeError(f"runner source cannot be parsed for completion-boundary review: {source}") from exc
        relative = source.relative_to(root).as_posix()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(_function_findings(node, relative))

    rendered = [
        asdict(item)
        for item in sorted(
            findings,
            key=lambda item: (item.path, item.function, item.secret_line, item.candidate_line),
        )
    ]
    return {
        "schema": _SCHEMA,
        "authority_level": "source-topology-diagnostic-not-terminal",
        "source_file_count": len(files),
        "finding_count": len(rendered),
        "findings": rendered,
        "passed": not rendered,
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
