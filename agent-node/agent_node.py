#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
ROOT = pathlib.Path(os.environ.get("AGENT_NODE_REPO_ROOT", ".")).resolve()
TOKEN = os.environ.get("AGENT_NODE_BEARER", "")
MODEL_ENDPOINT = os.environ.get("AGENT_NODE_MODEL_ENDPOINT", "http://127.0.0.1:11434/v1/chat/completions")
MODEL_NAME = os.environ.get("AGENT_NODE_MODEL", "")
TEST_ALLOWLIST = tuple(x.strip() for x in os.environ.get("AGENT_NODE_TEST_ALLOWLIST", "").split(",") if x.strip())
TEST_OUTPUT_LIMIT = 20_000
RUNTIME_POLICY = "agent-node-python-runtime-v24"


def _resolve_git_bin() -> str:
    configured = os.environ.get("AGENT_NODE_GIT_BIN", "")
    candidates = [configured] if configured else ["/usr/bin/git", shutil.which("git") or ""]
    for candidate in candidates:
        if not candidate:
            continue
        path = pathlib.Path(candidate)
        if configured and not path.is_absolute():
            raise RuntimeError("AGENT_NODE_GIT_BIN must be an absolute path")
        try:
            resolved = path.resolve(strict=True)
            mode = resolved.stat().st_mode
        except OSError:
            continue
        if stat.S_ISREG(mode) and os.access(resolved, os.X_OK):
            return str(resolved)
    raise RuntimeError("a trusted executable git binary is required")


GIT_BIN = _resolve_git_bin()


def _resolve_ldd_bin() -> str:
    if not sys.platform.startswith("linux"):
        return ""
    path = pathlib.Path("/usr/bin/ldd")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError("Linux native runtime closure requires trusted /usr/bin/ldd") from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise RuntimeError("Linux native runtime closure requires executable /usr/bin/ldd")
    return str(resolved)


LDD_BIN = _resolve_ldd_bin()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _git_env() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
        and not key.startswith("LD_")
        and not key.startswith("DYLD_")
    }
    env.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


def _python_env() -> dict[str, str]:
    """Remove interpreter, loader, and shell-startup injection variables for child Python/tools."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("PYTHON")
        and not key.startswith("LD_")
        and not key.startswith("DYLD_")
        and not key.startswith("BASH_FUNC_")
        and key
        not in {
            "VIRTUAL_ENV",
            "__PYVENV_LAUNCHER__",
            "BASH_ENV",
            "ENV",
            "SHELLOPTS",
            "BASHOPTS",
        }
    }
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _stable_regular_file_sha256(path: pathlib.Path) -> str:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("secure runtime identity requires O_NOFOLLOW")
    resolved = path.resolve(strict=True)
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(resolved, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError("Python runtime is not a regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            raise RuntimeError("Python runtime changed during identity read")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _child_runtime_search_paths(executable: str) -> tuple[str, ...]:
    """Read sys.path from the exact scrubbed isolated child configuration."""
    probe = (
        "import sys;"
        "sys.stdout.buffer.write(b'\\0'.join("
        "value.encode('utf-8','surrogateescape') for value in sys.path))"
    )
    cp = subprocess.run(
        [executable, "-I", "-B", "-S", "-c", probe],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        env=_python_env(),
    )
    values = tuple(part.decode("utf-8", "surrogateescape") for part in cp.stdout.split(b"\0"))
    if not values or any(not value for value in values):
        raise RuntimeError("isolated Python child returned an empty runtime search path")
    for value in values:
        if not pathlib.Path(value).is_absolute():
            raise RuntimeError(f"isolated Python child returned a non-absolute runtime search path: {value}")
    return values


def _runtime_archive_boundary(value: str) -> pathlib.Path | None:
    """Return the lexical archive file underlying one executable sys.path entry."""
    if not value:
        return None
    candidate = pathlib.Path(value)
    if not candidate.is_absolute():
        candidate = pathlib.Path.cwd() / candidate
    lexical = candidate

    textual_zip_boundary: pathlib.Path | None = None
    parts = lexical.parts
    for index in range(1, len(parts) + 1):
        prefix = pathlib.Path(*parts[:index])
        if textual_zip_boundary is None and prefix.name.lower().endswith(".zip"):
            textual_zip_boundary = prefix
        try:
            metadata = prefix.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RuntimeError(f"Python runtime search path cannot be inspected: {prefix}") from exc

        if stat.S_ISREG(metadata.st_mode):
            return prefix
        if stat.S_ISLNK(metadata.st_mode):
            try:
                resolved_target = prefix.resolve(strict=True)
                target_metadata = resolved_target.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeError(f"Python runtime search-path symlink cannot be resolved: {prefix}") from exc
            if stat.S_ISREG(target_metadata.st_mode):
                return prefix
            if stat.S_ISDIR(target_metadata.st_mode):
                continue
            raise RuntimeError(f"Python runtime search-path symlink target is unsupported: {prefix}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"Python runtime search-path component is unsupported: {prefix}")

    return textual_zip_boundary


def _runtime_roots(search_paths: tuple[str, ...] | None = None) -> tuple[pathlib.Path, ...]:
    if search_paths is None:
        search_paths = _child_runtime_search_paths(str(pathlib.Path(sys.executable).resolve(strict=True)))
    roots: list[pathlib.Path] = []
    for value in search_paths:
        if _runtime_archive_boundary(value) is not None:
            continue
        lexical = pathlib.Path(value)
        try:
            metadata = lexical.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RuntimeError(f"Python runtime root cannot be inspected: {lexical}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            try:
                resolved = lexical.resolve(strict=True)
                target_metadata = resolved.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeError(f"Python runtime root symlink cannot be resolved: {lexical}") from exc
            if not stat.S_ISDIR(target_metadata.st_mode):
                raise RuntimeError(f"Python runtime root symlink target is not a directory: {lexical}")
            root = resolved
        elif stat.S_ISDIR(metadata.st_mode):
            root = lexical.resolve(strict=True)
        elif stat.S_ISREG(metadata.st_mode):
            continue
        else:
            raise RuntimeError(f"Python runtime search root is unsupported: {lexical}")
        if root not in roots:
            roots.append(root)
    if not roots:
        raise RuntimeError("Python standard-library runtime roots are unavailable")
    return tuple(roots)


def _runtime_tree_sha256(roots: tuple[pathlib.Path, ...]) -> str:
    records: list[dict[str, object]] = []
    for root_index, root_value in enumerate(roots):
        root = pathlib.Path(root_value).resolve(strict=True)
        if not root.is_dir():
            raise RuntimeError(f"Python runtime root is not a directory: {root}")
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            dirnames[:] = sorted(dirnames)
            directory = pathlib.Path(dirpath)
            for dirname in dirnames:
                child = directory / dirname
                if child.is_symlink():
                    raise RuntimeError(f"Python runtime tree contains a directory symlink: {child}")
            for filename in sorted(filenames):
                path = directory / filename
                relative = path.relative_to(root).as_posix()
                if path.is_symlink():
                    try:
                        link_target = os.readlink(path)
                        resolved_target = path.resolve(strict=True)
                        target_metadata = resolved_target.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise RuntimeError(f"Python runtime symlink cannot be resolved: {path}") from exc
                    if not stat.S_ISREG(target_metadata.st_mode):
                        raise RuntimeError(f"Python runtime symlink target is not a regular file: {path}")
                    records.append(
                        {
                            "root": root_index,
                            "path": relative,
                            "kind": "symlink-file",
                            "link_target": link_target,
                            "target_size": target_metadata.st_size,
                            "target_sha256": _stable_regular_file_sha256(resolved_target),
                        }
                    )
                    continue
                try:
                    metadata = path.stat(follow_symlinks=False)
                except OSError as exc:
                    raise RuntimeError(f"Python runtime tree entry cannot be inspected: {path}") from exc
                if not stat.S_ISREG(metadata.st_mode):
                    raise RuntimeError(f"Python runtime tree entry is not a regular file: {path}")
                records.append(
                    {
                        "root": root_index,
                        "path": relative,
                        "kind": "file",
                        "mode": stat.S_IMODE(metadata.st_mode),
                        "size": metadata.st_size,
                        "sha256": _stable_regular_file_sha256(path),
                    }
                )
    if not records:
        raise RuntimeError("Python runtime tree contains no bindable files")
    digest = hashlib.sha256(canonical(records)).hexdigest()
    if not SHA64.fullmatch(digest):
        raise RuntimeError("Python runtime tree identity is invalid")
    return digest


def _runtime_archive_sha256(search_paths: tuple[str, ...] | None = None) -> str:
    if search_paths is None:
        search_paths = _child_runtime_search_paths(str(pathlib.Path(sys.executable).resolve(strict=True)))
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for value in search_paths:
        boundary = _runtime_archive_boundary(value)
        if boundary is None:
            continue
        lexical = boundary
        identity_path = os.fspath(lexical)
        if identity_path in seen:
            continue
        seen.add(identity_path)
        try:
            metadata = lexical.lstat()
        except FileNotFoundError:
            records.append({"path": identity_path, "kind": "missing"})
            continue
        except OSError as exc:
            raise RuntimeError(f"Python runtime archive cannot be inspected: {lexical}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            try:
                link_target = os.readlink(lexical)
                resolved_target = lexical.resolve(strict=True)
                target_metadata = resolved_target.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeError(f"Python runtime archive symlink cannot be resolved: {lexical}") from exc
            if not stat.S_ISREG(target_metadata.st_mode):
                raise RuntimeError(f"Python runtime archive symlink target is not a regular file: {lexical}")
            records.append(
                {
                    "path": identity_path,
                    "kind": "symlink-file",
                    "link_target": link_target,
                    "target_size": target_metadata.st_size,
                    "target_sha256": _stable_regular_file_sha256(resolved_target),
                }
            )
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"Python runtime archive is not a regular file: {lexical}")
        records.append(
            {
                "path": identity_path,
                "kind": "file",
                "mode": stat.S_IMODE(metadata.st_mode),
                "size": metadata.st_size,
                "sha256": _stable_regular_file_sha256(lexical),
            }
        )
    digest = hashlib.sha256(canonical(records)).hexdigest()
    if not SHA64.fullmatch(digest):
        raise RuntimeError("Python runtime archive identity is invalid")
    return digest


def _elf_needed_name_bytes(path: pathlib.Path) -> tuple[bytes, ...]:
    """Read exact DT_NEEDED strings from ELF bytes so ldd line boundaries are not authority."""
    resolved = path.resolve(strict=True)
    data = resolved.read_bytes()
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise RuntimeError(f"native runtime candidate is not a supported ELF file: {path}")

    elf_class = data[4]
    elf_data = data[5]
    if elf_data == 1:
        prefix = "<"
    elif elf_data == 2:
        prefix = ">"
    else:
        raise RuntimeError(f"unsupported ELF byte order for native runtime candidate: {path}")

    if elf_class == 2:
        header_format = prefix + "HHIQQQIHHHHHH"
        program_format = prefix + "IIQQQQQQ"
        dynamic_format = prefix + "qQ"
    elif elf_class == 1:
        header_format = prefix + "HHIIIIIHHHHHH"
        program_format = prefix + "IIIIIIII"
        dynamic_format = prefix + "iI"
    else:
        raise RuntimeError(f"unsupported ELF class for native runtime candidate: {path}")

    header_size = struct.calcsize(header_format)
    if 16 + header_size > len(data):
        raise RuntimeError(f"truncated ELF header for native runtime candidate: {path}")
    header = struct.unpack_from(header_format, data, 16)
    program_offset = header[4]
    program_entry_size = header[8]
    program_count = header[9]
    required_program_size = struct.calcsize(program_format)
    if program_count == 0xFFFF or program_entry_size < required_program_size:
        raise RuntimeError(f"unsupported ELF program-header layout for native runtime candidate: {path}")

    loads: list[tuple[int, int, int]] = []
    dynamic_region: tuple[int, int, int] | None = None
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        if offset + required_program_size > len(data):
            raise RuntimeError(f"truncated ELF program headers for native runtime candidate: {path}")
        values = struct.unpack_from(program_format, data, offset)
        if elf_class == 2:
            p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = values
        else:
            p_type, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _flags, _align = values
        if p_offset + p_filesz > len(data):
            raise RuntimeError(f"ELF segment exceeds file bytes for native runtime candidate: {path}")
        if p_type == 1:
            loads.append((p_offset, p_vaddr, p_filesz))
        elif p_type == 2:
            dynamic_region = (p_offset, p_vaddr, p_filesz)

    if dynamic_region is None:
        return ()

    try:
        page_size = int(os.sysconf("SC_PAGESIZE"))
    except (AttributeError, OSError, ValueError) as exc:
        raise RuntimeError(f"Linux page size is unavailable for native runtime candidate: {path}") from exc
    if page_size <= 0 or page_size & (page_size - 1):
        raise RuntimeError(f"unsupported Linux page size for native runtime candidate: {path}")

    page_mask = page_size - 1

    def validate_loader_page_aliases(
        range_vaddr: int,
        range_size: int,
        mapped_file_offset: int,
        label: str,
    ) -> None:
        if range_size <= 0:
            raise RuntimeError(f"ELF {label} has an empty loader range for native runtime candidate: {path}")
        range_end = range_vaddr + range_size
        authoritative_deltas = {
            load_offset - load_vaddr
            for load_offset, load_vaddr, load_filesz in loads
            if load_vaddr <= range_vaddr
            and range_end <= load_vaddr + load_filesz
            and load_offset + (range_vaddr - load_vaddr) == mapped_file_offset
        }
        if len(authoritative_deltas) != 1:
            raise RuntimeError(
                f"ELF {label} has no unique loader-equivalent mapping for native runtime candidate: {path}"
            )
        expected_delta = next(iter(authoritative_deltas))
        range_page_start = range_vaddr & ~page_mask
        range_page_end = (range_end + page_mask) & ~page_mask

        for load_offset, load_vaddr, load_filesz in loads:
            if load_filesz <= 0:
                continue
            load_page_start = load_vaddr & ~page_mask
            load_page_end = (load_vaddr + load_filesz + page_size - 1) & ~page_mask
            page_overlaps = load_page_start < range_page_end and range_page_start < load_page_end
            if page_overlaps and load_offset - load_vaddr != expected_delta:
                raise RuntimeError(
                    f"ELF {label} page overlaps conflicting PT_LOAD mapping for native runtime candidate: {path}"
                )

    dynamic_file_offset, dynamic_vaddr, dynamic_size = dynamic_region
    mapped_offsets: set[int] = set()
    for load_offset, load_vaddr, load_filesz in loads:
        if load_vaddr <= dynamic_vaddr and dynamic_vaddr + dynamic_size <= load_vaddr + load_filesz:
            mapped_offset = load_offset + (dynamic_vaddr - load_vaddr)
            if mapped_offset + dynamic_size > len(data):
                raise RuntimeError(f"ELF PT_DYNAMIC virtual mapping exceeds file bytes for native runtime candidate: {path}")
            mapped_offsets.add(mapped_offset)
    if len(mapped_offsets) != 1:
        raise RuntimeError(f"ELF PT_DYNAMIC virtual address has no unique PT_LOAD mapping for native runtime candidate: {path}")
    dynamic_offset = next(iter(mapped_offsets))
    if dynamic_file_offset != dynamic_offset:
        raise RuntimeError(f"ELF PT_DYNAMIC file offset disagrees with loaded virtual-address mapping for native runtime candidate: {path}")
    validate_loader_page_aliases(dynamic_vaddr, dynamic_size, dynamic_offset, "PT_DYNAMIC")
    dynamic_entry_size = struct.calcsize(dynamic_format)
    if dynamic_size % dynamic_entry_size != 0:
        raise RuntimeError(f"invalid ELF dynamic table for native runtime candidate: {path}")

    needed_offsets: list[int] = []
    string_table_vaddr: int | None = None
    string_table_size: int | None = None
    saw_dynamic_null = False
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, dynamic_entry_size):
        tag, value = struct.unpack_from(dynamic_format, data, offset)
        if tag == 0:
            saw_dynamic_null = True
            break
        if tag == 1:
            needed_offsets.append(value)
        elif tag == 5:
            string_table_vaddr = value
        elif tag == 10:
            string_table_size = value

    if not saw_dynamic_null:
        raise RuntimeError(f"ELF dynamic table lacks DT_NULL within PT_DYNAMIC file region for native runtime candidate: {path}")
    if not needed_offsets:
        return ()
    if string_table_vaddr is None or string_table_size is None:
        raise RuntimeError(f"ELF dynamic strings are unavailable for native runtime candidate: {path}")

    string_table_offsets: set[int] = set()
    for p_offset, p_vaddr, p_filesz in loads:
        if p_vaddr <= string_table_vaddr and string_table_vaddr + string_table_size <= p_vaddr + p_filesz:
            mapped_offset = p_offset + (string_table_vaddr - p_vaddr)
            if mapped_offset + string_table_size > len(data):
                raise RuntimeError(f"ELF dynamic string table mapping exceeds file bytes for native runtime candidate: {path}")
            string_table_offsets.add(mapped_offset)
    if len(string_table_offsets) != 1:
        raise RuntimeError(f"ELF dynamic string table has no unique PT_LOAD mapping for native runtime candidate: {path}")
    string_table_offset = next(iter(string_table_offsets))
    validate_loader_page_aliases(
        string_table_vaddr, string_table_size, string_table_offset, "dynamic string table"
    )
    string_table_end = string_table_offset + string_table_size
    if string_table_end > len(data):
        raise RuntimeError(f"ELF dynamic string table exceeds file bytes for native runtime candidate: {path}")

    names: list[bytes] = []
    for needed_offset in needed_offsets:
        start = string_table_offset + needed_offset
        if start < string_table_offset or start >= string_table_end:
            raise RuntimeError(f"ELF DT_NEEDED offset is invalid for native runtime candidate: {path}")
        end = data.find(b"\0", start, string_table_end)
        if end < 0:
            raise RuntimeError(f"ELF DT_NEEDED string is unterminated for native runtime candidate: {path}")
        names.append(data[start:end])
    return tuple(names)


def _ldd_dependency_paths(path: pathlib.Path) -> tuple[pathlib.Path, ...]:
    if not sys.platform.startswith("linux") or not LDD_BIN:
        raise RuntimeError("native runtime dependency discovery is supported only on Linux")
    if path.exists():
        needed_names = _elf_needed_name_bytes(path)
        if any(b"\n" in name or b"\r" in name for name in needed_names):
            raise RuntimeError(f"unsupported multiline DT_NEEDED record for native runtime candidate: {path}")
    env = _python_env()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    cp = subprocess.run(
        [LDD_BIN, os.fspath(path)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        env=env,
    )
    text = cp.stdout + "\n" + cp.stderr
    if "not found" in text:
        raise RuntimeError(f"native runtime dependency is unresolved for {path}: {text.strip()}")
    if cp.returncode != 0:
        raise RuntimeError(f"native runtime dependency discovery failed for {path}: {text.strip()}")

    dependencies: set[pathlib.Path] = set()
    address_suffix = re.compile(r" \(0x[0-9a-fA-F]+\)\s*$")
    mapped_path = re.compile(r" => (?P<path>/.*)$")
    pseudo_objects = {"linux-vdso.so.1", "linux-gate.so.1"}
    saw_static_marker = False
    saw_dependency_record = False

    for raw_line in cp.stdout.splitlines():
        line = raw_line[1:] if raw_line.startswith("\t") else raw_line
        if not line:
            raise RuntimeError(f"unsupported or multiline native dependency from ldd for {path}: {raw_line}")
        if line == "statically linked":
            if saw_static_marker or saw_dependency_record:
                raise RuntimeError(f"unsupported or multiline native dependency from ldd for {path}: {raw_line}")
            saw_static_marker = True
            continue
        if saw_static_marker:
            raise RuntimeError(f"unsupported or multiline native dependency from ldd for {path}: {raw_line}")
        if address_suffix.search(line) is None:
            raise RuntimeError(f"unsupported or multiline native dependency from ldd for {path}: {raw_line}")

        body = address_suffix.sub("", line, count=1)
        candidate = ""
        if body.startswith("/"):
            candidate = body
        else:
            match = mapped_path.search(body)
            if match:
                left = body[: match.start()]
                if "/" in left:
                    raise RuntimeError(f"ambiguous direct native dependency from ldd for {path}: {body}")
                candidate = match.group("path")
            elif "/" in body:
                try:
                    candidate = os.fspath(pathlib.Path(body).resolve(strict=True))
                except OSError as exc:
                    raise RuntimeError(f"direct native dependency cannot be resolved for {path}: {body}") from exc
            elif body in pseudo_objects:
                saw_dependency_record = True
                continue
            else:
                raise RuntimeError(f"unsupported or multiline native dependency from ldd for {path}: {raw_line}")

        if not candidate.startswith("/"):
            raise RuntimeError(f"native runtime dependency discovery returned non-absolute path for {path}: {candidate}")
        dependencies.add(pathlib.Path(candidate))
        saw_dependency_record = True

    return tuple(sorted(dependencies, key=os.fspath))

def _child_native_runtime_paths(executable: str) -> tuple[pathlib.Path, ...]:
    """Return Linux loader/DSO closure for the exact isolated Python runtime."""
    if not sys.platform.startswith("linux"):
        raise RuntimeError("native runtime closure is not implemented for this platform")

    probe = (
        "import os,sys,unittest;"
        "paths=set();"
        "lines=open('/proc/self/maps','r',encoding='utf-8').read().splitlines();"
        "[(paths.add(parts[5])) for line in lines "
        "if len((parts:=line.split(None,5)))>=6 and 'x' in parts[1] "
        "and parts[5].startswith('/') and not parts[5].endswith(' (deleted)')];"
        "sys.stdout.buffer.write(b'\\0'.join("
        "p.encode('utf-8','surrogateescape') for p in sorted(paths)))"
    )
    cp = subprocess.run(
        [executable, "-I", "-B", "-S", "-c", probe],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        env=_python_env(),
    )
    discovered: set[pathlib.Path] = {
        pathlib.Path(part.decode("utf-8", "surrogateescape"))
        for part in cp.stdout.split(b"\0")
        if part
    }

    search_paths = _child_runtime_search_paths(executable)
    roots = _runtime_roots(search_paths)
    candidates: set[pathlib.Path] = {pathlib.Path(executable).resolve(strict=True)}
    for root in roots:
        for dirpath, _dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            directory = pathlib.Path(dirpath)
            for filename in filenames:
                if ".so" not in filename:
                    continue
                candidate = directory / filename
                try:
                    metadata = candidate.stat(follow_symlinks=False)
                except OSError as exc:
                    raise RuntimeError(f"native runtime candidate cannot be inspected: {candidate}") from exc
                if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    candidates.add(candidate)

    for candidate in sorted(candidates, key=os.fspath):
        discovered.add(candidate)
        discovered.update(_ldd_dependency_paths(candidate))
    discovered.add(pathlib.Path(LDD_BIN))

    result = tuple(sorted(discovered, key=os.fspath))
    if not result:
        raise RuntimeError("isolated Python child has no bindable native runtime dependencies")
    if any(not path.is_absolute() for path in result):
        raise RuntimeError("native runtime dependency discovery returned a non-absolute path")
    return result


def _runtime_native_sha256(paths: tuple[pathlib.Path, ...]) -> str:
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for value in paths:
        lexical = pathlib.Path(value)
        if not lexical.is_absolute():
            raise RuntimeError(f"native runtime dependency path is not absolute: {lexical}")
        identity_path = os.fspath(lexical)
        if identity_path in seen:
            continue
        seen.add(identity_path)
        try:
            metadata = lexical.lstat()
        except OSError as exc:
            raise RuntimeError(f"native runtime dependency cannot be inspected: {lexical}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            try:
                link_target = os.readlink(lexical)
                resolved_target = lexical.resolve(strict=True)
                target_metadata = resolved_target.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeError(f"native runtime dependency symlink cannot be resolved: {lexical}") from exc
            if not stat.S_ISREG(target_metadata.st_mode):
                raise RuntimeError(f"native runtime dependency target is not a regular file: {lexical}")
            records.append(
                {
                    "path": identity_path,
                    "kind": "symlink-file",
                    "link_target": link_target,
                    "resolved_target": os.fspath(resolved_target),
                    "target_mode": stat.S_IMODE(target_metadata.st_mode),
                    "target_size": target_metadata.st_size,
                    "target_sha256": _stable_regular_file_sha256(resolved_target),
                }
            )
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"native runtime dependency is not a regular file: {lexical}")
        records.append(
            {
                "path": identity_path,
                "kind": "file",
                "mode": stat.S_IMODE(metadata.st_mode),
                "size": metadata.st_size,
                "sha256": _stable_regular_file_sha256(lexical),
            }
        )
    if not records:
        raise RuntimeError("native runtime closure contains no bindable files")
    digest = hashlib.sha256(canonical(records)).hexdigest()
    if not SHA64.fullmatch(digest):
        raise RuntimeError("native runtime identity is invalid")
    return digest


def python_runtime_identity() -> tuple[str, str]:
    executable = pathlib.Path(sys.executable).resolve(strict=True)
    binary_sha256 = _stable_regular_file_sha256(executable)
    runtime_search_paths = _child_runtime_search_paths(str(executable))
    runtime_search_path_sha256 = hashlib.sha256(canonical(list(runtime_search_paths))).hexdigest()
    runtime_tree_sha256 = _runtime_tree_sha256(_runtime_roots(runtime_search_paths))
    runtime_archive_sha256 = _runtime_archive_sha256(runtime_search_paths)
    runtime_native_paths = _child_native_runtime_paths(str(executable))
    runtime_native_sha256 = _runtime_native_sha256(runtime_native_paths)
    material = {
        "policy": RUNTIME_POLICY,
        "implementation": sys.implementation.name,
        "cache_tag": sys.implementation.cache_tag or "",
        "version": ".".join(str(part) for part in sys.version_info[:3]),
        "binary_sha256": binary_sha256,
        "runtime_search_path_sha256": runtime_search_path_sha256,
        "runtime_tree_sha256": runtime_tree_sha256,
        "runtime_archive_sha256": runtime_archive_sha256,
        "runtime_native_sha256": runtime_native_sha256,
        "isolated_flag": "-I",
        "bytecode_flag": "-B",
        "no_site_flag": "-S",
        "loader_env_scrubbed": True,
    }
    runtime_sha256 = hashlib.sha256(canonical(material)).hexdigest()
    if not SHA64.fullmatch(runtime_sha256):
        raise RuntimeError("Python runtime identity is invalid")
    return str(executable), runtime_sha256


def git_bytes(*args: str) -> bytes:
    cp = subprocess.run(
        [GIT_BIN, "-C", str(ROOT), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_git_env(),
    )
    return cp.stdout


def git(*args: str) -> str:
    return git_bytes(*args).decode("utf-8").strip()


def bound_identity(expected: str) -> tuple[str, str]:
    if not SHA40.fullmatch(expected):
        raise ValueError("expected_head must be lowercase 40-hex")
    head = git("rev-parse", "--verify", "HEAD^{commit}")
    if head != expected:
        raise ValueError(f"head mismatch: expected {expected}, got {head}")
    tree = git("rev-parse", "--verify", f"{expected}^{{tree}}")
    if not SHA40.fullmatch(tree):
        raise ValueError("tree identity is invalid")
    return head, tree


def _tree_entries(expected_head: str) -> list[tuple[str, str, str]]:
    raw = git_bytes("ls-tree", "-r", "-z", "--full-tree", expected_head)
    entries: list[tuple[str, str, str]] = []
    seen_paths: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, path_bytes = record.split(b"\t", 1)
            mode, object_type, object_sha = metadata.decode("ascii").split()
            path = path_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("unsupported Git tree entry encoding") from exc
        pure = pathlib.PurePosixPath(path)
        if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
            raise ValueError("unsafe Git tree path")
        normalized_path = pure.as_posix()
        if normalized_path in seen_paths:
            raise ValueError(f"duplicate Git tree path: {normalized_path}")
        seen_paths.add(normalized_path)
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(f"unsupported Git tree entry: {mode} {object_type} {path}")
        if not SHA40.fullmatch(object_sha):
            raise ValueError("invalid Git blob identity")
        entries.append((mode, object_sha, normalized_path))
    return entries


def _git_blob_sha1(data: bytes) -> str:
    prefix = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(prefix + data).hexdigest()


@contextlib.contextmanager
def committed_snapshot(expected_head: str):
    head, tree = bound_identity(expected_head)
    entries = _tree_entries(expected_head)
    with tempfile.TemporaryDirectory(prefix="amazingbecca-agent-node-") as temp_dir:
        snapshot = pathlib.Path(temp_dir) / "repo"
        snapshot.mkdir(mode=0o700)
        for mode, object_sha, relative in entries:
            data = git_bytes("cat-file", "blob", object_sha)
            if _git_blob_sha1(data) != object_sha:
                raise ValueError(f"Git blob bytes do not match object identity: {relative}")
            destination = snapshot.joinpath(*pathlib.PurePosixPath(relative).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(0o755 if mode == "100755" else 0o644)
        after_head, after_tree = bound_identity(expected_head)
        if (after_head, after_tree) != (head, tree):
            raise ValueError("repository identity changed while snapshotting")
        yield head, tree, snapshot


def repo_index(expected_head: str) -> dict:
    head, tree = bound_identity(expected_head)
    files = [path for _, _, path in _tree_entries(expected_head)]
    after_head, after_tree = bound_identity(expected_head)
    if (after_head, after_tree) != (head, tree):
        raise ValueError("repository identity changed during indexing")
    payload = {"repository_root": str(ROOT), "head": head, "tree": tree, "files": files}
    payload["sha256"] = hashlib.sha256(canonical(payload)).hexdigest()
    return payload


def run_tests(expected_head: str, selector: str) -> dict:
    if not TEST_ALLOWLIST or selector not in TEST_ALLOWLIST:
        raise ValueError("test selector not allowlisted")
    bootstrap = (
        "import sys,unittest;"
        "root,selector=sys.argv[1:3];"
        "sys.path.insert(0,root);"
        "suite=unittest.defaultTestLoader.loadTestsFromName(selector);"
        "result=unittest.TextTestRunner(verbosity=2).run(suite);"
        "raise SystemExit(0 if result.wasSuccessful() else 1)"
    )
    python_bin, runtime_sha256 = python_runtime_identity()
    with committed_snapshot(expected_head) as (head, tree, snapshot):
        cp = subprocess.run(
            [python_bin, "-I", "-B", "-S", "-c", bootstrap, str(snapshot), selector],
            cwd=snapshot,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=900,
            env=_python_env(),
        )
        returned_output = cp.stdout[-TEST_OUTPUT_LIMIT:]
    after_python_bin, after_runtime_sha256 = python_runtime_identity()
    if after_python_bin != python_bin or after_runtime_sha256 != runtime_sha256:
        raise RuntimeError("Python runtime identity changed during test execution")
    return {
        "head": head,
        "tree": tree,
        "runtime_sha256": runtime_sha256,
        "selector": selector,
        "returncode": cp.returncode,
        "stdout_sha256": hashlib.sha256(returned_output.encode()).hexdigest(),
        "stdout": returned_output,
    }


def second_opinion(expected_head: str, compact_evidence: str) -> dict:
    head, tree = bound_identity(expected_head)
    _python_bin, runtime_sha256 = python_runtime_identity()
    if not MODEL_NAME:
        raise ValueError("AGENT_NODE_MODEL is not configured")
    parsed = urllib.parse.urlparse(MODEL_ENDPOINT)
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("model endpoint must be loopback-only")
    req_body = {
        "model": MODEL_NAME,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": "Act as an independent adversarial code reviewer. Separate verified facts, inference, and unknowns. Propose deterministic falsifying tests."},
            {"role": "user", "content": compact_evidence},
        ],
    }
    request = urllib.request.Request(
        MODEL_ENDPOINT,
        data=json.dumps(req_body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        raw = response.read()
    decoded = json.loads(raw)
    after_head, after_tree = bound_identity(expected_head)
    _after_python_bin, after_runtime_sha256 = python_runtime_identity()
    if (after_head, after_tree) != (head, tree):
        raise ValueError("repository identity changed during second-opinion execution")
    if after_runtime_sha256 != runtime_sha256:
        raise RuntimeError("Python runtime identity changed during second-opinion execution")
    return {
        "head": head,
        "tree": tree,
        "runtime_sha256": runtime_sha256,
        "model": MODEL_NAME,
        "response": decoded,
        "response_sha256": hashlib.sha256(raw).hexdigest(),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AmazingBeccaAgentNode/1"

    def _authorized(self) -> bool:
        if not TOKEN:
            return False
        supplied = self.headers.get("Authorization", "")
        prefix = "Bearer "
        return supplied.startswith(prefix) and hmac.compare_digest(supplied[len(prefix):], TOKEN)

    def _send(self, status: int, value: object) -> None:
        data = canonical(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"ok": True, "git": (ROOT / ".git").exists()})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2_000_000:
                raise ValueError("invalid body length")
            body = json.loads(self.rfile.read(length))
            if self.path == "/repo-index":
                result = repo_index(body["expected_head"])
            elif self.path == "/run-tests":
                result = run_tests(body["expected_head"], body["selector"])
            elif self.path == "/second-opinion":
                result = second_opinion(body["expected_head"], body["compact_evidence"])
            else:
                self._send(404, {"error": "not found"})
                return
            self._send(200, result)
        except Exception as exc:
            self._send(400, {"error": type(exc).__name__, "message": str(exc)})

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("agent-node " + (fmt % args) + "\n")


def main() -> None:
    host = os.environ.get("AGENT_NODE_HOST", "127.0.0.1")
    port = int(os.environ.get("AGENT_NODE_PORT", "8765"))
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit("AGENT_NODE_HOST must be loopback-only")
    if not TOKEN:
        raise SystemExit("AGENT_NODE_BEARER is required")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
