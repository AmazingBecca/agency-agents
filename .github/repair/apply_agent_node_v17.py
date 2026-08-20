from __future__ import annotations

from pathlib import Path

SOURCE = Path("agent-node/agent_node.py")
TEST = Path("agent-node/tests/test_native_runtime_multiline_spoof.py")

source = SOURCE.read_text(encoding="utf-8")
if source.count('RUNTIME_POLICY = "agent-node-python-runtime-v16"') != 1:
    raise SystemExit("expected exact runtime policy v16 source")
source = source.replace(
    'RUNTIME_POLICY = "agent-node-python-runtime-v16"',
    'RUNTIME_POLICY = "agent-node-python-runtime-v17"',
    1,
)

start = source.find("def _ldd_dependency_paths(path: pathlib.Path) -> tuple[pathlib.Path, ...]:\n")
end = source.find("\ndef _child_native_runtime_paths(executable: str) -> tuple[pathlib.Path, ...]:\n", start)
if start < 0 or end < 0:
    raise SystemExit("exact ldd dependency function boundary not found")

replacement = r'''def _ldd_dependency_paths(path: pathlib.Path) -> tuple[pathlib.Path, ...]:
    if not sys.platform.startswith("linux") or not LDD_BIN:
        raise RuntimeError("native runtime dependency discovery is supported only on Linux")
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
            continue
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
'''
source = source[:start] + replacement + source[end:]
SOURCE.write_text(source, encoding="utf-8")

# The exact-bound discriminator must remain present and must not be weakened.
test = TEST.read_text(encoding="utf-8")
for required in (
    "test_static_marker_cannot_hide_multiline_needed_record",
    "test_address_like_first_segment_cannot_hide_multiline_needed_record",
    "assertRaisesRegex(RuntimeError, \"multiline|dependency\")",
):
    if required not in test:
        raise SystemExit(f"required v17 discriminator missing: {required}")
