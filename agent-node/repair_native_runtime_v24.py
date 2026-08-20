from __future__ import annotations

import hashlib
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "agent-node" / "agent_node.py"
WORKFLOW = ROOT / ".github" / "workflows" / "agent-node-native-runtime-closure.yml"
EXPECTED_SOURCE_BLOB = "223883bc7ca6f3733dddd77a883bf50c8723af1d"
EXPECTED_TEST_BLOB = "c6ce8bf1ed031e41cbbfdb92965a608ae8a7fa5e"
EXPECTED_WORKFLOW_BLOB = "ffaca4c3a16c50af80a11a58f2c861f64b39e3c9"
TEST_PATH = ROOT / "agent-node" / "tests" / "test_native_runtime_string_table_overlap.py"


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


source_bytes = SOURCE.read_bytes()
if git_blob_sha1(source_bytes) != EXPECTED_SOURCE_BLOB:
    raise SystemExit("unexpected production source blob")
if git_blob_sha1(TEST_PATH.read_bytes()) != EXPECTED_TEST_BLOB:
    raise SystemExit("unexpected discriminator blob")
if git_blob_sha1(WORKFLOW.read_bytes()) != EXPECTED_WORKFLOW_BLOB:
    raise SystemExit("unexpected validation workflow blob")

text = source_bytes.decode("utf-8")
if text.count('RUNTIME_POLICY = "agent-node-python-runtime-v23"') != 1:
    raise SystemExit("runtime policy marker mismatch")
text = text.replace(
    'RUNTIME_POLICY = "agent-node-python-runtime-v23"',
    'RUNTIME_POLICY = "agent-node-python-runtime-v24"',
    1,
)

old_page_start_marker = '    try:\n        page_size = int(os.sysconf("SC_PAGESIZE"))\n'
string_table_marker = '    string_table_offsets: set[int] = set()\n'
string_context = text.index('    if string_table_vaddr is None or string_table_size is None:')
old_page_start = text.index(old_page_start_marker, string_context)
old_page_end = text.index(string_table_marker, old_page_start)
text = text[:old_page_start] + text[old_page_end:]

helper_anchor = '''    if dynamic_region is None:\n        return ()\n\n'''
if text.count(helper_anchor) != 1:
    raise SystemExit("PT_DYNAMIC helper insertion anchor mismatch")
helper = '''    if dynamic_region is None:\n        return ()\n\n    try:\n        page_size = int(os.sysconf("SC_PAGESIZE"))\n    except (AttributeError, OSError, ValueError) as exc:\n        raise RuntimeError(f"Linux page size is unavailable for native runtime candidate: {path}") from exc\n    if page_size <= 0 or page_size & (page_size - 1):\n        raise RuntimeError(f"unsupported Linux page size for native runtime candidate: {path}")\n\n    page_mask = page_size - 1\n\n    def validate_loader_page_aliases(\n        range_vaddr: int,\n        range_size: int,\n        mapped_file_offset: int,\n        label: str,\n    ) -> None:\n        if range_size <= 0:\n            raise RuntimeError(f"ELF {label} has an empty loader range for native runtime candidate: {path}")\n        range_end = range_vaddr + range_size\n        authoritative_deltas = {\n            load_offset - load_vaddr\n            for load_offset, load_vaddr, load_filesz in loads\n            if load_vaddr <= range_vaddr\n            and range_end <= load_vaddr + load_filesz\n            and load_offset + (range_vaddr - load_vaddr) == mapped_file_offset\n        }\n        if len(authoritative_deltas) != 1:\n            raise RuntimeError(\n                f"ELF {label} has no unique loader-equivalent mapping for native runtime candidate: {path}"\n            )\n        expected_delta = next(iter(authoritative_deltas))\n        range_page_start = range_vaddr & ~page_mask\n        range_page_end = (range_end + page_mask) & ~page_mask\n\n        for load_offset, load_vaddr, load_filesz in loads:\n            if load_filesz <= 0:\n                continue\n            load_page_start = load_vaddr & ~page_mask\n            load_page_end = (load_vaddr + load_filesz + page_mask) & ~page_mask\n            page_overlaps = load_page_start < range_page_end and range_page_start < load_page_end\n            if page_overlaps and load_offset - load_vaddr != expected_delta:\n                raise RuntimeError(\n                    f"ELF {label} page overlaps conflicting PT_LOAD mapping for native runtime candidate: {path}"\n                )\n\n'''
text = text.replace(helper_anchor, helper, 1)

dynamic_anchor = '''    if dynamic_file_offset != dynamic_offset:\n        raise RuntimeError(f"ELF PT_DYNAMIC file offset disagrees with loaded virtual-address mapping for native runtime candidate: {path}")\n'''
if text.count(dynamic_anchor) != 1:
    raise SystemExit("PT_DYNAMIC validation anchor mismatch")
text = text.replace(
    dynamic_anchor,
    dynamic_anchor + '    validate_loader_page_aliases(dynamic_vaddr, dynamic_size, dynamic_offset, "PT_DYNAMIC")\n',
    1,
)

string_anchor = '    string_table_offset = next(iter(string_table_offsets))\n'
if text.count(string_anchor) != 1:
    raise SystemExit("DT_STRTAB validation anchor mismatch")
text = text.replace(
    string_anchor,
    string_anchor
    + '    validate_loader_page_aliases(\n'
    + '        string_table_vaddr, string_table_size, string_table_offset, "dynamic string table"\n'
    + '    )\n',
    1,
)

SOURCE.write_text(text, encoding="utf-8")
new_source_blob = git_blob_sha1(SOURCE.read_bytes())
if new_source_blob == EXPECTED_SOURCE_BLOB:
    raise SystemExit("repair did not change production source")

workflow_text = WORKFLOW.read_text(encoding="utf-8")
old_pin = f"test \"$(git hash-object agent-node/agent_node.py)\" = '{EXPECTED_SOURCE_BLOB}'"
new_pin = f"test \"$(git hash-object agent-node/agent_node.py)\" = '{new_source_blob}'"
if workflow_text.count(old_pin) != 1:
    raise SystemExit("workflow source pin mismatch")
if EXPECTED_TEST_BLOB not in workflow_text:
    raise SystemExit("workflow discriminator pin mismatch")
WORKFLOW.write_text(workflow_text.replace(old_pin, new_pin, 1), encoding="utf-8")
print(new_source_blob)
