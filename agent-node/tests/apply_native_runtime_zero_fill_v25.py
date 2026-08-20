from __future__ import annotations

import hashlib
import pathlib

SOURCE = pathlib.Path(__file__).parents[1] / "agent_node.py"
EXPECTED_INPUT_BLOB = "0654ecccd0a26e50ec7e30e3d43f4efe1330f99d"
EXPECTED_OUTPUT_BLOB = "6d58e0dee61de0f8b0feb6b05684695f2751db37"


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def main() -> None:
    original = SOURCE.read_text(encoding="utf-8")
    original_bytes = original.encode("utf-8")
    if git_blob_sha(original_bytes) != EXPECTED_INPUT_BLOB:
        raise SystemExit("refusing to repair unexpected source blob")

    candidate = original
    replacements = [
        (
            'RUNTIME_POLICY = "agent-node-python-runtime-v24"',
            'RUNTIME_POLICY = "agent-node-python-runtime-v25"',
            1,
        ),
        (
            "loads: list[tuple[int, int, int]] = []",
            "loads: list[tuple[int, int, int, int]] = []",
            1,
        ),
        (
            "p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = values",
            "p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = values",
            1,
        ),
        (
            "p_type, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _flags, _align = values",
            "p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _flags, _align = values",
            1,
        ),
        (
            """        if p_offset + p_filesz > len(data):
            raise RuntimeError(f"ELF segment exceeds file bytes for native runtime candidate: {path}")
        if p_type == 1:
            loads.append((p_offset, p_vaddr, p_filesz))
""",
            """        if p_offset + p_filesz > len(data):
            raise RuntimeError(f"ELF segment exceeds file bytes for native runtime candidate: {path}")
        if p_memsz < p_filesz:
            raise RuntimeError(f"ELF PT_LOAD memory size is smaller than file size for native runtime candidate: {path}")
        if p_type == 1:
            loads.append((p_offset, p_vaddr, p_filesz, p_memsz))
""",
            1,
        ),
        (
            "for load_offset, load_vaddr, load_filesz in loads",
            "for load_offset, load_vaddr, load_filesz, load_memsz in loads",
            3,
        ),
        (
            "for p_offset, p_vaddr, p_filesz in loads",
            "for p_offset, p_vaddr, p_filesz, p_memsz in loads",
            1,
        ),
        (
            """        for load_offset, load_vaddr, load_filesz, load_memsz in loads:
            if load_filesz <= 0:
                continue
            load_page_start = load_vaddr & ~page_mask
""",
            """        for load_offset, load_vaddr, load_filesz, load_memsz in loads:
            if load_memsz > load_filesz:
                zero_fill_start = load_vaddr + load_filesz
                zero_fill_end = load_vaddr + load_memsz
                zero_fill_overlaps = zero_fill_start < range_end and range_vaddr < zero_fill_end
                if zero_fill_overlaps:
                    raise RuntimeError(
                        f"ELF {label} overlaps PT_LOAD zero-fill range for native runtime candidate: {path}"
                    )
            if load_filesz <= 0:
                continue
            load_page_start = load_vaddr & ~page_mask
""",
            1,
        ),
    ]

    for old, new, expected_count in replacements:
        actual_count = candidate.count(old)
        if actual_count != expected_count:
            raise SystemExit(
                f"replacement cardinality mismatch: expected {expected_count}, got {actual_count}: {old!r}"
            )
        candidate = candidate.replace(old, new)

    compile(candidate, str(SOURCE), "exec")
    candidate_bytes = candidate.encode("utf-8")
    actual_output = git_blob_sha(candidate_bytes)
    if actual_output != EXPECTED_OUTPUT_BLOB:
        raise SystemExit(f"candidate blob mismatch: expected {EXPECTED_OUTPUT_BLOB}, got {actual_output}")
    SOURCE.write_bytes(candidate_bytes)
    print("V25_SOURCE_BLOB=" + actual_output)


if __name__ == "__main__":
    main()
