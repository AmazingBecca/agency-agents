from __future__ import annotations

import base64
import hashlib
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agent_node.py"


class NativeRuntimeZeroFillCandidateBuilderTests(unittest.TestCase):
    def test_emit_exact_v25_candidate(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        candidate = source

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
            raise RuntimeError(f\"ELF segment exceeds file bytes for native runtime candidate: {path}\")
        if p_type == 1:
            loads.append((p_offset, p_vaddr, p_filesz))
""",
                """        if p_offset + p_filesz > len(data):
            raise RuntimeError(f\"ELF segment exceeds file bytes for native runtime candidate: {path}\")
        if p_memsz < p_filesz:
            raise RuntimeError(f\"ELF PT_LOAD memory size is smaller than file size for native runtime candidate: {path}\")
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
                        f\"ELF {label} overlaps PT_LOAD zero-fill range for native runtime candidate: {path}\"
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
            self.assertEqual(actual_count, expected_count, (old, actual_count, expected_count))
            candidate = candidate.replace(old, new)

        compile(candidate, str(MODULE_PATH), "exec")
        encoded = candidate.encode("utf-8")
        blob_sha = hashlib.sha1(f"blob {len(encoded)}\0".encode("ascii") + encoded).hexdigest()
        print("V25_CANDIDATE_BLOB=" + blob_sha)
        print("V25_CANDIDATE_BASE64=" + base64.b64encode(encoded).decode("ascii"))


if __name__ == "__main__":
    unittest.main()
