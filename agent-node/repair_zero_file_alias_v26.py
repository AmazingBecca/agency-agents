from __future__ import annotations

import pathlib

SOURCE = pathlib.Path(__file__).with_name("agent_node.py")

old_policy = 'RUNTIME_POLICY = "agent-node-python-runtime-v25"'
new_policy = 'RUNTIME_POLICY = "agent-node-python-runtime-v26"'
old_block = '''            if load_filesz <= 0:\n                continue\n            load_page_start = load_vaddr & ~page_mask\n            load_page_end = (load_vaddr + load_filesz + page_size - 1) & ~page_mask\n            page_overlaps = load_page_start < range_page_end and range_page_start < load_page_end\n'''
new_block = '''            if load_filesz <= 0:\n                # glibc may still map the containing file page for a non-page-aligned\n                # zero-length file range. Treat that page as loader-visible so a conflicting\n                # alternate mapping cannot replace protected PT_DYNAMIC/DT_STRTAB bytes.\n                if load_memsz <= 0 or (load_vaddr & page_mask) == 0:\n                    continue\n                load_page_start = load_vaddr & ~page_mask\n                load_page_end = load_page_start + page_size\n            else:\n                load_page_start = load_vaddr & ~page_mask\n                load_page_end = (load_vaddr + load_filesz + page_size - 1) & ~page_mask\n            page_overlaps = load_page_start < range_page_end and range_page_start < load_page_end\n'''

text = SOURCE.read_text(encoding="utf-8")
if text.count(old_policy) != 1:
    raise SystemExit("expected exactly one v25 runtime policy marker")
if text.count(old_block) != 1:
    raise SystemExit("expected exactly one v25 zero-file page-skip block")
text = text.replace(old_policy, new_policy, 1).replace(old_block, new_block, 1)
SOURCE.write_text(text, encoding="utf-8")
