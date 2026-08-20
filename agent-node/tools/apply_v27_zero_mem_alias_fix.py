from __future__ import annotations

import hashlib
import pathlib

SOURCE = pathlib.Path(__file__).parents[1] / "agent_node.py"
EXPECTED_BLOB = "febd1f2ae6be05eaf0b53901722ca9ae3484dc16"


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def main() -> None:
    before = SOURCE.read_bytes()
    if git_blob_sha1(before) != EXPECTED_BLOB:
        raise SystemExit("refusing v27 repair: source blob is not exact v26 predecessor")

    text = before.decode("utf-8")
    old_policy = 'RUNTIME_POLICY = "agent-node-python-runtime-v26"'
    new_policy = 'RUNTIME_POLICY = "agent-node-python-runtime-v27"'
    old_guard = '                if load_memsz <= 0 or (load_vaddr & page_mask) == 0:\n                    continue\n'
    new_guard = '                if (load_vaddr & page_mask) == 0:\n                    continue\n'

    if text.count(old_policy) != 1:
        raise SystemExit("refusing v27 repair: policy marker count is not one")
    if text.count(old_guard) != 1:
        raise SystemExit("refusing v27 repair: zero-file guard count is not one")

    text = text.replace(old_policy, new_policy, 1).replace(old_guard, new_guard, 1)
    SOURCE.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
