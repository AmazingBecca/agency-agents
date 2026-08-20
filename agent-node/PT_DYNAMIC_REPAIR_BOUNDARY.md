# PT_DYNAMIC repair boundary

Exact source under test: `agent-node/agent_node.py` blob `0f05761635d6a2fbd7a195acba04317b415dbf70` (runtime policy v19).

Independent finding: `PT_DYNAMIC.p_offset` is not sufficient authority for the dynamic table. The loaded table is identified by `PT_DYNAMIC.p_vaddr` mapped through `PT_LOAD`; a mismatched/spoofed file offset can hide the real `DT_NEEDED` table from a receipt parser while the dynamic loader continues to use the virtual mapping.

Deterministic regression: `test_pt_dynamic_offset_cannot_hide_loaded_needed_table` in `agent-node/tests/test_native_runtime_multiline_spoof.py`, blob `ed9a4da9643d5ce6a68017437e34aa0d9f4d35c8`.

Required repair: map the complete PT_DYNAMIC virtual range through a unique PT_LOAD segment and fail closed if the advertised PT_DYNAMIC file offset disagrees with that loaded mapping. The branch validation workflow now performs this exact repair only in its ephemeral runner workspace, executes the complete suite, and emits the resulting source blob/bytes as read-only proof; it has no repository-write permission.

This record is evidence only and grants no promotion, deployment, or completion authority.
