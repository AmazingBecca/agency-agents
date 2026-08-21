# Agent + MCP Composition Layer

This directory is a bounded, source-controlled multi-agent substrate. It is deliberately model-agnostic and keeps execution authority outside the language-model agents.

## Included agents

- `research_scout`: finds current external tools, runtimes, MCP servers, and primary-source evidence.
- `source_verifier`: verifies exact repository/ref/file/hash identity and rejects stale or ambiguous inputs.
- `adversarial_reviewer`: attacks provenance, authority, replay, path-expansion, mutable-dependency, and false-green assumptions.
- `capability_architect`: turns validated findings into the smallest useful architecture change.

The agents are advisory. They do not receive Git write, cloud, billing, credential, deployment, or production authority.

## Local MCP server

`mcp/repo_guard_server.py` exposes a read-only workspace MCP surface:

- workspace identity
- bounded file listing
- bounded text reads
- SHA-256 hashing

All paths are confined to `AGENT_WORKSPACE_ROOT`. No write or shell tool is exposed.

## Running the agent team

Install the isolated requirements, configure an OpenAI-compatible endpoint, then run:

```bash
python agent_system/orchestrator.py "your task"
```

Environment variables:

- `AGENT_BASE_URL` (default `http://127.0.0.1:11434/v1`)
- `AGENT_API_KEY` (default `ollama`, suitable for a local Ollama endpoint)
- `AGENT_MODEL` (required)
- `AGENT_TIMEOUT_SECONDS` (default `45`)
- `AGENT_MAX_OUTPUT_CHARS` (default `12000`)

The orchestrator runs the four agents concurrently under one hard wall-clock timeout and produces a JSON bundle. Failure of one agent is recorded rather than silently converted into agreement.

## Timeout doctrine

Every external call is bounded. A timeout is evidence about an execution surface, not a model conclusion. No agent may convert a timeout, missing result, or unavailable MCP server into a PASS verdict.

## Model / runtime direction

The composition target is:

1. local or provider-neutral OpenAI-compatible model endpoint,
2. MCP for tool boundaries,
3. multiple independent agent roles,
4. deterministic source/hash verification outside model output,
5. explicit timeouts and failure states,
6. no ambient credentials.

See `RESEARCH_2026-08-20.md` for the current external-tool evaluation.