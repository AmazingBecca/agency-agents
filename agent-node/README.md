# AmazingBecca Agent Node v1

A narrow persistent worker for an already-owned Linux/Mac host. It is designed to turn a recovered OCI VM, an existing Mac/Linux machine, or a separately authorized free VM into a bounded execution/reasoning node without granting generic shell or Git-write authority.

## Security properties

- loopback-only listener by default and enforced at startup;
- bearer authentication required for every mutation-capable request;
- repository operations are bound to an exact 40-hex Git `HEAD` supplied by the caller;
- no Git write, branch, merge, checkout, credential, billing, cloud, or deployment endpoints;
- test execution is exact-selector allowlisted and uses argv, never a shell;
- optional second-model endpoint must itself be loopback-only;
- second-model output is advisory evidence only, not promotion authority.

## Endpoints

- `GET /health`
- `POST /repo-index` with `{ "expected_head": "<sha>" }`
- `POST /run-tests` with `{ "expected_head": "<sha>", "selector": "tests.test_module" }`
- `POST /second-opinion` with `{ "expected_head": "<sha>", "compact_evidence": "..." }`

## Minimal host setup

```bash
export AGENT_NODE_REPO_ROOT=/srv/work/repository
export AGENT_NODE_BEARER="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export AGENT_NODE_TEST_ALLOWLIST='tests.test_control_contract,tests.test_security_regressions'
python3 agent_node.py
```

Keep the bearer in a host secret store or service environment; never commit it. Reach the node through an already-authorized private transport such as localhost port-forwarding or a private tailnet. Do not expose port 8765 publicly.

## Optional local second model

Run an OpenAI-compatible Qwen/DeepSeek/Ollama/vLLM endpoint on the same host, then set:

```bash
export AGENT_NODE_MODEL_ENDPOINT=http://127.0.0.1:11434/v1/chat/completions
export AGENT_NODE_MODEL='your-local-model-name'
```

The node refuses non-loopback model endpoints in v1. This intentionally separates local-model experimentation from credential-bearing external APIs.

## OCI fit

The historical `Wisdom-Engine-Final` shape (2 OCPU / 16 GB) is sufficient for this control service and deterministic repository tooling. It may be adequate for a small quantized local code model, but model selection must be based on live available RAM/disk/architecture after the host is actually recovered or replaced. Do not restore or rely on legacy SSH/private-key material merely to bootstrap this node.
