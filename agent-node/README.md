# AmazingBecca Agent Node v1

A narrow persistent worker for an already-owned Linux/Mac host. It is designed to turn a recovered OCI VM, an existing Mac/Linux machine, or a separately authorized free VM into a bounded execution/reasoning node without granting generic shell or Git-write authority.

## Security properties

- loopback-only listener by default and enforced at startup;
- bearer authentication required for every mutation-capable request;
- repository execution is bound to an exact 40-hex Git commit and tree read from replacement-disabled Git object storage;
- test source is materialized from reviewed Git blobs into a fresh temporary snapshot rather than trusted from the mutable worktree;
- symlinks, submodules, unsafe tree paths, and unsupported Git tree entries fail closed;
- Git subprocesses scrub inherited Git/dynamic-loader injection state;
- Python execution binds a stable SHA-256 identity over the resolved interpreter binary, implementation/version, isolation flags, and loader-scrub policy;
- child Python scrubs `PYTHON*`, `LD_*`, `DYLD_*`, virtualenv launcher state, uses `-I -B`, and revalidates runtime identity after execution;
- no Git write, branch, merge, checkout, credential, billing, cloud, or deployment endpoints;
- test execution is exact-selector allowlisted and uses argv, never a shell;
- optional second-model endpoint must itself be loopback-only;
- second-model output is advisory evidence only, not promotion authority.

## Endpoints

- `GET /health`
- `POST /repo-index` with `{ "expected_head": "<sha>" }`
- `POST /run-tests` with `{ "expected_head": "<sha>", "selector": "tests.test_module" }`
- `POST /second-opinion` with `{ "expected_head": "<sha>", "compact_evidence": "..." }`

A successful `/run-tests` result includes exact commit `head`, Git `tree`, `runtime_sha256`, selector, return code, the bounded returned stdout, and a SHA-256 over those exact returned stdout bytes.

## Minimal host setup

```bash
export AGENT_NODE_REPO_ROOT=/srv/work/repository
export AGENT_NODE_BEARER="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export AGENT_NODE_TEST_ALLOWLIST='tests.test_control_contract,tests.test_security_regressions'
python3 agent_node.py
```

Keep the bearer in a host secret store or service environment; never commit it. Reach the node through an already-authorized private transport such as localhost port-forwarding or a private tailnet. Do not expose port 8765 publicly.

## Optional local second model

Run an OpenAI-compatible local model endpoint on the same host, then set:

```bash
export AGENT_NODE_MODEL_ENDPOINT=http://127.0.0.1:11434/v1/chat/completions
export AGENT_NODE_MODEL='your-local-model-name'
```

The node refuses non-loopback model endpoints in v1. This intentionally separates local-model experimentation from credential-bearing external APIs.

## Demonstrated public validation route

The candidate branch contains `.github/workflows/agent-node-candidate-validation.yml`. It is deliberately limited to the public `agency-agents` candidate lane, uses a standard public GitHub-hosted Ubuntu runner, unsets workflow credentials before exact-source fetch, compiles/runs the adversarial suite, then starts the real loopback service against a temporary Git fixture. The live check requires unauthenticated test execution to return HTTP 401 and authenticated allowlisted execution to return an exact head/tree/runtime/stdout receipt.

This public validation route demonstrates the worker implementation without exposing or fetching private BFM/FMP source. It is not a persistent host and is not promotion authority.

## Host fit

The control service and deterministic repository tooling are lightweight enough for an already-owned Linux/Mac host or a separately authorized free VM. Local-model suitability must be based on live available RAM/disk/architecture after a host is actually reachable. Do not restore or rely on legacy SSH/private-key material merely to bootstrap this node.
