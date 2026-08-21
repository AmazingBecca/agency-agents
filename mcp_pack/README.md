# Read-only MCP Pack

This branch adds three narrow MCP servers intended for an owned local agent host. They are separate from the broader multi-agent harness so each capability can be reviewed and enabled independently.

## 1. GitHub Source Witness

`github_source_witness.py` resolves an allowlisted repository/ref to an immutable commit SHA and binds a file to:

- requested ref
- resolved commit SHA
- Git blob SHA
- byte size
- SHA-256

It uses only the fixed `https://api.github.com` origin, rejects redirects, bounds network timeouts and file size, and does not expose arbitrary URL fetches or Git writes. It intentionally ignores ambient `GITHUB_TOKEN`; private-repository reads require an explicitly supplied `SOURCE_WITNESS_TOKEN`. Allowed owners default to `AmazingBecca` and can be narrowed/expanded with `SOURCE_WITNESS_ALLOWED_OWNERS`.

This MCP is evidence for source identity, not evidence that code executed or passed tests.

## 2. Browser Policy Gate

`browser_policy.py` plus `browser_policy_core.py` implement a deterministic pre-action gate suitable for Browser Use, Agent TARS/UI-TARS, or another browser/computer-use executor.

Default posture:

- no configured domains = deny navigation
- only HTTP/HTTPS
- credentials embedded in URLs rejected
- private/loopback/link-local/reserved IP destinations rejected unless explicitly enabled
- unknown actions denied
- read-oriented actions allowed
- click/type/select/submit/download require approval
- JavaScript execution, uploads, file chooser, external protocol opens and clipboard writes denied
- max steps and timeout are bounded

Important: this MCP is only an enforcement boundary when the real browser executor is wired to call it before every step. A client that bypasses the gate is not constrained by policy output alone.

## 3. Capability Catalog

`capability_catalog.py` exposes the source-controlled `catalog.json` research ledger over MCP. It can list candidates, return one candidate, and produce the remaining validation queue. It has no network or mutation surface.

The catalog records external-agent/MCP research decisions and primary-source links. A `VALIDATED_DESIGN` state means the published architecture was confirmed from primary material; it does not mean the third-party package has been installed or execution-tested here.

## Running locally

Install in an isolated environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r mcp_pack/requirements.txt
```

Run exactly one server over stdio:

```bash
python mcp_pack/github_source_witness.py
python mcp_pack/browser_policy.py
python mcp_pack/capability_catalog.py
```

Example browser boundary configuration:

```bash
export BROWSER_POLICY_ALLOWED_DOMAINS='github.com,*.github.com'
export BROWSER_POLICY_MAX_STEPS=40
export BROWSER_POLICY_TIMEOUT_SECONDS=30
```

Example source witness configuration:

```bash
export SOURCE_WITNESS_ALLOWED_OWNERS='AmazingBecca'
export SOURCE_WITNESS_TIMEOUT_SECONDS=12
```

Do not place credentials in repository files or MCP arguments.

## Validation contract

The included PR workflow performs dependency-free syntax compilation and pure browser-policy unit tests. Import/runtime tests for FastMCP/httpx require an isolated environment with the requirements installed and must be reported separately from syntax tests.

A workflow with no allocated job/steps/logs is execution-admission failure, not a code verdict.
