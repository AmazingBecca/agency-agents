#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="$ROOT/toolchain.lock.json"
DEST="${AGENT_NODE_TOOLCHAIN_DIR:-$HOME/.cache/amazingbecca-agent-node/tools}"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
NPM_BIN="${NPM_BIN:-$(command -v npm)}"

[[ -x "$PYTHON_BIN" ]] || { echo "python3 is required" >&2; exit 127; }
[[ -x "$NPM_BIN" ]] || { echo "npm is required" >&2; exit 127; }
[[ -f "$LOCK" ]] || { echo "toolchain lock missing" >&2; exit 2; }

readarray -t versions < <("$PYTHON_BIN" - "$LOCK" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding='utf-8'))
assert value.get('schema') == 'amazingbecca-toolchain/v1'
tools={item['name']: item for item in value['tools']}
for name in ('ruff','ast-grep'):
    item=tools[name]
    print(item['version'])
PY
)
RUFF_VERSION="${versions[0]}"
AST_GREP_VERSION="${versions[1]}"

mkdir -p "$DEST"
"$PYTHON_BIN" -m venv "$DEST/ruff-venv"
"$DEST/ruff-venv/bin/python" -m pip install --disable-pip-version-check --no-input "ruff==$RUFF_VERSION"
"$NPM_BIN" install --prefix "$DEST/ast-grep" --no-save "@ast-grep/cli@$AST_GREP_VERSION"

RUFF="$DEST/ruff-venv/bin/ruff"
AST_GREP="$DEST/ast-grep/node_modules/.bin/ast-grep"
"$RUFF" --version | grep -Fx "ruff $RUFF_VERSION"
"$AST_GREP" --version | grep -F "$AST_GREP_VERSION"

printf 'RUFF=%s\n' "$RUFF"
printf 'AST_GREP=%s\n' "$AST_GREP"
