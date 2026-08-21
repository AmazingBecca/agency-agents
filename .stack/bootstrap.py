#!/usr/bin/env python3
"""Repo-local shared composition stack bootstrap.

Installs reviewed capability profiles into .stack/.venv without modifying global
Python or repository dependency manifests. Execution-only: no Git writes, no
cloud/resource creation, no secrets, and no Docker authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import venv

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
RECEIPTS = ROOT / "receipts"

BASE = [
    "httpx>=0.27.0,<1",
    "pydantic>=2.0.0,<3",
    "python-dotenv>=1.0.0,<2",
    "pytest>=8.0.0,<9",
    "pytest-asyncio>=0.23.0,<1",
    "hypothesis>=6.0.0,<7",
]

MIROFISH = [
    "flask>=3.0.0,<4",
    "flask-cors>=6.0.0,<7",
    "openai>=1.0.0",
    "zep-cloud==3.25.0",
    "camel-oasis==0.2.5",
    "camel-ai==0.2.78",
    "PyMuPDF>=1.24.0",
    "charset-normalizer>=3.0.0,<4",
    "chardet>=5.0.0,<6",
]

PROFILES = {"base": BASE, "mirofish": BASE + MIROFISH}
SOURCES = {"mirofish": "https://github.com/666ghj/MiroFish", "oasis": "https://github.com/camel-ai/oasis", "camel": "https://github.com/camel-ai/camel"}

def sha256_bytes(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def python_bin() -> Path: return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
def run(cmd: list[str]) -> None: subprocess.run(cmd, check=True)

def main() -> int:
    ap = argparse.ArgumentParser(description="Install the shared composition stack in a repo-local venv.")
    ap.add_argument("--profile", choices=sorted(PROFILES), default="base")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--recreate", action="store_true")
    args = ap.parse_args()
    if args.profile == "mirofish" and sys.version_info[:2] != (3, 11):
        raise SystemExit("mirofish profile requires CPython 3.11 because camel-oasis==0.2.5 declares Python <3.12; current interpreter is " + sys.version.split()[0])
    selected = PROFILES[args.profile]
    manifest = {"schema":"amazingbecca-shared-composition-stack-v1","profile":args.profile,"python":sys.version.split()[0],"requirements":selected,"sources":SOURCES}
    manifest["manifest_sha256"] = sha256_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
    if args.dry_run:
        print(json.dumps(manifest, indent=2, sort_keys=True)); return 0
    if args.recreate and VENV.exists():
        import shutil; shutil.rmtree(VENV)
    if not VENV.exists(): venv.EnvBuilder(with_pip=True, clear=False, symlinks=os.name != "nt").create(VENV)
    py = python_bin(); run([str(py),"-m","pip","install","--disable-pip-version-check","--no-input",*selected])
    freeze = subprocess.check_output([str(py),"-m","pip","freeze","--all"], text=True)
    RECEIPTS.mkdir(parents=True, exist_ok=True)
    receipt = {**manifest,"created_unix":int(time.time()),"venv":str(VENV),"freeze_sha256":sha256_bytes(freeze.encode()),"installed":sorted(line for line in freeze.splitlines() if line.strip())}
    out = RECEIPTS / f"{args.profile}.json"; out.write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n", encoding="utf-8"); print(out); return 0

if __name__ == "__main__": raise SystemExit(main())
