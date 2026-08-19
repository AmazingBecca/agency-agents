#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
from typing import Any


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def stable_sha256(path: pathlib.Path) -> str:
    resolved = path.resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(resolved, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"not a regular file: {resolved}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after):
            raise RuntimeError(f"tool changed during fingerprint: {resolved}")
        return digest.hexdigest()
    finally:
        os.close(fd)


def describe(name: str, executable: str, version_args: list[str]) -> dict[str, str]:
    path = pathlib.Path(executable).resolve(strict=True)
    cp = subprocess.run([str(path), *version_args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    version = cp.stdout.strip().splitlines()[0]
    return {
        "name": name,
        "path": str(path),
        "version": version,
        "binary_sha256": stable_sha256(path),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        raise SystemExit("usage: toolchain_fingerprint.py RUFF_PATH AST_GREP_PATH")
    tools = [
        describe("ast-grep", argv[2], ["--version"]),
        describe("ruff", argv[1], ["--version"]),
    ]
    tools.sort(key=lambda item: item["name"])
    payload = {
        "schema": "amazingbecca-toolchain-fingerprint/v1",
        "python": {
            "implementation": sys.implementation.name,
            "version": ".".join(str(x) for x in sys.version_info[:3]),
        },
        "tools": tools,
    }
    payload["toolchain_sha256"] = hashlib.sha256(canonical(payload)).hexdigest()
    sys.stdout.buffer.write(canonical(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
