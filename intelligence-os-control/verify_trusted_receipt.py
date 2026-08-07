#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import sys

import execution_expectation as ee


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=pathlib.Path, required=True)
    parser.add_argument("--expectation", type=pathlib.Path, required=True)
    parser.add_argument("--trusted-expectation-root", type=pathlib.Path, required=True)
    parser.add_argument("--expected-compiler-head", required=True)
    args = parser.parse_args()
    try:
        receipt_id = ee.verify_trusted_receipt_from_root(
            args.receipt,
            args.expectation,
            args.trusted_expectation_root,
            args.expected_compiler_head,
        )
    except Exception as exc:
        print(f"trusted executor receipt verification rejected input: {exc}", file=sys.stderr)
        return 2
    print(receipt_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
