from __future__ import annotations

import importlib.util
import sys
import unittest
from email.message import Message
from pathlib import Path


CONTROL_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = CONTROL_DIR / "verify_publication_github_api.py"


def _load_module():
    if str(CONTROL_DIR) not in sys.path:
        sys.path.insert(0, str(CONTROL_DIR))
    spec = importlib.util.spec_from_file_location("verify_publication_github_api_te", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load GitHub API verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Response:
    def __init__(self, body: bytes, transfer_encoding: str) -> None:
        self._body = body
        self._offset = 0
        headers = Message()
        headers.add_header("Transfer-Encoding", transfer_encoding)
        self.headers = headers

    def read(self, amount: int) -> bytes:
        if self._offset >= len(self._body):
            return b""
        chunk = self._body[self._offset : self._offset + amount]
        self._offset += len(chunk)
        return chunk


class PublicationGithubApiTransferEncodingAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = _load_module()

    def test_single_chunked_transfer_encoding_is_accepted(self) -> None:
        response = _Response(b"data", "chunked")
        self.assertEqual(
            self.module._read_bounded_response(response, 32, "artifact archive"),
            b"data",
        )

    def test_case_insensitive_chunked_transfer_encoding_is_accepted(self) -> None:
        response = _Response(b"data", "Chunked")
        self.assertEqual(
            self.module._read_bounded_response(response, 32, "artifact archive"),
            b"data",
        )

    def test_duplicate_chunked_coding_in_one_field_is_rejected(self) -> None:
        response = _Response(b"data", "chunked,chunked")
        with self.assertRaises(self.module.GithubApiAuthorityVerificationError):
            self.module._read_bounded_response(response, 32, "artifact archive")

    def test_unknown_transfer_coding_is_rejected(self) -> None:
        response = _Response(b"data", "gzip")
        with self.assertRaises(self.module.GithubApiAuthorityVerificationError):
            self.module._read_bounded_response(response, 32, "artifact archive")

    def test_identity_transfer_coding_is_rejected(self) -> None:
        response = _Response(b"data", "identity")
        with self.assertRaises(self.module.GithubApiAuthorityVerificationError):
            self.module._read_bounded_response(response, 32, "artifact archive")


if __name__ == "__main__":
    unittest.main()
