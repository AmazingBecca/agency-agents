from __future__ import annotations

import email.message
import io
import unittest

import verify_publication_github_api as verifier


class _Response:
    def __init__(
        self,
        body: bytes,
        content_lengths: tuple[str, ...] = (),
        transfer_encodings: tuple[str, ...] = (),
    ) -> None:
        self._body = io.BytesIO(body)
        self.headers = email.message.Message()
        for value in content_lengths:
            self.headers["Content-Length"] = value
        for value in transfer_encodings:
            self.headers["Transfer-Encoding"] = value

    def read(self, amount: int = -1) -> bytes:
        return self._body.read(amount)


class PublicationGithubApiResponseFramingAuthorityTests(unittest.TestCase):
    def test_single_content_length_is_accepted(self) -> None:
        response = _Response(b"test", ("4",))
        self.assertEqual(
            verifier._read_bounded_response(response, 16, "artifact archive"),
            b"test",
        )

    def test_duplicate_equal_content_length_is_rejected_as_ambiguous(self) -> None:
        response = _Response(b"test", ("4", "4"))
        with self.assertRaisesRegex(
            verifier.GithubApiAuthorityVerificationError,
            "Content-Length is ambiguous",
        ):
            verifier._read_bounded_response(response, 16, "artifact archive")

    def test_duplicate_conflicting_content_length_is_rejected_as_ambiguous(self) -> None:
        response = _Response(b"test", ("4", "5"))
        with self.assertRaisesRegex(
            verifier.GithubApiAuthorityVerificationError,
            "Content-Length is ambiguous",
        ):
            verifier._read_bounded_response(response, 16, "artifact archive")

    def test_transfer_encoding_and_content_length_are_rejected_as_ambiguous(self) -> None:
        response = _Response(
            b"test",
            content_lengths=("4",),
            transfer_encodings=("chunked",),
        )
        with self.assertRaisesRegex(
            verifier.GithubApiAuthorityVerificationError,
            "response framing is ambiguous",
        ):
            verifier._read_bounded_response(response, 16, "artifact archive")

    def test_multiple_transfer_encoding_fields_are_rejected_as_ambiguous(self) -> None:
        response = _Response(
            b"test",
            transfer_encodings=("gzip", "chunked"),
        )
        with self.assertRaisesRegex(
            verifier.GithubApiAuthorityVerificationError,
            "Transfer-Encoding is ambiguous",
        ):
            verifier._read_bounded_response(response, 16, "artifact archive")

    def test_single_chunked_transfer_encoding_remains_bounded(self) -> None:
        response = _Response(
            b"test",
            transfer_encodings=("chunked",),
        )
        self.assertEqual(
            verifier._read_bounded_response(response, 16, "artifact archive"),
            b"test",
        )


if __name__ == "__main__":
    unittest.main()
