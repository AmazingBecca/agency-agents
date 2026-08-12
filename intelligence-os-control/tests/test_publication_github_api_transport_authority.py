from __future__ import annotations

import os
import ssl
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

import verify_publication_github_api as verifier


class _FakeOpener:
    def open(self, request, timeout):  # type: ignore[no-untyped-def]
        return (request.full_url, timeout)


class PublicationGithubApiTransportAuthorityTests(unittest.TestCase):
    def test_network_open_disables_environment_proxy_authority(self) -> None:
        captured: list[object] = []

        def build_opener(*handlers):  # type: ignore[no-untyped-def]
            captured.extend(handlers)
            return _FakeOpener()

        request = urllib.request.Request("https://api.github.com/repos/AmazingBecca/agency-agents")
        with mock.patch.dict(
            os.environ,
            {
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "https_proxy": "http://127.0.0.1:9",
                "SSL_CERT_FILE": "/tmp/attacker-ca.pem",
                "SSL_CERT_DIR": "/tmp/attacker-certs",
            },
            clear=False,
        ), mock.patch.object(verifier.urllib.request, "build_opener", side_effect=build_opener):
            verifier._open_no_redirect(request)

        proxy_handlers = [
            handler for handler in captured if isinstance(handler, urllib.request.ProxyHandler)
        ]
        self.assertEqual(len(proxy_handlers), 1)
        self.assertEqual(proxy_handlers[0].proxies, {})

    def test_network_open_uses_explicit_trusted_https_context(self) -> None:
        self.assertEqual(
            verifier.TRUSTED_CA_FILE,
            "/etc/ssl/certs/ca-certificates.crt",
        )
        sentinel = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        captured: list[object] = []

        def build_opener(*handlers):  # type: ignore[no-untyped-def]
            captured.extend(handlers)
            return _FakeOpener()

        request = urllib.request.Request("https://api.github.com/repos/AmazingBecca/agency-agents")
        with mock.patch.object(verifier, "_build_https_context", return_value=sentinel), mock.patch.object(
            verifier.urllib.request, "build_opener", side_effect=build_opener
        ):
            verifier._open_no_redirect(request)

        https_handlers = [
            handler for handler in captured if isinstance(handler, urllib.request.HTTPSHandler)
        ]
        self.assertEqual(len(https_handlers), 1)
        self.assertIs(https_handlers[0]._context, sentinel)

    def test_trusted_https_context_is_hostname_checked_and_certificate_required(self) -> None:
        context = verifier._build_https_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_trusted_https_context_ignores_sslkeylogfile_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            keylog = Path(directory) / "attacker-controlled.keys"
            with mock.patch.dict(
                os.environ,
                {"SSLKEYLOGFILE": str(keylog)},
                clear=False,
            ):
                context = verifier._build_https_context()

            self.assertIsNone(context.keylog_filename)
            self.assertFalse(
                keylog.exists(),
                "trusted TLS setup must not create an ambient key-log file",
            )


if __name__ == "__main__":
    unittest.main()
