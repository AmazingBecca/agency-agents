from __future__ import annotations

import pathlib
import unittest

import sys

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import distinct_principal_boundary as subject


class DistinctPrincipalBoundaryTests(unittest.TestCase):
    def _identity(self) -> subject.SandboxIdentity:
        return subject.SandboxIdentity(
            user="nobody",
            uid=65534,
            gid=65534,
            sudo=pathlib.Path("/usr/bin/sudo"),
        )

    def _good_payload(self) -> dict[str, object]:
        return {
            "candidate_euid": 65534,
            "candidate_egid": 65534,
            "signal_control_allowed": False,
            "sentinel_readable": False,
            "proc_environ_readable": False,
            "proc_mem_readable": False,
            "secret_env_names": [],
        }

    def test_good_probe_payload_is_accepted(self) -> None:
        subject._evaluate_probe(self._good_payload(), self._identity())

    def test_control_access_channels_fail_closed(self) -> None:
        for field in (
            "signal_control_allowed",
            "sentinel_readable",
            "proc_environ_readable",
            "proc_mem_readable",
        ):
            with self.subTest(field=field):
                payload = self._good_payload()
                payload[field] = True
                with self.assertRaisesRegex(RuntimeError, "distinct-principal boundary failed"):
                    subject._evaluate_probe(payload, self._identity())

    def test_candidate_identity_drift_is_rejected(self) -> None:
        payload = self._good_payload()
        payload["candidate_euid"] = 1000
        with self.assertRaisesRegex(RuntimeError, "requested sandbox identity"):
            subject._evaluate_probe(payload, self._identity())

    def test_secret_environment_inheritance_is_rejected(self) -> None:
        payload = self._good_payload()
        payload["secret_env_names"] = ["GITHUB_TOKEN"]
        with self.assertRaisesRegex(RuntimeError, "control secret"):
            subject._evaluate_probe(payload, self._identity())

    def test_probe_schema_drift_is_rejected(self) -> None:
        payload = self._good_payload()
        payload["extra"] = "forged"
        with self.assertRaisesRegex(RuntimeError, "schema drifted"):
            subject._evaluate_probe(payload, self._identity())

    def test_wrapped_command_uses_noninteractive_env_empty_sudo_boundary(self) -> None:
        command = subject.wrap_command(["/usr/bin/python3", "-I", "/tmp/probe.py"], self._identity())
        self.assertEqual(
            command[:8],
            [
                "/usr/bin/sudo",
                "-n",
                "-u",
                "nobody",
                "--",
                "/usr/bin/env",
                "-i",
                "PATH=/usr/local/bin:/usr/bin:/bin",
            ],
        )
        rendered = " ".join(command)
        for secret in subject._SECRET_ENV_NAMES:
            self.assertNotIn(secret, rendered)
        self.assertIn("PYTHONNOUSERSITE=1", command)
        self.assertIn("PYTHONWARNINGS=error", command)

    def test_malformed_command_is_rejected(self) -> None:
        for command in ([], [""], ["/bin/true", ""]):
            with self.subTest(command=command):
                with self.assertRaisesRegex(RuntimeError, "malformed"):
                    subject.wrap_command(command, self._identity())


if __name__ == "__main__":
    unittest.main()
