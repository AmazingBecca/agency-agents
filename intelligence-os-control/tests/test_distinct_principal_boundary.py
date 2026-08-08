from __future__ import annotations

import pathlib
import unittest
from unittest.mock import patch

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
            "candidate_groups": [],
            "signal_control_allowed": False,
            "sentinel_readable": False,
            "proc_environ_readable": False,
            "proc_mem_readable": False,
            "secret_env_names": [],
            "no_new_privs": "1",
            "cap_eff": "0000000000000000",
            "cap_bnd": "0000000000000000",
            "nproc_soft": 1,
            "nproc_hard": 1,
            "fork_blocked": True,
            "control_net_ns": 1001,
            "candidate_net_ns": 2002,
            "network_interfaces": ["lo"],
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

    def test_supplementary_groups_are_rejected(self) -> None:
        payload = self._good_payload()
        payload["candidate_groups"] = [27]
        with self.assertRaisesRegex(RuntimeError, "supplementary groups"):
            subject._evaluate_probe(payload, self._identity())

    def test_secret_environment_inheritance_is_rejected(self) -> None:
        payload = self._good_payload()
        payload["secret_env_names"] = ["GITHUB_TOKEN"]
        with self.assertRaisesRegex(RuntimeError, "control secret"):
            subject._evaluate_probe(payload, self._identity())

    def test_privilege_reacquisition_controls_fail_closed(self) -> None:
        mutations = (
            ("no_new_privs", "0", "no-new-privileges"),
            ("cap_eff", "0000000000000001", "capabilities"),
            ("cap_bnd", "0000000000000001", "capabilities"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field):
                payload = self._good_payload()
                payload[field] = value
                with self.assertRaisesRegex(RuntimeError, message):
                    subject._evaluate_probe(payload, self._identity())

    def test_process_creation_controls_fail_closed(self) -> None:
        for field, value in (("nproc_soft", 2), ("nproc_hard", 2), ("fork_blocked", False)):
            with self.subTest(field=field):
                payload = self._good_payload()
                payload[field] = value
                with self.assertRaisesRegex(RuntimeError, "process-count|descendant"):
                    subject._evaluate_probe(payload, self._identity())

    def test_network_namespace_controls_fail_closed(self) -> None:
        mutations = (
            ("candidate_net_ns", 1001, "network namespace"),
            ("control_net_ns", 0, "network namespace"),
            ("candidate_net_ns", True, "network namespace"),
            ("network_interfaces", ["eth0", "lo"], "unexpected interfaces"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field):
                payload = self._good_payload()
                payload[field] = value
                with self.assertRaisesRegex(RuntimeError, message):
                    subject._evaluate_probe(payload, self._identity())

    def test_probe_schema_drift_is_rejected(self) -> None:
        payload = self._good_payload()
        payload["extra"] = "forged"
        with self.assertRaisesRegex(RuntimeError, "schema drifted"):
            subject._evaluate_probe(payload, self._identity())

    def test_wrapped_command_locks_privileges_descendants_and_network(self) -> None:
        tools = {
            "unshare": pathlib.Path("/usr/bin/unshare"),
            "prlimit": pathlib.Path("/usr/bin/prlimit"),
            "setpriv": pathlib.Path("/usr/bin/setpriv"),
            "env": pathlib.Path("/usr/bin/env"),
        }
        with patch.object(subject, "_trusted_tool", side_effect=lambda name: tools[name]):
            command = subject.wrap_command(["/usr/bin/python3", "-I", "/tmp/probe.py"], self._identity())

        self.assertEqual(command[:3], ["/usr/bin/sudo", "-n", "--"])
        rendered = " ".join(command)
        self.assertIn("/usr/bin/unshare --net -- /usr/bin/prlimit --nproc=1:1 --core=0:0 --", rendered)
        self.assertIn("/usr/bin/setpriv --reuid=65534 --regid=65534 --clear-groups", rendered)
        self.assertIn("--no-new-privs", command)
        self.assertIn("--inh-caps=-all", command)
        self.assertIn("--ambient-caps=-all", command)
        self.assertIn("--bounding-set=-all", command)
        self.assertIn("/usr/bin/env", command)
        self.assertIn("-i", command)
        for secret in subject._SECRET_ENV_NAMES:
            self.assertNotIn(secret, rendered)
        self.assertIn("PYTHONNOUSERSITE=1", command)
        self.assertIn("PYTHONWARNINGS=error", command)
        self.assertIn("OPENBLAS_NUM_THREADS=1", command)
        self.assertIn("OMP_NUM_THREADS=1", command)
        self.assertIn("MKL_NUM_THREADS=1", command)

    def test_malformed_command_is_rejected(self) -> None:
        for command in ([], [""], ["/bin/true", ""]):
            with self.subTest(command=command):
                with self.assertRaisesRegex(RuntimeError, "malformed"):
                    subject.wrap_command(command, self._identity())


if __name__ == "__main__":
    unittest.main()
