from __future__ import annotations

import pathlib
import tempfile
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
            "candidate_pid": 1,
            "signal_control_allowed": False,
            "sentinel_readable": False,
            "public_sentinel_readable": False,
            "control_pid_visible": False,
            "proc_environ_readable": False,
            "proc_mem_readable": False,
            "proc_visible_pids": [1],
            "secret_env_names": [],
            "no_new_privs": "1",
            "cap_eff": "0000000000000000",
            "cap_bnd": "0000000000000000",
            "nproc_soft": 2,
            "nproc_hard": 2,
            "spawn_one_allowed": True,
            "second_concurrent_spawn_blocked": True,
            "control_net_ns": 1001,
            "candidate_net_ns": 2002,
            "control_pid_ns": 3003,
            "candidate_pid_ns": 4004,
            "control_mnt_ns": 5005,
            "candidate_mnt_ns": 6006,
            "network_interfaces": ["lo"],
        }

    def test_good_probe_payload_is_accepted(self) -> None:
        subject._evaluate_probe(self._good_payload(), self._identity())

    def test_control_access_channels_fail_closed(self) -> None:
        for field in (
            "signal_control_allowed",
            "sentinel_readable",
            "public_sentinel_readable",
            "control_pid_visible",
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

    def test_supervised_worker_process_budget_fails_closed(self) -> None:
        mutations = (
            ("nproc_soft", 1, "process-count"),
            ("nproc_hard", 3, "process-count"),
            ("spawn_one_allowed", False, "single worker"),
            ("second_concurrent_spawn_blocked", False, "unsupervised concurrent descendant"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field):
                payload = self._good_payload()
                payload[field] = value
                with self.assertRaisesRegex(RuntimeError, message):
                    subject._evaluate_probe(payload, self._identity())

    def test_pid_namespace_proc_view_fails_closed(self) -> None:
        mutations = (
            ("candidate_pid", 2),
            ("proc_visible_pids", [1, 2]),
            ("proc_visible_pids", []),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                payload = self._good_payload()
                payload[field] = value
                with self.assertRaisesRegex(RuntimeError, "isolated PID namespace"):
                    subject._evaluate_probe(payload, self._identity())

    def test_namespace_controls_fail_closed(self) -> None:
        mutations = (
            ("candidate_net_ns", 1001, "network namespace"),
            ("control_net_ns", 0, "network namespace"),
            ("candidate_net_ns", True, "network namespace"),
            ("candidate_pid_ns", 3003, "PID namespace"),
            ("control_pid_ns", 0, "PID namespace"),
            ("candidate_pid_ns", True, "PID namespace"),
            ("candidate_mnt_ns", 5005, "mount namespace"),
            ("control_mnt_ns", 0, "mount namespace"),
            ("candidate_mnt_ns", True, "mount namespace"),
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

    def test_wrapped_command_locks_privileges_and_reserves_one_worker_slot(self) -> None:
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
        self.assertIn(
            "/usr/bin/unshare --mount --net --pid --fork --mount-proc -- /usr/bin/prlimit --nproc=2:2 --core=0:0 --",
            rendered,
        )
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

    def test_hidden_directory_is_masked_before_privilege_drop(self) -> None:
        tools = {
            "unshare": pathlib.Path("/usr/bin/unshare"),
            "prlimit": pathlib.Path("/usr/bin/prlimit"),
            "setpriv": pathlib.Path("/usr/bin/setpriv"),
            "env": pathlib.Path("/usr/bin/env"),
            "sh": pathlib.Path("/usr/bin/sh"),
            "mount": pathlib.Path("/usr/bin/mount"),
        }
        with tempfile.TemporaryDirectory() as directory:
            hidden = pathlib.Path(directory).resolve(strict=True)
            with patch.object(subject, "_trusted_tool", side_effect=lambda name: tools[name]):
                command = subject.wrap_command(
                    ["/usr/bin/python3", "-I", "/tmp/probe.py"],
                    self._identity(),
                    hidden_paths=(hidden,),
                )

        rendered = " ".join(command)
        self.assertIn("/usr/bin/unshare --mount --net --pid --fork --mount-proc -- /usr/bin/sh -ceu", rendered)
        self.assertIn(subject._MOUNT_SETUP_SCRIPT, command)
        self.assertIn("/usr/bin/mount", command)
        self.assertIn(str(hidden), command)
        self.assertLess(command.index(str(hidden)), command.index("/usr/bin/prlimit"))
        self.assertLess(command.index("/usr/bin/prlimit"), command.index("/usr/bin/setpriv"))

    def test_hidden_path_policy_rejects_aliases_files_duplicates_and_root(self) -> None:
        tools = {
            "unshare": pathlib.Path("/usr/bin/unshare"),
            "prlimit": pathlib.Path("/usr/bin/prlimit"),
            "setpriv": pathlib.Path("/usr/bin/setpriv"),
            "env": pathlib.Path("/usr/bin/env"),
            "sh": pathlib.Path("/usr/bin/sh"),
            "mount": pathlib.Path("/usr/bin/mount"),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve(strict=True)
            file_path = root / "file"
            file_path.write_text("x", encoding="utf-8")
            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            cases = (
                ((pathlib.Path("relative"),), "absolute"),
                ((pathlib.Path("/"),), "root"),
                ((file_path,), "real directory"),
                ((alias,), "real directory"),
                ((root, root), "unique"),
            )
            for hidden_paths, message in cases:
                with self.subTest(hidden_paths=hidden_paths):
                    with patch.object(subject, "_trusted_tool", side_effect=lambda name: tools[name]):
                        with self.assertRaisesRegex(RuntimeError, message):
                            subject.wrap_command(
                                ["/usr/bin/python3", "-I", "/tmp/probe.py"],
                                self._identity(),
                                hidden_paths=hidden_paths,
                            )

    def test_malformed_command_is_rejected(self) -> None:
        for command in ([], [""], ["/bin/true", ""]):
            with self.subTest(command=command):
                with self.assertRaisesRegex(RuntimeError, "malformed"):
                    subject.wrap_command(command, self._identity())


if __name__ == "__main__":
    unittest.main()
