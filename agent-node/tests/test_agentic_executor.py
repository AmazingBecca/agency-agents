from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "agentic_executor.py"
spec = importlib.util.spec_from_file_location("agentic_executor", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def task(**changes):
    value = {
        "schema": mod.SCHEMA_TASK,
        "task_id": "task-1",
        "objective": "capability_discovery",
        "workspace": str(pathlib.Path(__file__).parents[1]),
        "max_attempts": 2,
        "network_access": "none",
        "advisory_only": True,
        "promotion_authorized": False,
        "completion_authorized": False,
    }
    value.update(changes)
    return value


class AgenticExecutorTests(unittest.TestCase):
    def test_authority_widening_and_unknown_objective_fail_closed(self):
        cases = [
            {"network_access": "full"},
            {"promotion_authorized": True},
            {"completion_authorized": True},
            {"objective": "shell"},
            {"extra": "field"},
        ]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                mod.validate_task(task(**change))

    def test_noncanonical_and_duplicate_task_json_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "task.json"
            pretty = json.dumps(task(), indent=2).encode()
            path.write_bytes(pretty)
            with self.assertRaisesRegex(ValueError, "canonical"):
                mod.load_json(path)
            path.write_bytes(mod.canonical(task()).replace(b'"task_id":"task-1",', b'"task_id":"task-1","task_id":"task-2",', 1))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                mod.load_json(path)

    def test_executor_retries_then_emits_nonpromotional_receipt(self):
        calls = []
        def flaky(_workspace, _task):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("transient")
            return {"success": True, "value": "recovered"}
        with mock.patch.dict(mod.ACTIONS, {"capability_discovery": flaky}, clear=False), \
             mock.patch.object(mod, "inventory", return_value={"stable": True}):
            receipt = mod.execute_task(task(max_attempts=2))
        self.assertTrue(receipt["success"])
        self.assertEqual(len(receipt["attempts"]), 2)
        self.assertFalse(receipt["promotion_authorized"])
        self.assertFalse(receipt["completion_authorized"])
        self.assertEqual(len(receipt["receipt_sha256"]), 64)

    def test_code_execution_requires_executor_authorized_workspace_root(self):
        with tempfile.TemporaryDirectory() as allowed_td, tempfile.TemporaryDirectory() as outside_td:
            outside = pathlib.Path(outside_td)
            (outside / "x.py").write_text("x = 1\n", encoding="utf-8")
            code_task = task(objective="static_python_audit", workspace=str(outside), max_attempts=1)
            with mock.patch.dict(mod.os.environ, {"AB_AGENT_WORKSPACE_ROOTS": allowed_td}, clear=False):
                with self.assertRaisesRegex(ValueError, "outside executor-authorized roots"):
                    mod.execute_task(code_task)
            with mock.patch.dict(mod.os.environ, {}, clear=False):
                mod.os.environ.pop("AB_AGENT_WORKSPACE_ROOTS", None)
                with self.assertRaisesRegex(ValueError, "require AB_AGENT_WORKSPACE_ROOTS"):
                    mod.execute_task(code_task)

    def test_static_python_audit_has_deterministic_fallback_without_optional_tools(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
            original = mod.shutil.which
            def which(name):
                if name in {"ruff", "rg"}:
                    return None
                return original(name)
            with mock.patch.object(mod.shutil, "which", side_effect=which):
                result = mod.action_static_python(root, {})
        self.assertTrue(result["success"])
        self.assertEqual(result["python_file_count"], 1)

    def test_queue_transitions_pending_to_done_and_replay_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            queue = pathlib.Path(td) / "queue"
            source = pathlib.Path(td) / "task.json"
            source.write_bytes(mod.canonical(task()))
            with mock.patch.object(mod, "QUEUE_ROOT", queue), \
                 mock.patch.dict(mod.ACTIONS, {"capability_discovery": lambda _w, _t: {"success": True}}, clear=False), \
                 mock.patch.object(mod, "inventory", return_value={"stable": True}):
                pending = mod.submit(source)
                self.assertTrue(pending.name.endswith(".pending.json"))
                with self.assertRaisesRegex(RuntimeError, "queue history"):
                    mod.submit(source)
                done = mod.work_once()
                self.assertIsNotNone(done)
                receipt = json.loads(done.read_text(encoding="utf-8"))
                with self.assertRaisesRegex(RuntimeError, "queue history"):
                    mod.submit(source)
        self.assertTrue(receipt["success"])
        self.assertEqual(receipt["schema"], mod.SCHEMA_RECEIPT)

    def test_lost_queue_claim_race_returns_idle_instead_of_crashing(self):
        with tempfile.TemporaryDirectory() as td:
            queue = pathlib.Path(td)
            pending = queue / "race.pending.json"
            pending.write_bytes(mod.canonical(task(task_id="race")))
            with mock.patch.object(mod, "QUEUE_ROOT", queue), mock.patch.object(mod.os, "replace", side_effect=FileNotFoundError):
                self.assertIsNone(mod.work_once())

    def test_failed_queue_receipt_is_hash_bound_and_nonpromotional(self):
        with tempfile.TemporaryDirectory() as td:
            queue = pathlib.Path(td) / "queue"
            source = pathlib.Path(td) / "task.json"
            code_task = task(task_id="fail", objective="static_python_audit", workspace=td, max_attempts=1)
            source.write_bytes(mod.canonical(code_task))
            with mock.patch.object(mod, "QUEUE_ROOT", queue), mock.patch.dict(mod.os.environ, {}, clear=False):
                mod.os.environ.pop("AB_AGENT_WORKSPACE_ROOTS", None)
                mod.submit(source)
                failed = mod.work_once()
                receipt = json.loads(failed.read_text(encoding="utf-8"))
        claimed = receipt.pop("receipt_sha256")
        self.assertEqual(claimed, mod.sha256_bytes(mod.canonical(receipt)))
        self.assertFalse(receipt["promotion_authorized"])
        self.assertFalse(receipt["completion_authorized"])


if __name__ == "__main__":
    unittest.main()
