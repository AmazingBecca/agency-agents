from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/publish-retained-evidence.yml").read_text(
    encoding="utf-8"
)


class PublisherWorkflowContractTests(unittest.TestCase):
    def test_reusable_workflow_inputs_are_exact(self) -> None:
        expected = {
            "envelope_b64",
            "repository",
            "reviewed_head",
            "reviewed_base",
            "synthetic_merge",
            "workflow_ref",
            "workflow_sha",
            "run_id",
            "run_attempt",
        }
        block = WORKFLOW.split("    inputs:\n", 1)[1].split("\npermissions:\n", 1)[0]
        names = set(re.findall(r"(?m)^      ([a-z0-9_]+):$", block))
        self.assertEqual(names, expected)
        self.assertEqual(block.count("        required: true"), len(expected))
        self.assertEqual(block.count("        type: string"), len(expected))

    def test_job_checks_out_only_its_exact_workflow_repository(self) -> None:
        self.assertIn("repository: ${{ job.workflow_repository }}", WORKFLOW)
        self.assertIn("ref: ${{ job.workflow_sha }}", WORKFLOW)
        self.assertIn("persist-credentials: false", WORKFLOW)
        self.assertIn("fetch-depth: 1", WORKFLOW)
        self.assertNotIn("${{ github.repository }}", WORKFLOW)
        self.assertNotIn("secrets:", WORKFLOW)
        self.assertNotIn("github.token", WORKFLOW)

    def test_actions_and_runtime_are_immutable(self) -> None:
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            WORKFLOW,
        )
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            WORKFLOW,
        )
        self.assertNotRegex(WORKFLOW, r"actions/(?:checkout|upload-artifact)@v")
        self.assertIn("runs-on: ubuntu-24.04", WORKFLOW)
        self.assertIn("timeout-minutes: 5", WORKFLOW)

    def test_publisher_derives_control_and_caller_authority_from_contexts(self) -> None:
        for context in (
            "job.workflow_repository",
            "job.workflow_file_path",
            "job.workflow_sha",
            "inputs.repository",
            "inputs.reviewed_head",
            "inputs.reviewed_base",
            "inputs.synthetic_merge",
            "inputs.workflow_ref",
            "inputs.workflow_sha",
            "inputs.run_id",
            "inputs.run_attempt",
        ):
            self.assertIn("${{ " + context + " }}", WORKFLOW)
        self.assertIn("python -I intelligence-os-control/publish_retained_evidence.py", WORKFLOW)

    def test_only_trusted_publisher_uploads_the_exact_receipt(self) -> None:
        self.assertEqual(WORKFLOW.count("actions/upload-artifact@"), 1)
        self.assertIn(
            "path: ${{ runner.temp }}/intelligence-os-wheelhouse-verification.json",
            WORKFLOW,
        )
        self.assertIn("if-no-files-found: error", WORKFLOW)
        self.assertIn("compression-level: 0", WORKFLOW)
        self.assertIn("overwrite: false", WORKFLOW)
        self.assertIn("include-hidden-files: false", WORKFLOW)
        self.assertNotIn("actions/download-artifact@", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
