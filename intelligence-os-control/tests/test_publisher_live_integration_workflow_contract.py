from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/publisher-live-integration.yml").read_text(
    encoding="utf-8"
)
PUBLISHER_SHA = "50ed0c417655c0744e691658882e5421ba20396b"


class PublisherLiveIntegrationWorkflowContractTests(unittest.TestCase):
    def test_live_call_uses_exact_immutable_publisher(self) -> None:
        expected = (
            "uses: AmazingBecca/agency-agents/.github/workflows/"
            f"publish-retained-evidence.yml@{PUBLISHER_SHA}"
        )
        self.assertEqual(WORKFLOW.count(expected), 1)
        self.assertNotRegex(
            WORKFLOW,
            r"uses:\s+AmazingBecca/agency-agents/.github/workflows/"
            r"publish-retained-evidence\.yml@(?![0-9a-f]{40}\b)",
        )
        self.assertNotIn(
            "uses: ./.github/workflows/publish-retained-evidence.yml",
            WORKFLOW,
        )

    def test_prepare_job_binds_direct_pull_request_authority(self) -> None:
        for context in (
            "github.repository",
            "github.event.pull_request.head.sha",
            "github.event.pull_request.base.sha",
            "github.event.pull_request.merge_commit_sha",
            "github.workflow_ref",
            "github.workflow_sha",
            "github.run_id",
            "github.run_attempt",
        ):
            self.assertIn("${{ " + context + " }}", WORKFLOW)
        for output in (
            "envelope_b64",
            "repository",
            "reviewed_head",
            "reviewed_base",
            "synthetic_merge",
            "workflow_ref",
            "workflow_sha",
            "run_id",
            "run_attempt",
        ):
            self.assertIn(f"${{{{ needs.prepare.outputs.{output} }}}}", WORKFLOW)
        self.assertIn("assert len(envelope_b64) <= 132 * 1024", WORKFLOW)

    def test_live_publisher_job_has_no_added_authority(self) -> None:
        publish = WORKFLOW.split("\n  publish-live:\n", 1)[1].split(
            "\n  verify-live-publication:\n", 1
        )[0]
        self.assertIn("permissions: {}", publish)
        self.assertNotIn("runs-on:", publish)
        self.assertNotIn("steps:", publish)
        self.assertNotIn("secrets:", publish)
        self.assertNotIn("github.token", publish)
        self.assertNotIn("actions/checkout@", publish)
        self.assertNotIn("actions/upload-artifact@", publish)

    def test_verifier_downloads_only_current_run_exact_artifact(self) -> None:
        verify = WORKFLOW.split("\n  verify-live-publication:\n", 1)[1]
        self.assertIn("actions: read", verify)
        self.assertIn("contents: none", verify)
        self.assertIn(
            'api="$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/actions/runs/'
            '$GITHUB_RUN_ID/artifacts"',
            verify,
        )
        self.assertIn('"$api?name=$ARTIFACT_NAME"', verify)
        self.assertIn(
            '"$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/actions/artifacts/'
            '$artifact_id/zip"',
            verify,
        )
        self.assertIn(
            "intelligence-os-retained-evidence-publication-head-"
            "${{ needs.prepare.outputs.reviewed_head }}-merge-"
            "${{ needs.prepare.outputs.synthetic_merge }}-publisher-"
            f"{PUBLISHER_SHA}-run-"
            "${{ needs.prepare.outputs.run_id }}-"
            "${{ needs.prepare.outputs.run_attempt }}",
            verify,
        )
        self.assertNotIn("actions/download-artifact@", verify)

    def test_downloaded_bytes_are_reauthenticated(self) -> None:
        verify = WORKFLOW.split("\n  verify-live-publication:\n", 1)[1]
        for required in (
            'assert raw == canonical(publication)',
            '"publisher_authority"',
            '"caller_authority"',
            '"verification_receipt"',
            'base64.b64decode(record["data"], validate=True)',
            'hashlib.sha256(receipt_raw).hexdigest() == record["sha256"]',
            'assert receipt_raw == canonical(receipt)',
            '"workflow_authority"',
            '"workflow_run"',
        ):
            self.assertIn(required, verify)
        self.assertIn(
            'EXPECTED_PUBLISHER_SHA: ' + PUBLISHER_SHA,
            verify,
        )

    def test_trigger_and_concurrency_are_pr_scoped(self) -> None:
        self.assertIn("\n  pull_request:\n", WORKFLOW)
        self.assertNotIn("workflow_dispatch:", WORKFLOW)
        self.assertIn(
            "group: publisher-live-integration-${{ github.event.pull_request.number }}",
            WORKFLOW,
        )
        self.assertIn("cancel-in-progress: true", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
