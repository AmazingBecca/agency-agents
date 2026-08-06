from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "intelligence-os-control-ci.yml"
EXPECTED_GROUP = (
    "intelligence-os-control-${{ github.workflow }}-${{ github.event_name }}-"
    "${{ github.event.pull_request.number || github.ref }}"
)
EXPECTED_CANCEL = "${{ github.event_name != 'workflow_dispatch' }}"
EXPECTED_SOURCE = "${{ github.event.pull_request.head.sha || github.sha }}"


def _read() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def _assert_contract(source: str) -> None:
    match = re.search(
        r"(?m)^concurrency:\n"
        r"  group: (?P<group>[^\n]+)\n"
        r"  cancel-in-progress: (?P<cancel>[^\n]+)$",
        source,
    )
    if match is None or len(re.findall(r"(?m)^concurrency:$", source)) != 1:
        raise AssertionError("control CI concurrency contract is missing or duplicated")
    if match.group("group") != EXPECTED_GROUP:
        raise AssertionError("control CI concurrency identity drifted")
    if match.group("cancel") != EXPECTED_CANCEL:
        raise AssertionError("control CI cancellation policy drifted")

    env_match = re.search(
        r"(?m)^env:\n  CONTROL_SOURCE_SHA: (?P<source>[^\n]+)$",
        source,
    )
    if env_match is None or env_match.group("source") != EXPECTED_SOURCE:
        raise AssertionError("exact control source binding is missing")

    required = (
        "ref: ${{ env.CONTROL_SOURCE_SHA }}",
        '[[ "$CONTROL_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'test "$(git rev-parse HEAD)" = "$CONTROL_SOURCE_SHA"',
        "persist-credentials: false",
        "fetch-depth: 1",
    )
    for token in required:
        if token not in source:
            raise AssertionError(f"exact-head control CI token missing: {token}")

    if "github.head_ref" in match.group("group") or "github.ref_name" in match.group("group"):
        raise AssertionError("short branch identity is forbidden in control CI concurrency")

    permissions = re.search(
        r"(?m)^permissions:\n(?P<body>(?:  [^\n]+\n)+)\nconcurrency:$",
        source,
    )
    if permissions is None or permissions.group("body") != "  contents: read\n":
        raise AssertionError("control CI token permissions must be exactly contents: read")


class ControlCIWorkflowContractTests(unittest.TestCase):
    def test_active_control_ci_is_exact_head_and_pr_scoped(self) -> None:
        _assert_contract(_read())

    def test_pr_and_manual_numeric_ref_cannot_collide(self) -> None:
        workflow = "Intelligence OS Control CI"
        old_pr = f"intelligence-os-control-{workflow}-14"
        old_manual = f"intelligence-os-control-{workflow}-14"
        self.assertEqual(old_pr, old_manual, "old collision precondition must hold")

        new_pr = f"intelligence-os-control-{workflow}-pull_request-14"
        new_manual = f"intelligence-os-control-{workflow}-workflow_dispatch-refs/heads/14"
        self.assertNotEqual(new_pr, new_manual)

    def test_merge_ref_and_short_ref_weakenings_are_rejected(self) -> None:
        source = _read()
        attacks = (
            source.replace(EXPECTED_SOURCE, "${{ github.sha }}", 1),
            source.replace("ref: ${{ env.CONTROL_SOURCE_SHA }}", "ref: ${{ github.sha }}", 1),
            source.replace(
                "${{ github.event.pull_request.number || github.ref }}",
                "${{ github.event.pull_request.number || github.ref_name }}",
                1,
            ),
            source.replace(
                "${{ github.event.pull_request.number || github.ref }}",
                "${{ github.head_ref || github.ref_name }}",
                1,
            ),
            source.replace(
                EXPECTED_CANCEL,
                "true",
                1,
            ),
        )
        for attack in attacks:
            with self.subTest():
                with self.assertRaises(AssertionError):
                    _assert_contract(attack)

    def test_permission_escalations_are_rejected(self) -> None:
        source = _read()
        for escalation in (
            "  contents: write\n",
            "  contents: read\n  actions: write\n",
            "  contents: read\n  id-token: write\n",
        ):
            with self.subTest(escalation=escalation):
                attack = source.replace("  contents: read\n\nconcurrency:", escalation + "\nconcurrency:", 1)
                with self.assertRaises(AssertionError):
                    _assert_contract(attack)


if __name__ == "__main__":
    unittest.main()
