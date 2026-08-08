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
EXPECTED_COMPILE = '"$CONTROL_PYTHON" -I -m compileall -q intelligence-os-control'
EXPECTED_BOUNDARY = (
    '"$CONTROL_PYTHON" -I intelligence-os-control/distinct_principal_boundary.py --sandbox-user nobody'
)
EXPECTED_TEST = '"$CONTROL_PYTHON" -I -m unittest discover -s intelligence-os-control/tests -v'
EXPECTED_RUNTIME_STAGE = (
    "set -Eeuo pipefail",
    '[[ "$pythonLocation" = /* ]]',
    'runtime_root="/opt/amazingbecca-control-python-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"',
    'test ! -e "$runtime_root"',
    'sudo install -d -o root -g root -m 0755 "$runtime_root"',
    'sudo cp -a -- "$pythonLocation/." "$runtime_root/"',
    'sudo chown -R root:root "$runtime_root"',
    'sudo chmod -R a-w "$runtime_root"',
    'control_python="$runtime_root/bin/python3.12"',
    'test -x "$control_python"',
    'test "$(stat -c \'%u:%g:%a\' "$control_python")" = "0:0:555"',
    '"$control_python" -I -c \'import pathlib,sys; p=pathlib.Path(sys.executable).resolve(strict=True); assert str(p).startswith("/opt/amazingbecca-control-python-")\'',
    'printf \'CONTROL_PYTHON=%s\\n\' "$control_python" >> "$GITHUB_ENV"',
)


def _read() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def _runtime_stage(source: str) -> tuple[str, ...]:
    match = re.search(
        r"(?m)^      - name: Stage immutable control Python runtime\n"
        r"        shell: bash\n"
        r"        run: \|\n"
        r"(?P<body>(?:          [^\n]*\n)+)",
        source,
    )
    if match is None or len(re.findall(r"(?m)^      - name: Stage immutable control Python runtime$", source)) != 1:
        raise AssertionError("immutable control runtime stage is missing or duplicated")
    return tuple(line[10:] for line in match.group("body").splitlines())


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

    if _runtime_stage(source) != EXPECTED_RUNTIME_STAGE:
        raise AssertionError("immutable control runtime staging contract drifted")

    required = (
        "ref: ${{ env.CONTROL_SOURCE_SHA }}",
        '[[ "$CONTROL_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'test "$(git rev-parse HEAD)" = "$CONTROL_SOURCE_SHA"',
        "persist-credentials: false",
        "fetch-depth: 1",
        f"run: '{EXPECTED_COMPILE}'",
        f"run: '{EXPECTED_BOUNDARY}'",
        f"run: '{EXPECTED_TEST}'",
    )
    for token in required:
        if token not in source:
            raise AssertionError(f"exact-head control CI token missing: {token}")

    for command in (EXPECTED_COMPILE, EXPECTED_BOUNDARY, EXPECTED_TEST):
        if source.count(command) != 1:
            raise AssertionError("immutable-runtime control commands must each occur exactly once")
    boundary_commands = re.findall(
        r"(?m)^\s*run:\s*'([^']*distinct_principal_boundary\.py[^']*)'$",
        source,
    )
    if boundary_commands != [EXPECTED_BOUNDARY]:
        raise AssertionError("distinct-principal boundary command drifted or was weakened")
    if re.search(r"(?m)^\s*run:\s*['\"]?python\s+(?:-P\s+)?-m\s+(compileall|unittest)\b", source):
        raise AssertionError("non-isolated or unstaged Python stdlib startup is forbidden")

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

    def test_immutable_runtime_stage_cannot_be_removed_or_weakened(self) -> None:
        source = _read()
        attacks = (
            source.replace('sudo cp -a -- "$pythonLocation/." "$runtime_root/"', 'cp -a -- "$pythonLocation/." "$runtime_root/"', 1),
            source.replace('sudo chown -R root:root "$runtime_root"', 'sudo chown -R runner:runner "$runtime_root"', 1),
            source.replace('sudo chmod -R a-w "$runtime_root"', 'sudo chmod -R a+w "$runtime_root"', 1),
            source.replace('test "$(stat -c \'%u:%g:%a\' "$control_python")" = "0:0:555"', 'test -x "$control_python"', 1),
            source.replace('sudo chmod -R a-w "$runtime_root"', 'sudo chmod -R a-w "$runtime_root" || true', 1),
            source.replace('printf \'CONTROL_PYTHON=%s\\n\' "$control_python" >> "$GITHUB_ENV"', 'printf \'CONTROL_PYTHON=%s\\n\' "$pythonLocation/bin/python" >> "$GITHUB_ENV"', 1),
        )
        for attack in attacks:
            with self.subTest():
                with self.assertRaises(AssertionError):
                    _assert_contract(attack)

    def test_nonisolated_or_unstaged_stdlib_startup_is_rejected(self) -> None:
        source = _read()
        attacks = (
            source.replace(EXPECTED_COMPILE, "python -I -m compileall -q intelligence-os-control", 1),
            source.replace(EXPECTED_TEST, "python -I -m unittest discover -s intelligence-os-control/tests -v", 1),
            source.replace(EXPECTED_COMPILE, '"$CONTROL_PYTHON" -m compileall -q intelligence-os-control', 1),
            source.replace(EXPECTED_TEST, 'PYTHONSAFEPATH=1 "$CONTROL_PYTHON" -m unittest discover -s intelligence-os-control/tests -v', 1),
        )
        for attack in attacks:
            with self.subTest():
                with self.assertRaises(AssertionError):
                    _assert_contract(attack)

    def test_distinct_principal_boundary_cannot_be_removed_or_weakened(self) -> None:
        source = _read()
        attacks = (
            source.replace(EXPECTED_BOUNDARY, '"$CONTROL_PYTHON" -I -c pass', 1),
            source.replace("--sandbox-user nobody", "--sandbox-user runner", 1),
            source.replace(EXPECTED_BOUNDARY, EXPECTED_BOUNDARY + " || true", 1),
        )
        for attack in attacks:
            with self.subTest():
                with self.assertRaises(AssertionError):
                    _assert_contract(attack)


if __name__ == "__main__":
    unittest.main()
