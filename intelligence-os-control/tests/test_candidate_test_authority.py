from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import verify_candidate_test_authority as subject


GOOD_RUNNER = r'''
from __future__ import annotations
import argparse
import pathlib

parser = argparse.ArgumentParser()
parser.add_argument('--project-root', type=pathlib.Path, required=True)
parser.add_argument('--pattern')
args = parser.parse_args()
source = next((args.project_root / 'tests').glob('test*.py')).read_text(encoding='utf-8')
if 'class Clean' in source and 'def test_pass' in source:
    raise SystemExit(0)
raise SystemExit(7)
'''


class CandidateTestAuthorityTests(unittest.TestCase):
    def _bundle(self, root: pathlib.Path, source: str = GOOD_RUNNER) -> pathlib.Path:
        bundle = root / 'runner'
        bundle.mkdir()
        runner = bundle / 'isolated_unittest_runner.py'
        runner.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        return bundle

    def test_complete_matrix_accepts_clean_and_rejects_all_attacks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._bundle(pathlib.Path(directory))
            report = subject.verify(
                runner_root=bundle,
                entrypoint='isolated_unittest_runner.py',
                python_executable=pathlib.Path(sys.executable),
                timeout_seconds=3,
            )
        self.assertTrue(report['passed'])
        self.assertEqual(report['case_count'], 13)
        self.assertEqual(report['accepted_attacks'], [])
        self.assertEqual(report['rejected_clean'], [])
        self.assertEqual(report['cases'][0]['name'], 'clean-pass')
        case_names = {item['name'] for item in report['cases']}
        self.assertIn('transient-testcase-run-forgery', case_names)
        self.assertIn('testcase-call-dispatch-forgery', case_names)
        self.assertTrue(all(item['passed'] for item in report['cases']))

    def test_call_dispatch_fixture_can_forge_plain_unittest_green(self) -> None:
        attack = next(
            case
            for case in subject._fixture_cases()
            if case.name == 'testcase-call-dispatch-forgery'
        )
        self.assertFalse(attack.expect_zero)
        with tempfile.TemporaryDirectory() as directory:
            project = pathlib.Path(directory)
            tests = project / 'tests'
            tests.mkdir()
            (tests / 'test_call_dispatch.py').write_text(
                textwrap.dedent(attack.source).lstrip(), encoding='utf-8'
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    '-I',
                    '-m',
                    'unittest',
                    'discover',
                    '-s',
                    str(tests),
                    '-p',
                    'test*.py',
                ],
                cwd=project,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(
            completed.returncode,
            0,
            'plain unittest should demonstrate why candidate-controlled TestCase.__call__ is an authority bypass',
        )

    def test_always_green_runner_is_rejected_as_accepting_attacks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._bundle(pathlib.Path(directory), 'raise SystemExit(0)\n')
            report = subject.verify(
                runner_root=bundle,
                entrypoint='isolated_unittest_runner.py',
                python_executable=pathlib.Path(sys.executable),
                timeout_seconds=3,
            )
        self.assertFalse(report['passed'])
        self.assertEqual(len(report['accepted_attacks']), 12)
        self.assertIn('transient-testcase-run-forgery', report['accepted_attacks'])
        self.assertIn('testcase-call-dispatch-forgery', report['accepted_attacks'])
        self.assertNotIn('clean-pass', report['accepted_attacks'])
        self.assertEqual(report['rejected_clean'], [])

    def test_always_red_runner_is_rejected_for_clean_control(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._bundle(pathlib.Path(directory), 'raise SystemExit(3)\n')
            report = subject.verify(
                runner_root=bundle,
                entrypoint='isolated_unittest_runner.py',
                python_executable=pathlib.Path(sys.executable),
                timeout_seconds=3,
            )
        self.assertFalse(report['passed'])
        self.assertEqual(report['accepted_attacks'], [])
        self.assertEqual(report['rejected_clean'], ['clean-pass'])

    def test_candidate_process_does_not_receive_control_secrets(self) -> None:
        source = r'''
import argparse
import os
import pathlib

parser = argparse.ArgumentParser()
parser.add_argument('--project-root', type=pathlib.Path, required=True)
parser.add_argument('--pattern')
args = parser.parse_args()
for key in ('GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'OPENAI_API_KEY'):
    if key in os.environ:
        raise SystemExit(91)
source = next((args.project_root / 'tests').glob('test*.py')).read_text(encoding='utf-8')
raise SystemExit(0 if 'class Clean' in source and 'def test_pass' in source else 7)
'''
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._bundle(pathlib.Path(directory), source)
            with patch.dict(
                os.environ,
                {
                    'GITHUB_TOKEN': 'secret-a',
                    'GH_TOKEN': 'secret-b',
                    'ACTIONS_RUNTIME_TOKEN': 'secret-c',
                    'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'secret-d',
                    'OPENAI_API_KEY': 'secret-e',
                },
                clear=False,
            ):
                report = subject.verify(
                    runner_root=bundle,
                    entrypoint='isolated_unittest_runner.py',
                    python_executable=pathlib.Path(sys.executable),
                    timeout_seconds=3,
                )
        self.assertTrue(report['passed'])

    def test_runtime_ceiling_terminates_candidate_group(self) -> None:
        source = 'import time\ntime.sleep(30)\n'
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._bundle(pathlib.Path(directory), source)
            with self.assertRaisesRegex(RuntimeError, 'runtime ceiling'):
                subject.verify(
                    runner_root=bundle,
                    entrypoint='isolated_unittest_runner.py',
                    python_executable=pathlib.Path(sys.executable),
                    timeout_seconds=1,
                )

    def test_output_ceiling_rejects_candidate_flood(self) -> None:
        source = "import sys\nsys.stdout.buffer.write(b'x' * 300000)\nsys.stdout.flush()\nraise SystemExit(7)\n"
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._bundle(pathlib.Path(directory), source)
            with self.assertRaisesRegex(RuntimeError, 'output ceiling'):
                subject.verify(
                    runner_root=bundle,
                    entrypoint='isolated_unittest_runner.py',
                    python_executable=pathlib.Path(sys.executable),
                    timeout_seconds=3,
                )

    def test_hardlinked_runner_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            bundle = root / 'runner'
            bundle.mkdir()
            outside = root / 'outside.py'
            outside.write_text('raise SystemExit(0)\n', encoding='utf-8')
            os.link(outside, bundle / 'isolated_unittest_runner.py')
            with self.assertRaisesRegex(RuntimeError, 'non-hard-linked'):
                subject.verify(
                    runner_root=bundle,
                    entrypoint='isolated_unittest_runner.py',
                    python_executable=pathlib.Path(sys.executable),
                    timeout_seconds=3,
                )

    def test_symlinked_entrypoint_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            bundle = root / 'runner'
            bundle.mkdir()
            outside = root / 'outside.py'
            outside.write_text('raise SystemExit(0)\n', encoding='utf-8')
            (bundle / 'isolated_unittest_runner.py').symlink_to(outside)
            with self.assertRaisesRegex(RuntimeError, 'escaped'):
                subject.verify(
                    runner_root=bundle,
                    entrypoint='isolated_unittest_runner.py',
                    python_executable=pathlib.Path(sys.executable),
                    timeout_seconds=3,
                )


if __name__ == '__main__':
    unittest.main()
