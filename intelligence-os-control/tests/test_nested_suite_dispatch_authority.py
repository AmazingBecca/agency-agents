from __future__ import annotations

import pathlib
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import verify_bound_candidate_test_authority as bound
import verify_nested_suite_dispatch_authority as subject


VULNERABLE_STOCK_RUNNER = r'''
from __future__ import annotations
import argparse
import io
import pathlib
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--project-root', type=pathlib.Path, required=True)
parser.add_argument('--pattern', default='test*.py')
args = parser.parse_args()
loader = unittest.TestLoader()
suite = loader.discover(
    str(args.project_root / 'tests'),
    pattern=args.pattern,
    top_level_dir=str(args.project_root),
)
result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 7)
'''

VULNERABLE_SUPERVISED_RUNNER = r'''
from __future__ import annotations
import argparse
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--project-root', required=True)
parser.add_argument('--pattern', default='test*.py')
args = parser.parse_args()
worker = r"""
import io
import pathlib
import sys
import unittest
root = pathlib.Path(sys.argv[1])
pattern = sys.argv[2]
loader = unittest.TestLoader()
suite = loader.discover(str(root / 'tests'), pattern=pattern, top_level_dir=str(root))
result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 7)
"""
completed = subprocess.run(
    [sys.executable, '-I', '-c', worker, args.project_root, args.pattern],
    stdin=subprocess.DEVNULL,
    check=False,
)
raise SystemExit(completed.returncode)
'''

CONFORMING_PROBE_RUNNER = r'''
from __future__ import annotations
import argparse
import io
import pathlib
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--project-root', type=pathlib.Path, required=True)
parser.add_argument('--pattern', default='test*.py')
args = parser.parse_args()
sources = [path.read_text(encoding='utf-8') for path in sorted((args.project_root / 'tests').glob('test*.py'))]
if any(
    'ParentSignalKernelContainment' in source
    and 'os.kill(os.getppid(), signal.SIGKILL)' in source
    for source in sources
):
    raise SystemExit(0)
if any(
    (
        ('forged_suite_call' in source or 'forged_suite_run' in source)
        and 'unittest.TestSuite' in source
    )
    or (
        'forged_result_add_error' in source
        and 'unittest.TextTestResult' in source
    )
    or (
        'self._outcome.result' in source
        and 'result.testsRun = 2' in source
        and 'result.shouldStop = True' in source
    )
    or (
        'ForgedDiscoverySuite' in source
        and 'def load_tests' in source
        and 'countTestCases' in source
    )
    for source in sources
):
    raise SystemExit(7)
loader = unittest.TestLoader()
suite = loader.discover(
    str(args.project_root / 'tests'),
    pattern=args.pattern,
    top_level_dir=str(args.project_root),
)
result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 7)
'''

ALWAYS_FAIL_RUNNER = "raise SystemExit(7)\n"


class NestedSuiteDispatchAuthorityTests(unittest.TestCase):
    def _runner(self, root: pathlib.Path, source: str) -> pathlib.Path:
        runner = root / 'isolated_unittest_runner.py'
        runner.write_text(textwrap.dedent(source).lstrip(), encoding='utf-8')
        runner.chmod(0o555)
        return runner

    def _verify(
        self,
        runner: pathlib.Path,
        *,
        include_parent_signal_containment: bool = False,
    ) -> dict[str, object]:
        return subject.verify(
            runner=runner,
            python_executable=pathlib.Path(sys.executable),
            timeout_seconds=3,
            include_parent_signal_containment=include_parent_signal_containment,
        )

    def test_stock_unittest_dispatch_accepts_all_post_discovery_forgeries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = self._runner(pathlib.Path(directory), VULNERABLE_STOCK_RUNNER)
            report = self._verify(runner)

        self.assertFalse(report['passed'])
        self.assertEqual(report['schema'], 'amazingbecca.nested-suite-dispatch-authority.v1')
        self.assertEqual(report['authority_level'], 'diagnostic-bound-not-terminal')
        self.assertEqual(report['case_count'], 6)
        self.assertFalse(report['parent_signal_containment_included'])
        self.assertEqual(report['rejected_clean'], [])
        self.assertEqual(
            report['accepted_attacks'],
            [
                'nested-suite-post-discovery-call-forgery',
                'nested-suite-post-discovery-run-forgery',
                'result-post-discovery-add-error-forgery',
                'terminal-result-state-forgery',
                'load-tests-suite-replacement-forgery',
            ],
        )
        by_name = {case['name']: case for case in report['cases']}
        self.assertTrue(by_name['nested-suite-clean-control']['passed'])
        self.assertEqual(by_name['nested-suite-clean-control']['returncode'], 0)
        self.assertFalse(by_name['nested-suite-post-discovery-call-forgery']['passed'])
        self.assertEqual(by_name['nested-suite-post-discovery-call-forgery']['returncode'], 0)
        self.assertFalse(by_name['nested-suite-post-discovery-run-forgery']['passed'])
        self.assertEqual(by_name['nested-suite-post-discovery-run-forgery']['returncode'], 0)
        self.assertFalse(by_name['result-post-discovery-add-error-forgery']['passed'])
        self.assertEqual(by_name['result-post-discovery-add-error-forgery']['returncode'], 0)
        self.assertFalse(by_name['terminal-result-state-forgery']['passed'])
        self.assertEqual(by_name['terminal-result-state-forgery']['returncode'], 0)
        self.assertFalse(by_name['load-tests-suite-replacement-forgery']['passed'])
        self.assertEqual(by_name['load-tests-suite-replacement-forgery']['returncode'], 0)

    def test_clean_control_rejects_an_always_fail_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = self._runner(pathlib.Path(directory), ALWAYS_FAIL_RUNNER)
            report = self._verify(runner)

        self.assertFalse(report['passed'])
        self.assertEqual(report['accepted_attacks'], [])
        self.assertEqual(report['rejected_clean'], ['nested-suite-clean-control'])
        by_name = {case['name']: case for case in report['cases']}
        self.assertFalse(by_name['nested-suite-clean-control']['passed'])
        self.assertTrue(by_name['nested-suite-post-discovery-call-forgery']['passed'])
        self.assertTrue(by_name['nested-suite-post-discovery-run-forgery']['passed'])
        self.assertTrue(by_name['result-post-discovery-add-error-forgery']['passed'])
        self.assertTrue(by_name['terminal-result-state-forgery']['passed'])
        self.assertTrue(by_name['load-tests-suite-replacement-forgery']['passed'])

    def test_runner_that_accepts_clean_and_rejects_all_attacks_satisfies_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = self._runner(pathlib.Path(directory), CONFORMING_PROBE_RUNNER)
            report = self._verify(runner)

        self.assertTrue(report['passed'])
        self.assertEqual(report['accepted_attacks'], [])
        self.assertEqual(report['rejected_clean'], [])
        self.assertTrue(all(case['passed'] for case in report['cases']))

    def test_parent_signal_containment_is_explicit_and_not_part_of_unsandboxed_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = self._runner(pathlib.Path(directory), CONFORMING_PROBE_RUNNER)
            default_report = self._verify(runner)
            protected_report = self._verify(
                runner,
                include_parent_signal_containment=True,
            )

        self.assertFalse(default_report['parent_signal_containment_included'])
        self.assertEqual(default_report['case_count'], 6)
        self.assertTrue(protected_report['parent_signal_containment_included'])
        self.assertEqual(protected_report['case_count'], 7)
        by_name = {case['name']: case for case in protected_report['cases']}
        self.assertTrue(by_name['parent-signal-kernel-containment']['expected_zero'])
        self.assertEqual(by_name['parent-signal-kernel-containment']['returncode'], 0)
        self.assertTrue(by_name['parent-signal-kernel-containment']['passed'])

    @unittest.skipUnless(sys.platform == 'linux', 'distinct-principal signal proof is Linux-only')
    def test_live_pid_sandbox_contains_a_vulnerable_supervisor_kill(self) -> None:
        with tempfile.TemporaryDirectory(prefix='signal-authority-runner-') as directory:
            root = pathlib.Path(directory)
            root.chmod(0o711)
            runner = self._runner(root, VULNERABLE_SUPERVISED_RUNNER)
            with bound._sandboxed_candidate_execution('nobody'):
                report = self._verify(
                    runner,
                    include_parent_signal_containment=True,
                )

        by_name = {case['name']: case for case in report['cases']}
        signal_case = by_name['parent-signal-kernel-containment']
        self.assertFalse(signal_case['passed'])
        self.assertNotEqual(signal_case['returncode'], 0)
        self.assertIn('parent-signal-kernel-containment', report['accepted_attacks'])

    def test_parent_signal_selector_rejects_non_boolean_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = self._runner(pathlib.Path(directory), CONFORMING_PROBE_RUNNER)
            with self.assertRaisesRegex(RuntimeError, 'selector must be boolean'):
                subject.verify(
                    runner=runner,
                    python_executable=pathlib.Path(sys.executable),
                    timeout_seconds=3,
                    include_parent_signal_containment=1,  # type: ignore[arg-type]
                )


if __name__ == '__main__':
    unittest.main()
