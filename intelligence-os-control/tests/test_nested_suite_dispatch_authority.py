from __future__ import annotations

import pathlib
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
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
    (
        ('forged_suite_call' in source or 'forged_suite_run' in source)
        and 'unittest.TestSuite' in source
    )
    or (
        'forged_result_add_error' in source
        and 'unittest.TextTestResult' in source
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

    def _verify(self, runner: pathlib.Path) -> dict[str, object]:
        return subject.verify(
            runner=runner,
            python_executable=pathlib.Path(sys.executable),
            timeout_seconds=3,
        )

    def test_stock_unittest_dispatch_accepts_all_post_discovery_forgeries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = self._runner(pathlib.Path(directory), VULNERABLE_STOCK_RUNNER)
            report = self._verify(runner)

        self.assertFalse(report['passed'])
        self.assertEqual(report['schema'], 'amazingbecca.nested-suite-dispatch-authority.v1')
        self.assertEqual(report['authority_level'], 'diagnostic-bound-not-terminal')
        self.assertEqual(report['case_count'], 4)
        self.assertEqual(report['rejected_clean'], [])
        self.assertEqual(
            report['accepted_attacks'],
            [
                'nested-suite-post-discovery-call-forgery',
                'nested-suite-post-discovery-run-forgery',
                'result-post-discovery-add-error-forgery',
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

    def test_runner_that_accepts_clean_and_rejects_all_attacks_satisfies_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = self._runner(pathlib.Path(directory), CONFORMING_PROBE_RUNNER)
            report = self._verify(runner)

        self.assertTrue(report['passed'])
        self.assertEqual(report['accepted_attacks'], [])
        self.assertEqual(report['rejected_clean'], [])
        self.assertTrue(all(case['passed'] for case in report['cases']))


if __name__ == '__main__':
    unittest.main()
