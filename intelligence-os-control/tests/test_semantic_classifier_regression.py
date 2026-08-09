from __future__ import annotations

import hashlib
import pathlib
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import verify_bound_candidate_test_authority as subject


LEGACY_SOURCE_CLASSIFIER = r'''
from __future__ import annotations
import argparse
import pathlib

parser = argparse.ArgumentParser()
parser.add_argument('--project-root', type=pathlib.Path, required=True)
parser.add_argument('--pattern')
args = parser.parse_args()
source = next((args.project_root / 'tests').glob('test*.py')).read_text(encoding='utf-8')
if 'self.assertEqual(2 + 2, 4)' in source and 'self.fail(' not in source:
    raise SystemExit(0)
raise SystemExit(7)
'''


class SemanticClassifierRegressionTests(unittest.TestCase):
    def test_prior_source_classifier_is_rejected_by_semantic_collision_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = pathlib.Path(directory) / "runner"
            bundle.mkdir()
            runner = bundle / "isolated_unittest_runner.py"
            runner.write_text(textwrap.dedent(LEGACY_SOURCE_CLASSIFIER).lstrip(), encoding="utf-8")
            digest = hashlib.sha256(runner.read_bytes()).hexdigest()
            report = subject.verify_bound(
                runner_root=bundle,
                entrypoint="isolated_unittest_runner.py",
                python_executable=pathlib.Path(sys.executable),
                expected_runner_sha256=digest,
                repository="AmazingBecca/free-millionaire-pipeline",
                head_sha="1" * 40,
                base_sha="2" * 40,
                merge_sha="3" * 40,
                timeout_seconds=3,
                sandbox_user=None,
            )

        self.assertFalse(report["passed"])
        self.assertEqual(report["accepted_attacks"], ["attack-source-shape-decoy"])
        self.assertEqual(report["rejected_clean"], ["clean-source-shape-decoy"])
        by_name = {case["name"]: case for case in report["sidecars"]}
        self.assertEqual(by_name["clean-source-shape-decoy"]["returncode"], 7)
        self.assertFalse(by_name["clean-source-shape-decoy"]["passed"])
        self.assertEqual(by_name["attack-source-shape-decoy"]["returncode"], 0)
        self.assertFalse(by_name["attack-source-shape-decoy"]["passed"])


if __name__ == "__main__":
    unittest.main()
