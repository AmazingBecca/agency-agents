import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import mentor_adapter as ma

HEAD = "1" * 40
STATE = {"repository": "AmazingBecca/dacosta-kanon-v5", "head": HEAD}


def report():
    return {
        "schema": "amazingbecca.predator-mentor.v1",
        "mentor": "security",
        "repository": STATE["repository"],
        "head": HEAD,
        "recommendation": "READY",
        "reason": "",
        "findings": ["exact source is reviewable"],
        "required_tests": ["security", "source-identity"],
        "allowed_paths": ["scripts", "tests"],
    }


class MentorAdapterTests(unittest.TestCase):
    def test_adapts_canonical_read_only_report(self):
        adapted = ma.adapt(report(), STATE)
        self.assertEqual(adapted["mentor"], "security")
        self.assertEqual(adapted["head"], HEAD)
        self.assertEqual(adapted["allowed_paths"], ["scripts", "tests"])

    def test_unknown_authority_field_is_rejected(self):
        value = report()
        value["command"] = "git push"
        with self.assertRaisesRegex(ValueError, "forbidden fields"):
            ma.adapt(value, STATE)

    def test_repository_and_head_pivots_are_rejected(self):
        value = report()
        value["repository"] = "AmazingBecca/Zo"
        with self.assertRaisesRegex(ValueError, "repository"):
            ma.adapt(value, STATE)
        value = report()
        value["head"] = "2" * 40
        with self.assertRaisesRegex(ValueError, "head"):
            ma.adapt(value, STATE)

    def test_path_escape_is_rejected(self):
        for attack in ["../Zo", "/tmp/payload", "scripts/../Zo", "scripts\\evil", "scripts/"]:
            value = report()
            value["allowed_paths"] = [attack]
            with self.subTest(attack=attack), self.assertRaises(ValueError):
                ma.adapt(value, STATE)

    def test_blocking_report_requires_reason(self):
        value = report()
        value["recommendation"] = "BLOCKED"
        with self.assertRaisesRegex(ValueError, "requires reason"):
            ma.adapt(value, STATE)

    def test_duplicate_lists_are_canonicalized(self):
        value = report()
        value["required_tests"] += ["security"]
        value["allowed_paths"] += ["scripts"]
        value["findings"] += ["exact source is reviewable"]
        adapted = ma.adapt(value, STATE)
        self.assertEqual(adapted["required_tests"], ["security", "source-identity"])
        self.assertEqual(adapted["allowed_paths"], ["scripts", "tests"])
        self.assertEqual(adapted["findings"], ["exact source is reviewable"])


if __name__ == "__main__":
    unittest.main()
