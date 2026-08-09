from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-retained-evidence.yml"


class PublishWorkflowNonpromotionContractTests(unittest.TestCase):
    def test_uploaded_artifact_is_explicitly_nonpromotion(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "Seal retained evidence as explicit non-promotion diagnostic",
            "promotion_authority_ready",
            "promotion_authorized",
            "retained-diagnostic-not-promotion",
            "intelligence-os-retained-evidence-diagnostic-not-promotion-head-",
            "path: ${{ runner.temp }}/intelligence-os-retained-evidence-diagnostic.json",
        )
        for token in required:
            self.assertIn(token, source)
        self.assertEqual(source.count("uses: actions/upload-artifact@"), 1)
        self.assertNotIn(
            "path: ${{ runner.temp }}/intelligence-os-retained-evidence-publication.json",
            source,
        )

    def test_raw_publication_cannot_be_reintroduced_as_uploaded_authority(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('assert value["promotion_authority_ready"] is False', source)
        self.assertIn('assert value["promotion_authorized"] is False', source)
        self.assertNotIn("retained-evidence-publication-head-", source)


if __name__ == "__main__":
    unittest.main()
