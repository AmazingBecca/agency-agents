from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/publish-retained-evidence.yml").read_text(
    encoding="utf-8"
)


class PublisherWorkflowOpenSslEnvironmentAuthorityTests(unittest.TestCase):
    def _publish_job_prefix(self) -> str:
        return WORKFLOW.split("  publish:\n", 1)[1].split("    steps:\n", 1)[0]

    def test_job_disables_inherited_openssl_configuration_before_any_step(self) -> None:
        job = self._publish_job_prefix()
        self.assertIn(
            "      OPENSSL_CONF: ''\n",
            job,
            "publisher job must disable inherited OpenSSL configuration before any action, shell, Git, Node, or Python execution",
        )


if __name__ == "__main__":
    unittest.main()
