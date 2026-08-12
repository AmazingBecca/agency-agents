from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/publish-retained-evidence.yml").read_text(
    encoding="utf-8"
)


class PublisherWorkflowAmbientExecutionAuthorityTests(unittest.TestCase):
    def _publish_job_prefix(self) -> str:
        return WORKFLOW.split("  publish:\n", 1)[1].split("    steps:\n", 1)[0]

    def _source_fetch_step(self) -> str:
        return WORKFLOW.split(
            "      - name: Fetch exact public publisher source without caller credentials\n",
            1,
        )[1].split("      - uses: actions/setup-python@", 1)[0]

    def test_job_neutralizes_shell_and_dynamic_loader_startup_authority(self) -> None:
        job = self._publish_job_prefix()
        for name in (
            "BASH_ENV",
            "ENV",
            "LD_PRELOAD",
            "LD_AUDIT",
            "LD_LIBRARY_PATH",
            "PYTHONHOME",
            "PYTHONPATH",
            "PYTHONSTARTUP",
        ):
            self.assertIn(
                f"      {name}: ''\n",
                job,
                f"publisher job must neutralize inherited {name} before its first shell or executable",
            )

    def test_git_source_fetch_ignores_inherited_config_authority(self) -> None:
        job = self._publish_job_prefix()
        expected = {
            "GIT_CONFIG_NOSYSTEM": "'1'",
            "GIT_CONFIG_GLOBAL": "'/dev/null'",
            "GIT_CONFIG_SYSTEM": "'/dev/null'",
            "GIT_CONFIG_COUNT": "'0'",
            "GIT_CONFIG_PARAMETERS": "''",
        }
        for name, value in expected.items():
            self.assertIn(
                f"      {name}: {value}\n",
                job,
                f"publisher job must pin {name} before git init/fetch/checkout",
            )

    def test_git_init_cannot_inherit_template_hook_or_repository_redirection_authority(self) -> None:
        fetch = self._source_fetch_step()
        git_init = fetch.index("git init .")
        before_init = fetch[:git_init]
        self.assertIn(
            "unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY "
            "GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_TEMPLATE_DIR",
            before_init,
        )
        self.assertIn(
            'template_dir="$RUNNER_TEMP/intelligence-os-empty-git-template"',
            before_init,
        )
        self.assertIn('mkdir -m 0700 "$template_dir"', before_init)
        self.assertIn('export GIT_TEMPLATE_DIR="$template_dir"', before_init)
        self.assertIn("test ! -e .git/hooks", fetch[git_init:])

    def test_credential_scrub_still_precedes_git_repository_creation(self) -> None:
        fetch = self._source_fetch_step()
        self.assertLess(fetch.index("unset GITHUB_TOKEN GH_TOKEN"), fetch.index("git init ."))
        self.assertIn("-c credential.helper= -c http.extraHeader= fetch", fetch)


if __name__ == "__main__":
    unittest.main()
